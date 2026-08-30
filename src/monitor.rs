use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc as blocking_mpsc};
use std::time::{Duration, Instant};

use anime_game_data::AnimeGameData;
use anyhow::{Context, Result, anyhow};
use auto_artifactarium::{
    CommandMatch, ConnectionPacket, GameCommand, GamePacket, GameSniffer, classify_command,
};
use base64::prelude::*;
use chrono::prelude::*;
use flate2::read::GzDecoder;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::capture::{self, BackendType, CaptureSource, create_capture};
use crate::game_watch::{self, GameStatus, GameWatch, SystemProcessDetector};
use crate::player_data::PlayerData;
use crate::{AppState, DataUpdated, Message, State};

/// How long the automation trigger waits after the last new data before it
/// exports. A login burst arrives over several seconds, so exporting on the
/// first packet would snapshot a half-parsed account.
const AUTOMATION_DEBOUNCE: Duration = Duration::from_secs(5);

/// Whole-request timeout for a tracker call that only asks a question.
///
/// `reqwest::Client` has no timeout of its own, so a wedged self-hosted backend
/// used to hang the verify task -- and the "Verifying key…" modal with it -- for
/// the rest of the process's life.
const TRACKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Whole-request timeout for a snapshot upload, replacing
/// [`TRACKER_REQUEST_TIMEOUT`] on that one request.
///
/// An upload is not a question: the tracker parses the GOOD JSON, hashes every
/// artifact and runs the Prisma upserts *inside* the request, so a first
/// full-inventory import against a slow self-hosted Postgres can legitimately
/// run for minutes. Holding it to the verify budget would fail uploads that
/// used to succeed, which is the whole reason this is a separate number.
const TRACKER_UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// Connect timeout for every tracker call.
///
/// Covers only the TCP/TLS phase -- it does not bound the request body -- so an
/// unreachable host fails fast while a reachable but slow one still gets the
/// whole-request budget above.
const TRACKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a cancelled capture task to actually finish before
/// building its replacement.
///
/// `CancellationToken::cancel` only *signals*; the backend is released when the
/// task's `Drop` runs, and on Windows pktmon opens a fixed global ETW session
/// (`"PktMon Rust"`), so a replacement built before that teardown completes can
/// lose the race for the session and then capture nothing, silently, forever.
///
/// `app::MONITOR_SHUTDOWN_TIMEOUT` -- the deadline `IrminsulApp::drop` gives
/// the whole monitor thread -- is derived from this and must stay strictly
/// larger than it, or a teardown spending its full budget here is detached
/// at the moment it would have succeeded. `app.rs` mirrors the value and a
/// test there checks the two against this line.
const CAPTURE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Undecoded packets queued for the sniffer thread before it is worth saying so.
///
/// The queue is deliberately unbounded: KCP delivery is strictly ordered and
/// this app is a passive listener that can never ask for a retransmit, so
/// *dropping* a packet stalls that direction of the stream permanently. Falling
/// behind costs memory; dropping costs the rest of the session.
const PACKET_BACKLOG_WARN: usize = 8192;

/// How often the game's process list entry is looked for.
///
/// Two seconds is fast enough that the status line follows a game launch while
/// the splash screen is still up, and slow enough to be free: one tick is a
/// process-name scan with every expensive refresh turned off (see
/// [`game_watch::SystemProcessDetector`]). It deliberately runs in the
/// monitor's `select!` loop rather than on the UI thread, where it would run
/// per frame.
const GAME_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Raw packet logs kept, newest first, including the one being written.
///
/// `rotate_logs` only sweeps `log_dir()`; the packet log lives under
/// `storage_dir(APP_ID)/packet_log`, a tree nothing else touches, so it prunes
/// itself. These files are decrypted account data, so keeping them forever is a
/// privacy problem as much as a disk one.
const PACKET_LOG_RETENTION: usize = 6;

struct AppStateManager {
    app_state: AppState,
    state_tx: watch::Sender<AppState>,
}

impl AppStateManager {
    fn new(app_state: AppState, state_tx: watch::Sender<AppState>) -> Self {
        Self {
            app_state,
            state_tx,
        }
    }

    pub fn update_app_state(&mut self, state: State) {
        self.app_state.state = state;
        let _ = self.state_tx.send(self.app_state.clone());
    }

    pub fn update_capturing_state(&mut self, capturing: bool) {
        self.app_state.capturing = capturing;
        let _ = self.state_tx.send(self.app_state.clone());
    }

    pub fn update_timestamps(&mut self, updated: DataUpdated) {
        self.app_state.updated = updated;
        let _ = self.state_tx.send(self.app_state.clone());
    }

    /// Publish a new game status, and only a *new* one.
    ///
    /// Unlike the other setters this one is driven by a timer rather than by an
    /// event, and every send wakes the repaint task on the other end of the
    /// watch channel. Sending an unchanged status would repaint the window
    /// twice a second for as long as the app is open.
    pub fn update_game_status(&mut self, game_status: GameStatus) {
        if self.app_state.game_status == game_status {
            return;
        }
        // Logged because this line makes a claim about why a capture is or is
        // not working, and when it gets that wrong the only way to tell what it
        // saw is from the log a user can send back.
        tracing::info!(
            from = ?self.app_state.game_status,
            to = ?game_status,
            "game status changed"
        );
        self.app_state.game_status = game_status;
        let _ = self.state_tx.send(self.app_state.clone());
    }
}

/// Where the outcome of a tracker upload should be reported.
///
/// Both upload paths run the same request; only the reporting differs, and
/// keeping them in one function is what stops them drifting apart again (the
/// repo's own `CLAUDE.md` calls the duplication out).
enum UploadReport {
    /// Answer the UI's oneshot. `app.rs` turns it into a toast and drops the
    /// verified state when it recognises a 401/403.
    Reply(oneshot::Sender<std::result::Result<(), String>>),
    /// An automated upload nobody is waiting on: toast it directly, and hand
    /// the snapshot's signature back on failure so it can be retried.
    Toast {
        retry_tx: mpsc::UnboundedSender<AutomationSignature>,
        signature: AutomationSignature,
    },
}

/// The three timestamps that identify one snapshot of captured data.
///
/// An export is suppressed while this still matches the last one that
/// succeeded, so it doubles as the retry token: clearing it lets the same data
/// be exported again.
type AutomationSignature = (Option<Instant>, Option<Instant>, Option<Instant>);

/// What a capture task reports to the monitor.
///
/// [`CaptureEvent::Started`] exists so `capturing` can be set when the backend
/// actually exists rather than when its task is spawned -- the failure path is
/// entirely inside the task, so spawning proves nothing.
enum CaptureEvent {
    Started,
    Packet(Vec<u8>),
    Failed(anyhow::Error),
}

/// Handle to the thread that owns the [`GameSniffer`].
struct SnifferThread {
    packet_tx: blocking_mpsc::Sender<Vec<u8>>,
    /// Packets handed over but not yet decoded.
    queued: Arc<AtomicUsize>,
}

/// What the sniffer thread sends back.
///
/// The [`GameSniffer`] itself never crosses the channel, so its session state
/// has to be reported alongside the packets rather than queried by the monitor.
enum SnifferEvent {
    /// auto-artifactarium concluded that the game connection restarted. Always
    /// sent *before* the packet that concluded it.
    SessionReset,
    Packet(GamePacket),
}

/// Move packet decoding off the monitor's `select!` loop.
///
/// Recovering a session key can take seconds -- it is a search over candidate
/// send times -- and running that inline in a `select!` arm made every other arm
/// wait for it: cancellation, Stop Capture, and every export or upload request
/// the UI is holding a channel open for. The sniffer therefore lives on its own
/// thread, handed raw frames and sending decoded packets back, so a slow decode
/// delays nothing but decoding.
fn spawn_sniffer_thread(
    mut sniffer: GameSniffer,
    decoded_tx: mpsc::UnboundedSender<SnifferEvent>,
) -> Result<SnifferThread> {
    let (packet_tx, packet_rx) = blocking_mpsc::channel::<Vec<u8>>();
    let queued = Arc::new(AtomicUsize::new(0));
    let thread_queued = Arc::clone(&queued);

    std::thread::Builder::new()
        .name("irminsul-sniffer".to_string())
        .spawn(move || {
            let mut last_generation = sniffer.session_generation();
            // Ends when the monitor drops its sender, i.e. when the app exits.
            while let Ok(packet) = packet_rx.recv() {
                let delivered =
                    decode_one_packet(&mut sniffer, &mut last_generation, packet, &decoded_tx);
                thread_queued.fetch_sub(1, Ordering::Relaxed);
                if !delivered {
                    break;
                }
            }
            tracing::info!("sniffer thread exiting");
        })
        .context("Unable to start the packet decoding thread")?;

    Ok(SnifferThread { packet_tx, queued })
}

/// Decode one captured frame and forward everything it produced.
///
/// Returns `false` once the monitor is gone and the thread should stop.
///
/// The session reset is sent *before* the decoded packet, and that ordering is
/// the point of this function existing separately: one `receive_packet` call can
/// both conclude the connection restarted and return the first commands of the
/// new connection, and those commands must not land in the old account's maps.
///
/// `session_generation` is read rather than
/// [`ConnectionPacket::HandshakeRequested`] because the handshake datagram is
/// unauthenticated -- any local process can forge one with 20 bytes on a game
/// port -- while the generation moves only when auto-artifactarium has itself
/// corroborated the restart (a new KCP conversation, or the live session key
/// going dead). Latching on the raw event instead handed anyone a one-packet
/// "erase this user's capture" button, one layer above the library check that
/// exists to prevent exactly that.
fn decode_one_packet(
    sniffer: &mut GameSniffer,
    last_generation: &mut u64,
    packet: Vec<u8>,
    decoded_tx: &mpsc::UnboundedSender<SnifferEvent>,
) -> bool {
    let decoded = sniffer.receive_packet(packet);

    let generation = sniffer.session_generation();
    if generation != *last_generation {
        *last_generation = generation;
        if decoded_tx.send(SnifferEvent::SessionReset).is_err() {
            return false;
        }
    }

    match decoded {
        Some(decoded) => decoded_tx.send(SnifferEvent::Packet(decoded)).is_ok(),
        None => true,
    }
}

/// One binary record for the raw packet log.
///
/// `GameCommand::proto_data` is the payload *only* -- the `PacketHead` lives in
/// `proto_header` -- so the two are written with explicit lengths rather than
/// concatenated. Writing just the payload (what the matchers consume) would
/// quietly drop the envelope, and writing the two back to back would leave no
/// way to tell where one ends.
///
/// Layout, little endian: `command_id: u16`, `header_len: u32`, `data_len: u32`,
/// then the header and payload bytes.
fn encode_packet_log_record(command: &GameCommand) -> Vec<u8> {
    let header = &command.proto_header;
    let data = &command.proto_data;

    let mut record = Vec::with_capacity(10 + header.len() + data.len());
    record.extend_from_slice(&command.command_id.to_le_bytes());
    record.extend_from_slice(&(header.len() as u32).to_le_bytes());
    record.extend_from_slice(&(data.len() as u32).to_le_bytes());
    record.extend_from_slice(header);
    record.extend_from_slice(data);
    record
}

/// The raw packet log written while the "Log raw packets" power tool is on.
///
/// One appended-to file per session. This used to be one *file per command*,
/// each preceded by a known-folder lookup and a `create_dir_all`, on the
/// monitor's hot loop -- 4 KiB of NTFS allocation per decrypted command.
///
/// The directory is pruned to [`PACKET_LOG_RETENTION`] files when a session
/// first opens one; `main.rs::rotate_logs` cannot do it, because it only sweeps
/// `log_dir()` and this tree lives under `storage_dir(APP_ID)`.
struct PacketLog {
    /// `None` when the storage directory could not be resolved at all.
    dir: Option<PathBuf>,
    writer: Option<BufWriter<std::fs::File>>,
}

impl PacketLog {
    fn new() -> Self {
        Self::with_dir(crate::data_dir().ok().map(|mut path| {
            path.push("packet_log");
            path
        }))
    }

    fn with_dir(dir: Option<PathBuf>) -> Self {
        Self { dir, writer: None }
    }

    fn append(&mut self, command: &GameCommand) -> Result<()> {
        let record = encode_packet_log_record(command);

        let writer = match self.writer {
            Some(ref mut writer) => writer,
            None => {
                let file = self.open_file()?;
                self.writer.insert(BufWriter::new(file))
            }
        };

        writer.write_all(&record)?;
        // Buffered writing still beats the file-per-command this replaced by a
        // long way, but the log is only ever read after something went wrong,
        // so it must not lose its tail to a crash.
        writer.flush()?;
        Ok(())
    }

    fn open_file(&self) -> Result<std::fs::File> {
        let dir = self.dir.as_ref().context("Storage dir not found")?;
        std::fs::create_dir_all(dir).with_context(|| format!("can't create directory {dir:?}"))?;
        // Room is made *before* the new file exists, so the one about to be
        // written can never be the file that gets deleted.
        prune_packet_logs(dir, PACKET_LOG_RETENTION.saturating_sub(1));
        let path = dir.join(format!(
            "{}.bin",
            Local::now().format("%Y-%m-%d_%H-%M-%S%.3f")
        ));
        std::fs::File::create(&path).with_context(|| format!("can't create file {path:?}"))
    }
}

/// Delete all but the newest `keep` `*.bin` files in the packet-log directory.
///
/// Ordered by file *name*, not by mtime: the names are fixed-width
/// `%Y-%m-%d_%H-%M-%S%.3f` stamps, so lexicographic order is chronological
/// order, and unlike mtime it does not depend on the filesystem's timestamp
/// resolution or survive a copy that rewrites it.
///
/// Every failure here is ignored on purpose. Failing to tidy up is not a reason
/// to refuse to log.
fn prune_packet_logs(dir: &std::path::Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    let mut logs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("bin"))
        .collect();

    if logs.len() <= keep {
        return;
    }

    logs.sort_unstable_by(|a, b| b.file_name().cmp(&a.file_name()));
    for path in logs.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
}

/// First delay before restarting a capture that failed, doubling each further
/// consecutive failure up to [`CAPTURE_RETRY_MAX`].
///
/// Capture has no on/off control any more: it is meant to be running whenever
/// Irminsul is, so a backend that dies has to come back on its own. Common
/// causes are transient by nature -- an ETW session still held by a previous
/// process, an adapter going down with a VPN -- and retrying is what turns them
/// from "restart the app" into a pause nobody notices.
const CAPTURE_RETRY_BASE: std::time::Duration = std::time::Duration::from_secs(3);
/// Ceiling for the retry backoff, so a permanent failure (no elevation, no
/// capture device) settles into a slow poll instead of hammering the OS.
const CAPTURE_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to let a killed game process actually exit before re-deriving the
/// game status. See `Message::KillGame`.
const KILL_GAME_SETTLE: std::time::Duration = std::time::Duration::from_millis(400);

pub struct Monitor {
    app_state: AppStateManager,
    ui_message_rx: mpsc::UnboundedReceiver<Message>,
    log_packet_rx: watch::Receiver<bool>,
    player_data: PlayerData,
    /// `None` once the decoding thread has died. Nothing can be decoded after
    /// that, and the user has been told.
    sniffer: Option<SnifferThread>,
    decoded_rx: mpsc::UnboundedReceiver<SnifferEvent>,
    backlog_warned: bool,
    cancel_token: CancellationToken,
    capture_cancel_token: Option<CancellationToken>,
    capture_handle: Option<JoinHandle<Result<()>>>,
    packet_tx: mpsc::UnboundedSender<CaptureEvent>,
    packet_rx: mpsc::UnboundedReceiver<CaptureEvent>,
    capture_backend: BackendType,
    capture_source: CaptureSource,

    /// Did Irminsul watch the current game session start? Without that, the
    /// handshake -- and so the session key -- was missed and nothing will ever
    /// decrypt, however healthy the capture backend looks.
    /// When the supervisor may next try to bring capture back up.
    capture_retry_at: Option<Instant>,
    /// Consecutive capture failures, for the backoff.
    capture_failures: u32,
    game_watch: GameWatch,
    game_detector: SystemProcessDetector,
    game_poll: tokio::time::Interval,

    saved_state_rx: watch::Receiver<crate::app::SavedAppState>,
    toast_tx: mpsc::UnboundedSender<(String, bool)>,
    http: reqwest::Client,
    packet_log: PacketLog,

    /// When the newest captured data arrived, in epoch milliseconds. Uploaded as
    /// the snapshot's timestamp so the dashboard dates it by capture rather than
    /// by delivery.
    capture_timestamp_ms: Option<i64>,

    automation_pending_since: Option<Instant>,
    automation_last_signature: Option<AutomationSignature>,
    automation_cycle_started_at: Option<Instant>,
    /// A failed automated upload hands its signature back here so the same
    /// snapshot can be exported again. Without it one transient failure means
    /// no snapshot at all for that login.
    automation_retry_tx: mpsc::UnboundedSender<AutomationSignature>,
    automation_retry_rx: mpsc::UnboundedReceiver<AutomationSignature>,

    /// Debug builds keep a rolling pcapng of everything captured. One writer per
    /// *process*: it used to be one per capture task, which truncated the file
    /// on every capture restart.
    #[cfg(debug_assertions)]
    pcapng: Option<crate::pcapng::PcapngWriter>,

    ctx: egui::Context,
}

impl Monitor {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        cancel_token: CancellationToken,
        state_tx: watch::Sender<AppState>,
        mut ui_message_rx: mpsc::UnboundedReceiver<Message>,
        log_packet_rx: watch::Receiver<bool>,
        capture_backend: BackendType,
        capture_source: CaptureSource,
        saved_state_rx: watch::Receiver<crate::app::SavedAppState>,
        toast_tx: mpsc::UnboundedSender<(String, bool)>,
        ctx: egui::Context,
    ) -> Result<Self> {
        let mut app_state = AppStateManager::new(state_tx.borrow().clone(), state_tx.clone());
        let game_data = get_database(&mut app_state, &mut ui_message_rx).await?;
        let player_data = PlayerData::new(game_data);
        let keys = load_keys()?;
        let sniffer = GameSniffer::new().set_initial_keys(keys);
        let (packet_tx, packet_rx) = mpsc::unbounded_channel();
        let (decoded_tx, decoded_rx) = mpsc::unbounded_channel();
        let (automation_retry_tx, automation_retry_rx) = mpsc::unbounded_channel();
        let sniffer = spawn_sniffer_thread(sniffer, decoded_tx)?;

        // One client for the whole process: clones share its connection pool,
        // and building one per request was also how every tracker call ended up
        // with no timeout at all.
        let http = reqwest::Client::builder()
            .timeout(TRACKER_REQUEST_TIMEOUT)
            .connect_timeout(TRACKER_CONNECT_TIMEOUT)
            .build()
            .context("Unable to build the tracker HTTP client")?;

        #[cfg(debug_assertions)]
        let pcapng = crate::data_dir().ok().and_then(|mut path| {
            path.push("log");
            std::fs::create_dir_all(&path).ok()?;
            path.push("latest.pcapng");
            match crate::pcapng::PcapngWriter::new(path) {
                Ok(writer) => Some(writer),
                Err(e) => {
                    tracing::warn!("could not open the debug capture file: {e}");
                    None
                }
            }
        });

        // `interval` fires its first tick immediately, which is what makes
        // the "you started Irminsul second" case visible at startup rather than
        // two seconds into it. `Delay` keeps a monitor loop that was busy for
        // several seconds from answering with a burst of back-to-back scans.
        let mut game_poll = tokio::time::interval(GAME_POLL_INTERVAL);
        game_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        Ok(Self {
            app_state,
            player_data,
            ui_message_rx,
            log_packet_rx,
            sniffer: Some(sniffer),
            decoded_rx,
            backlog_warned: false,
            cancel_token,
            capture_cancel_token: None,
            capture_handle: None,
            packet_tx,
            packet_rx,
            capture_backend,
            capture_source,
            capture_retry_at: None,
            capture_failures: 0,
            game_watch: GameWatch::default(),
            game_detector: SystemProcessDetector::new(),
            game_poll,
            saved_state_rx,
            toast_tx,
            http,
            packet_log: PacketLog::new(),
            capture_timestamp_ms: None,
            automation_pending_since: None,
            automation_last_signature: None,
            automation_cycle_started_at: None,
            automation_retry_tx,
            automation_retry_rx,
            #[cfg(debug_assertions)]
            pcapng,
            ctx,
        })
    }

    pub async fn run(mut self) {
        self.app_state.update_app_state(State::Main);

        loop {
            // Checked before the `select!` rather than only inside it. On the
            // self-update restart path the token is already cancelled when
            // `run` is entered, and the startup `Message::StartCapture` is
            // already queued, so `select!` -- which picks pseudo-randomly among
            // ready branches -- would start a capture backend during shutdown
            // about half the time and then race the replacement process for the
            // device.
            if self.cancel_token.is_cancelled() {
                break;
            }

            let sleep_fut = async {
                if let Some(pending_since) = self.automation_pending_since {
                    let elapsed = pending_since.elapsed();
                    if let Some(rem) = AUTOMATION_DEBOUNCE.checked_sub(elapsed) {
                        tokio::time::sleep(rem).await;
                    }
                } else {
                    std::future::pending::<()>().await;
                }
            };

            #[rustfmt::skip]
            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    break;
                }
                _ = sleep_fut => {
                    self.execute_automation_export().await;
                }
                Some(event) = self.packet_rx.recv() => {
                    self.handle_capture_event(event);
                }
                Some(event) = self.decoded_rx.recv() => {
                    self.handle_sniffer_event(event);
                }
                Some(signature) = self.automation_retry_rx.recv() => {
                    self.release_automation_signature(signature);
                }
                _ = self.game_poll.tick() => {
                    self.poll_game_status();
                    self.supervise_capture().await;
                }
                capture_result = join_capture(&mut self.capture_handle) => {
                    self.handle_capture_exit(capture_result);
                }
                Some(msg) = self.ui_message_rx.recv() => self.handle_ui_msg(msg).await,
            }
        }

        // The backend is only released when the capture task's `Drop` runs, and
        // `main` does not wait for the tokio runtime to unwind before spawning
        // the replacement executable on the self-update path. Releasing the
        // device here is what keeps the two processes from fighting over it.
        self.stop_capture().await;
    }

    async fn handle_ui_msg(&mut self, msg: Message) {
        match msg {
            Message::StartCapture => self.start_capture().await,
            Message::StopCapture => {
                // Reported before the (bounded, but not instant) teardown, so
                // the UI reacts to the click rather than to the backend.
                self.set_capturing(false);
                self.stop_capture().await;
            }
            Message::ClearData => {
                self.reset_captured_data("clear data requested");
            }
            Message::KillGame(reply_tx) => {
                let killed = self.game_detector.kill_game_processes();
                tracing::info!("Kill game requested: {killed} game process(es) terminated");

                // The kill is asynchronous at the OS level, so an immediate
                // rescan can still see the dying process and leave the status
                // line stuck on the very warning the user just acted on. One
                // short wait is enough, and it costs a user-initiated click's
                // worth of latency on this loop rather than a poll interval's
                // worth of a stale, alarming line.
                tokio::time::sleep(KILL_GAME_SETTLE).await;
                self.poll_game_status();

                let _ = reply_tx.send(killed);
                self.ctx.request_repaint();
            }
            Message::ExportGenshinOptimizer(settings, reply_tx) => {
                let result = match self
                    .player_data
                    .export_genshin_optimizer_with_report(&settings)
                {
                    Ok((json, report)) => {
                        self.report_export_gaps(&report);
                        Ok(json)
                    }
                    Err(e) => Err(e),
                };
                let _ = reply_tx.send(result);
                self.ctx.request_repaint();
            }
            Message::ExportAchievements(reply_tx) => {
                let _ = reply_tx.send(self.player_data.export_achievements());
                self.ctx.request_repaint();
            }
            Message::FindWishUrl(reply_tx) => {
                let ctx = self.ctx.clone();
                tokio::spawn(async move {
                    let _ = reply_tx.send(crate::wish::force_find_url().await);
                    ctx.request_repaint();
                });
            }
            Message::VerifyTrackerKey(url, key, reply_tx) => {
                let ctx = self.ctx.clone();
                let client = self.http.clone();
                tokio::spawn(async move {
                    let _ = reply_tx.send(verify_tracker_key(&client, &url, &key).await);
                    ctx.request_repaint();
                });
            }
            Message::UploadToTracker(json, url, key, reply_tx) => {
                self.spawn_tracker_upload(url, key, json, UploadReport::Reply(reply_tx));
            }
            _ => (),
        }
    }

    /// Start a capture backend, replacing any that is still running.
    async fn start_capture(&mut self) {
        if self.capture_cancel_token.is_some() || self.capture_handle.is_some() {
            tracing::warn!("Capture start request with a capture already running. Replacing it.");
        }
        self.stop_capture().await;

        let cancel_token = CancellationToken::new();
        let capture_handle = tokio::spawn(capture_task(
            cancel_token.clone(),
            self.packet_tx.clone(),
            self.capture_backend,
            self.capture_source.clone(),
        ));
        self.capture_cancel_token = Some(cancel_token);
        self.capture_handle = Some(capture_handle);
        self.automation_cycle_started_at = Some(Instant::now());
        // Not `true`: everything that can fail -- no elevation, no such device,
        // an ETW session already owned by a previous process -- fails inside the
        // task, so a spawned task is not a running capture. The task says so
        // itself with `CaptureEvent::Started`.
        self.set_capturing(false);
    }

    /// Bring capture back up if it is not running.
    ///
    /// Capture is always-on: there is no user control for it, so nothing else
    /// would ever restart a backend that died. Driven from the game-status poll
    /// rather than a timer of its own, because that already ticks at a sensible
    /// rate and this only has to be approximately prompt.
    async fn supervise_capture(&mut self) {
        if self.capture_handle.is_some() || self.cancel_token.is_cancelled() {
            return;
        }
        if self.capture_retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }

        let attempt = self.capture_failures.saturating_add(1);
        tracing::info!(attempt, "restarting packet capture");
        self.start_capture().await;

        // Armed before the outcome is known: if this attempt also fails, the
        // next one has to wait. `CaptureEvent::Started` clears it.
        let backoff = CAPTURE_RETRY_BASE
            .saturating_mul(1u32 << self.capture_failures.min(4))
            .min(CAPTURE_RETRY_MAX);
        self.capture_failures = attempt;
        self.capture_retry_at = Some(Instant::now() + backoff);
    }

    /// Cancel the capture task *and wait for it to finish*.
    ///
    /// The wait is the point: the backend is only released when the task's
    /// `Drop` runs, so a replacement started before that races the corpse of its
    /// predecessor for a device (pcap) or for a fixed-name ETW session (pktmon),
    /// and loses without saying anything.
    async fn stop_capture(&mut self) {
        if let Some(cancel_token) = self.capture_cancel_token.take() {
            cancel_token.cancel();
        }
        let Some(handle) = self.capture_handle.take() else {
            return;
        };

        match tokio::time::timeout(CAPTURE_SHUTDOWN_TIMEOUT, handle).await {
            Ok(result) => self.report_capture_exit(result),
            Err(_) => tracing::warn!(
                "capture task did not stop within {CAPTURE_SHUTDOWN_TIMEOUT:?}; \
                 continuing without it"
            ),
        }
    }

    fn handle_capture_event(&mut self, event: CaptureEvent) {
        match event {
            // Every capture task shares one channel, so a `Started` from a task
            // that has since been stopped can still be queued behind its own
            // packets. Reporting that as "capturing" would put the lie the
            // status line used to tell straight back into it.
            CaptureEvent::Started if self.capture_handle.is_some() => {
                tracing::info!("capture backend is running");
                // It came up, so the next failure starts its backoff from
                // scratch rather than inheriting a long delay from an outage
                // that is over.
                self.capture_failures = 0;
                self.capture_retry_at = None;
                self.set_capturing(true);
                self.ctx.request_repaint();
            }
            CaptureEvent::Started => {
                tracing::debug!("ignoring a start report from a capture that already stopped");
            }
            CaptureEvent::Packet(packet) => self.handle_packet(packet),
            CaptureEvent::Failed(e) => {
                tracing::error!("Capture task encountered an error: {e}");
                let _ = self
                    .toast_tx
                    .send((format!("Packet capture stopped: {e}"), true));
                self.set_capturing(false);
                self.capture_cancel_token = None;
                self.ctx.request_repaint();
            }
        }
    }

    /// The capture task ended.
    ///
    /// Anything but a clean end is worth a toast: this used to be a `JoinHandle`
    /// nobody ever read, so a backend that failed to start -- or a task that
    /// panicked -- left the UI claiming to be capturing, with no log line, no
    /// toast, and nothing to notice.
    fn handle_capture_exit(&mut self, result: std::result::Result<Result<()>, JoinError>) {
        // A completed `JoinHandle` panics when polled again.
        self.capture_handle = None;
        self.capture_cancel_token = None;
        self.report_capture_exit(result);
        self.set_capturing(false);
        self.ctx.request_repaint();
    }

    fn report_capture_exit(&self, result: std::result::Result<Result<()>, JoinError>) {
        match result {
            Ok(Ok(())) => tracing::info!("capture task finished"),
            Ok(Err(e)) => {
                tracing::error!("capture task ended with an error: {e}");
                let _ = self
                    .toast_tx
                    .send((format!("Packet capture stopped: {e}"), true));
            }
            Err(e) => {
                tracing::error!("capture task did not finish cleanly: {e}");
                let _ = self.toast_tx.send((
                    "Packet capture stopped unexpectedly. See the log for details.".to_string(),
                    true,
                ));
            }
        }
    }

    /// Report the capture backend's state, and re-judge the game against it.
    ///
    /// The two travel together deliberately. Capture stopping while the game
    /// keeps running is precisely what turns a capturable session into an
    /// uncapturable one -- KCP is strictly ordered and this app can never ask
    /// for a retransmit -- so the verdict has to move with the backend rather
    /// than wait out a poll interval and let the line lag the button.
    fn set_capturing(&mut self, capturing: bool) {
        self.app_state.update_capturing_state(capturing);
        let game_status = self.game_watch.recheck(capturing);
        self.app_state.update_game_status(game_status);
    }

    /// Look for the game process and publish what its presence means.
    ///
    /// Nothing here talks to the UI directly: the status goes out on the
    /// `AppState` watch channel, and the repaint task `app.rs` already runs on
    /// the other end does the rest.
    fn poll_game_status(&mut self) {
        let first_look = !self.game_watch.has_polled();
        let capturing = self.app_state.app_state.capturing;
        let status = self.game_watch.poll(&mut self.game_detector, capturing);

        // The two facts that explain any wrong verdict: whether the scan can
        // name the game's process on this machine at all, and how stale the
        // "data decrypting" claim is.
        tracing::debug!(
            ?status,
            capturing,
            scan_ever_found_game = self.game_watch.scan_ever_found_game(),
            decoded_age_secs = self.game_watch.decoded_age().map(|d| d.as_secs()),
            "game poll"
        );

        // Once, and only from the very first look. The user-facing notification
        // is `app.rs`'s modal, which offers the three ways out; this is the log
        // record, so a support log still shows why a session captured nothing.
        // Matched on the specific cause, not on `LaunchMissed(_)`: the toast
        // below says "already running" in so many words, and that is the only
        // verdict a first look can reach today. Pinning it here means a later
        // change to the transition table cannot quietly put the wrong sentence
        // in front of the user.
        if first_look
            && matches!(
                status,
                GameStatus::LaunchMissed(game_watch::MissedLaunch::AlreadyRunning)
            )
        {
            tracing::warn!(
                "Genshin was already running when Irminsul started: the login handshake, and \
                 with it the session key, was missed, so nothing from this game session can be \
                 decrypted"
            );
        }

        self.app_state.update_game_status(status);
    }

    /// Hand a captured frame to the sniffer thread.
    fn handle_packet(&mut self, packet: Vec<u8>) {
        #[cfg(debug_assertions)]
        if let Some(writer) = self.pcapng.as_mut() {
            // Nanoseconds: `pcapng.rs` declares `if_tsresol = 9` in the
            // interface description block.
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since_epoch| since_epoch.as_nanos() as u64)
                .unwrap_or_default();
            let _ = writer.write_packet(ts, &packet);
        }

        let Some(sniffer) = self.sniffer.as_ref() else {
            return;
        };

        let queued = sniffer.queued.fetch_add(1, Ordering::Relaxed) + 1;
        if queued >= PACKET_BACKLOG_WARN && !self.backlog_warned {
            self.backlog_warned = true;
            tracing::warn!(queued, "packet decoding is falling behind capture");
        } else if self.backlog_warned && queued < PACKET_BACKLOG_WARN / 2 {
            self.backlog_warned = false;
        }

        if sniffer.packet_tx.send(packet).is_err() {
            self.sniffer = None;
            tracing::error!("the packet decoding thread is gone; no further data can be captured");
            let _ = self.toast_tx.send((
                "Packet decoding stopped. Restart Irminsul to capture again.".to_string(),
                true,
            ));
            self.set_capturing(false);
            self.ctx.request_repaint();
        }
    }

    fn handle_sniffer_event(&mut self, event: SnifferEvent) {
        match event {
            // Sent by the sniffer thread before any packet from the new
            // connection, so nothing from the new account can land in the old
            // account's maps. Captured state is insert-only, so without this a
            // second account logged in without restarting Irminsul uploads the
            // *union* of both inventories to whichever tracker account holds the
            // import key.
            SnifferEvent::SessionReset => self.reset_captured_data("new game session"),
            SnifferEvent::Packet(packet) => self.handle_game_packet(packet),
        }
    }

    fn handle_game_packet(&mut self, game_packet: GamePacket) {
        let commands = match game_packet {
            GamePacket::Commands(commands) => commands,
            GamePacket::Connection(conn) => {
                self.handle_connection_packet(&conn);
                return;
            }
        };

        // Non-empty is the whole point: a bare KCP ACK decodes to
        // `Commands(vec![])` with no key involved at all, while an actual
        // command batch means the XOR stream decrypted and the protobuf parsed.
        // That is the only evidence this app has that the session key was
        // really recovered, so it is what the status line is allowed to claim
        // "decrypting" on.
        if !commands.is_empty() && self.game_watch.note_decoded_data() {
            let status = self.game_watch.status();
            self.app_state.update_game_status(status);
        }

        let log_packets = *self.log_packet_rx.borrow_and_update();

        let mut updated = self.app_state.app_state.updated.clone();
        let mut has_new_data = false;
        let now = Instant::now();

        for command in commands {
            let _span = tracing::info_span!("command", id = command.command_id).entered();
            if log_packets && let Err(e) = self.packet_log.append(&command) {
                tracing::info!("error logging command {e}");
            }

            // One classification pass instead of an `else if` chain of matchers:
            // the chain could not notice that two of them claimed the same
            // command, which is exactly how a shape collision turns into
            // silently missing data.
            match classify_command(&command) {
                Some(CommandMatch::Items(items)) => {
                    tracing::info!("Found item packet with {} items", items.len());
                    self.player_data.process_items(&items);
                    updated.items_updated = Some(now);
                    has_new_data = true;
                }
                Some(CommandMatch::Properties(properties)) => {
                    tracing::info!("Found properties packet: {:?}", properties);
                    self.player_data.process_properties(&properties);
                    // Deliberately stamps no timestamp: a property packet used
                    // to set `items_updated`, so the UI's "Items" tick and the
                    // export/upload readiness gate could both be green with not
                    // one item ever parsed.
                    has_new_data = true;
                }
                Some(CommandMatch::Avatars(avatars)) => {
                    tracing::info!("Found avatar packet with {} avatars", avatars.len());
                    self.player_data.process_characters(&avatars);
                    updated.characters_updated = Some(now);
                    has_new_data = true;
                }
                Some(CommandMatch::Achievements(achievements)) => {
                    tracing::info!(
                        "Found achievement packet with {} achievements",
                        achievements.len()
                    );
                    self.player_data.process_achievements(&achievements);
                    updated.achievements_updated = Some(now);
                    updated.achievements_updated_time = Some(chrono::Local::now());
                    has_new_data = true;
                }
                _ => {}
            }
        }

        if has_new_data {
            self.capture_timestamp_ms = Some(Local::now().timestamp_millis());
            self.app_state.update_timestamps(updated);
            self.check_automation_trigger();
        }
    }

    /// Log a connection event. Deliberately does not touch captured data.
    ///
    /// None of these packets is authenticated: any process able to put a 20-byte
    /// datagram on a game port produces a `HandshakeRequested` or a
    /// `Disconnected`, so resetting on one is a one-packet "erase this user's
    /// capture" button -- and the "wait for the next command" latch that used to
    /// stand in for authentication was no protection either, since an ACK of the
    /// *still-live* session decodes to `Commands(vec![])` and consumed it.
    ///
    /// The reset now rides on [`SnifferEvent::SessionReset`], which
    /// auto-artifactarium only raises once it has corroborated the reconnect.
    /// A real disconnect is always followed by the handshake it corroborates,
    /// so nothing is lost by ignoring these here.
    fn handle_connection_packet(&mut self, conn: &ConnectionPacket) {
        match conn {
            ConnectionPacket::HandshakeRequested => {
                tracing::info!("Connection: Handshake Requested");
            }
            ConnectionPacket::HandshakeEstablished => {
                tracing::info!("Connection: Handshake Established")
            }
            ConnectionPacket::Disconnected => {
                tracing::info!("Connection: Disconnected");
            }
            // A KCP segment that did not complete a command.
            _ => {}
        }
    }

    /// Forget everything captured about the account.
    fn reset_captured_data(&mut self, reason: &str) {
        tracing::info!(reason, "clearing captured data");
        self.player_data.reset();
        // Nothing has decoded for whatever comes next, so the status line drops
        // back to what the process transitions can prove on their own.
        if self.game_watch.note_data_cleared() {
            let status = self.game_watch.status();
            self.app_state.update_game_status(status);
        }
        self.app_state.update_timestamps(DataUpdated::new());
        self.capture_timestamp_ms = None;
        // Without these the signature check can suppress the first export after
        // an account switch, because it still matches the previous account's.
        self.automation_pending_since = None;
        self.automation_last_signature = None;
        self.automation_cycle_started_at = Some(Instant::now());
        self.ctx.request_repaint();
    }

    /// Tell the user when an export silently left entities out.
    ///
    /// The game data is baked in at build time, so after a Genshin version bump
    /// a brand new character or artifact set simply vanishes from the snapshot
    /// -- indistinguishable, on the dashboard, from never having owned it.
    fn report_export_gaps(&self, report: &crate::player_data::ExportReport) {
        if report.is_empty() {
            return;
        }
        tracing::warn!("export dropped entities: {}", report.summary());
        let _ = self
            .toast_tx
            .send((format!("Export incomplete: {}", report.summary()), true));
    }

    fn check_automation_trigger(&mut self) {
        let saved_state = self.saved_state_rx.borrow().clone();
        let want_file = saved_state.save_result_to_file;
        // The same predicate the manual upload button uses. This used to omit
        // `tracker_verified`, so a key the dashboard had revoked still got a
        // POST on every login.
        let want_tracker = crate::app::want_tracker_upload(&saved_state);

        if !want_file && !want_tracker {
            self.automation_pending_since = None;
            return;
        }

        let updated = &self.app_state.app_state.updated;

        let Some(cycle_started) = self.automation_cycle_started_at else {
            return;
        };
        // Only the data classes this export will actually write, and all of
        // them captured since the current capture cycle began. Demanding
        // achievements as well -- as this and both manual export gates used to
        // -- meant an account whose achievement packet was never identified got
        // no automated export at all, not even of the characters and artifacts
        // it did capture.
        let classes = crate::app::export_data_classes(&saved_state.export_settings, updated);
        if classes.is_empty()
            || !classes
                .iter()
                .all(|class| class.captured_at.is_some_and(|at| at > cycle_started))
        {
            return;
        }

        let signature = (
            updated.items_updated,
            updated.characters_updated,
            updated.achievements_updated,
        );

        // What stops an export repeating is this signature, not a capture
        // restart: the cycle only advances when genuinely new data arrives.
        if self.automation_last_signature == Some(signature) {
            return;
        }

        if self.automation_pending_since.is_none() {
            tracing::info!(
                "All automation triggers met! Starting {} second countdown...",
                AUTOMATION_DEBOUNCE.as_secs()
            );
            self.automation_pending_since = Some(Instant::now());
        }
    }

    /// Let a snapshot that failed to reach its destination be exported again.
    fn release_automation_signature(&mut self, signature: AutomationSignature) {
        if release_signature(&mut self.automation_last_signature, signature) {
            tracing::info!("automation export did not complete; it will be retried");
        }
    }

    async fn execute_automation_export(&mut self) {
        tracing::info!("Executing background automation export!");
        self.automation_pending_since = None;
        let saved_state = self.saved_state_rx.borrow().clone();

        let signature = (
            self.app_state.app_state.updated.items_updated,
            self.app_state.app_state.updated.characters_updated,
            self.app_state.app_state.updated.achievements_updated,
        );

        let (json, report) = match self
            .player_data
            .export_genshin_optimizer_with_report(&saved_state.export_settings)
        {
            Ok(export) => export,
            Err(e) => {
                let _ = self
                    .toast_tx
                    .send((format!("Failed to generate GO format: {}", e), true));
                // The signature is deliberately not recorded: a failed export
                // should be retried when the next data arrives.
                return;
            }
        };
        self.report_export_gaps(&report);
        // Recorded now so a second trigger for the same data cannot start a
        // second export while this one is in flight, and given back below (or
        // by `release_automation_signature`) if any half of it failed.
        self.automation_last_signature = Some(signature);

        if saved_state.save_result_to_file {
            match self.save_to_automation_file(&saved_state, &json) {
                Ok(path) => {
                    let _ = self
                        .toast_tx
                        .send((format!("Automation saved to {}", path.display()), false));
                }
                Err(e) => {
                    let _ = self
                        .toast_tx
                        .send((format!("Failed to save automation file: {}", e), true));
                    self.release_automation_signature(signature);
                }
            }
        }

        // Same predicate as the trigger above and as the manual button.
        if crate::app::want_tracker_upload(&saved_state) {
            let _ = self
                .toast_tx
                .send(("Uploading to Tracker...".to_string(), false));
            self.spawn_tracker_upload(
                import_url(&saved_state.tracker_api_url),
                saved_state.tracker_import_key.clone(),
                json,
                UploadReport::Toast {
                    retry_tx: self.automation_retry_tx.clone(),
                    signature,
                },
            );
        }

        // Capture is deliberately left running. Restarting it here used to make
        // the first automated export the last one of the game session: KCP
        // delivery is strictly ordered and this app can never ask for a
        // retransmit, so every segment missed during the restart stalled that
        // direction permanently -- with the UI still showing "Capturing".
        self.ctx.request_repaint();
    }

    fn save_to_automation_file(
        &self,
        saved_state: &crate::app::SavedAppState,
        json: &str,
    ) -> Result<std::path::PathBuf> {
        let output_dir = if let Some(folder) = &saved_state.save_result_folder {
            folder.clone()
        } else {
            let exe_path =
                std::env::current_exe().context("Unable to locate current executable")?;
            exe_path
                .parent()
                .map(|path| path.to_path_buf())
                .unwrap_or(std::env::current_dir()?)
        };

        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("Unable to create output directory {:?}", output_dir))?;
        let file_name = format!(
            "genshin_export_{}.json",
            chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
        );
        let path = output_dir.join(file_name);

        // `fs::write` rather than a `BufWriter`: the buffered version reported
        // success from `write_all`, leaving whatever was still in the buffer to
        // a `Drop` that discards its error.
        std::fs::write(&path, json).with_context(|| format!("Unable to write file {:?}", path))?;

        Ok(path)
    }

    fn spawn_tracker_upload(&self, url: String, key: String, json: String, report: UploadReport) {
        let client = self.http.clone();
        let ctx = self.ctx.clone();
        let toast_tx = self.toast_tx.clone();
        let captured_at = self.capture_timestamp_ms;

        tokio::spawn(async move {
            let result = upload_to_tracker(&client, &url, &key, json, captured_at).await;
            match report {
                UploadReport::Reply(reply_tx) => {
                    let _ = reply_tx.send(result);
                }
                UploadReport::Toast {
                    retry_tx,
                    signature,
                } => {
                    let _ = match result {
                        Ok(()) => toast_tx
                            .send(("Successfully auto-uploaded to Tracker".to_string(), false)),
                        Err(e) => {
                            let _ = retry_tx.send(signature);
                            toast_tx.send((format!("Tracker upload failed: {e}"), true))
                        }
                    };
                }
            }
            ctx.request_repaint();
        });
    }
}

/// Forget the recorded signature of an export that did not actually land.
///
/// The signature is what suppresses a repeat export, so leaving it recorded for
/// a failed one means the user gets no snapshot at all for that login:
/// `check_automation_trigger` refuses every later attempt for the same data, and
/// the data itself only changes at the next login.
///
/// Only clears the signature it was given. A newer export may already have
/// replaced it, and that one is not this failure's to cancel. `true` when
/// something was actually released.
fn release_signature(
    last_signature: &mut Option<AutomationSignature>,
    signature: AutomationSignature,
) -> bool {
    if *last_signature == Some(signature) {
        *last_signature = None;
        return true;
    }
    false
}

/// Await the capture task, or wait forever when there is none.
///
/// `select!` needs a future on every arm. The handle is cleared by the arm that
/// receives this, because polling a `JoinHandle` that has already completed
/// panics.
async fn join_capture(
    handle: &mut Option<JoinHandle<Result<()>>>,
) -> std::result::Result<Result<()>, JoinError> {
    match handle.as_mut() {
        Some(handle) => handle.await,
        None => std::future::pending().await,
    }
}

/// The tracker's snapshot import endpoint for a configured base URL.
fn import_url(base_url: &str) -> String {
    format!(
        "{}/genshin-accounts-public/import-by-key",
        base_url.trim_end_matches('/')
    )
}

/// POST a GOOD snapshot to the tracker.
///
/// The failure string is `HTTP {status} - {body}`, and that shape is load
/// bearing: `app.rs::tracker_error_status` parses the status back out of it to
/// notice a 401/403 and re-verify the key.
async fn upload_to_tracker(
    client: &reqwest::Client,
    url: &str,
    key: &str,
    json: String,
    captured_at_ms: Option<i64>,
) -> std::result::Result<(), String> {
    let part = reqwest::multipart::Part::bytes(json.into_bytes())
        .file_name("irminsul_capture.json")
        .mime_str("application/json")
        .map_err(|e| format!("could not build the upload body: {e}"))?;

    // Sent before the file part, because the backend reads it while streaming
    // the upload. Without it a snapshot is stamped with the server's receive
    // time, which both misdates a delayed upload and stops the server's
    // duplicate check from ever firing on a re-upload of unchanged data.
    let mut form = reqwest::multipart::Form::new();
    if let Some(captured_at_ms) = captured_at_ms {
        form = form.text("timestamp", captured_at_ms.to_string());
    }
    let form = form.part("file", part);

    let response = client
        .post(url)
        // Overrides the client-wide verify budget: see
        // [`TRACKER_UPLOAD_TIMEOUT`].
        .timeout(TRACKER_UPLOAD_TIMEOUT)
        .header("x-import-key", key)
        .multipart(form)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Tracker upload request failed: {e}");
            e.to_string()
        })?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status.is_success() {
        tracing::info!("Successfully uploaded data to tracker");
        Ok(())
    } else {
        tracing::error!("Tracker upload failed ({}): {}", status, body);
        Err(format!("HTTP {} - {}", status, body))
    }
}

/// Ask the tracker who an import key belongs to.
async fn verify_tracker_key(
    client: &reqwest::Client,
    url: &str,
    key: &str,
) -> Result<(String, String, String)> {
    let response = client
        .get(url)
        .header("x-import-key", key)
        .send()
        .await
        .map_err(|e| anyhow!("Request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| anyhow!("Failed to read response: {}", e))?;

    tracing::info!("Verify key response ({}): {}", status, body);
    if !status.is_success() {
        return Err(anyhow!("Verify failed: HTTP {}", status));
    }

    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| anyhow!("Invalid JSON response"))?;

    // Backend wraps responses in { data: { ... } }
    let inner = json.get("data").unwrap_or(&json);
    let name = inner
        .get("accountName")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();
    let uid = inner
        .get("uid")
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => "N/A".to_string(),
        })
        .unwrap_or_else(|| "N/A".to_string());
    let server = inner
        .get("server")
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_string();

    Ok((name, uid, server))
}

async fn get_database(
    app_state: &mut AppStateManager,
    _ui_message_rx: &mut mpsc::UnboundedReceiver<Message>,
) -> Result<AnimeGameData> {
    app_state.update_app_state(State::CheckingForData);

    static DATABASE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/game_data.gz"));
    let reader = GzDecoder::new(DATABASE);
    let db = anime_game_data::AnimeGameData::new_from_reader(reader)?;

    Ok(db)
}

async fn capture_task(
    cancel_token: CancellationToken,
    packet_tx: mpsc::UnboundedSender<CaptureEvent>,
    backend: BackendType,
    capture_source: capture::CaptureSource,
) -> Result<()> {
    let mut capture = match create_capture(backend, capture_source) {
        Ok(capture) => capture,
        Err(e) => {
            // Reported through the channel rather than out of the task: the
            // `JoinHandle` is watched now, but this is the arm that clears
            // `capturing` and toasts, and "not elevated" or "no such device" is
            // the most common first-run failure there is.
            let error = anyhow!("Error creating packet capture using {:?}: {e}", backend);
            tracing::error!("{error}");
            let _ = packet_tx.send(CaptureEvent::Failed(error));
            return Ok(());
        }
    };
    tracing::info!("starting capture");
    // Only now is there a backend to capture with. The monitor sets `capturing`
    // from this, not from having spawned the task.
    let _ = packet_tx.send(CaptureEvent::Started);

    loop {
        let packet = tokio::select!(
            packet = capture.next_packet() => packet,
            _ = cancel_token.cancelled() => break,
        );
        let packet = match packet {
            Ok(packet) => packet,
            Err(e) => {
                tracing::error!("Error receiving packet: {e}");
                let _ = packet_tx.send(CaptureEvent::Failed(anyhow!(
                    "Capture stream closed or errored: {e}"
                )));
                break;
            }
        };

        if let Err(e) = packet_tx.send(CaptureEvent::Packet(packet)) {
            tracing::error!("Error sending captured packet to monitor: {e}");
            break;
        }
    }
    tracing::info!("ending capture");
    Ok(())
}

fn load_keys() -> Result<HashMap<u16, Vec<u8>>> {
    let keys: HashMap<u16, String> = serde_json::from_slice(include_bytes!("../keys/gi.json"))?;

    keys.iter()
        .map(|(key, value)| -> Result<_, _> { Ok((*key, BASE64_STANDARD.decode(value)?)) })
        .collect::<Result<HashMap<_, _>>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(command_id: u16, header: &[u8], data: &[u8]) -> GameCommand {
        GameCommand {
            command_id,
            header_len: header.len() as u16,
            data_len: data.len() as u32,
            proto_header: header.to_vec(),
            proto_data: data.to_vec(),
        }
    }

    #[test]
    fn a_log_record_keeps_the_header_and_the_payload_apart() {
        let record = encode_packet_log_record(&command(4242, &[1, 2, 3], &[9, 8]));

        assert_eq!(record.len(), 10 + 3 + 2);
        assert_eq!(&record[0..2], &4242u16.to_le_bytes());
        assert_eq!(&record[2..6], &3u32.to_le_bytes());
        assert_eq!(&record[6..10], &2u32.to_le_bytes());
        assert_eq!(&record[10..13], &[1, 2, 3]);
        assert_eq!(&record[13..15], &[9, 8]);
    }

    #[test]
    fn a_log_record_with_no_header_is_still_self_describing() {
        // `proto_header` is empty for a command whose `header_len` was 0, and a
        // reader has to be able to tell that from a one-byte header.
        let record = encode_packet_log_record(&command(1, &[], &[7]));

        assert_eq!(record.len(), 10 + 1);
        assert_eq!(&record[2..6], &0u32.to_le_bytes());
        assert_eq!(&record[6..10], &1u32.to_le_bytes());
        assert_eq!(&record[10..11], &[7]);
    }

    #[test]
    fn the_packet_log_appends_to_one_file_per_session() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = PacketLog::with_dir(Some(dir.path().to_path_buf()));

        log.append(&command(1, &[], &[7])).unwrap();
        log.append(&command(2, &[], &[8, 8])).unwrap();

        let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert_eq!(files.len(), 1, "one file per session, not per command");

        let written = std::fs::read(files[0].path()).unwrap();
        assert_eq!(written.len(), (10 + 1) + (10 + 2));
        assert_eq!(&written[0..2], &1u16.to_le_bytes());
        assert_eq!(&written[11..13], &2u16.to_le_bytes());
    }

    #[test]
    fn the_packet_log_reports_an_unusable_directory_instead_of_panicking() {
        let mut log = PacketLog::with_dir(None);
        assert!(log.append(&command(1, &[], &[7])).is_err());
    }

    /// An Ethernet II / IPv4 / UDP frame around `payload`.
    ///
    /// Both checksums are left zero: `SlicedPacket::from_ethernet`, which is
    /// what auto-artifactarium parses with, does not verify them, and a zero UDP
    /// checksum means "not computed" over IPv4 anyway.
    fn udp_frame(src_port: u16, dest_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let total_len = 20 + udp_len;

        let mut frame = Vec::with_capacity(14 + total_len as usize);
        frame.extend_from_slice(&[1, 2, 3, 4, 5, 6]); // destination mac
        frame.extend_from_slice(&[7, 8, 9, 10, 11, 12]); // source mac
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype: ipv4

        frame.push(0x45); // version 4, 5 * 4 = 20 byte header
        frame.push(0); // dscp/ecn
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes()); // identification
        frame.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
        frame.push(64); // ttl
        frame.push(17); // protocol: udp
        frame.extend_from_slice(&0u16.to_be_bytes()); // header checksum
        frame.extend_from_slice(&[10, 0, 0, 2]); // source ip
        frame.extend_from_slice(&[10, 0, 0, 1]); // destination ip

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dest_port.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes()); // checksum
        frame.extend_from_slice(payload);
        frame
    }

    /// A connection-management datagram: 20 bytes led by a 4-byte big-endian
    /// code. This is the whole forgery -- nothing about it is authenticated, and
    /// a datagram sent *to* a game port counts just like one from it.
    fn connection_frame(code: u32) -> Vec<u8> {
        let mut payload = vec![0u8; 20];
        payload[..4].copy_from_slice(&code.to_be_bytes());
        udp_frame(50000, 22102, &payload)
    }

    fn handshake_frame() -> Vec<u8> {
        connection_frame(0xFF)
    }

    /// One segment in the game's KCP framing: `conv(4) extra(4) cmd(1) frg(1)
    /// wnd(2) ts(4) sn(4) una(4) len(4) extra(4) content`.
    fn segment_frame(conv: u32, content: &[u8]) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&conv.to_le_bytes());
        segment.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        segment.push(81); // cmd: push
        segment.push(0); // frg
        segment.extend_from_slice(&128u16.to_le_bytes()); // wnd
        segment.extend_from_slice(&0u32.to_le_bytes()); // ts
        segment.extend_from_slice(&0u32.to_le_bytes()); // sn
        segment.extend_from_slice(&0u32.to_le_bytes()); // una
        segment.extend_from_slice(&(content.len() as u32).to_le_bytes());
        segment.extend_from_slice(&0xFEED_FACEu32.to_le_bytes());
        segment.extend_from_slice(content);
        udp_frame(22102, 50000, &segment)
    }

    #[test]
    fn a_session_reset_reaches_the_monitor_before_the_packet_that_caused_it() {
        // One `receive_packet` can both conclude the connection restarted and
        // return the first commands of the new connection. If the reset arrived
        // second the monitor would wipe the new account's data instead of the
        // old account's.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sniffer = GameSniffer::new();
        let mut generation = sniffer.session_generation();

        assert!(decode_one_packet(
            &mut sniffer,
            &mut generation,
            handshake_frame(),
            &tx
        ));

        assert!(matches!(rx.try_recv(), Ok(SnifferEvent::SessionReset)));
        assert!(matches!(
            rx.try_recv(),
            Ok(SnifferEvent::Packet(GamePacket::Connection(
                ConnectionPacket::HandshakeRequested
            )))
        ));
        assert!(rx.try_recv().is_err());

        // The generation only moved once, so the reset is announced once.
        assert!(decode_one_packet(
            &mut sniffer,
            &mut generation,
            segment_frame(7, &[0u8; 40]),
            &tx
        ));
        assert!(matches!(rx.try_recv(), Ok(SnifferEvent::Packet(_))));
        assert!(
            rx.try_recv().is_err(),
            "one reset per session, not per packet"
        );
    }

    #[test]
    fn an_unauthenticated_connection_packet_does_not_ask_the_monitor_to_wipe_anything() {
        // The monitor used to latch a data reset on `Disconnected` -- as
        // forgeable as any other 20-byte datagram on a game port -- and then
        // spend the latch on the next `Commands`, which an ACK of the *live*
        // session satisfies with an empty vec. One datagram wiped a live
        // capture. Only a reset auto-artifactarium has corroborated counts now,
        // and a real disconnect is always followed by the handshake that
        // corroborates one.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sniffer = GameSniffer::new();
        let mut generation = sniffer.session_generation();

        // 404 is `Disconnected`; any other code is `HandshakeEstablished`.
        for code in [404, 1] {
            assert!(decode_one_packet(
                &mut sniffer,
                &mut generation,
                connection_frame(code),
                &tx
            ));
            assert!(matches!(
                rx.try_recv(),
                Ok(SnifferEvent::Packet(GamePacket::Connection(_)))
            ));
        }

        assert!(
            rx.try_recv().is_err(),
            "no reset without a corroborated reconnect"
        );
    }

    #[test]
    fn a_kcp_segment_that_restarts_nothing_announces_no_reset() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sniffer = GameSniffer::new();
        let mut generation = sniffer.session_generation();

        assert!(decode_one_packet(
            &mut sniffer,
            &mut generation,
            segment_frame(7, &[0u8; 40]),
            &tx
        ));

        assert!(matches!(rx.try_recv(), Ok(SnifferEvent::Packet(_))));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn the_packet_log_prunes_old_sessions_when_it_opens_a_new_one() {
        let dir = tempfile::tempdir().unwrap();
        for second in 0..10 {
            std::fs::write(
                dir.path()
                    .join(format!("2024-01-01_00-00-{second:02}.000.bin")),
                b"old",
            )
            .unwrap();
        }
        // Anything that is not a packet log is none of the pruner's business.
        std::fs::write(dir.path().join("notes.txt"), b"keep me").unwrap();

        let mut log = PacketLog::with_dir(Some(dir.path().to_path_buf()));
        log.append(&command(1, &[], &[7])).unwrap();
        // Pruning happens when the session's file is opened, not per record.
        log.append(&command(2, &[], &[8])).unwrap();

        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".bin"))
            .collect();
        names.sort();

        assert_eq!(names.len(), PACKET_LOG_RETENTION, "kept {names:?}");
        assert_eq!(names[0], "2024-01-01_00-00-05.000.bin", "oldest kept");
        assert!(
            !names.contains(&"2024-01-01_00-00-04.000.bin".to_string()),
            "the oldest sessions should be gone"
        );
        assert!(dir.path().join("notes.txt").exists());
    }

    #[test]
    fn a_failed_export_releases_its_signature_so_the_same_data_is_retried() {
        let signature = (Some(Instant::now()), None, None);
        let mut last = Some(signature);

        assert!(release_signature(&mut last, signature));
        assert_eq!(last, None, "the same snapshot must be exportable again");
    }

    #[test]
    fn a_failed_export_does_not_cancel_a_newer_one() {
        // The upload runs off the monitor loop, so its failure can arrive after
        // fresher data has already been exported. Clearing the signature then
        // would re-export data that did land.
        let stale = (Some(Instant::now()), None, None);
        let newer = (None, Some(Instant::now()), None);
        let mut last = Some(newer);

        assert!(!release_signature(&mut last, stale));
        assert_eq!(last, Some(newer));
    }

    #[test]
    fn the_import_url_is_the_same_with_or_without_a_trailing_slash() {
        let expected = "http://localhost:49000/genshin-accounts-public/import-by-key";
        assert_eq!(import_url("http://localhost:49000"), expected);
        assert_eq!(import_url("http://localhost:49000/"), expected);
        assert_eq!(import_url("http://localhost:49000///"), expected);
    }
}
