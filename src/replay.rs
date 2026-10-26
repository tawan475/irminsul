//! `--replay-export`: decode a packet recording without the app, and write the
//! export it yields.
//!
//! For debugging exports against a session that was recorded once (debug
//! builds record every captured frame to `irminsul-data/log/latest.pcapng`),
//! without asking anyone to log in again.
//!
//! The recording goes through the same decoding the live app runs --
//! [`monitor::decode_one_packet`] into a [`GameSniffer`] holding the baked-in
//! dispatch keys, so the session key is recovered from the recorded login;
//! [`monitor::classify_commands`]; the [`DataReplacement`] rules for
//! reconnects; [`monitor::apply_commands`] into a [`PlayerData`] -- and the
//! state at the end of the recording is exported as a tracker upload would be
//! ([`ExportSettings::for_tracker`]: everything, whatever the Genshin
//! Optimizer settings filter out).
//!
//! What a replay must never do, whatever the recording holds: upload anything
//! or ask the tracker about a key (the data is old, and would be filed under
//! today), save an automation file, check for or install an update, read or
//! write the app's saved settings or anything under its data directory, ask
//! for administrator rights, or take the single-instance lock (so it can run
//! beside a running Irminsul). That holds by construction rather than by a
//! flag: this module builds no HTTP client, no monitor, no window and no saved
//! state, and the tracker calls are private to `monitor.rs`, so they cannot be
//! reached from here. `main.rs` routes here before it takes the lock, rotates
//! the logs in the data directory or checks for elevation. A test below keeps
//! this file from growing a reference to any of those.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use auto_artifactarium::{CommandMatch, ConnectionPacket, GamePacket, GameSniffer, KeyState};
use tokio::sync::mpsc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use crate::good::Good;
use crate::live::{Action, BatchAnswer, ImportAnswer, LiveSync, Reason};
use crate::monitor::{
    self, AppliedData, DataReplacement, DataVerdict, KeyReport, SnifferEvent, SnifferStats,
};
use crate::player_data::{ExportSettings, PlayerData};
use crate::recording::{self, RecordedFrame, Recording};

/// Run a replay from the command line and return the process exit code: 0
/// when an export was written, 1 when nothing could be decoded or a file could
/// not be read or written.
pub fn run(recording: &Path, out: &Path) -> i32 {
    let log_path = log_path_for(out);
    init_tracing(&log_path);
    crate::crash::install_panic_hook();

    let code = match replay_to_file(recording, out) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("replay failed: {e:#}");
            1
        }
    };
    tracing::info!(log = %log_path.display(), "replay finished");
    code
}

/// `--replay-journal`: replay `recording` through live sync's sender, with
/// the recording's own clock and a stand-in tracker that stores everything,
/// and write what would have been sent to `out` (NDJSON): each snapshot as
/// uploaded, each batch, and the whole state just before each snapshot and
/// at the end. The tracker's `live-replay.test.ts` checks that every
/// snapshot with the batches after it gives each state (plan section 6.4).
/// Exit code as for [`run`].
pub fn run_journal(recording: &Path, out: &Path) -> i32 {
    run_journal_with(recording, out, |_| Ok(Box::new(StoreEverything::default())))
}

/// [`run_journal`] against the tracker `tracker` makes (once tracing is up).
pub(crate) fn run_journal_with(
    recording: &Path,
    out: &Path,
    tracker: impl FnOnce(&Path) -> Result<Box<dyn StandInTracker>>,
) -> i32 {
    let log_path = log_path_for(out);
    init_tracing(&log_path);
    crate::crash::install_panic_hook();

    let code = match tracker(recording)
        .and_then(|tracker| replay_journal_to_file(recording, out, tracker))
    {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("journal replay failed: {e:#}");
            1
        }
    };
    tracing::info!(log = %log_path.display(), "journal replay finished");
    code
}

/// `OUT_JSON.log`: next to the export, and never the export itself.
fn log_path_for(out: &Path) -> PathBuf {
    let mut name = out.file_name().unwrap_or_default().to_os_string();
    name.push(".log");
    out.with_file_name(name)
}

/// Log to stdout and to `log_path`, or to stdout alone when the file cannot
/// be created. `RUST_LOG` overrides the level, which is `info` by default.
fn init_tracing(log_path: &Path) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stdout = fmt::layer().with_writer(std::io::stdout).with_ansi(false);

    if let Some(dir) = log_path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(dir);
    }
    let (file, file_error) = match File::create(log_path) {
        Ok(file) => (
            Some(fmt::layer().with_writer(Mutex::new(file)).with_ansi(false)),
            None,
        ),
        Err(e) => (None, Some(e)),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout)
        .with(file)
        .init();
    if let Some(e) = file_error {
        tracing::warn!(
            "could not create the log file {}: {e}; logging to stdout only",
            log_path.display()
        );
    }
}

/// Replay `recording_path` and write its export to `out`.
fn replay_to_file(recording_path: &Path, out: &Path) -> Result<()> {
    tracing::info!(
        recording = %recording_path.display(),
        out = %out.display(),
        "replaying a recording: nothing is uploaded, and no app settings or data are read or written"
    );
    if is_same_file(recording_path, out) || is_same_file(recording_path, &log_path_for(out)) {
        bail!("the output would overwrite the recording itself");
    }

    let mut recording = Recording::open(recording_path)?;
    let player_data = PlayerData::new(monitor::load_game_data()?)
        .with_game_data_sha(monitor::embedded_game_data_sha());
    let sniffer = GameSniffer::new().set_initial_keys(monitor::load_keys()?);
    let mut replay = Replay::new(sniffer, player_data);

    loop {
        match recording.next_frame() {
            Ok(Some(frame)) => replay.feed(frame),
            Ok(None) => break,
            Err(e) => {
                // Nothing after a corrupt block can be trusted to line up, but
                // everything before it decoded fine and is worth exporting.
                tracing::error!(
                    frames = replay.frames,
                    "stopped reading the recording: {e:#}; exporting what came before"
                );
                break;
            }
        }
    }
    if recording.truncated() {
        tracing::warn!(
            "the recording ends part-way through a packet (is it still being written?); \
             everything before that was replayed"
        );
    }

    let good = replay.finish()?;
    let json = serde_json::to_string_pretty(&good)?;
    if let Some(dir) = out.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create the directory {}", dir.display()))?;
    }
    std::fs::write(out, json).with_context(|| format!("cannot write {}", out.display()))?;
    tracing::info!("wrote the export to {}", out.display());
    Ok(())
}

/// Replay `recording_path` through live sync and write the journal to `out`.
fn replay_journal_to_file(
    recording_path: &Path,
    out: &Path,
    tracker: Box<dyn StandInTracker>,
) -> Result<()> {
    tracing::info!(
        recording = %recording_path.display(),
        out = %out.display(),
        "replaying a recording through live sync: nothing is uploaded, and no app \
         settings or data are read or written"
    );
    if is_same_file(recording_path, out) || is_same_file(recording_path, &log_path_for(out)) {
        bail!("the output would overwrite the recording itself");
    }
    if let Some(dir) = out.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create the directory {}", dir.display()))?;
    }
    let file = File::create(out).with_context(|| format!("cannot write {}", out.display()))?;

    let mut recording = Recording::open(recording_path)?;
    let player_data = PlayerData::new(monitor::load_game_data()?)
        .with_game_data_sha(monitor::embedded_game_data_sha());
    let sniffer = GameSniffer::new().set_initial_keys(monitor::load_keys()?);
    let mut replay = Replay::new(sniffer, player_data);
    replay.journal = Some(JournalSim::new(BufWriter::new(file), tracker));

    loop {
        match recording.next_frame() {
            Ok(Some(frame)) => {
                let at = frame.timestamp_ns;
                replay.feed(frame);
                if let Some(ns) = at {
                    replay.advance_journal(ns / 1_000_000)?;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::error!(
                    frames = replay.frames,
                    "stopped reading the recording: {e:#}; keeping what came before"
                );
                break;
            }
        }
    }
    replay.finish_journal()
}

/// What a journal replay sends its snapshots and batches to.
pub(crate) trait StandInTracker {
    /// A snapshot upload of `good`: `None` when it failed.
    fn snapshot(&mut self, good: &Good) -> Option<ImportAnswer>;
    fn batch(&mut self, delta: &crate::delta::GoodDelta) -> BatchAnswer;
}

/// The stand-in `--replay-journal` uses: every snapshot is stored and gets
/// a journal, every batch is stored.
#[derive(Default)]
struct StoreEverything {
    bases: u64,
}

impl StandInTracker for StoreEverything {
    fn snapshot(&mut self, _: &Good) -> Option<ImportAnswer> {
        self.bases += 1;
        Some(ImportAnswer {
            base: Some(format!("replay{}", self.bases)),
            watching: false,
        })
    }

    fn batch(&mut self, _: &crate::delta::GoodDelta) -> BatchAnswer {
        BatchAnswer::Stored {
            collapse: false,
            watching: false,
        }
    }
}

/// Live sync's sender driven by a replay's clock, against a stand-in tracker.
struct JournalSim {
    live: LiveSync,
    tracker: Box<dyn StandInTracker>,
    out: BufWriter<File>,
    /// When the debounced automation export would run (5 s after data).
    automation_at: Option<u64>,
    /// The recording's clock, from the newest frame.
    now_ms: u64,
    snapshots: u64,
    batches: u64,
    changes: u64,
    states: u64,
    error: Option<anyhow::Error>,
}

/// How long the automation waits after the last data (monitor.rs).
const JOURNAL_DEBOUNCE_MS: u64 = 5_000;

impl JournalSim {
    fn new(out: BufWriter<File>, tracker: Box<dyn StandInTracker>) -> Self {
        Self {
            live: LiveSync::new(),
            tracker,
            out,
            automation_at: None,
            now_ms: 0,
            snapshots: 0,
            batches: 0,
            changes: 0,
            states: 0,
            error: None,
        }
    }

    fn line(&mut self, value: &serde_json::Value) {
        if self.error.is_some() {
            return;
        }
        let written = serde_json::to_writer(&mut self.out, value)
            .map_err(anyhow::Error::from)
            .and_then(|()| self.out.write_all(b"\n").map_err(anyhow::Error::from));
        if let Err(e) = written {
            self.error = Some(e);
        }
    }

    fn batch(&mut self, delta: &crate::delta::GoodDelta) {
        self.batches += 1;
        self.changes += delta.changes.len() as u64;
        tracing::info!(
            seq = delta.seq,
            changes = delta.changes.len(),
            at = %when(Some(delta.at.saturating_mul(1_000_000))),
            "batch"
        );
        self.line(&serde_json::json!({ "type": "batch", "delta": delta }));
    }

    /// Flush what is unsent and write the whole state, when a journal is
    /// open (else there is nothing to check it against).
    fn checkpoint(&mut self, player_data: &PlayerData) {
        let now = self.now_ms;
        if !self.live.is_live(now) {
            return;
        }
        let (good, _, keyed) = player_data.live_export(now);
        if let Some(delta) = self.live.flush(now, &good, keyed) {
            self.batch(&delta);
        }
        self.states += 1;
        self.line(
            &serde_json::json!({ "type": "state", "good": crate::delta::as_uploaded(&good) }),
        );
    }

    fn snapshot(&mut self, reason: Reason, player_data: &PlayerData) {
        self.checkpoint(player_data);
        let now = self.now_ms;
        let (mut good, _, keyed) = player_data.live_export(now);
        good.gi_capture = self.live.capture(reason);
        self.snapshots += 1;
        tracing::info!(
            reason = reason.as_str(),
            world = good.gi_capture.as_ref().map(|capture| capture.world),
            at = %when(Some(now.saturating_mul(1_000_000))),
            "snapshot"
        );
        let ticket = self.live.snapshot_started(reason, keyed);
        let answer = self.tracker.snapshot(&good);
        // The capture beside the account, not in it: `good` is compared
        // with the states, which carry no capture of their own.
        let capture = good.gi_capture.take();
        self.line(&serde_json::json!({
            "type": "snapshot",
            "capture": capture,
            "good": crate::delta::as_uploaded(&good),
        }));
        self.live.snapshot_answered(ticket, answer, now);
    }

    /// Run the sender up to `now_ms`.
    fn advance(&mut self, now_ms: u64, player_data: &PlayerData) {
        self.now_ms = self.now_ms.max(now_ms);
        let now = self.now_ms;
        if self.automation_at.is_some_and(|at| at <= now) {
            self.automation_at = None;
            if let Some(reason) = self.live.automation_reason(true, now) {
                self.snapshot(reason, player_data);
            }
        }
        // A handful at most per frame: each step sends or settles something.
        for _ in 0..16 {
            if !self
                .live
                .next_tick_ms(true, now)
                .is_some_and(|at| at <= now)
            {
                break;
            }
            match self.live.tick(true, now, || {
                let (good, _, keyed) = player_data.live_export(now);
                Some((good, keyed))
            }) {
                Action::Nothing => break,
                Action::Snapshot(reason) => self.snapshot(reason, player_data),
                Action::Batch(delta) => {
                    let answer = self.tracker.batch(&delta);
                    if matches!(answer, BatchAnswer::Stored { .. } | BatchAnswer::Duplicate) {
                        self.batch(&delta);
                    } else {
                        tracing::warn!(seq = delta.seq, ?answer, "batch not stored");
                    }
                    self.live.batch_answered(answer, now);
                }
            }
        }
    }
}

/// Whether two paths name one existing file.
fn is_same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// One game connection seen in the recording.
#[derive(Debug)]
struct Connection {
    /// 1-based, as logged.
    number: usize,
    /// The sniffer concluded it began (a login or reconnect), rather than it
    /// being already under way when the recording started.
    began_in_recording: bool,
    began_ns: Option<u64>,
    key: KeyState,
    /// When the session key was recovered, if it was.
    session_key_ns: Option<u64>,
    session_key: bool,
    recovery_failed: bool,
    commands: u64,
    applied: AppliedData,
}

/// The decoding state of one replay, fed frame by frame.
struct Replay {
    sniffer: GameSniffer,
    generation: u64,
    stats: SnifferStats,
    events_tx: mpsc::UnboundedSender<SnifferEvent>,
    events_rx: mpsc::UnboundedReceiver<SnifferEvent>,
    player_data: PlayerData,
    replacement: DataReplacement,

    frames: u64,
    /// Frames on a link layer the sniffer cannot parse, by link type.
    skipped: BTreeMap<u16, u64>,
    /// Anything at all decoded off the game ports.
    game_traffic: bool,
    connections: Vec<Connection>,
    /// Index of the connection whose data `player_data` holds.
    data_from: Option<usize>,
    /// What `player_data` holds, since it was last replaced.
    captured: AppliedData,
    /// When the newest data in `player_data` was captured.
    last_data_ns: Option<u64>,
    /// `--replay-journal`'s sender, when this is one.
    journal: Option<JournalSim>,
}

impl Replay {
    fn new(sniffer: GameSniffer, player_data: PlayerData) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            generation: sniffer.session_generation(),
            sniffer,
            stats: SnifferStats::default(),
            events_tx,
            events_rx,
            player_data,
            replacement: DataReplacement::default(),
            frames: 0,
            skipped: BTreeMap::new(),
            game_traffic: false,
            connections: Vec::new(),
            data_from: None,
            captured: AppliedData::default(),
            last_data_ns: None,
            journal: None,
        }
    }

    /// Decode one recorded frame, as the live sniffer thread would.
    fn feed(&mut self, frame: RecordedFrame) {
        self.frames += 1;
        let Some(data) = recording::as_ethernet(frame.link_type, frame.data) else {
            let count = self.skipped.entry(frame.link_type).or_default();
            if *count == 0 {
                tracing::warn!(
                    link_type = frame.link_type,
                    "skipping frames that are neither Ethernet nor bare IP"
                );
            }
            *count += 1;
            return;
        };

        monitor::decode_one_packet(
            &mut self.sniffer,
            &mut self.generation,
            data,
            &self.events_tx,
            &mut self.stats,
        );
        while let Ok(event) = self.events_rx.try_recv() {
            self.handle(event, frame.timestamp_ns);
        }
    }

    /// What the monitor does with a sniffer event, minus everything that
    /// talks to the UI, the tracker or the disk.
    fn handle(&mut self, event: SnifferEvent, at: Option<u64>) {
        match event {
            SnifferEvent::SessionReset => {
                self.close_connection();
                if let Some(journal) = &mut self.journal {
                    journal.live.note_connection_ended();
                    if let Some(ns) = at {
                        journal.advance(ns / 1_000_000, &self.player_data);
                    }
                }
                let news = self.replacement.connection_reset();
                let number = self.connections.len() + 1;
                self.connections.push(Connection {
                    number,
                    began_in_recording: true,
                    began_ns: at,
                    key: KeyState::None,
                    session_key_ns: None,
                    session_key: false,
                    recovery_failed: false,
                    commands: 0,
                    applied: AppliedData::default(),
                });
                tracing::info!(
                    connection = number,
                    frame = self.frames,
                    at = %when(at),
                    "new game connection (a login or a reconnect){}",
                    if news && self.data_from.is_some() {
                        "; the data so far stays until it delivers its own"
                    } else {
                        ""
                    }
                );
            }
            SnifferEvent::Packet(packet, report) => {
                self.game_traffic = true;
                self.note_key(report, at);
                match packet {
                    GamePacket::Connection(connection) => self.connection_packet(&connection, at),
                    GamePacket::Commands(commands) => {
                        if commands.is_empty() {
                            return;
                        }
                        self.current(at).commands += commands.len() as u64;
                        let classified = monitor::classify_commands(&commands);
                        self.apply(report.state, classified, at);
                    }
                }
            }
        }
    }

    /// The connection packets arrive on, opening one for traffic that was
    /// already under way when the recording started.
    fn current(&mut self, at: Option<u64>) -> &mut Connection {
        if self.connections.is_empty() {
            tracing::info!(
                frame = self.frames,
                at = %when(at),
                "game traffic from a connection that began before the recording did"
            );
            self.connections.push(Connection {
                number: 1,
                began_in_recording: false,
                began_ns: at,
                key: KeyState::None,
                session_key_ns: None,
                session_key: false,
                recovery_failed: false,
                commands: 0,
                applied: AppliedData::default(),
            });
        }
        self.connections.last_mut().expect("just ensured")
    }

    fn note_key(&mut self, report: KeyReport, at: Option<u64>) {
        let frame = self.frames;
        let connection = self.current(at);
        if report.state != connection.key {
            let what = match report.state {
                KeyState::Session => "session key recovered: this login's data decrypts",
                KeyState::Dispatch => "login exchange under the dispatch key",
                KeyState::None => "no key for this connection",
            };
            tracing::info!(
                connection = connection.number,
                frame,
                at = %when(at),
                from = ?connection.key,
                to = ?report.state,
                "{what}"
            );
            connection.key = report.state;
            if report.state == KeyState::Session && !connection.session_key {
                connection.session_key = true;
                connection.session_key_ns = at;
            }
        }
        if report.recovery_failed && !connection.recovery_failed {
            connection.recovery_failed = true;
            tracing::warn!(
                connection = connection.number,
                frame,
                at = %when(at),
                "the session key search gave up: nothing more from this connection decrypts"
            );
        }
    }

    fn connection_packet(&mut self, packet: &ConnectionPacket, at: Option<u64>) {
        let number = self.current(at).number;
        match packet {
            ConnectionPacket::HandshakeRequested => tracing::info!(
                connection = number,
                frame = self.frames,
                at = %when(at),
                "handshake requested"
            ),
            ConnectionPacket::HandshakeEstablished => tracing::debug!(
                connection = number,
                frame = self.frames,
                "handshake established"
            ),
            ConnectionPacket::Disconnected => tracing::info!(
                connection = number,
                frame = self.frames,
                at = %when(at),
                "disconnected"
            ),
            // A KCP segment that did not complete a command.
            _ => {}
        }
    }

    /// Fold one classified batch into the captured data, by the rules the
    /// monitor applies: a new connection's data replaces the old once it is
    /// real data under the session key.
    fn apply(&mut self, key: KeyState, classified: Vec<(u16, CommandMatch)>, at: Option<u64>) {
        if classified.is_empty() {
            return;
        }
        let index = self.current(at).number - 1;
        match self.replacement.verdict_for_batch(key, &classified) {
            DataVerdict::Apply => {}
            DataVerdict::ReplaceThenApply => {
                match self.data_from {
                    Some(from) => tracing::info!(
                        connection = index + 1,
                        frame = self.frames,
                        "the new connection delivered data; it replaces connection #{}'s",
                        from + 1
                    ),
                    None => tracing::info!(
                        connection = index + 1,
                        frame = self.frames,
                        "first account data of this connection"
                    ),
                }
                self.player_data.reset();
                self.captured = AppliedData::default();
                self.data_from = None;
                if let Some(journal) = &mut self.journal {
                    journal.live.note_data_replaced();
                }
            }
            DataVerdict::Hold => {
                tracing::debug!(
                    commands = classified.len(),
                    ?key,
                    "keeping the previous connection's data; not applying these"
                );
                return;
            }
        }

        let held = self.player_data.item_count();
        let full_send = monitor::full_send_in(&classified, held);
        let noted = monitor::changes_in(&classified);
        let applied = monitor::apply_commands(&mut self.player_data, classified);
        if applied.any()
            && let Some(journal) = &mut self.journal
        {
            if full_send {
                journal.live.note_full_send();
            }
            journal.live.note_change(noted);
            if let Some(ns) = at {
                journal.automation_at = Some(ns / 1_000_000 + JOURNAL_DEBOUNCE_MS);
            }
        }
        if applied.any() {
            self.captured = self.captured.union(applied);
            let connection = &mut self.connections[index];
            connection.applied = connection.applied.union(applied);
            self.data_from = Some(index);
            if at.is_some() {
                self.last_data_ns = at;
            }
        }
    }

    /// Log the summary line of the connection that just ended.
    fn close_connection(&self) {
        let Some(connection) = self.connections.last() else {
            return;
        };
        let began = if connection.began_in_recording {
            when(connection.began_ns)
        } else {
            "before the recording".to_string()
        };
        let session_key = if connection.session_key {
            format!("recovered at {}", when(connection.session_key_ns))
        } else if connection.recovery_failed {
            "not recovered (the search gave up)".to_string()
        } else {
            "not recovered".to_string()
        };
        tracing::info!(
            connection = connection.number,
            %began,
            %session_key,
            commands = connection.commands,
            data = %describe(connection.applied),
            "connection summary"
        );
    }

    /// End of the recording: summarise it and build the export, or say why
    /// there is nothing to export.
    fn finish(&mut self) -> Result<Good> {
        self.close_connection();
        let recovered = self.connections.iter().filter(|c| c.session_key).count();
        tracing::info!(
            frames = self.frames,
            skipped_not_ethernet = self.skipped.values().sum::<u64>(),
            connections = self.connections.len(),
            session_keys_recovered = recovered,
            "replay summary"
        );

        if !self.captured.any() {
            bail!("{}", self.nothing_decoded());
        }
        if let Some(index) = self.data_from
            && index + 1 < self.connections.len()
        {
            tracing::warn!(
                "exporting connection #{}'s data: the later connection(s) delivered none",
                index + 1
            );
        }

        let now_ms = self
            .last_data_ns
            .map(|ns| ns / 1_000_000)
            .unwrap_or_else(|| {
                tracing::warn!(
                    "the recording has no timestamps; stamping the export with the time now"
                );
                chrono::Utc::now().timestamp_millis() as u64
            });
        // What a tracker upload of this data would hold. The replay reads no
        // saved settings, so the Genshin Optimizer ones would only ever have
        // been their defaults, which leave 1★ and 2★ gear out.
        let (good, report) = self
            .player_data
            .export_at(&ExportSettings::for_tracker(), now_ms);

        let counts = report.counts();
        tracing::info!(
            characters = counts.characters,
            artifacts = counts.artifacts,
            weapons = counts.weapons,
            materials = counts.materials,
            achievements = counts.achievements,
            anecdotes = good.gi_anecdotes.as_ref().map_or(0, |book| book.anecdotes.len()),
            uid = ?good.gi_player.as_ref().and_then(|player| player.uid),
            data = %describe(self.captured),
            stamped = %when(Some(now_ms.saturating_mul(1_000_000))),
            "export built with the tracker's export settings (nothing filtered out)"
        );
        if !self.captured.items {
            tracing::warn!("no inventory was decoded: artifacts, weapons and materials are empty");
        }
        if !self.captured.characters {
            tracing::warn!("no character data was decoded: characters are empty");
        }
        if !report.is_empty() {
            tracing::warn!("export dropped entities: {}", report.summary());
        }
        if report.has_degradations() {
            tracing::info!(
                "export kept defaults for some fields: {}",
                report.degraded_summary()
            );
        }
        Ok(good)
    }

    /// Run the sender for what a frame brought.
    fn advance_journal(&mut self, now_ms: u64) -> Result<()> {
        if let Some(journal) = &mut self.journal {
            journal.advance(now_ms, &self.player_data);
            if let Some(e) = journal.error.take() {
                return Err(e);
            }
        }
        Ok(())
    }

    /// End of a `--replay-journal`: the last debounced snapshot, the final
    /// state, and the counts.
    fn finish_journal(&mut self) -> Result<()> {
        self.close_connection();
        let Some(mut journal) = self.journal.take() else {
            bail!("not a journal replay");
        };
        if !self.captured.any() {
            bail!("{}", self.nothing_decoded());
        }
        // Whatever the automation was waiting on, and the sender after it.
        if let Some(at) = journal.automation_at {
            journal.advance(at, &self.player_data);
        }
        let later = journal.now_ms + crate::live::LONE_CHANGE_MS;
        journal.advance(later, &self.player_data);
        journal.checkpoint(&self.player_data);
        journal.out.flush()?;
        if let Some(e) = journal.error.take() {
            return Err(e);
        }
        tracing::info!(
            snapshots = journal.snapshots,
            batches = journal.batches,
            changes = journal.changes,
            states = journal.states,
            "journal replay summary"
        );
        Ok(())
    }

    /// Why a recording yielded no data, as specifically as it can be told.
    fn nothing_decoded(&self) -> String {
        if self.frames == 0 {
            return "nothing decoded: the recording holds no frames".to_string();
        }
        if self.skipped.values().sum::<u64>() == self.frames {
            return format!(
                "nothing decoded: none of the recording's {} frames is Ethernet or bare IP                  (link types {:?})",
                self.frames,
                self.skipped.keys().collect::<Vec<_>>()
            );
        }
        if !self.game_traffic {
            return format!(
                "nothing decoded: none of the recording's {} frames is game traffic \
                 (UDP ports 22101-22102)",
                self.frames
            );
        }
        if self.connections.iter().any(|c| c.session_key) {
            let commands: u64 = self.connections.iter().map(|c| c.commands).sum();
            return format!(
                "nothing decoded: the session key was recovered and {commands} commands \
                 decrypted, but none of them carried account data (does the recording end \
                 before the login's data arrived?)"
            );
        }
        if self.connections.iter().any(|c| c.recovery_failed) {
            return "nothing decoded: the recording has a login, but its session key could \
                    not be recovered (the search gave up)"
                .to_string();
        }
        if self.connections.iter().any(|c| c.began_in_recording) {
            return "nothing decoded: the recording has a login, but its session key was \
                    never recovered (does it end before the login finished?)"
                .to_string();
        }
        "nothing decoded: the recording has no login in it, so there is no session key. \
         Start recording before the game connects (before launching it, or before entering \
         the world)"
            .to_string()
    }
}

/// A recorded time, in local time to the millisecond.
fn when(ns: Option<u64>) -> String {
    match ns.and_then(|ns| i64::try_from(ns).ok()) {
        Some(ns) => chrono::DateTime::from_timestamp_nanos(ns)
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S%.3f")
            .to_string(),
        None => "unknown time".to_string(),
    }
}

/// The data classes in `applied`, for a log line.
fn describe(applied: AppliedData) -> String {
    let classes: Vec<&str> = [
        (applied.items, "inventory"),
        (applied.characters, "characters"),
        (applied.achievements, "achievements"),
        (applied.properties, "player properties"),
        (applied.anecdotes, "anecdotes"),
        (applied.routine, "planner routine"),
    ]
    .into_iter()
    .filter_map(|(present, name)| present.then_some(name))
    .collect();
    if classes.is_empty() {
        "none".to_string()
    } else {
        classes.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use anime_game_data::AnimeGameData;
    use auto_artifactarium::r#gen::protos::{Item, Material};

    use super::*;
    use crate::monitor::tests::{handshake_frame, segment_frame, udp_frame};
    use crate::recording::tests::{enhanced_packet, interface, section_header};

    /// Ten material stacks whose guids carry `uid` in their top half, as a
    /// real inventory notify's do.
    fn inventory(uid: u64) -> CommandMatch {
        let items = (1..=10u64)
            .map(|n| {
                let mut item = Item::new();
                item.item_id = 100_000 + n as u32;
                item.guid = (uid << 32) + n;
                item.set_material(Material {
                    count: 5,
                    ..Default::default()
                });
                item
            })
            .collect();
        CommandMatch::Items(items)
    }

    fn replay() -> Replay {
        Replay::new(GameSniffer::new(), PlayerData::new(AnimeGameData::new()))
    }

    fn session() -> KeyReport {
        KeyReport {
            state: KeyState::Session,
            recovery_failed: false,
        }
    }

    /// A realistic capture time, in nanoseconds since the epoch.
    const LOGIN_NS: u64 = 1_759_553_801_000_000_000;
    const HOUR_NS: u64 = 3_600_000_000_000;

    /// The events the sniffer sends for a login whose key was recovered.
    fn log_in(replay: &mut Replay, at: u64) {
        replay.handle(SnifferEvent::SessionReset, Some(at));
        replay.note_key(session(), Some(at));
    }

    #[test]
    fn the_last_logins_data_is_what_gets_exported() {
        let mut replay = replay();
        log_in(&mut replay, LOGIN_NS);
        replay.apply(KeyState::Session, vec![(1, inventory(111))], Some(LOGIN_NS));

        // A second account logs in. Its login exchange proves nothing about
        // it yet, so the first account's data stays...
        let relog_ns = LOGIN_NS + HOUR_NS;
        replay.handle(SnifferEvent::SessionReset, Some(relog_ns));
        replay.apply(
            KeyState::Dispatch,
            vec![(1, inventory(999))],
            Some(relog_ns),
        );
        assert_eq!(replay.player_data.uid_check().uid, Some(111));

        // ...until its own data arrives under its session key, which replaces
        // the first account's rather than merging with it.
        replay.note_key(session(), Some(relog_ns + 1_000_000_000));
        let data_ns = relog_ns + 2_000_000_123;
        replay.apply(KeyState::Session, vec![(1, inventory(222))], Some(data_ns));

        let good = replay.finish().unwrap();
        let uid_check = replay.player_data.uid_check();
        assert_eq!(uid_check.uid, Some(222));
        assert_eq!(uid_check.total, 10, "not merged with the first account");
        assert_eq!(good.gi_player.unwrap().uid, Some(222));
        // Stamped with the time the data was captured, not the time now.
        assert_eq!(good.timestamp, Some(data_ns / 1_000_000));
        assert_eq!(replay.data_from, Some(1));
    }

    #[test]
    fn a_reconnect_that_never_decrypts_leaves_the_earlier_data_exportable() {
        let mut replay = replay();
        log_in(&mut replay, LOGIN_NS);
        replay.apply(KeyState::Session, vec![(1, inventory(111))], Some(LOGIN_NS));
        replay.handle(SnifferEvent::SessionReset, Some(LOGIN_NS + HOUR_NS));
        replay.note_key(
            KeyReport {
                state: KeyState::Dispatch,
                recovery_failed: true,
            },
            Some(LOGIN_NS + HOUR_NS),
        );

        let good = replay.finish().unwrap();
        assert_eq!(good.gi_player.unwrap().uid, Some(111));
        assert_eq!(good.timestamp, Some(LOGIN_NS / 1_000_000));
        assert!(replay.connections[1].recovery_failed);
    }

    #[test]
    fn an_empty_or_foreign_recording_says_why_nothing_decoded() {
        let mut empty = replay();
        let error = empty.finish().err().unwrap().to_string();
        assert!(error.contains("no frames"), "{error}");

        let mut wifi = replay();
        wifi.feed(RecordedFrame {
            timestamp_ns: Some(1),
            link_type: 105, // IEEE 802.11
            data: vec![0x45; 40],
        });
        let error = wifi.finish().err().unwrap().to_string();
        assert!(error.contains("Ethernet or bare IP"), "{error}");

        // A phone capture (PCAPdroid: bare IP) is read, so what it lacks is game traffic.
        let mut phone = replay();
        phone.feed(RecordedFrame {
            timestamp_ns: Some(1),
            link_type: recording::LINKTYPE_RAW,
            data: udp_frame(50000, 53, &[0; 32])[14..].to_vec(),
        });
        let error = phone.finish().err().unwrap().to_string();
        assert!(error.contains("game traffic"), "{error}");

        let mut other_traffic = replay();
        other_traffic.feed(RecordedFrame {
            timestamp_ns: Some(1),
            link_type: recording::LINKTYPE_ETHERNET,
            data: udp_frame(50000, 53, &[0; 32]),
        });
        let error = other_traffic.finish().err().unwrap().to_string();
        assert!(error.contains("game traffic"), "{error}");
    }

    #[test]
    fn a_recording_without_a_login_fails_and_writes_nothing() {
        // A real file through the whole path -- reader, sniffer with the real
        // dispatch keys, the embedded game data -- with traffic the sniffer
        // can see but never decrypt: game segments from a connection whose
        // login is not in the recording.
        let dir = tempfile::tempdir().unwrap();
        let recording = dir.path().join("session.pcapng");
        let mut bytes = section_header(false);
        bytes.extend(interface(recording::LINKTYPE_ETHERNET, &[(9, &[9])], false));
        for (n, frame) in [
            udp_frame(50000, 53, &[0; 32]),
            segment_frame(7, &[0u8; 40]),
            segment_frame(7, &[1u8; 40]),
        ]
        .iter()
        .enumerate()
        {
            bytes.extend(enhanced_packet(0, LOGIN_NS + n as u64, frame, false));
        }
        std::fs::write(&recording, bytes).unwrap();
        let out = dir.path().join("out").join("export.json");

        let error = replay_to_file(&recording, &out).unwrap_err().to_string();
        assert!(error.contains("no login"), "{error}");

        // No export, and nothing else either: the directory holds the
        // recording alone.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec!["session.pcapng"]);
    }

    #[test]
    fn a_login_whose_key_is_never_recovered_is_reported_as_such() {
        let dir = tempfile::tempdir().unwrap();
        let recording = dir.path().join("login.pcapng");
        let mut bytes = section_header(false);
        bytes.extend(interface(recording::LINKTYPE_ETHERNET, &[], false));
        bytes.extend(enhanced_packet(0, 1, &handshake_frame(), false));
        bytes.extend(enhanced_packet(0, 2, &segment_frame(9, &[0u8; 40]), false));
        std::fs::write(&recording, bytes).unwrap();

        let error = replay_to_file(&recording, &dir.path().join("x.json"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("has a login"), "{error}");
        assert!(!dir.path().join("x.json").exists());
    }

    #[test]
    fn the_output_may_not_overwrite_the_recording() {
        let dir = tempfile::tempdir().unwrap();
        let recording = dir.path().join("rec.pcapng");
        let mut bytes = section_header(false);
        bytes.extend(interface(recording::LINKTYPE_ETHERNET, &[], false));
        std::fs::write(&recording, &bytes).unwrap();

        let error = replay_to_file(&recording, &recording)
            .unwrap_err()
            .to_string();
        assert!(error.contains("overwrite"), "{error}");
        assert_eq!(std::fs::read(&recording).unwrap(), bytes);
    }

    #[test]
    fn the_log_sits_next_to_the_export() {
        assert_eq!(
            log_path_for(Path::new("dir/out.json")),
            Path::new("dir/out.json.log")
        );
    }

    /// The guarantee in the module comment, kept honest: the replay's code
    /// names none of the things a replay must never reach. Uploads, key
    /// checks and automation saves are private to `monitor.rs` and would not
    /// compile here anyway; the rest would.
    #[test]
    fn the_replay_reaches_nothing_that_uploads_or_touches_app_state() {
        let source = include_str!("replay.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("the code comes first");
        for forbidden in [
            "reqwest",
            "upload_to_tracker",
            "spawn_tracker_upload",
            "verify_tracker_key",
            "UploadToTracker",
            "execute_automation_export",
            "save_to_automation_file",
            "SavedAppState",
            "Monitor::new",
            "signin",
            "TrackerAuth",
            "KeyringStore",
            "IrminsulApp",
            "eframe",
            "data_dir(",
            "log_dir(",
            "tracing_init(",
            "check_for_app_update",
            "ensure_admin",
            "single_instance",
            "SingleInstance",
        ] {
            assert!(!code.contains(forbidden), "replay.rs mentions {forbidden}");
        }
    }
}
