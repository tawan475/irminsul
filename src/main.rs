#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, reload};

use crate::game_watch::GameStatus;
use crate::player_data::ExportSettings;

mod admin;
mod app;
mod capture;
mod game_watch;
mod good;
mod monitor;
mod pcapng;
mod player_data;
mod update;
mod wish;

const APP_ID: &str = "Irminsul";

#[derive(Clone, Copy, Debug)]
pub enum ConfirmationType {
    Initial,
    Update,
}

#[derive(Clone, Debug)]
pub enum State {
    Starting,
    CheckingForUpdate,
    WaitingForUpdateConfirmation(String),
    Updating,
    Updated,
    CheckingForData,
    WaitingForDownloadConfirmation(ConfirmationType),
    Downloading,
    Main,
}

/// A request from the UI to the background monitor.
///
/// The update prompt deliberately does *not* travel on this channel: see
/// [`update::UpdateAnswer`]. Draining this one to wait for an update
/// acknowledgement is what used to swallow the startup `StartCapture`.
#[derive(Debug)]
pub enum Message {
    DownloadAcknowledged,
    StartCapture,
    StopCapture,
    ClearData,
    ExportGenshinOptimizer(ExportSettings, oneshot::Sender<Result<String>>),
    ExportAchievements(oneshot::Sender<Result<Vec<u32>>>),
    /// Only sent by the wish UI, which exists on Windows and on Linux (through
    /// a Proton/Wine prefix) — the platforms where the game writes the
    /// `output_log.txt` the URL is recovered from. `monitor.rs` still handles
    /// it everywhere.
    #[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
    FindWishUrl(oneshot::Sender<Result<String>>),
    VerifyTrackerKey(
        String,
        String,
        oneshot::Sender<Result<(String, String, String)>>,
    ),
    UploadToTracker(String, String, String, oneshot::Sender<Result<(), String>>),
    /// Terminate the running game, from the "game already running" modal.
    ///
    /// Handled in `monitor.rs` rather than in the UI because the process
    /// scanner lives there, and because the reply has to wait for the process
    /// to actually go away before the status line is re-derived. Carries the
    /// number of processes stopped; zero is a real answer, not a failure.
    KillGame(oneshot::Sender<usize>),
}

#[derive(Clone, Debug)]
pub struct DataUpdated {
    achievements_updated: Option<Instant>,
    achievements_updated_time: Option<chrono::DateTime<chrono::Local>>,
    characters_updated: Option<Instant>,
    items_updated: Option<Instant>,
}

impl DataUpdated {
    pub fn new() -> Self {
        Self {
            achievements_updated: None,
            achievements_updated_time: None,
            characters_updated: None,
            items_updated: None,
        }
    }
}

impl Default for DataUpdated {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct AppState {
    state: State,
    capturing: bool,
    updated: DataUpdated,
    /// Whether the game is running and, more to the point, whether Irminsul
    /// watched this game session start. `capturing` says the backend is up; it
    /// says nothing about whether the traffic it sees can be decrypted at all.
    /// See [`game_watch`].
    game_status: GameStatus,
}

impl AppState {
    fn new() -> Self {
        AppState {
            state: State::Starting,
            capturing: false,
            updated: DataUpdated::new(),
            game_status: GameStatus::default(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        long,
        default_value_t = false,
        long_help = "Skip the packet-capture privilege check.\n\n\
                     No effect on Windows: build.rs embeds an application manifest with \
                     requestedExecutionLevel=requireAdministrator, so Windows decides elevation \
                     before main() runs and the process is already elevated by the time this flag \
                     is parsed."
    )]
    no_admin: bool,

    #[arg(
        long = "capture-backend",
        short = 'b',
        value_enum,
        default_value_t = capture::DEFAULT_CAPTURE_BACKEND_TYPE
    )]
    capture_backend: capture::BackendType,

    #[arg(long, short, default_value_t = false, requires("savefile_path"))]
    read_from_file: bool,

    #[arg(
        value_name = "SAVEFILE_PATH",
        help = "Capture file to replay with --read-from-file, or a filename template to record to",
        long_help = "Capture file to replay with --read-from-file, or a filename template to \
                     record live traffic to.\n\n\
                     With --read-from-file the path is used as given: it is the recording to \
                     replay.\n\n\
                     Without it the path is a template, not an output file. Irminsul captures on \
                     every eligible network interface at once, and each one is recorded to its \
                     own file named after the device, because one pcap dump file cannot be shared \
                     by several capture handles. `irminsul -b pcap session.pcap` therefore writes \
                     `session-<interface>.pcap` once per interface and no plain `session.pcap`; \
                     the log line \"Recording <device> to savefile ...\" names each file as it is \
                     opened.\n\n\
                     Recording is only supported by the pcap capture backend (-b pcap)."
    )]
    savefile_path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Default)]
pub enum TracingLevel {
    #[default]
    Default,
    VerboseInfo,
    VerboseDebug,
    VerboseTrace,
}

impl Display for TracingLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TracingLevel::Default => write!(f, "Default"),
            TracingLevel::VerboseInfo => write!(f, "Verbose Info"),
            TracingLevel::VerboseDebug => write!(f, "Verbose Debug"),
            TracingLevel::VerboseTrace => write!(f, "Verbose Trace"),
        }
    }
}

impl TracingLevel {
    fn get_filter(&self) -> &'static str {
        match self {
            TracingLevel::Default => {
                if cfg!(debug_assertions) {
                    "info"
                } else {
                    "warn,irminsul=info,auto_artifactarium=info"
                }
            }
            TracingLevel::VerboseInfo => "info",
            TracingLevel::VerboseDebug => "debug",
            TracingLevel::VerboseTrace => "trace",
        }
    }
}

struct ReloadHandle(reload::Handle<EnvFilter, tracing_subscriber::Registry>);

impl ReloadHandle {
    pub fn set_filter(&mut self, filter: &str) {
        if let Err(e) = self.0.reload(filter) {
            tracing::warn!("Failed to set tracing filter to \"{filter}\": {e}");
        }
        tracing::info!("Set tracing filter to \"{filter}\"");
    }
}

fn main() -> eframe::Result {
    let instance = single_instance::SingleInstance::new("irminsul_app_instance").unwrap();
    if !instance.is_single() {
        eprintln!("Another instance of Irminsul is already running.");
        std::process::exit(1);
    }

    let (_guard, reload_handle) = tracing_init().unwrap();

    let args = Args::parse();

    if !args.no_admin && !args.read_from_file {
        #[cfg(any(windows, unix))]
        admin::ensure_admin();
    }

    let capture_source = if args.read_from_file {
        capture::CaptureSource::File(args.savefile_path.unwrap()) // Should be checked by clap
    } else {
        capture::CaptureSource::Device(args.savefile_path)
    };

    let capture_backend = args.capture_backend;

    let background_image_size = [1600., 1000.];

    // Set by the UI once a self-update has been installed. The relaunch has to
    // happen out here, after `run_native` returns and `instance` is dropped:
    // the replacement process takes the same single-instance mutex on startup,
    // so spawning it from inside the running app made the child exit
    // immediately with "Another instance is already running".
    let restart_requested = Arc::new(AtomicBool::new(false));
    let app_restart_requested = Arc::clone(&restart_requested);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(background_image_size.map(|v| v * 0.5))
            .with_resizable(false)
            .with_decorations(false)
            .with_icon(
                // NOTE: Adding an icon is optional
                eframe::icon_data::from_png_bytes(&include_bytes!("../assets/icon-256.png")[..])
                    .expect("Failed to load icon"),
            ),
        persist_window: false,
        ..Default::default()
    };
    let result = eframe::run_native(
        "Irminsul",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(app::IrminsulApp::new(
                cc,
                reload_handle,
                capture_backend,
                capture_source,
                app_restart_requested,
            )))
        }),
    );

    // Release the single-instance mutex before the replacement tries to take
    // it.
    drop(instance);

    if restart_requested.load(Ordering::SeqCst) {
        // The command line is reproduced as faithfully as it can be. argv[0]
        // is deliberately *not* reused: it is whatever the launcher passed,
        // which can be a bare name or a path relative to a working directory
        // that no longer applies. argv[1..] on the other hand has to be carried
        // across -- without it a user who started
        // `irminsul-windows-pcap.exe -b pcap` came back on the pktmon default
        // after an update, and `--no-admin` and `-r <file>` replay mode were
        // dropped the same way.
        let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        match std::env::current_exe() {
            Ok(exe) => match std::process::Command::new(&exe).args(&args).spawn() {
                Ok(_) => tracing::info!("relaunched {exe:?} with {args:?} after update"),
                Err(e) => tracing::error!("could not relaunch {exe:?} after update: {e}"),
            },
            Err(e) => tracing::error!("could not find the current executable to relaunch: {e}"),
        }
    }

    result
}

/// The root everything Irminsul writes for itself hangs off.
///
/// Release builds use the platform's per-application data directory, which is
/// where a user's installed copy should keep its state. Debug builds use the
/// working directory instead, so a `cargo run` drops its log, packet log and
/// pcapng trace next to the source being debugged rather than somewhere under
/// `AppData` that has to be hunted for -- and so a developer's traces never mix
/// with an installed copy's.
pub fn data_dir() -> Result<PathBuf> {
    if cfg!(debug_assertions) {
        let mut dir = std::env::current_dir().context("Working directory not found")?;
        dir.push("irminsul-data");
        return Ok(dir);
    }
    eframe::storage_dir(APP_ID).context("Storage dir not found")
}

fn log_dir() -> Result<PathBuf> {
    let mut dir = data_dir()?;
    dir.push("log");
    Ok(dir)
}

/// Where `monitor.rs` writes the raw packet log when the power tool is on.
///
/// One file per session, and every one of them is decrypted account data --
/// characters, inventory, achievements -- so an unbounded directory is a
/// privacy problem as much as a disk one. `monitor.rs` prunes it as it opens a
/// new session file; this is the startup sweep that also catches the files an
/// older build left behind (it wrote one *per command*) on a machine where raw
/// packet logging is never turned on again.
fn packet_log_dir() -> Result<PathBuf> {
    let mut dir = data_dir()?;
    dir.push("packet_log");
    Ok(dir)
}

fn open_log_dir() -> Result<()> {
    let dir = log_dir()?;
    open::that(dir)?;
    Ok(())
}

/// How many rotated files to keep, per kind.
const LOG_RETENTION: usize = 6;

/// Move `latest.<extension>` aside, renamed after its modification time.
fn rotate_latest(log_dir: &Path, extension: &str) {
    let latest_path = log_dir.join(format!("latest.{extension}"));
    let Ok(modified) = std::fs::metadata(&latest_path).and_then(|metadata| metadata.modified())
    else {
        // Missing (first run) or unreadable: nothing to rotate either way.
        return;
    };

    let dt: chrono::DateTime<chrono::Local> = modified.into();
    let new_path = log_dir.join(format!("{}.{extension}", dt.format("%Y-%m-%d_%H-%M-%S")));
    let _ = std::fs::rename(&latest_path, &new_path);
}

/// Delete all but the newest [`LOG_RETENTION`] rotated `*.<extension>` files.
///
/// Each extension gets its own budget. Sharing one between `.log` and `.pcapng`
/// roughly halved the log history in debug builds — exactly when a developer
/// wants to compare several runs.
fn prune_rotated(log_dir: &Path, extension: &str) {
    let latest_name = format!("latest.{extension}");

    let Ok(dir) = std::fs::read_dir(log_dir) else {
        return;
    };

    let mut entries = Vec::new();
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(extension) {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some(latest_name.as_str()) {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|metadata| metadata.modified()) else {
            continue;
        };
        entries.push((path, modified));
    }

    entries.sort_by_key(|(_, modified)| std::cmp::Reverse(*modified));
    for (path, _) in entries.into_iter().skip(LOG_RETENTION) {
        let _ = std::fs::remove_file(path);
    }
}

fn rotate_logs(log_dir: &Path) {
    rotate_latest(log_dir, "log");
    prune_rotated(log_dir, "log");

    // Not under `log_dir`, and nothing else sweeps it at startup. Keep the same
    // budget as monitor.rs's `PACKET_LOG_RETENTION`; the live file for this
    // session has not been created yet, so nothing in flight can be caught.
    if let Ok(packet_log_dir) = packet_log_dir() {
        prune_rotated(&packet_log_dir, "bin");
    }

    // Both the pcapng writer (monitor.rs) and its rotation are debug-only, so a
    // release build must not touch pcapng files at all: it used to quietly
    // delete captures left over from debug runs that a developer was keeping.
    #[cfg(debug_assertions)]
    {
        rotate_latest(log_dir, "pcapng");
        prune_rotated(log_dir, "pcapng");
    }
}

/// Route panics into the log file.
///
/// Release builds set `windows_subsystem = "windows"`, so the default hook's
/// stderr goes nowhere and every panic in this app is invisible — including
/// panics inside egui's own update loop, which take the window with them.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");
        // `PanicHookInfo::payload_as_str` would do this, but it is only stable
        // from 1.91 and this crate supports 1.88.
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        let location = match info.location() {
            Some(location) => location.to_string(),
            None => "<unknown location>".to_string(),
        };
        let backtrace = std::backtrace::Backtrace::force_capture();

        tracing::error!("panic in thread '{thread_name}' at {location}: {message}\n{backtrace}");

        // Debug builds keep their console, so leave the usual output in place.
        default_hook(info);
    }));
}

fn tracing_init() -> Result<(tracing_appender::non_blocking::WorkerGuard, ReloadHandle)> {
    let dir = log_dir()?;
    std::fs::create_dir_all(&dir)?;
    rotate_logs(&dir);

    let latest_path = dir.join("latest.log");
    let file = std::fs::File::create(&latest_path)?;
    let (non_blocking_appender, guard) = tracing_appender::non_blocking(file);

    let filter = EnvFilter::new(TracingLevel::default().get_filter());
    let (filter, reload_handle) = reload::Layer::new(filter);
    let writer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking_appender)
        .with_ansi(false);
    tracing_subscriber::registry()
        .with(filter)
        .with(writer)
        .init();
    install_panic_hook();
    tracing::info!("Tracing initialized and logging to file.");

    Ok((guard, ReloadHandle(reload_handle)))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    /// A fixed instant to age the fixtures relative to, so mtime ordering does
    /// not depend on how fast the filesystem is.
    const BASE: u64 = 1_700_000_000;

    /// Create `name` with an mtime `age_secs` in the past.
    fn write_aged(dir: &Path, name: &str, age_secs: u64) {
        let file = std::fs::File::create(dir.join(name)).unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(BASE - age_secs))
            .unwrap();
    }

    fn names_with_extension(dir: &Path, extension: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(&format!(".{extension}")))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn pruning_keeps_the_newest_files_of_one_kind_only() {
        let dir = tempfile::tempdir().unwrap();

        // Ten rotated logs, `log-0` the newest.
        for i in 0..10u64 {
            write_aged(dir.path(), &format!("log-{i}.log"), i);
        }
        // Ten rotated captures, which must not be touched by the .log budget.
        for i in 0..10u64 {
            write_aged(dir.path(), &format!("cap-{i}.pcapng"), i);
        }

        prune_rotated(dir.path(), "log");

        let logs = names_with_extension(dir.path(), "log");
        assert_eq!(logs.len(), LOG_RETENTION, "kept {logs:?}");
        for i in 0..LOG_RETENTION as u64 {
            assert!(logs.contains(&format!("log-{i}.log")), "kept {logs:?}");
        }

        assert_eq!(
            names_with_extension(dir.path(), "pcapng").len(),
            10,
            "the two kinds must not share a retention budget"
        );
    }

    #[test]
    fn pruning_bounds_the_raw_packet_log_without_touching_the_text_logs() {
        // `rotate_logs` swept only `log_dir()`, so `packet_log` grew forever --
        // one file per session now, one per *command* in builds before that.
        let dir = tempfile::tempdir().unwrap();

        for i in 0..40u64 {
            write_aged(dir.path(), &format!("2024-01-01_00-00-{i:02}.bin"), i);
        }
        write_aged(dir.path(), "latest.log", 100);

        prune_rotated(dir.path(), "bin");

        let kept = names_with_extension(dir.path(), "bin");
        assert_eq!(kept.len(), LOG_RETENTION, "kept {kept:?}");
        assert!(
            kept.contains(&"2024-01-01_00-00-00.bin".to_string()),
            "{kept:?}"
        );
        assert!(
            !kept.contains(&"2024-01-01_00-00-39.bin".to_string()),
            "{kept:?}"
        );
        assert!(dir.path().join("latest.log").exists());
    }

    #[test]
    fn pruning_never_deletes_the_live_file() {
        let dir = tempfile::tempdir().unwrap();

        // `latest.log` is deliberately the oldest, so a budget that counted it
        // would delete it first.
        write_aged(dir.path(), "latest.log", 1_000);
        for i in 0..10u64 {
            write_aged(dir.path(), &format!("log-{i}.log"), i);
        }

        prune_rotated(dir.path(), "log");

        assert!(dir.path().join("latest.log").exists());
    }

    #[test]
    fn rotating_renames_the_live_file_and_is_a_no_op_without_one() {
        let dir = tempfile::tempdir().unwrap();

        // No latest.log yet: the first run must not fail or invent a file.
        rotate_latest(dir.path(), "log");
        assert!(names_with_extension(dir.path(), "log").is_empty());

        write_aged(dir.path(), "latest.log", 0);
        rotate_latest(dir.path(), "log");

        assert!(!dir.path().join("latest.log").exists());
        assert_eq!(names_with_extension(dir.path(), "log").len(), 1);
    }
}
