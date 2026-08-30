use std::fmt::Display;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow};
use chrono::Local;
use egui::{
    Button, Color32, Context, DragValue, Id, Key, KeyboardShortcut, Modal, Modifiers, OpenUrl,
    PointerButton, RichText, Sense, ViewportCommand,
};
use egui_file_dialog::FileDialog;
use egui_notify::Toasts;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::capture;

type AsyncRuntimeHandles = (
    mpsc::UnboundedSender<Message>,
    mpsc::UnboundedSender<UpdateAnswer>,
    watch::Receiver<AppState>,
    watch::Receiver<Option<String>>,
    mpsc::UnboundedReceiver<(String, bool)>,
    JoinHandle<()>,
);
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
#[cfg(not(target_os = "linux"))]
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};
use tray_icon::{TrayIcon, TrayIconBuilder};

use crate::game_watch::{GameStatus, MissedLaunch, Severity};
use crate::monitor::Monitor;
use crate::player_data::ExportSettings;
use crate::update::{InstallLock, UpdateAnswer, check_for_app_update};
use crate::{
    AppState, ConfirmationType, DataUpdated, Message, ReloadHandle, State, TracingLevel,
    open_log_dir, wish,
};

/// How long a capture backend may take to release its device or ETW session.
///
/// A mirror of `monitor::CAPTURE_SHUTDOWN_TIMEOUT`, which is private to that
/// module. The two are checked against each other by
/// `the_monitor_budget_outlasts_the_capture_teardown_it_waits_for` below, so
/// they cannot drift apart unnoticed.
const CAPTURE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the monitor thread is given to wind down before shutdown gives up
/// on it and lets the process exit anyway.
///
/// Derived from, and strictly larger than, the capture teardown it is waiting
/// on. Clicking Stop and then closing the window leaves `handle_ui_msg`
/// awaiting `stop_capture()` for up to a full CAPTURE_SHUTDOWN_TIMEOUT while
/// this timer runs concurrently: with both set to the same 5 s, a teardown
/// that legitimately uses its whole budget is detached at the exact moment it
/// would have succeeded, abandoning a pktmon ETW session or a pcap device that
/// the next launch then silently loses the race for.
const MONITOR_SHUTDOWN_TIMEOUT: Duration =
    Duration::from_secs(CAPTURE_SHUTDOWN_TIMEOUT.as_secs() + 3);

/// How long "Status: Capture success" counts down before the status line goes
/// back to reporting the time of the last capture.
const CAPTURE_SUCCESS_DISPLAY: Duration = Duration::from_secs(5);

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SavedAppState {
    pub export_settings: ExportSettings,
    #[serde(default)]
    pub start_on_startup: bool,
    #[serde(default)]
    pub save_result_to_file: bool,
    #[serde(default)]
    pub save_result_folder: Option<PathBuf>,
    pub log_raw_packets: bool,
    #[serde(default)]
    pub tracing_level: TracingLevel,
    /// A non-expiring bearer credential for this account's snapshot writes,
    /// stored in cleartext in eframe's `app.ron` alongside the rest of this
    /// struct. Anyone who gets a copy of that file can push arbitrary GOOD
    /// snapshots into the account's history until the key is rotated, so the
    /// tracker settings modal says so and offers a "Clear key" button.
    #[serde(default)]
    pub tracker_import_key: String,
    /// Persisted, not `serde(skip)`: it is editable in the tracker settings
    /// modal, and an edit that silently reverted on the next launch would be
    /// worse than no field at all. `default` keeps `app.ron` files written
    /// before the field was persisted loading cleanly.
    #[serde(default = "default_tracker_url")]
    pub tracker_api_url: String,
    #[serde(default)]
    pub auto_export_to_tracker: bool,
    /// Whether the stored key was accepted by the tracker *in this session*.
    ///
    /// `serde(skip)`, because it records a round trip that actually happened
    /// rather than a preference: persisting it would let a key revoked between
    /// runs start the next one looking verified. It lives on the saved state
    /// rather than on `IrminsulApp` because this struct is the channel
    /// `monitor.rs` reads, and the automation upload has to gate on the same
    /// thing the manual button does.
    #[serde(skip)]
    pub tracker_verified: bool,
    #[serde(default)]
    pub minimize_to_tray: Option<bool>,
}

/// Where the tracker lives when nothing has been configured in the UI.
const FALLBACK_TRACKER_URL: &str = "http://localhost:49000";

/// Resolve the compile-time `TRACKER_API_URL` against the local default.
///
/// `option_env!` yields `Some("")` for a variable that is *set but empty*, so
/// `unwrap_or` alone silently lost the fallback and left every request built
/// against a relative URL — reqwest then failed at `send()` with "builder
/// error", and with the field serde-skipped there was no way for a user to
/// repair it.
fn resolve_tracker_url(baked_in: Option<&str>) -> String {
    baked_in
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .unwrap_or(FALLBACK_TRACKER_URL)
        .to_string()
}

/// The tracker base URL baked in at compile time, or the local default.
fn default_tracker_url() -> String {
    resolve_tracker_url(option_env!("TRACKER_API_URL"))
}

impl Default for SavedAppState {
    fn default() -> Self {
        Self {
            export_settings: ExportSettings {
                include_characters: true,
                include_artifacts: true,
                include_weapons: true,
                include_materials: true,
                fake_initialize_4th_line: false,
                min_character_level: 1,
                min_character_ascension: 0,
                min_character_constellation: 0,
                min_artifact_level: 0,
                min_artifact_rarity: 3,
                min_weapon_level: 1,
                min_weapon_refinement: 0,
                min_weapon_ascension: 0,
                min_weapon_rarity: 3,
            },
            start_on_startup: false,
            save_result_to_file: false,
            save_result_folder: None,
            log_raw_packets: false,
            tracing_level: Default::default(),
            tracker_import_key: String::new(),
            tracker_api_url: default_tracker_url(),
            auto_export_to_tracker: false,
            tracker_verified: false,
            minimize_to_tray: None,
        }
    }
}

#[derive(Clone, Debug)]
enum OptimizerExportTarget {
    None,
    Clipboard,
    File,
    TrackerManual,
}

/// The outcome of polling a background reply channel.
enum Polled<T> {
    /// No answer yet; keep waiting.
    Pending,
    /// The background task answered.
    Ready(T),
    /// The sender went away without answering — a dead or restarted monitor
    /// thread. Treated as a failure so the UI cannot sit on "Verifying…"
    /// forever, which is what it used to do.
    Dropped,
}

/// Poll a oneshot without blocking, clearing `slot` once it can never produce
/// anything more.
fn poll_oneshot<T>(slot: &mut Option<oneshot::Receiver<T>>) -> Polled<T> {
    let Some(rx) = slot.as_mut() else {
        return Polled::Pending;
    };

    match rx.try_recv() {
        Ok(value) => {
            *slot = None;
            Polled::Ready(value)
        }
        Err(oneshot::error::TryRecvError::Empty) => Polled::Pending,
        Err(oneshot::error::TryRecvError::Closed) => {
            *slot = None;
            Polled::Dropped
        }
    }
}

/// Recover the HTTP status from the error string `monitor.rs` builds for a
/// failed tracker request, which is always `format!("HTTP {status} - {body}")`.
///
/// The old test searched the *whole* string — response body included — for
/// "401" or "403", so any non-2xx body that happened to contain those digits
/// (a numeric id, a byte count, a proxy error page) dropped the verified state
/// and fired an extra verification round trip.
fn tracker_error_status(error: &str) -> Option<u16> {
    let rest = error.strip_prefix("HTTP ")?;
    let digits = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    digits.parse().ok()
}

/// Whether a tracker upload can be attempted at all.
///
/// The manual cloud-upload button gates on this. It used to share the
/// automation predicate below, which also requires the "Auto export to
/// tracker" checkbox, so on the default settings -- key verified, auto export
/// off -- clicking the *enabled* button ran a full export and then toasted
/// "Tracker key not verified. Open settings to re-link."
pub(crate) fn can_upload_to_tracker(state: &SavedAppState) -> bool {
    !state.tracker_import_key.is_empty() && state.tracker_verified
}

/// Whether the automation path should upload after an export.
///
/// `monitor.rs`'s automation trigger and `execute_automation_export` call this
/// rather than keeping their own copy of the condition, which is how the copy
/// came to omit `tracker_verified` -- a key the dashboard had revoked still got
/// a POST on every login.
pub(crate) fn want_tracker_upload(state: &SavedAppState) -> bool {
    state.auto_export_to_tracker && can_upload_to_tracker(state)
}

/// One captured data class a GOOD export writes, and when it last arrived.
pub(crate) struct ExportDataClass {
    /// How the class is named in the toast that says what is missing.
    pub name: &'static str,
    pub captured_at: Option<Instant>,
}

/// The captured data classes an export writes, given the user's settings.
///
/// The single place that answers "what does this export need?", shared by the
/// GOOD file/clipboard export, the manual tracker upload and the automation
/// trigger in `monitor.rs` -- the three sites that used to each demand
/// characters *and* items *and* achievements.
pub(crate) fn export_data_classes(
    settings: &ExportSettings,
    updated: &DataUpdated,
) -> Vec<ExportDataClass> {
    let mut classes = Vec::new();

    if settings.include_characters {
        classes.push(ExportDataClass {
            name: "character data",
            captured_at: updated.characters_updated,
        });
    }

    // Artifacts, weapons and materials all arrive in the one inventory burst
    // that stamps `items_updated`.
    if settings.include_artifacts || settings.include_weapons || settings.include_materials {
        classes.push(ExportDataClass {
            name: "inventory data (artifacts, weapons and materials)",
            captured_at: updated.items_updated,
        });
    }

    classes
}

/// The captured data classes an export still needs, named for a toast.
///
/// Only what the user actually asked to export is required. All three export
/// paths used to demand characters *and* items *and* achievements, so an
/// account whose achievement packet was never seen -- or never identified --
/// could not export its artifacts either, and the toast said only "Data not
/// found. Please open the game first."
///
/// Achievements are deliberately not in this list:
/// `export_genshin_optimizer_with_report` attaches whatever achievements have
/// been captured (`gi_achievements`, an empty list when none have) and there
/// is no setting to include or exclude them, so they can never *block* a GOOD
/// export. The achievement export button has its own check.
pub(crate) fn missing_export_data(
    settings: &ExportSettings,
    updated: &DataUpdated,
) -> Vec<&'static str> {
    export_data_classes(settings, updated)
        .into_iter()
        .filter(|class| class.captured_at.is_none())
        .map(|class| class.name)
        .collect()
}

/// Name what is missing instead of the old catch-all "Data not found".
fn missing_export_data_toast(missing: &[&'static str]) -> String {
    format!(
        "No {} captured yet. Log in to the game with the account you want to export.",
        missing.join(" or ")
    )
}

pub struct IrminsulApp {
    ui_message_tx: mpsc::UnboundedSender<Message>,
    /// Answers to the update prompt only. Keeping these off `ui_message_tx` is
    /// what stops the update check from eating unrelated startup messages.
    update_answer_tx: mpsc::UnboundedSender<UpdateAnswer>,
    state_rx: watch::Receiver<AppState>,
    #[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
    wish_url_rx: watch::Receiver<Option<String>>,
    log_packets_tx: watch::Sender<bool>,
    saved_state_tx: watch::Sender<SavedAppState>,
    tracing_reload_handle: ReloadHandle,
    toast_rx: mpsc::UnboundedReceiver<(String, bool)>,

    monitor_handle: Option<JoinHandle<()>>,
    monitor_cancel_token: CancellationToken,
    /// Held by the update path while the running executable is being replaced.
    /// `Drop` waits on it before its bounded join gets to give up on anything.
    install_lock: Arc<InstallLock>,

    toasts: Toasts,

    power_tools_open: bool,
    bug_report_open: bool,

    automation_settings_open: bool,
    automation_folder_dialog: Option<FileDialog>,

    optimizer_settings_open: bool,
    optimizer_export_rx: Option<oneshot::Receiver<Result<String>>>,
    achievements_export_rx: Option<oneshot::Receiver<Result<Vec<u32>>>>,
    #[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
    wish_url_rx_oneshot: Option<oneshot::Receiver<Result<String>>>,
    wish_link_failed_for: Option<String>,
    pending_open_url: Option<String>,
    optimizer_save_dialog: Option<FileDialog>,
    optimizer_save_path: Option<PathBuf>,
    optimizer_export_target: OptimizerExportTarget,

    restarting: bool,
    /// Shared with `main`, which does the relaunch after `run_native` returns
    /// and the single-instance mutex has been released.
    restart_requested: Arc<AtomicBool>,

    saved_state: SavedAppState,

    tracker_key_modal_open: bool,
    tracker_account_name: Option<(String, String, String)>,
    tracker_verify_rx: Option<oneshot::Receiver<Result<(String, String, String)>>>,
    tracker_upload_rx: Option<oneshot::Receiver<Result<(), String>>>,

    /// The "Genshin is already running" modal.
    game_missed_modal_open: bool,
    /// The verdict the modal was last raised for, so it appears once per
    /// occurrence instead of on every two-second poll. Cleared whenever the
    /// game status leaves the problem state, so a later recurrence -- a second
    /// game session started while capture was off -- raises it again.
    game_missed_modal_shown_for: Option<MissedLaunch>,
    game_kill_rx: Option<oneshot::Receiver<usize>>,

    #[allow(dead_code)]
    tray_icon: Option<TrayIcon>,
    /// Whether there is a tray icon with a menu the user can actually act on.
    ///
    /// On Linux `TrayIconEvent` is never delivered, so the menu is the only way
    /// back to a hidden window — hiding without one is a one-way trip that
    /// leaves killing the process as the only exit. Set from the Linux tray
    /// thread once its menu is up, hence the atomic.
    tray_menu_ready: Arc<AtomicBool>,

    minimize_modal_open: bool,
    minimize_modal_remember: bool,

    app_settings_open: bool,
}

trait ToastError<T> {
    fn toast_error(self, app: &mut IrminsulApp) -> Option<T>;
}

impl<T, E: Display> ToastError<T> for std::result::Result<T, E> {
    fn toast_error(self, app: &mut IrminsulApp) -> Option<T> {
        match self {
            Ok(val) => Some(val),
            Err(e) => {
                tracing::error!("{e}");
                app.toasts.error(e.to_string());
                None
            }
        }
    }
}

#[cfg(windows)]
fn set_launch_on_startup(enabled: bool) -> Result<()> {
    const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_VALUE_NAME: &str = "Irminsul";

    if enabled {
        let current_exe = std::env::current_exe()?;
        let command_value = format!("\"{}\"", current_exe.display());
        let status = Command::new("reg")
            .args([
                "add",
                RUN_KEY,
                "/v",
                RUN_VALUE_NAME,
                "/t",
                "REG_SZ",
                "/d",
                &command_value,
                "/f",
            ])
            .status()?;
        if !status.success() {
            return Err(anyhow!("Failed to register Irminsul startup entry"));
        }
    } else {
        let status = Command::new("reg")
            .args(["delete", RUN_KEY, "/v", RUN_VALUE_NAME, "/f"])
            .status()?;
        if !status.success() {
            return Err(anyhow!("Failed to remove Irminsul startup entry"));
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn set_launch_on_startup(_enabled: bool) -> Result<()> {
    Err(anyhow!("Start on startup is only supported on Windows"))
}

/// Decode the bundled icon into the form `tray-icon` wants.
///
/// Built where the tray lives rather than passed across a thread boundary, so
/// no assumption is made about `tray_icon::Icon` being `Send`.
fn load_tray_icon() -> Option<tray_icon::Icon> {
    let icon_data = image::load_from_memory(include_bytes!("../assets/icon-256.png")).ok()?;
    let rgba = icon_data.into_rgba8();
    let (width, height) = rgba.dimensions();
    tray_icon::Icon::from_rgba(rgba.into_raw(), width, height).ok()
}

/// Bring a window hidden to the tray back.
fn restore_window(ctx: &Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    ctx.request_repaint();
    #[cfg(windows)]
    show_window();
}

/// Quit from the tray menu.
fn quit_from_tray(ctx: &Context) {
    #[cfg(windows)]
    close_window();
    #[cfg(not(windows))]
    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    ctx.request_repaint();
}

fn start_async_runtime(
    cancel_token: CancellationToken,
    egui_ctx: Context,
    log_packets_rx: watch::Receiver<bool>,
    saved_state_rx: watch::Receiver<SavedAppState>,
    capture_backend: capture::BackendType,
    capture_source: capture::CaptureSource,
    install_lock: Arc<InstallLock>,
) -> AsyncRuntimeHandles {
    tracing::info!("starting tokio async");
    let (ui_message_tx, ui_message_rx) = mpsc::unbounded_channel::<Message>();
    let (update_answer_tx, mut update_answer_rx) = mpsc::unbounded_channel::<UpdateAnswer>();
    let (toast_tx, toast_rx) = mpsc::unbounded_channel::<(String, bool)>();

    let (state_tx, state_rx) = watch::channel(AppState::new());
    let (wish_url_tx, wish_url_rx) = watch::channel(None);
    let mut updater_state_rx = state_rx.clone();
    let updater_ctx = egui_ctx.clone();
    let monitor_handle = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            let monitor_ctx = updater_ctx.clone();
            // Notify egui of state changes. This has to be running *before* the
            // update check: the check pushes the "update available" prompt
            // through `state_tx`, and without a repainter listening the window
            // sat on "Checking for Irminsul updates" until the user happened to
            // move the pointer over it.
            tokio::spawn(async move {
                loop {
                    let _ = updater_state_rx.changed().await;
                    updater_ctx.request_repaint();
                }
            });

            // Before starting the monitor, check for updates if not in debug mode
            tracing::info!("Checking for update");
            if let Err(e) = check_for_app_update(
                &state_tx,
                &mut update_answer_rx,
                &cancel_token,
                &toast_tx,
                &install_lock,
            )
            .await
            {
                tracing::error!("error checking for update: {e}");
            }

            // Check for wish URL
            tokio::spawn(async move {
                let mut wish = match wish::Wish::new(wish_url_tx).await {
                    Ok(wish) => wish,
                    Err(e) => {
                        // Not an error: "no Genshin log on this machine" is the
                        // normal state on a box that has never run the game,
                        // and the message names the paths that were probed.
                        tracing::info!("wish monitoring unavailable: {e}");
                        return;
                    }
                };

                if let Err(e) = wish.monitor().await {
                    tracing::error!("Error monitoring for wishes: {e}");
                }
            });

            tracing::info!("Starting monitor");
            let monitor = match Monitor::new(
                cancel_token,
                state_tx,
                ui_message_rx,
                log_packets_rx,
                capture_backend,
                capture_source,
                saved_state_rx,
                toast_tx,
                monitor_ctx,
            )
            .await
            {
                Ok(monitor) => monitor,
                Err(e) => {
                    tracing::error!("error loading monitor task: {e}");
                    return;
                }
            };
            monitor.run().await;
        });
    });
    tracing::info!("started tokio");
    (
        ui_message_tx,
        update_answer_tx,
        state_rx,
        wish_url_rx,
        toast_rx,
        monitor_handle,
    )
}

impl IrminsulApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        mut tracing_reload_handle: ReloadHandle,
        capture_backend: capture::BackendType,
        capture_source: capture::CaptureSource,
        restart_requested: Arc<AtomicBool>,
    ) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        egui_material_icons::initialize(&cc.egui_ctx);

        let saved_state: SavedAppState = if let Some(storage) = cc.storage {
            eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default()
        } else {
            Default::default()
        };

        tracing::info!("Tracker API URL: {}", saved_state.tracker_api_url);

        let cancel_token = CancellationToken::new();
        let install_lock = Arc::new(InstallLock::new());
        tracing_reload_handle.set_filter(saved_state.tracing_level.get_filter());
        let (log_packets_tx, log_packets_rx) = watch::channel(saved_state.log_raw_packets);
        let (saved_state_tx, saved_state_rx) = watch::channel(saved_state.clone());

        let (ui_message_tx, update_answer_tx, state_rx, wish_url_rx, toast_rx, monitor_handle) =
            start_async_runtime(
                cancel_token.clone(),
                cc.egui_ctx.clone(),
                log_packets_rx,
                saved_state_rx,
                capture_backend,
                capture_source,
                Arc::clone(&install_lock),
            );

        if let Err(e) = ui_message_tx.send(Message::StartCapture) {
            tracing::error!("Failed to send auto start message: {e}");
        }

        let toasts = Toasts::default().with_anchor(egui_notify::Anchor::BottomLeft);

        // Auto-verify tracker key on startup
        let tracker_verify_rx = if !saved_state.tracker_import_key.is_empty() {
            let key = saved_state.tracker_import_key.clone();
            let url = format!(
                "{}/genshin-accounts-public/verify-key",
                saved_state.tracker_api_url.trim_end_matches('/')
            );
            let (tx, rx) = oneshot::channel();
            let _ = ui_message_tx.send(Message::VerifyTrackerKey(url, key, tx));
            Some(rx)
        } else {
            None
        };

        #[allow(unused_mut)]
        let mut tray_icon = None;
        let tray_menu_ready = Arc::new(AtomicBool::new(false));

        #[cfg(not(target_os = "linux"))]
        if let Some(icon) = load_tray_icon() {
            let tray_menu = Menu::new();
            let restore_i = MenuItem::new("Restore", true, None);
            let quit_i = MenuItem::new("Quit", true, None);
            let restore_id = restore_i.id().clone();
            let quit_id = quit_i.id().clone();
            let menu_populated = tray_menu.append_items(&[&restore_i, &quit_i]).is_ok();

            tray_icon = TrayIconBuilder::new()
                .with_tooltip("Irminsul")
                .with_icon(icon)
                .with_menu(Box::new(tray_menu))
                .build()
                .ok();

            if tray_icon.is_some() && menu_populated {
                tray_menu_ready.store(true, Ordering::Relaxed);
            }

            let ctx_clone1 = cc.egui_ctx.clone();
            TrayIconEvent::set_event_handler(Some(move |event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    restore_window(&ctx_clone1);
                }
            }));

            let ctx_clone2 = cc.egui_ctx.clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                if event.id == restore_id {
                    restore_window(&ctx_clone2);
                } else if event.id == quit_id {
                    quit_from_tray(&ctx_clone2);
                }
            }));
        }

        // `Menu` and `MenuItem` are GTK objects and are not `Send`, so on Linux
        // the whole tray — icon, menu, items and the menu-event handler — has
        // to be built on the thread that owns the GTK main loop. Building the
        // menu on this thread and passing `Menu::new()` to the builder is what
        // left Linux users with an empty right-click menu and, since
        // `TrayIconEvent` is never delivered there, no way at all to get a
        // hidden window back.
        #[cfg(target_os = "linux")]
        {
            let tray_menu_ready = Arc::clone(&tray_menu_ready);
            let ctx = cc.egui_ctx.clone();
            std::thread::spawn(move || {
                // `gtk::init().unwrap()` here took the whole app down on any
                // machine without a usable display.
                if let Err(e) = gtk::init() {
                    tracing::warn!("could not initialise GTK; the tray icon is disabled: {e}");
                    return;
                }

                let Some(icon) = load_tray_icon() else {
                    tracing::warn!("could not build the tray icon image; the tray is disabled");
                    return;
                };

                let tray_menu = Menu::new();
                let restore_i = MenuItem::new("Restore", true, None);
                let quit_i = MenuItem::new("Quit", true, None);
                let restore_id = restore_i.id().clone();
                let quit_id = quit_i.id().clone();
                if let Err(e) = tray_menu.append_items(&[&restore_i, &quit_i]) {
                    tracing::warn!("could not populate the tray menu; the tray is disabled: {e}");
                    return;
                }

                let _tray_icon = match TrayIconBuilder::new()
                    .with_tooltip("Irminsul")
                    .with_icon(icon)
                    .with_menu(Box::new(tray_menu))
                    .build()
                {
                    Ok(tray_icon) => tray_icon,
                    Err(e) => {
                        tracing::warn!("could not create the tray icon: {e}");
                        return;
                    }
                };

                MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                    if event.id == restore_id {
                        restore_window(&ctx);
                    } else if event.id == quit_id {
                        quit_from_tray(&ctx);
                    }
                }));

                // Only now is "minimize to tray" something the user can undo.
                tray_menu_ready.store(true, Ordering::Relaxed);

                gtk::main();
            });
        }

        Self {
            saved_state,
            ui_message_tx,
            update_answer_tx,
            restart_requested,
            tray_menu_ready,
            game_missed_modal_open: false,
            game_missed_modal_shown_for: None,
            game_kill_rx: None,
            log_packets_tx,
            saved_state_tx,
            tracing_reload_handle,
            toast_rx,
            toasts,
            power_tools_open: false,
            bug_report_open: false,
            automation_settings_open: false,
            automation_folder_dialog: None,
            optimizer_settings_open: false,
            optimizer_export_rx: None,
            achievements_export_rx: None,
            wish_url_rx_oneshot: None,
            wish_link_failed_for: None,
            pending_open_url: None,
            optimizer_save_dialog: None,
            optimizer_save_path: None,
            optimizer_export_target: OptimizerExportTarget::None,
            restarting: false,
            tracker_key_modal_open: false,
            tracker_account_name: None,
            tracker_verify_rx,
            tracker_upload_rx: None,
            tray_icon,
            state_rx,
            wish_url_rx,
            minimize_modal_open: false,
            minimize_modal_remember: true,
            app_settings_open: false,
            monitor_cancel_token: cancel_token,
            monitor_handle: Some(monitor_handle),
            install_lock,
        }
    }
}

impl Drop for IrminsulApp {
    fn drop(&mut self) {
        self.monitor_cancel_token.cancel();

        // Before any deadline applies: a `self_replace` already under way has
        // to be allowed to finish. It renames the running exe aside and then
        // renames the replacement into place, so a process killed inside that
        // window leaves *nothing* at the install path -- the unrecoverable
        // brick the update guards exist to prevent, caused by the guard
        // against a wedged exit. This also stops one starting from here on;
        // the download half checks the cancel token and gives up on its own.
        self.install_lock.shutdown_and_wait();

        let Some(handle) = self.monitor_handle.take() else {
            return;
        };

        // Join with a deadline. This used to be an unconditional `join()`, so a
        // background task that never noticed the cancel token — the update
        // check, which ignored it entirely — wedged process exit *while still
        // holding the single-instance mutex*, and every relaunch afterwards
        // died silently until the user found the process in Task Manager.
        // Nothing here is allowed to be able to do that again: past the
        // timeout the thread is detached and `main` returning takes it down.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let result = handle.join();
            let _ = done_tx.send(result.is_ok());
        });

        match done_rx.recv_timeout(MONITOR_SHUTDOWN_TIMEOUT) {
            Ok(true) => {
                let _ = waiter.join();
            }
            Ok(false) => {
                tracing::error!("monitor thread panicked");
                let _ = waiter.join();
            }
            Err(_) => tracing::warn!(
                "monitor thread did not shut down within {:?}; detaching it and exiting anyway",
                MONITOR_SHUTDOWN_TIMEOUT
            ),
        }
    }
}

impl eframe::App for IrminsulApp {
    /// Called by the framework to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.saved_state);
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Every reply from the background thread is collected here, without
        // blocking: these used to be `blocking_recv()` calls made from inside
        // the widget code, which froze the whole window for the length of an
        // export or an HTTPS round trip.
        self.poll_background_results(ctx);

        let minimize_modal_open = self.minimize_modal_open;
        if minimize_modal_open {
            Modal::new(Id::new("minimize_modal")).show(ctx, |ui| {
                ui.heading("Minimize Behavior");
                ui.label("Would you like to minimize to the system tray or the taskbar?");
                ui.checkbox(&mut self.minimize_modal_remember, "Remember my choice");

                ui.horizontal(|ui| {
                    if ui.button("System Tray").clicked() {
                        if self.minimize_modal_remember {
                            self.saved_state.minimize_to_tray = Some(true);
                        }
                        self.minimize_modal_open = false;
                        self.minimize(ui.ctx(), true);
                    }
                    if ui.button("Taskbar").clicked() {
                        if self.minimize_modal_remember {
                            self.saved_state.minimize_to_tray = Some(false);
                        }
                        self.minimize_modal_open = false;
                        self.minimize(ui.ctx(), false);
                    }
                    if ui.button("Cancel").clicked() {
                        self.minimize_modal_open = false;
                    }
                });
            });
        }

        let app_settings_open = self.app_settings_open;
        if app_settings_open {
            let modal = Modal::new(Id::new("app_settings_modal")).show(ctx, |ui| {
                ui.heading("App Settings");
                ui.horizontal(|ui| {
                    ui.label("Minimize Behavior:");
                    egui::ComboBox::from_id_salt("minimize_behavior_global")
                        .selected_text(match self.saved_state.minimize_to_tray {
                            Some(true) => "Minimize to System Tray",
                            Some(false) => "Minimize to Taskbar",
                            None => "Ask Me",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.saved_state.minimize_to_tray,
                                Some(true),
                                "Minimize to System Tray",
                            );
                            ui.selectable_value(
                                &mut self.saved_state.minimize_to_tray,
                                Some(false),
                                "Minimize to Taskbar",
                            );
                            ui.selectable_value(
                                &mut self.saved_state.minimize_to_tray,
                                None,
                                "Ask Me",
                            );
                        });
                });
            });
            if modal.should_close() {
                self.app_settings_open = false;
            }
        }

        ctx.style_mut(|style| {
            style.interaction.selectable_labels = false;
            style.interaction.tooltip_delay = 0.25;
        });

        if let Some(optimizer_save_dialog) = &mut self.optimizer_save_dialog {
            optimizer_save_dialog.update(ctx);
        }
        if let Some(automation_folder_dialog) = &mut self.automation_folder_dialog {
            automation_folder_dialog.update(ctx);
        }
        if let Some(automation_folder_dialog) = &mut self.automation_folder_dialog
            && let Some(path) = automation_folder_dialog.take_picked()
        {
            self.saved_state.save_result_folder = Some(path);
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                egui::Image::new(egui::include_image!("../assets/background.webp"))
                    .paint_at(ui, ui.ctx().screen_rect());
            });

            ui.vertical(|ui| {
                self.title_bar(ui);
                ui.add_space(25.);

                // Handle power tools here instead of main UI to allow it to be opened
                // in other app states.
                let power_tools_shortcut = KeyboardShortcut {
                    modifiers: Modifiers {
                        command: true,
                        shift: true,
                        ..Default::default()
                    },
                    logical_key: Key::P,
                };
                ui.ctx().input_mut(|i| {
                    if i.consume_shortcut(&power_tools_shortcut) {
                        self.power_tools_open = true;
                    }
                });

                if self.power_tools_open {
                    let modal = Modal::new(Id::new("Power Tools")).show(ui.ctx(), |ui| {
                        self.power_tools_modal(ui);
                    });
                    if modal.should_close() {
                        self.power_tools_open = false;
                    }
                }

                if self.bug_report_open {
                    let modal = Modal::new(Id::new("Bug Report")).show(ui.ctx(), |ui| {
                        self.bug_report_modal(ui);
                    });
                    if modal.should_close() {
                        self.bug_report_open = false;
                    }
                }

                ui.horizontal(|ui| {
                    ui.add_space(525.);
                    let state = self.state_rx.borrow_and_update().clone();
                    ui.vertical(|ui| match state.state {
                        State::Starting => (),
                        State::CheckingForUpdate => self.checking_for_update_ui(ui),
                        State::WaitingForUpdateConfirmation(status) => {
                            self.waiting_for_update_confirmation_ui(ui, status)
                        }
                        State::Updating => self.updating_ui(ui),
                        State::Updated => self.updated_ui(ui),
                        State::CheckingForData => self.checking_for_data_ui(ui),
                        State::WaitingForDownloadConfirmation(confirmation_type) => {
                            self.waiting_for_download_confirmation_ui(ui, confirmation_type)
                        }
                        State::Downloading => self.load_data_ui(ui),
                        State::Main => self.main_ui(ui, &state),
                    });
                });
            });

            ui.with_layout(egui::Layout::bottom_up(egui::Align::RIGHT), |ui| {
                ui.horizontal(|ui| {
                    let discord_icon = egui::include_image!("../assets/discord.svg");
                    if ui
                        .add(
                            Button::image(discord_icon)
                                .frame(false)
                                .image_tint_follows_text_color(true),
                        )
                        .clicked()
                    {
                        ui.ctx()
                            .open_url(OpenUrl::new_tab("https://discord.gg/aQqdZPHEpP"));
                    }

                    use egui::special_emojis::GITHUB;
                    if ui
                        .add(Button::new(RichText::new(GITHUB).size(16.)).frame(false))
                        .clicked()
                    {
                        ui.ctx()
                            .open_url(OpenUrl::new_tab("https://github.com/tawan475/irminsul"));
                    }

                    let button = ui.add(
                        Button::new(
                            RichText::new(egui_material_icons::icons::ICON_BUG_REPORT).size(16.),
                        )
                        .frame(false),
                    );
                    if button.clicked() {
                        self.bug_report_open = true;
                    }
                    let settings_button = ui.add(
                        Button::new(
                            RichText::new(egui_material_icons::icons::ICON_SETTINGS).size(16.),
                        )
                        .frame(false),
                    );
                    if settings_button.clicked() {
                        self.app_settings_open = true;
                    }
                    ui.label(env!("CARGO_PKG_VERSION").to_string());
                    egui::warn_if_debug_build(ui);
                });
            });
        });

        // Drain toast_rx but only keep the most recent success/error to avoid spam when waking up from tray
        let mut latest_error = None;
        let mut latest_success = None;
        while let Ok((msg, is_error)) = self.toast_rx.try_recv() {
            if is_error {
                latest_error = Some(msg);
            } else {
                latest_success = Some(msg);
            }
        }
        if let Some(msg) = latest_error {
            self.toasts.error(msg);
        }
        if let Some(msg) = latest_success {
            self.toasts.success(msg);
        }

        self.toasts.show(ctx);

        // Push the latest saved state to the background thread
        let _ = self.saved_state_tx.send(self.saved_state.clone());
    }
}

impl IrminsulApp {
    /// Collect everything the background thread has answered since the last
    /// frame. Called once at the top of `update`.
    fn poll_background_results(&mut self, ctx: &Context) {
        self.optimizer_handle_export(ctx).toast_error(self);
        #[cfg(any(windows, target_os = "linux"))]
        self.wish_handle_find_url(ctx).toast_error(self);
        self.achievements_handle_export(ctx).toast_error(self);
        self.poll_tracker_upload();
        self.poll_tracker_verify();
    }

    fn poll_tracker_upload(&mut self) {
        let result = match poll_oneshot(&mut self.tracker_upload_rx) {
            Polled::Pending => return,
            Polled::Ready(result) => result,
            Polled::Dropped => {
                Err("the upload request was dropped before it completed".to_string())
            }
        };

        match result {
            Ok(()) => {
                self.toasts
                    .success("Successfully synced capture to Tracker!");
            }
            Err(e) => {
                if matches!(tracker_error_status(&e), Some(401 | 403)) {
                    self.saved_state.tracker_verified = false;
                    self.tracker_account_name = None;
                    self.request_tracker_verify();
                }
                self.toasts.error(format!("Tracker sync failed: {e}"));
            }
        }
    }

    fn poll_tracker_verify(&mut self) {
        let result = match poll_oneshot(&mut self.tracker_verify_rx) {
            Polled::Pending => return,
            Polled::Ready(result) => result,
            // Without this the panel stayed on "Verifying…" for the rest of the
            // session, with the cloud-upload button greyed out and auto-export
            // silently inert, and nothing told the user to hit refresh.
            Polled::Dropped => Err(anyhow!("the verification request was dropped")),
        };

        self.apply_tracker_verify_result(result);
    }

    /// Hide to the tray, or fall back to the taskbar when there is no tray menu
    /// to come back through.
    ///
    /// On Linux `TrayIconEvent` is never delivered, so a tray without a working
    /// menu is a one-way trip: the window disappears with no restore and no
    /// quit, and "Remember my choice" puts the next launch one click from the
    /// same trap.
    fn minimize(&self, ctx: &Context, to_tray: bool) {
        if to_tray && self.tray_menu_ready.load(Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            return;
        }

        if to_tray {
            tracing::warn!("no usable tray icon; minimizing to the taskbar instead");
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
    }

    fn title_bar(&mut self, ui: &mut egui::Ui) {
        let (_, button_width) = egui::Sides::new().show(
            ui,
            |_ui| {},
            |ui| {
                let mut width = 0.0;

                let close_button = ui.add(
                    Button::new(RichText::new(egui_material_icons::icons::ICON_CLOSE).size(24.))
                        .frame(false),
                );
                if close_button.clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                width += close_button.rect.width();

                let min_button = ui.add(
                    Button::new(RichText::new(egui_material_icons::icons::ICON_MINIMIZE).size(24.))
                        .frame(false),
                );
                if min_button.clicked() {
                    match self.saved_state.minimize_to_tray {
                        Some(to_tray) => self.minimize(ui.ctx(), to_tray),
                        None => {
                            self.minimize_modal_open = true;
                        }
                    }
                }
                width += min_button.rect.width();

                width
            },
        );

        let app_rect = ui.max_rect();

        let title_bar_height = 32.0;
        let title_bar_rect = {
            let mut rect = app_rect;
            rect.max.y = rect.min.y + title_bar_height;
            rect.max.x -= button_width;
            rect
        };

        let response = ui.interact(
            title_bar_rect,
            Id::new("title_bar"),
            Sense::click_and_drag(),
        );

        if response.drag_started_by(PointerButton::Primary) {
            ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
        }
    }

    fn checking_for_update_ui(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Checking for Irminsul updates".to_string());
        });
    }

    fn waiting_for_update_confirmation_ui(&self, ui: &mut egui::Ui, version: String) {
        ui.label(format!(
            "Update {} available.  Download and install?",
            version
        ));

        ui.horizontal(|ui| {
            // These go on their own channel: the update check used to read the
            // answer straight off the shared UI channel, which meant it also
            // consumed and discarded the startup StartCapture and
            // VerifyTrackerKey messages queued behind it.
            if ui.add(egui::Button::new("Yes")).clicked()
                && let Err(e) = self.update_answer_tx.send(UpdateAnswer::Accepted)
            {
                tracing::error!("Unable to send UI message: {e}");
            }
            if ui.add(egui::Button::new("No")).clicked()
                && let Err(e) = self.update_answer_tx.send(UpdateAnswer::Declined)
            {
                tracing::error!("Unable to send UI message: {e}");
            }
        });
    }

    fn updating_ui(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Downloading and updating...".to_string());
            ui.spinner();
        });
    }

    fn updated_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Updated. Restarting...".to_string());
        });
        if !self.restarting {
            self.restarting = true;
            // Only ask to close. The replacement is launched by `main` once
            // `run_native` has returned and the single-instance mutex has been
            // released — spawning it from here meant the child immediately hit
            // the mutex this process still held and exited with "Another
            // instance is already running", leaving the user with a frozen
            // window and no visible replacement.
            self.restart_requested.store(true, Ordering::SeqCst);
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn checking_for_data_ui(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Checking for game data updates".to_string());
        });
    }

    fn waiting_for_download_confirmation_ui(
        &self,
        ui: &mut egui::Ui,
        confirmation_type: ConfirmationType,
    ) {
        let label = match confirmation_type {
            ConfirmationType::Initial => "Irminsul needs to download initial data",
            ConfirmationType::Update => "New data available",
        };
        ui.label(label.to_string());
        if ui.add(egui::Button::new("Download")).clicked()
            && let Err(e) = self.ui_message_tx.send(Message::DownloadAcknowledged)
        {
            tracing::error!("Unable to send UI message: {e}");
        }
    }

    fn load_data_ui(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Downloading Data".to_string());
            ui.spinner();
        });
    }

    fn main_ui(&mut self, ui: &mut egui::Ui, app_state: &AppState) {
        if self.optimizer_settings_open {
            let modal = Modal::new(Id::new("Optimizer Settings")).show(ui.ctx(), |ui| {
                self.optimizer_settings_modal(ui);
            });
            if modal.should_close() {
                self.optimizer_settings_open = false;
            }
        }
        self.capture_ui(ui, app_state);
        ui.separator();
        // Wish history is recovered from the game's own `output_log.txt`, which
        // exists on Windows and, through a Proton/Wine prefix, on Linux.
        // Anywhere else the section could only ever be an empty box whose
        // buttons always fail, so it is honestly absent instead.
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.wish_ui(ui);
            ui.separator();
        }
        self.achievement_ui(ui, app_state);
        ui.separator();
        self.automation_ui(ui);
        ui.separator();
        self.tracker_ui(ui, app_state);
    }

    fn capture_ui(&mut self, ui: &mut egui::Ui, app_state: &AppState) {
        // Raise the modal on entering the problem state, not on every poll.
        // Keyed on the cause so that a *different* cause -- capture stopped
        // after an already-running session -- speaks up again rather than being
        // swallowed by the first one.
        // Only `AlreadyRunning` interrupts. `CaptureStopped` is reached by
        // pressing Stop -- telling someone they stopped capture, in a modal,
        // immediately after they chose to stop capture, is nagging. That state
        // still turns the status line red and carries its own tooltip, and a
        // backend that died on its own already raises its own error toast.
        match app_state.game_status {
            GameStatus::LaunchMissed(cause @ MissedLaunch::AlreadyRunning) => {
                if self.game_missed_modal_shown_for != Some(cause) {
                    self.game_missed_modal_shown_for = Some(cause);
                    self.game_missed_modal_open = true;
                }
            }
            // Re-arm once the game is gone or a watched session starts, so a
            // later already-running session speaks up again.
            GameStatus::LaunchMissed(MissedLaunch::CaptureStopped) => {}
            _ => self.game_missed_modal_shown_for = None,
        }

        if let Some(rx) = &mut self.game_kill_rx {
            match rx.try_recv() {
                Ok(0) => {
                    self.game_kill_rx = None;
                    // Not an error: the process may have exited on its own
                    // between the click and the kill.
                    self.toasts.info("No running Genshin process to close.");
                }
                Ok(killed) => {
                    self.game_kill_rx = None;
                    self.toasts.success(if killed == 1 {
                        "Genshin closed. Start it again to capture this session.".to_string()
                    } else {
                        format!(
                            "Closed {killed} Genshin processes. Start the game again to capture."
                        )
                    });
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    // The monitor thread is gone; without this arm the button
                    // would sit disabled for the rest of the session.
                    self.game_kill_rx = None;
                    self.toasts.error("Unable to reach the capture backend.");
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }

        if self.game_missed_modal_open {
            let cause = self.game_missed_modal_shown_for;
            let modal = Modal::new(Id::new("Game Already Running")).show(ui.ctx(), |ui| {
                self.game_missed_modal(ui, cause);
            });
            if modal.should_close() {
                self.game_missed_modal_open = false;
            }
        }

        ui.vertical(|ui| {
            egui::Sides::new().show(
                ui,
                |ui| {
                    Self::section_header(ui, "Packet Capture");
                },
                |ui| {
                    // No capture on/off control by design: capture is meant to
                    // be running for as long as Irminsul is, and a backend that
                    // dies is brought back by the supervisor in `monitor.rs`
                    // rather than by the user noticing a stopped indicator. The
                    // game status line below reports whether it is actually
                    // reading anything, which is the question a button could
                    // never answer.
                    if ui
                        .button(egui_material_icons::icons::ICON_SETTINGS)
                        .clicked()
                    {
                        self.optimizer_settings_open = true;
                    }

                    ui.add_enabled_ui(self.optimizer_export_rx.is_none(), |ui| {
                        // Only what this export writes. Requiring achievements
                        // here meant an account whose achievement packet was
                        // never seen could not export its artifacts either.
                        let missing = missing_export_data(
                            &self.saved_state.export_settings,
                            &app_state.updated,
                        );

                        if ui
                            .button(egui_material_icons::icons::ICON_DOWNLOAD)
                            .clicked()
                        {
                            if missing.is_empty() {
                                let now = Local::now();
                                let mut optimizer_save_dialog = FileDialog::new()
                                    .add_file_filter_extensions("JSON files", vec!["json"])
                                    .default_file_name(&format!(
                                        "genshin_export_{}.json",
                                        now.format("%Y-%m-%d_%H-%M")
                                    ));
                                optimizer_save_dialog.save_file();
                                self.optimizer_save_dialog = Some(optimizer_save_dialog);
                            } else {
                                self.toasts.error(missing_export_data_toast(&missing));
                            }
                        }

                        if let Some(optimizer_save_dialog) = &mut self.optimizer_save_dialog
                            && let Some(path) = optimizer_save_dialog.take_picked()
                        {
                            self.optimizer_save_path = Some(path);
                            self.genshin_optimizer_request_export(OptimizerExportTarget::File);
                        }

                        if ui
                            .button(egui_material_icons::icons::ICON_CONTENT_PASTE_GO)
                            .clicked()
                        {
                            if missing.is_empty() {
                                self.genshin_optimizer_request_export(
                                    OptimizerExportTarget::Clipboard,
                                );
                            } else {
                                self.toasts.error(missing_export_data_toast(&missing));
                            }
                        }
                    });
                },
            );
        });
        egui::Grid::new("capture_stats")
            .striped(false)
            .num_columns(2)
            .min_col_width(0.)
            .show(ui, |ui| {
                Self::data_state(ui, "Items", app_state.updated.items_updated);
                Self::data_state(ui, "Characters", app_state.updated.characters_updated);
                Self::data_state(ui, "Achievements", app_state.updated.achievements_updated);
            });

        ui.add_space(4.0);

        let status_text = match app_state.updated.achievements_updated_time {
            None => RichText::new("Status: Ready to capture").strong(),
            Some(updated_time) => {
                // The countdown runs for CAPTURE_SUCCESS_DISPLAY and then hands
                // over to the "Last capture at" line. Keying the two branches
                // off `achievements_updated.is_some()` instead made the second
                // one dead code — that field is only ever cleared by
                // Message::ClearData — and left the app asking for a repaint
                // every frame, forever, from the first achievement packet on.
                let remaining = app_state
                    .updated
                    .achievements_updated
                    .and_then(|updated| CAPTURE_SUCCESS_DISPLAY.checked_sub(updated.elapsed()));

                match remaining {
                    Some(remaining) => {
                        // Bounded: this stops on its own once the countdown
                        // reaches zero, instead of pinning the UI at vsync.
                        ui.ctx().request_repaint_after(Duration::from_millis(250));
                        RichText::new(format!(
                            "Status: Capture success [{}s]",
                            remaining.as_secs()
                        ))
                        .color(Color32::from_hex("#00ab3f").unwrap())
                        .strong()
                    }
                    None => RichText::new(format!(
                        "Status: Ready to capture, Last capture at {}",
                        updated_time.format("%H:%M:%S")
                    ))
                    .strong(),
                }
            }
        };
        ui.label(status_text);

        // Under "Status", as asked. The two lines above report Irminsul's own
        // health -- the backend is up, this much data has arrived -- and both
        // used to read perfectly green while the session could never be
        // decrypted at all, because the game had been started first. This line
        // reports that, and it is the only one of the three that can tell the
        // user to do something.
        let game_status = app_state.game_status;
        let mut line = match game_status.severity() {
            Severity::Problem => RichText::new(format!(
                "{} {}",
                egui_material_icons::icons::ICON_WARNING,
                game_status.label()
            ))
            .color(Color32::RED),
            Severity::Good => {
                RichText::new(game_status.label()).color(Color32::from_hex("#00ab3f").unwrap())
            }
            Severity::Neutral => RichText::new(game_status.label()),
        };
        line = line.strong();
        ui.label(line).on_hover_text(game_status.tooltip());
    }

    /// The modal raised when the game is running but its launch was missed, so
    /// nothing from this session can ever be decrypted.
    ///
    /// Three ways out, because there are genuinely three reasonable answers:
    /// give up on this session, restart the game, or carry on and deal with it
    /// later. Dismissing leaves the red status line in place, so the state is
    /// never hidden -- only the interruption is.
    fn game_missed_modal(&mut self, ui: &mut egui::Ui, cause: Option<MissedLaunch>) {
        // Wider than the other modals on purpose: this one carries two full
        // sentences of explanation, and at 420 the last word of a line kept
        // being pushed onto one of its own.
        ui.set_width(520.0);
        ui.heading(match cause {
            Some(MissedLaunch::CaptureStopped) => "Genshin ran while capture was off",
            _ => "Genshin is already running",
        });
        ui.separator();
        ui.label(match cause {
            Some(MissedLaunch::CaptureStopped) => {
                "Genshin was running while packet capture was stopped, so Irminsul missed the login handshake and has no key for this session. Nothing can be captured from it, however long you leave it running."
            }
            _ => {
                "Genshin was already running when Irminsul started, so Irminsul never saw the login handshake and has no key for this session. Nothing can be captured from it, however long you leave it running."
            }
        });
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Fix: close Genshin and start it again, leaving Irminsul running with capture on.",
            )
            .strong(),
        );
        ui.separator();

        // `egui::Sides` hands a `&mut Ui` to two closures at once, so neither
        // may borrow `self`. Decide here, act after.
        enum Choice {
            CloseIrminsul,
            KillGame,
            Dismiss,
        }
        // A `Cell` rather than a plain local: `Sides` takes both closures at
        // once, so the borrow checker cannot see that they never run together.
        let choice: std::cell::Cell<Option<Choice>> = std::cell::Cell::new(None);
        let kill_pending = self.game_kill_rx.is_some();

        egui::Sides::new().show(
            ui,
            |ui| {
                if ui
                    .button("Close Irminsul")
                    .on_hover_text(
                        "Quit Irminsul. Start it before Genshin next time so it can watch the login handshake.",
                    )
                    .clicked()
                {
                    choice.set(Some(Choice::CloseIrminsul));
                }

                ui.add_enabled_ui(!kill_pending, |ui| {
                    if ui
                        .button("Close Genshin")
                        .on_hover_text(
                            "Force the game to exit so you can start it again with capture running. Your account progress is stored on the server and is safe, but anything in progress right now -- a domain run, a boss fight -- is lost.",
                        )
                        .clicked()
                    {
                        choice.set(Some(Choice::KillGame));
                    }
                });
            },
            |ui| {
                if ui
                    .button("Close")
                    .on_hover_text(
                        "Dismiss this. The game status line stays red until a session Irminsul watched start.",
                    )
                    .clicked()
                {
                    choice.set(Some(Choice::Dismiss));
                }
            },
        );

        let Some(choice) = choice.take() else {
            return;
        };
        self.game_missed_modal_open = false;

        match choice {
            Choice::CloseIrminsul => {
                // The ordinary close path, so the monitor and capture backend
                // are torn down the way a window close tears them down rather
                // than abandoned.
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Choice::KillGame => {
                let (tx, rx) = oneshot::channel();
                if let Err(e) = self.ui_message_tx.send(Message::KillGame(tx)) {
                    tracing::error!("Unable to send kill game message: {e}");
                    self.toasts.error("Unable to reach the capture backend.");
                } else {
                    self.game_kill_rx = Some(rx);
                    self.toasts.info("Closing Genshin...");
                }
            }
            Choice::Dismiss => {}
        }
        ui.close();
    }

    fn data_state(ui: &mut egui::Ui, source: &str, last_updated: Option<Instant>) {
        let updated_icon = match last_updated {
            Some(_) => RichText::new(egui_material_icons::icons::ICON_CHECK_CIRCLE)
                .color(Color32::from_hex("#00ab3f").unwrap()),
            None => RichText::new(egui_material_icons::icons::ICON_CHECK_INDETERMINATE_SMALL),
        };
        ui.label(updated_icon);
        ui.label(source);
        ui.end_row();
    }

    fn genshin_optimizer_request_export(&mut self, target: OptimizerExportTarget) {
        let (tx, rx) = oneshot::channel();
        let _ = self.ui_message_tx.send(Message::ExportGenshinOptimizer(
            self.saved_state.export_settings.clone(),
            tx,
        ));
        self.optimizer_export_target = target;
        self.optimizer_export_rx = Some(rx);
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn wish_ui(&mut self, ui: &mut egui::Ui) {
        let wish_url = self.wish_url_rx.borrow_and_update().clone();
        ui.vertical(|ui| {
            egui::Sides::new().show(
                ui,
                |ui| {
                    Self::section_header(ui, "Wish History");
                    ui.label(egui_material_icons::icons::ICON_HELP)
                        .on_hover_text("Click the Copy icon to copy the wish URL to the clipboard.  Paste this into paimon.moe using the Manual auto-import method.");
                },
                |ui| {
                    ui.add_enabled_ui(self.wish_url_rx_oneshot.is_none(), |ui| {
                        if ui
                            .button(egui_material_icons::icons::ICON_CONTENT_PASTE_GO)
                            .clicked()
                        {
                            if let Some(url) = &wish_url {
                                ui.ctx().copy_text(url.clone());
                                self.toasts.info("Wish URL copied to clipboard");
                                self.wish_link_failed_for = None;
                            } else {
                                let (tx, rx) = oneshot::channel();
                                let _ = self.ui_message_tx.send(Message::FindWishUrl(tx));
                                self.wish_url_rx_oneshot = Some(rx);
                                self.pending_open_url = None;
                                self.wish_link_failed_for = None;
                            }
                        }
                    });
                },
            );
            ui.horizontal(|ui| {
                if ui.link("Open Paimon.moe").clicked() {
                    self.handle_wish_open_button(ui, wish_url.clone(), "https://paimon.moe/wish/import");
                }
                if ui.link("Open StarDB").clicked() {
                    self.handle_wish_open_button(ui, wish_url.clone(), "https://stardb.gg/en/genshin/wish-import");
                }
            });
        });
    }

    /// Collect the result of a `FindWishUrl` request.
    ///
    /// This used to `blocking_recv()` from inside the widget tree, freezing the
    /// whole window for a full HTTPS round trip to
    /// `hk4e-api-os.hoyoverse.com` — indefinitely, on a network where that host
    /// is blackholed.
    #[cfg(any(windows, target_os = "linux"))]
    fn wish_handle_find_url(&mut self, ctx: &Context) -> Result<()> {
        let url = match poll_oneshot(&mut self.wish_url_rx_oneshot) {
            Polled::Pending => return Ok(()),
            Polled::Ready(Ok(url)) => Some(url),
            Polled::Ready(Err(_)) | Polled::Dropped => None,
        };

        match url {
            Some(url) => {
                ctx.copy_text(url);
                self.toasts.info("Wish URL copied to clipboard");
                self.wish_link_failed_for = None;
                if let Some(target_url) = self.pending_open_url.take() {
                    ctx.open_url(egui::OpenUrl::new_tab(target_url));
                }
            }
            None => {
                if let Some(target_url) = self.pending_open_url.take() {
                    self.wish_link_failed_for = Some(target_url);
                    self.toasts
                        .error("Link not found, click again to open anyways");
                } else {
                    self.wish_link_failed_for = None;
                    self.toasts.error(
                        "Could not find Wish URL. Please open the Wish History in-game first.",
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn handle_wish_open_button(
        &mut self,
        ui: &mut egui::Ui,
        wish_url: Option<String>,
        target_url: &str,
    ) {
        if self.wish_link_failed_for.as_deref() == Some(target_url) {
            ui.ctx().open_url(egui::OpenUrl::new_tab(target_url));
            self.wish_link_failed_for = None;
        } else if let Some(url) = wish_url {
            ui.ctx().copy_text(url);
            self.toasts.info("Wish URL copied to clipboard");
            ui.ctx().open_url(egui::OpenUrl::new_tab(target_url));
            self.wish_link_failed_for = None;
        } else {
            let (tx, rx) = oneshot::channel();
            let _ = self.ui_message_tx.send(Message::FindWishUrl(tx));
            self.wish_url_rx_oneshot = Some(rx);
            self.pending_open_url = Some(target_url.to_string());
            self.wish_link_failed_for = None;
        }
    }

    fn automation_ui(&mut self, ui: &mut egui::Ui) {
        if self.automation_settings_open {
            let modal = Modal::new(Id::new("Automation Settings")).show(ui.ctx(), |ui| {
                self.automation_settings_modal(ui);
            });
            if modal.should_close() {
                self.automation_settings_open = false;
            }
        }

        ui.vertical(|ui| {
            egui::Sides::new().show(
                ui,
                |ui| {
                    Self::section_header(ui, "Automation");
                },
                |_ui| {},
            );

            ui.add_enabled_ui(true, |ui| {
                let previous_startup = self.saved_state.start_on_startup;
                if ui
                    .checkbox(
                        &mut self.saved_state.start_on_startup,
                        "Start Irminsul on startup",
                    )
                    .changed()
                    && let Err(e) = set_launch_on_startup(self.saved_state.start_on_startup)
                {
                    self.saved_state.start_on_startup = previous_startup;
                    tracing::error!("Unable to update startup behavior: {e}");
                    self.toasts.error("Unable to update startup behavior");
                }
                ui.horizontal(|ui| {
                    ui.checkbox(
                        &mut self.saved_state.save_result_to_file,
                        "Save result to file",
                    );
                    ui.add_enabled_ui(self.saved_state.save_result_to_file, |ui| {
                        if ui
                            .button(egui_material_icons::icons::ICON_SETTINGS)
                            .clicked()
                        {
                            self.automation_settings_open = true;
                        }
                    });
                });
            });
        });
    }

    fn apply_tracker_verify_result(&mut self, result: Result<(String, String, String)>) {
        match result {
            Ok(info) => {
                self.tracker_account_name = Some(info);
                self.saved_state.tracker_verified = true;
            }
            Err(e) => {
                self.tracker_account_name = None;
                self.saved_state.tracker_verified = false;
                self.toasts
                    .error(format!("Failed to verify tracker key: {}", e));
            }
        }
    }

    fn request_tracker_verify(&mut self) {
        let key = self.saved_state.tracker_import_key.clone();
        if key.is_empty() {
            self.tracker_account_name = None;
            self.saved_state.tracker_verified = false;
            // Drop any in-flight request too, so its (now meaningless) answer
            // cannot land later and re-toast a failure for a key that is gone.
            self.tracker_verify_rx = None;
            return;
        }
        let url = format!(
            "{}/genshin-accounts-public/verify-key",
            self.saved_state.tracker_api_url.trim_end_matches('/')
        );
        let (tx, rx) = oneshot::channel();
        let _ = self
            .ui_message_tx
            .send(Message::VerifyTrackerKey(url, key, tx));
        self.tracker_verify_rx = Some(rx);
        self.tracker_account_name = None;
        self.saved_state.tracker_verified = false;
    }

    fn tracker_ui(&mut self, ui: &mut egui::Ui, app_state: &AppState) {
        if self.tracker_key_modal_open {
            let modal = Modal::new(Id::new("Tracker Key Modal")).show(ui.ctx(), |ui| {
                ui.set_width(360.0);
                ui.heading("Set Tracker Import Key");
                ui.separator();

                // The URL used to be compile-time only (`#[serde(skip)]`, no
                // widget), so anyone self-hosting on another host or port had
                // to rebuild Irminsul to point it at their backend.
                ui.label("Tracker API base URL:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.saved_state.tracker_api_url)
                        .hint_text(default_tracker_url()),
                );
                if ui.button("Reset URL to default").clicked() {
                    self.saved_state.tracker_api_url = default_tracker_url();
                }

                ui.add_space(6.0);
                ui.label("Enter your Import Key generated from the GDT dashboard:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.saved_state.tracker_import_key)
                        .password(true),
                );
                ui.label(
                    RichText::new(
                        "The key is stored in plain text in Irminsul's app data directory and \
                         does not expire. Anyone who copies that folder can write snapshots to \
                         this account until you regenerate the key on the dashboard.",
                    )
                    .color(Color32::GRAY)
                    .small(),
                );
                if ui
                    .button("Clear key")
                    .on_hover_text("Remove the stored key from this machine.")
                    .clicked()
                {
                    self.saved_state.tracker_import_key.clear();
                    self.tracker_account_name = None;
                    self.saved_state.tracker_verified = false;
                    self.tracker_verify_rx = None;
                }

                if self.tracker_verify_rx.is_some() {
                    ui.label(RichText::new("Verifying key…").color(Color32::YELLOW));
                } else if self.saved_state.tracker_verified {
                    if let Some((name, uid, server)) = &self.tracker_account_name {
                        ui.label(
                            RichText::new(format!("Valid: {name} (UID {uid})"))
                                .color(Color32::from_hex("#00ab3f").unwrap()),
                        );
                        ui.label(RichText::new(format!("Server: {server}")).color(Color32::GRAY));
                    }
                } else if !self.saved_state.tracker_import_key.is_empty() {
                    ui.label(RichText::new("Key invalid or unreachable").color(Color32::RED));
                }
                ui.separator();
                if ui.button("Save & Close").clicked() {
                    self.tracker_key_modal_open = false;
                    self.request_tracker_verify();
                }
            });
            if modal.should_close() {
                self.tracker_key_modal_open = false;
            }
        }

        ui.add_enabled_ui(true, |ui| {
            ui.vertical(|ui| {
                egui::Sides::new().show(
                    ui,
                    |ui| {
                        Self::section_header(ui, "Tracker");
                    },
                    |ui| {
                        ui.horizontal(|ui| {
                            if ui
                                .button(egui_material_icons::icons::ICON_REFRESH)
                                .clicked()
                            {
                                self.request_tracker_verify();
                            }
                            // Only the classes this upload actually writes, and
                            // the same key check the click handler makes -- an
                            // enabled button whose handler then refuses is
                            // exactly what this used to be.
                            let missing = missing_export_data(
                                &self.saved_state.export_settings,
                                &app_state.updated,
                            );
                            ui.add_enabled_ui(
                                missing.is_empty()
                                    && can_upload_to_tracker(&self.saved_state)
                                    && self.optimizer_export_rx.is_none(),
                                |ui| {
                                    if ui
                                        .button(egui_material_icons::icons::ICON_CLOUD_UPLOAD)
                                        .on_hover_text("Export current capture to Tracker")
                                        .clicked()
                                    {
                                        self.genshin_optimizer_request_export(
                                            OptimizerExportTarget::TrackerManual,
                                        );
                                    }
                                },
                            );
                            if ui
                                .button(egui_material_icons::icons::ICON_SETTINGS)
                                .clicked()
                            {
                                self.tracker_key_modal_open = true;
                                self.request_tracker_verify();
                            }
                        });
                    },
                );

                if self.saved_state.tracker_import_key.is_empty() {
                    ui.label("No account linked.");
                } else if let Some((name, uid, server)) = &self.tracker_account_name {
                    ui.label(
                        RichText::new(format!("Account: {}", name))
                            .color(Color32::from_hex("#00ab3f").unwrap()),
                    );
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("UID: {}", uid)).color(Color32::GRAY));
                        ui.label(RichText::new("•").color(Color32::DARK_GRAY));
                        ui.label(RichText::new(format!("Server: {}", server)).color(Color32::GRAY));
                    });
                } else if self.tracker_verify_rx.is_some() {
                    ui.label(RichText::new("Verifying...").color(Color32::YELLOW));
                } else {
                    ui.label(RichText::new("Verification Failed").color(Color32::RED));
                }

                ui.checkbox(
                    &mut self.saved_state.auto_export_to_tracker,
                    "Auto export to tracker",
                );
                // Checked but inert is otherwise completely silent: the
                // automation upload simply never fires.
                if self.saved_state.auto_export_to_tracker
                    && !want_tracker_upload(&self.saved_state)
                {
                    ui.label(
                        RichText::new(
                            "Auto export is on, but the key is not linked and verified, \
                             so nothing will be uploaded.",
                        )
                        .color(Color32::RED)
                        .small(),
                    );
                }
            });
        });
    }

    fn automation_settings_modal(&mut self, ui: &mut egui::Ui) {
        ui.set_width(360.0);
        ui.heading("Save Result To File");
        ui.separator();
        let selected_folder = self
            .saved_state
            .save_result_folder
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "No folder selected".to_string());
        ui.label(format!("Selected folder: {selected_folder}"));
        ui.horizontal(|ui| {
            if ui.button("Choose folder").clicked() {
                let mut dialog = FileDialog::new();
                dialog.pick_directory();
                self.automation_folder_dialog = Some(dialog);
                self.automation_settings_open = false;
                ui.close();
            }
            if ui.button("Clear").clicked() {
                self.saved_state.save_result_folder = None;
            }
        });
        ui.separator();
        egui::Sides::new().show(
            ui,
            |_ui| {},
            |ui| {
                if ui.button("Ok").clicked() {
                    ui.close();
                }
            },
        );
    }

    fn power_tools_modal(&mut self, ui: &mut egui::Ui) {
        ui.set_width(300.0);
        ui.heading("Power Tools");
        ui.separator();
        if ui
            .checkbox(&mut self.saved_state.log_raw_packets, "Log raw packets")
            .changed()
        {
            let _ = self.log_packets_tx.send(self.saved_state.log_raw_packets);
        };
        let prev_level = self.saved_state.tracing_level;
        egui::ComboBox::from_label("Logging Level")
            .selected_text(format!("{}", self.saved_state.tracing_level))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut self.saved_state.tracing_level,
                    TracingLevel::Default,
                    "Default",
                );
                ui.selectable_value(
                    &mut self.saved_state.tracing_level,
                    TracingLevel::VerboseInfo,
                    "Verbose Info",
                );
                ui.selectable_value(
                    &mut self.saved_state.tracing_level,
                    TracingLevel::VerboseDebug,
                    "Verbose Debug",
                );
                // Named, not just "Verbose Trace": at this level
                // auto-artifactarium logs every decoded packet's payload as
                // base64, so latest.log becomes a dump of the account's game
                // data -- and the Bug Report modal asks users to attach it.
                ui.selectable_value(
                    &mut self.saved_state.tracing_level,
                    TracingLevel::VerboseTrace,
                    "Verbose Trace (dumps raw packet contents)",
                )
                .on_hover_text(
                    "Writes every captured packet's contents to the log file. That includes \
                     your characters, inventory and achievements, so review the log before \
                     sharing it.",
                );
            });
        if prev_level != self.saved_state.tracing_level {
            self.tracing_reload_handle
                .set_filter(self.saved_state.tracing_level.get_filter());
        }
        ui.end_row();
        ui.separator();
        egui::Sides::new().show(
            ui,
            |_ui| {},
            |ui| {
                if ui.button("Ok").clicked() {
                    ui.close()
                }
            },
        );
    }

    fn bug_report_modal(&mut self, ui: &mut egui::Ui) {
        ui.set_width(300.0);
        ui.heading("Bug Report");
        ui.separator();
        ui.label("When filing a bug, please include the latest log file:");
        ui.label(
            RichText::new(
                "Check it first: at the Verbose Trace logging level the log contains a \
                 dump of your account's game data.",
            )
            .color(Color32::GRAY)
            .small(),
        );
        if ui.button("Open log directory").clicked() {
            thread::spawn(|| {
                let _ = open_log_dir();
            });
        }
        ui.separator();
        egui::Sides::new().show(
            ui,
            |_ui| {},
            |ui| {
                if ui.button("New GitHub Issue").clicked() {
                    ui.ctx().open_url(OpenUrl::new_tab(
                        "https://github.com/tawan475/irminsul/issues/new",
                    ));
                    ui.close()
                }
                if ui.button("Cancel").clicked() {
                    ui.close()
                }
            },
        );
    }

    fn optimizer_settings_modal(&mut self, ui: &mut egui::Ui) {
        ui.set_width(300.0);
        ui.heading("Genshin Optimizer Settings");
        ui.separator();
        ui.checkbox(
            &mut self.saved_state.export_settings.include_characters,
            "Characters",
        );
        ui.horizontal(|ui| {
            ui.add_space(20.);
            egui::Grid::new("char_options")
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Min level".to_string());
                    ui.add(
                        DragValue::new(&mut self.saved_state.export_settings.min_character_level)
                            .range(1..=90),
                    );
                    ui.end_row();
                    ui.label("Min ascension".to_string());
                    ui.add(
                        DragValue::new(
                            &mut self.saved_state.export_settings.min_character_ascension,
                        )
                        .range(0..=6),
                    );
                    ui.end_row();
                    ui.label("Min constellation".to_string());
                    ui.add(
                        DragValue::new(
                            &mut self.saved_state.export_settings.min_character_constellation,
                        )
                        .range(0..=6),
                    );
                    ui.end_row();
                });
        });
        ui.checkbox(
            &mut self.saved_state.export_settings.include_artifacts,
            "Artifacts",
        );
        ui.horizontal(|ui| {
            ui.add_space(20.);
            egui::Grid::new("artifact_options")
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Min level".to_string());
                    ui.add(
                        DragValue::new(&mut self.saved_state.export_settings.min_artifact_level)
                            .range(0..=20),
                    );
                    ui.end_row();
                    ui.label("Min rarity".to_string());
                    ui.add(
                        DragValue::new(&mut self.saved_state.export_settings.min_artifact_rarity)
                            .range(0..=6),
                    );
                    ui.end_row();
                });
        });
        ui.checkbox(
            &mut self.saved_state.export_settings.include_weapons,
            "Weapons",
        );
        ui.horizontal(|ui| {
            ui.add_space(20.);
            egui::Grid::new("weapon_options")
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Min level".to_string());
                    ui.add(
                        DragValue::new(&mut self.saved_state.export_settings.min_weapon_level)
                            .range(1..=90),
                    );
                    ui.end_row();

                    ui.label("Min refinement".to_string());
                    ui.add(
                        DragValue::new(&mut self.saved_state.export_settings.min_weapon_refinement)
                            .range(1..=5),
                    );
                    ui.end_row();

                    ui.label("Min ascension".to_string());
                    ui.add(
                        DragValue::new(&mut self.saved_state.export_settings.min_weapon_ascension)
                            .range(0..=6),
                    );
                    ui.end_row();

                    ui.label("Min rarity".to_string());
                    ui.add(
                        DragValue::new(&mut self.saved_state.export_settings.min_weapon_rarity)
                            .range(1..=5),
                    );
                    ui.end_row();
                });
        });
        ui.checkbox(
            &mut self.saved_state.export_settings.include_materials,
            "Materials",
        );
        ui.checkbox(
            &mut self.saved_state.export_settings.fake_initialize_4th_line,
            "Fake level-up 5* artifacts with unactivated stats (hover for more info)"
        ).on_hover_text(
            "Genshin Optimizer still internally treats 5* 3-liners like pre-6.0, where the new stat is \"hidden\" and unknown to GO's optimizer.\nThis is a temporary workaround by activating that last stat line, but to prevent unintended effects, the artifacts are set to level 4, mimicking the player leveling it up.\nThe last line *should* be the unlockable 4th line."
        );
        ui.separator();
        egui::Sides::new().show(
            ui,
            |_ui| {},
            |ui| {
                if ui.button("Ok").clicked() {
                    ui.close()
                }
            },
        );
    }

    /// Collect the result of an `ExportGenshinOptimizer` request.
    ///
    /// Polled rather than awaited: `blocking_recv()` here stalled the egui
    /// update loop for the whole export.
    fn optimizer_handle_export(&mut self, ctx: &Context) -> Result<()> {
        let json = match poll_oneshot(&mut self.optimizer_export_rx) {
            Polled::Pending => return Ok(()),
            Polled::Ready(result) => result,
            Polled::Dropped => {
                self.optimizer_export_target = OptimizerExportTarget::None;
                return Err(anyhow!(
                    "the export request was dropped before it completed"
                ));
            }
        };
        let json = match json {
            Ok(json) => json,
            Err(e) => {
                self.optimizer_export_target = OptimizerExportTarget::None;
                return Err(e);
            }
        };

        match self.optimizer_export_target {
            OptimizerExportTarget::None => {
                tracing::warn!("Unexpected json export");
            }
            OptimizerExportTarget::Clipboard => {
                self.optimizer_save_to_clipboard(ctx, json)?;
            }
            OptimizerExportTarget::File => {
                self.optimizer_save_to_file(json)?;
            }

            OptimizerExportTarget::TrackerManual => {
                if can_upload_to_tracker(&self.saved_state) {
                    self.tracker_upload_json(json);
                } else if !self.saved_state.tracker_import_key.is_empty() {
                    self.toasts
                        .error("Tracker key not verified. Open settings to re-link.");
                } else {
                    self.toasts.error("No tracker import key configured.");
                }
            }
        }

        self.optimizer_export_target = OptimizerExportTarget::None;
        Ok(())
    }

    fn optimizer_save_to_clipboard(&mut self, ctx: &Context, json: String) -> Result<()> {
        ctx.copy_text(json);
        self.toasts
            .info("Genshin Optimizer data copied to clipboard");
        Ok(())
    }

    fn optimizer_save_to_file(&mut self, json: String) -> Result<()> {
        let path = self
            .optimizer_save_path
            .take()
            .ok_or_else(|| anyhow!("No save file path set"))?;

        let file = File::create(&path).with_context(|| format!("Unable to open file {path:?}"))?;
        let mut writer = BufWriter::new(file);
        writer.write_all(json.as_bytes())?;

        self.toasts.info("Genshin Optimizer data saved to file");
        Ok(())
    }

    fn tracker_upload_json(&mut self, json: String) {
        let key = self.saved_state.tracker_import_key.clone();
        let base_url = self.saved_state.tracker_api_url.clone();
        let url = format!(
            "{}/genshin-accounts-public/import-by-key",
            base_url.trim_end_matches('/')
        );

        self.toasts.info("Starting upload to Tracker...");

        let (tx, rx) = oneshot::channel();
        let _ = self
            .ui_message_tx
            .send(Message::UploadToTracker(json, url, key, tx));
        self.tracker_upload_rx = Some(rx);
    }

    /// The achievement export, which is the one path that genuinely needs
    /// achievement data.
    ///
    /// DEFERRED: this still cannot tell "no achievement packet has arrived"
    /// from "one arrived and could not be read". auto-artifactarium grew
    /// `try_matches_achievement_packet` and `AchievementMatchError`
    /// (`UnidentifiedFields` / `NoCandidateList`) for exactly that distinction,
    /// and nothing in irminsul calls either: surfacing it needs the classifier
    /// in `monitor.rs::handle_game_packet` to keep the last failure and put it
    /// on `AppState`, which is monitor's half of the change. Until then the
    /// toast below says only that nothing has been captured yet -- true in both
    /// cases, and no longer able to block a GOOD export either way.
    fn achievement_ui(&mut self, ui: &mut egui::Ui, app_state: &AppState) {
        ui.vertical(|ui| {
            egui::Sides::new().show(
                ui,
                |ui| {
                    Self::section_header(ui, "Achievement Export");
                    ui.label(egui_material_icons::icons::ICON_HELP)
                        .on_hover_text(
                            "Click the Copy icon to copy your achievements to the clipboard.",
                        );
                },
                |ui| {
                    ui.add_enabled_ui(self.achievements_export_rx.is_none(), |ui| {
                        if ui
                            .button(egui_material_icons::icons::ICON_CONTENT_PASTE_GO)
                            .clicked()
                        {
                            if app_state.updated.achievements_updated_time.is_some() {
                                let (tx, rx) = oneshot::channel();
                                let _ = self.ui_message_tx.send(Message::ExportAchievements(tx));
                                self.achievements_export_rx = Some(rx);
                                self.wish_link_failed_for = None;
                            } else {
                                self.wish_link_failed_for = None;
                                self.toasts.error(
                                    "No achievement data captured yet. Open the Achievements \
                                     menu in-game.",
                                );
                            }
                        }
                    });
                },
            );

            ui.horizontal(|ui| {
                if ui.link("Open StarDB").clicked() {
                    self.handle_achievement_open_button(app_state, ui, "https://stardb.gg/import");
                }
                if ui.link("Open Seelie.me").clicked() {
                    self.handle_achievement_open_button(
                        app_state,
                        ui,
                        "https://seelie.me/achievements",
                    );
                }
            });
        });
    }

    /// Collect the result of an `ExportAchievements` request.
    ///
    /// Polled rather than awaited, for the same reason as the other two.
    fn achievements_handle_export(&mut self, ctx: &Context) -> Result<()> {
        let achievements = match poll_oneshot(&mut self.achievements_export_rx) {
            Polled::Pending => return Ok(()),
            Polled::Ready(Ok(achievements)) => Some(achievements),
            Polled::Ready(Err(_)) | Polled::Dropped => None,
        };

        match achievements {
            Some(achievements) => {
                let json = serde_json::json!({ "gi_achievements": achievements }).to_string();
                ctx.copy_text(json);
                self.toasts.info(format!(
                    "{} Achievements copied to clipboard",
                    achievements.len()
                ));
                self.wish_link_failed_for = None;
                if let Some(target_url) = self.pending_open_url.take() {
                    ctx.open_url(egui::OpenUrl::new_tab(target_url));
                }
            }
            None => {
                if let Some(target_url) = self.pending_open_url.take() {
                    self.wish_link_failed_for = Some(target_url);
                    self.toasts
                        .error("Export failed, click again to open anyways");
                } else {
                    self.wish_link_failed_for = None;
                    self.toasts
                        .error("Export failed. Please open the achievements menu in-game first.");
                }
            }
        }
        Ok(())
    }

    fn handle_achievement_open_button(
        &mut self,
        app_state: &AppState,
        ui: &mut egui::Ui,
        target_url: &str,
    ) {
        if self.wish_link_failed_for.as_deref() == Some(target_url) {
            ui.ctx().open_url(egui::OpenUrl::new_tab(target_url));
            self.wish_link_failed_for = None;
        } else if app_state.updated.achievements_updated_time.is_some() {
            let (tx, rx) = oneshot::channel();
            let _ = self.ui_message_tx.send(Message::ExportAchievements(tx));
            self.achievements_export_rx = Some(rx);
            self.pending_open_url = Some(target_url.to_string());
            self.wish_link_failed_for = None;
        } else {
            self.wish_link_failed_for = Some(target_url.to_string());
            self.toasts
                .error("Achievements not found, click again to open anyways");
        }
    }

    fn section_header(ui: &mut egui::Ui, name: &str) {
        ui.label(RichText::new(name).size(18.));
    }
}

#[cfg(windows)]
fn show_window() {
    use std::os::windows::ffi::OsStrExt;

    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SW_RESTORE, SetForegroundWindow, ShowWindow,
    };
    use windows::core::PCWSTR;

    let title: Vec<u16> = std::ffi::OsStr::new("Irminsul")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let hwnd = FindWindowW(PCWSTR::null(), PCWSTR(title.as_ptr()));
        if let Ok(hwnd) = hwnd
            && !hwnd.0.is_null()
        {
            let _ = ShowWindow(hwnd, SW_RESTORE);
            let _ = SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(windows)]
fn close_window() {
    use std::os::windows::ffi::OsStrExt;

    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, PostMessageW, WM_CLOSE};
    use windows::core::PCWSTR;

    let title: Vec<u16> = std::ffi::OsStr::new("Irminsul")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let hwnd = FindWindowW(PCWSTR::null(), PCWSTR(title.as_ptr()));
        if let Ok(hwnd) = hwnd
            && !hwnd.0.is_null()
        {
            let _ = PostMessageW(
                Some(hwnd),
                WM_CLOSE,
                windows::Win32::Foundation::WPARAM(0),
                windows::Win32::Foundation::LPARAM(0),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `monitor::CAPTURE_SHUTDOWN_TIMEOUT` is private to its module, so the
    /// mirror above is checked against the source rather than the item. Two
    /// agents picked 5 s independently and left the outer budget with exactly
    /// zero margin over the inner one.
    #[test]
    fn the_monitor_budget_outlasts_the_capture_teardown_it_waits_for() {
        const MONITOR_SOURCE: &str = include_str!("monitor.rs");
        const DECLARATION: &str = "const CAPTURE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(";

        let secs: u64 = MONITOR_SOURCE
            .split(DECLARATION)
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .unwrap_or_else(|| {
                panic!("could not find {DECLARATION} in monitor.rs; keep this test in sync")
            })
            .trim()
            .parse()
            .expect("the capture shutdown timeout is a whole number of seconds");

        assert_eq!(
            CAPTURE_SHUTDOWN_TIMEOUT.as_secs(),
            secs,
            "app.rs mirrors monitor.rs's capture shutdown timeout; they have drifted"
        );
        assert!(
            MONITOR_SHUTDOWN_TIMEOUT > CAPTURE_SHUTDOWN_TIMEOUT,
            "the monitor is joined with a deadline while it may still be spending the \
             capture teardown budget, so the outer one has to be strictly larger"
        );
    }

    fn verified_state() -> SavedAppState {
        SavedAppState {
            tracker_import_key: "gdt_import_1_abc".to_string(),
            tracker_verified: true,
            ..Default::default()
        }
    }

    #[test]
    fn the_manual_upload_does_not_need_the_automation_checkbox() {
        // The regression: with a verified key and "Auto export to tracker"
        // unchecked -- the default -- the enabled cloud-upload button ran a
        // full export and then toasted "Tracker key not verified".
        let state = verified_state();
        assert!(!state.auto_export_to_tracker);
        assert!(can_upload_to_tracker(&state));
        assert!(!want_tracker_upload(&state));
    }

    #[test]
    fn neither_upload_path_runs_without_a_verified_key() {
        let mut state = verified_state();
        state.auto_export_to_tracker = true;
        assert!(want_tracker_upload(&state));

        // A key the dashboard has revoked fails verification, and the
        // automation path must stop posting per login just like the button.
        state.tracker_verified = false;
        assert!(!can_upload_to_tracker(&state));
        assert!(!want_tracker_upload(&state));

        let mut state = verified_state();
        state.auto_export_to_tracker = true;
        state.tracker_import_key.clear();
        assert!(!can_upload_to_tracker(&state));
        assert!(!want_tracker_upload(&state));
    }

    #[test]
    fn an_export_needs_only_the_data_classes_it_writes() {
        let settings = SavedAppState::default().export_settings;
        let mut updated = DataUpdated::new();

        // Nothing captured: both classes are named, so the toast can say which.
        let missing = missing_export_data(&settings, &updated);
        assert_eq!(missing.len(), 2, "{missing:?}");
        assert!(missing_export_data_toast(&missing).contains("character data"));

        updated.characters_updated = Some(Instant::now());
        updated.items_updated = Some(Instant::now());

        // Achievements are still missing, and used to block this. They are
        // attached best-effort and can never be asked for or turned off, so
        // they must not gate an export of the data that *is* there.
        assert!(updated.achievements_updated.is_none());
        assert!(missing_export_data(&settings, &updated).is_empty());
    }

    #[test]
    fn export_classes_carry_the_capture_time_the_automation_gate_compares() {
        // monitor.rs's automation trigger requires every class it will write to
        // have been captured *since the current capture cycle began*, so the
        // timestamps have to travel with the names.
        let settings = SavedAppState::default().export_settings;
        let cycle_started = Instant::now();

        let mut updated = DataUpdated::new();
        updated.characters_updated = Some(cycle_started);
        updated.items_updated = Some(cycle_started);

        let classes = export_data_classes(&settings, &updated);
        assert_eq!(classes.len(), 2);
        assert!(
            !classes
                .iter()
                .all(|class| class.captured_at.is_some_and(|at| at > cycle_started)),
            "data from before this cycle is the previous session's"
        );

        let fresh = Instant::now();
        updated.characters_updated = Some(fresh);
        updated.items_updated = Some(fresh);
        assert!(
            export_data_classes(&settings, &updated)
                .iter()
                .all(|class| class.captured_at.is_some_and(|at| at > cycle_started))
        );
    }

    #[test]
    fn an_export_of_characters_alone_does_not_wait_for_the_inventory() {
        let settings = ExportSettings {
            include_characters: true,
            include_artifacts: false,
            include_weapons: false,
            include_materials: false,
            ..SavedAppState::default().export_settings
        };
        let mut updated = DataUpdated::new();

        assert_eq!(
            missing_export_data(&settings, &updated),
            vec!["character data"]
        );

        updated.characters_updated = Some(Instant::now());
        assert!(missing_export_data(&settings, &updated).is_empty());
    }

    #[test]
    fn an_inventory_export_names_the_inventory_and_not_characters() {
        let settings = ExportSettings {
            include_characters: false,
            include_artifacts: true,
            ..SavedAppState::default().export_settings
        };
        let updated = DataUpdated::new();

        let missing = missing_export_data(&settings, &updated);
        assert_eq!(missing.len(), 1, "{missing:?}");
        assert!(missing[0].contains("inventory"), "{missing:?}");
        assert!(!missing_export_data_toast(&missing).contains("character"));
    }

    #[test]
    fn a_set_but_empty_tracker_url_falls_back_to_the_default() {
        // `option_env!` cannot tell "unset" from "set to nothing", and a build
        // with `TRACKER_API_URL=` used to bake in the empty string, which turns
        // every request into a relative URL reqwest refuses to send.
        assert_eq!(resolve_tracker_url(None), FALLBACK_TRACKER_URL);
        assert_eq!(resolve_tracker_url(Some("")), FALLBACK_TRACKER_URL);
        assert_eq!(resolve_tracker_url(Some("   ")), FALLBACK_TRACKER_URL);
        assert_eq!(resolve_tracker_url(Some("\n")), FALLBACK_TRACKER_URL);
    }

    #[test]
    fn a_configured_tracker_url_is_used_verbatim_after_trimming() {
        assert_eq!(
            resolve_tracker_url(Some("https://gdt.example/api")),
            "https://gdt.example/api"
        );
        // CI writes the value through a shell, so a stray newline is plausible.
        assert_eq!(
            resolve_tracker_url(Some("  https://gdt.example/api\n")),
            "https://gdt.example/api"
        );
    }

    #[test]
    fn tracker_errors_report_the_status_and_nothing_else() {
        // monitor.rs formats these as `HTTP {status} - {body}`.
        assert_eq!(
            tracker_error_status("HTTP 401 Unauthorized - {\"message\":\"bad key\"}"),
            Some(401)
        );
        assert_eq!(tracker_error_status("HTTP 403 Forbidden - nope"), Some(403));
        assert_eq!(
            tracker_error_status("HTTP 500 Internal Server Error - oops"),
            Some(500)
        );
    }

    #[test]
    fn digits_in_a_response_body_are_not_mistaken_for_a_status() {
        // The old check searched the whole string, so any of these dropped the
        // verified state and fired a spurious re-verification.
        for body in [
            "HTTP 500 Internal Server Error - upstream returned 401 for account 403",
            "HTTP 502 Bad Gateway - <html><title>403 error page</title></html>",
            "HTTP 413 Payload Too Large - 4030112 bytes",
        ] {
            assert!(
                !matches!(tracker_error_status(body), Some(401 | 403)),
                "{body} must not be read as an auth failure"
            );
        }

        // Transport failures are `reqwest::Error` strings with no status at
        // all, and must not be guessed at either.
        assert_eq!(
            tracker_error_status("error sending request for url (http://host:40100/x)"),
            None
        );
        assert_eq!(tracker_error_status("HTTP - no status"), None);
    }
}
