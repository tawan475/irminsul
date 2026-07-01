use std::fmt::Display;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Instant;

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
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::monitor::Monitor;
use crate::player_data::ExportSettings;
use crate::update::check_for_app_update;
use crate::{
    AppState, ConfirmationType, Message, ReloadHandle, State, TracingLevel, open_log_dir, wish,
};

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
    #[serde(default)]
    pub tracker_import_key: String,
    #[serde(skip, default = "default_tracker_url")]
    pub tracker_api_url: String,
    #[serde(default)]
    pub auto_export_to_tracker: bool,
    #[serde(default)]
    pub minimize_to_tray: Option<bool>,
}

fn default_tracker_url() -> String {
    option_env!("TRACKER_API_URL")
        .unwrap_or("http://localhost:49000")
        .to_string()
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

pub struct IrminsulApp {
    ui_message_tx: mpsc::UnboundedSender<Message>,
    state_rx: watch::Receiver<AppState>,
    wish_url_rx: watch::Receiver<Option<String>>,
    log_packets_tx: watch::Sender<bool>,
    saved_state_tx: watch::Sender<SavedAppState>,
    tracing_reload_handle: ReloadHandle,
    toast_rx: mpsc::UnboundedReceiver<(String, bool)>,

    toasts: Toasts,

    power_tools_open: bool,
    bug_report_open: bool,

    automation_settings_open: bool,
    automation_folder_dialog: Option<FileDialog>,

    optimizer_settings_open: bool,
    optimizer_export_rx: Option<oneshot::Receiver<Result<String>>>,
    achievements_export_rx: Option<oneshot::Receiver<Result<Vec<u32>>>>,
    wish_url_rx_oneshot: Option<oneshot::Receiver<Result<String>>>,
    wish_link_failed_for: Option<String>,
    pending_open_url: Option<String>,
    optimizer_save_dialog: Option<FileDialog>,
    optimizer_save_path: Option<PathBuf>,
    optimizer_export_target: OptimizerExportTarget,

    restarting: bool,

    saved_state: SavedAppState,

    tracker_key_modal_open: bool,
    tracker_account_name: Option<(String, String, String)>,
    tracker_verified: bool,
    tracker_verify_rx: Option<oneshot::Receiver<Result<(String, String, String)>>>,
    tracker_upload_rx: Option<oneshot::Receiver<Result<(), String>>>,

    #[allow(dead_code)]
    tray_icon: Option<TrayIcon>,

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

fn start_async_runtime(
    egui_ctx: Context,
    log_packets_rx: watch::Receiver<bool>,
    saved_state_rx: watch::Receiver<SavedAppState>,
) -> (
    mpsc::UnboundedSender<Message>,
    watch::Receiver<AppState>,
    watch::Receiver<Option<String>>,
    mpsc::UnboundedReceiver<(String, bool)>,
) {
    tracing::info!("starting tokio async");
    let (ui_message_tx, mut ui_message_rx) = mpsc::unbounded_channel::<Message>();
    let (toast_tx, toast_rx) = mpsc::unbounded_channel::<(String, bool)>();

    let (state_tx, state_rx) = watch::channel(AppState::new());
    let (wish_url_tx, wish_url_rx) = watch::channel(None);
    let mut updater_state_rx = state_rx.clone();
    let updater_ctx = egui_ctx.clone();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            // Before starting the monitor, check for updates if not in debug mode
            tracing::info!("Checking for update");
            if let Err(e) = check_for_app_update(&state_tx, &mut ui_message_rx).await {
                tracing::error!("error checking for update: {e}");
            }

            // Check for wish URL
            tokio::spawn(async move {
                let Ok(mut wish) = wish::Wish::new(wish_url_tx).await else {
                    tracing::error!("Failed to create new wish monitor");
                    return;
                };

                if let Err(e) = wish.monitor().await {
                    tracing::error!("Error monitoring for wishes: {e}");
                }
            });

            let monitor_ctx = updater_ctx.clone();
            // Notify egui of state changes.
            tokio::spawn(async move {
                loop {
                    let _ = updater_state_rx.changed().await;
                    updater_ctx.request_repaint();
                }
            });
            tracing::info!("Starting monitor");
            let monitor = match Monitor::new(
                state_tx,
                ui_message_rx,
                log_packets_rx,
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
    (ui_message_tx, state_rx, wish_url_rx, toast_rx)
}

impl IrminsulApp {
    pub fn new(cc: &eframe::CreationContext<'_>, mut tracing_reload_handle: ReloadHandle) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        egui_material_icons::initialize(&cc.egui_ctx);

        let saved_state: SavedAppState = if let Some(storage) = cc.storage {
            eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default()
        } else {
            Default::default()
        };

        tracing::info!("Tracker API URL: {}", saved_state.tracker_api_url);

        tracing_reload_handle.set_filter(saved_state.tracing_level.get_filter());
        let (log_packets_tx, log_packets_rx) = watch::channel(saved_state.log_raw_packets);
        let (saved_state_tx, saved_state_rx) = watch::channel(saved_state.clone());

        let (ui_message_tx, state_rx, wish_url_rx, toast_rx) =
            start_async_runtime(cc.egui_ctx.clone(), log_packets_rx, saved_state_rx);

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

        let mut tray_icon = None;

        if let Ok(icon_data) = image::load_from_memory(include_bytes!("../assets/icon-256.png")) {
            let rgba = icon_data.into_rgba8();
            let (w, h) = rgba.dimensions();
            if let Ok(icon) = tray_icon::Icon::from_rgba(rgba.into_raw(), w, h) {
                let tray_menu = Menu::new();
                let restore_i = MenuItem::new("Restore", true, None);
                let quit_i = MenuItem::new("Quit", true, None);
                let restore_id = restore_i.id().clone();
                let quit_id = quit_i.id().clone();
                let _ = tray_menu.append_items(&[&restore_i, &quit_i]);

                tray_icon = TrayIconBuilder::new()
                    .with_tooltip("Irminsul")
                    .with_icon(icon)
                    .with_menu(Box::new(tray_menu))
                    .build()
                    .ok();

                let ctx_clone1 = cc.egui_ctx.clone();
                TrayIconEvent::set_event_handler(Some(move |event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        ctx_clone1.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx_clone1.send_viewport_cmd(egui::ViewportCommand::Focus);
                        ctx_clone1.request_repaint();
                        #[cfg(windows)]
                        show_window();
                    }
                }));

                let ctx_clone2 = cc.egui_ctx.clone();
                MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                    if event.id == restore_id {
                        ctx_clone2.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx_clone2.send_viewport_cmd(egui::ViewportCommand::Focus);
                        ctx_clone2.request_repaint();
                        #[cfg(windows)]
                        show_window();
                    } else if event.id == quit_id {
                        #[cfg(windows)]
                        close_window();
                        #[cfg(not(windows))]
                        ctx_clone2.send_viewport_cmd(egui::ViewportCommand::Close);
                        ctx_clone2.request_repaint();
                    }
                }));
            }
        }

        Self {
            saved_state,
            ui_message_tx,
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
            tracker_verified: false,
            tracker_verify_rx,
            tracker_upload_rx: None,
            tray_icon,
            state_rx,
            wish_url_rx,
            minimize_modal_open: false,
            minimize_modal_remember: true,
            app_settings_open: false,
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
                        ui.ctx()
                            .send_viewport_cmd(egui::ViewportCommand::Visible(false));
                    }
                    if ui.button("Taskbar").clicked() {
                        if self.minimize_modal_remember {
                            self.saved_state.minimize_to_tray = Some(false);
                        }
                        self.minimize_modal_open = false;
                        ui.ctx()
                            .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
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

        if let Some(rx) = &mut self.tracker_upload_rx {
            if let Ok(result) = rx.try_recv() {
                self.tracker_upload_rx = None;
                match result {
                    Ok(_) => {
                        self.toasts
                            .success("Successfully synced capture to Tracker!");
                    }
                    Err(e) => {
                        if e.contains("401")
                            || e.contains("403")
                            || e.to_lowercase().contains("unauthorized")
                        {
                            self.tracker_verified = false;
                            self.tracker_account_name = None;
                            self.request_tracker_verify();
                        }
                        self.toasts.error(format!("Tracker sync failed: {}", e));
                    }
                }
            }
        }

        if let Some(rx) = &mut self.tracker_verify_rx {
            if let Ok(result) = rx.try_recv() {
                self.tracker_verify_rx = None;
                self.apply_tracker_verify_result(result);
            }
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

        // Drain toast_rx
        while let Ok((msg, is_error)) = self.toast_rx.try_recv() {
            if is_error {
                self.toasts.error(msg);
            } else {
                self.toasts.success(msg);
            }
        }

        self.toasts.show(ctx);

        // Push the latest saved state to the background thread
        let _ = self.saved_state_tx.send(self.saved_state.clone());
    }
}

impl IrminsulApp {
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
                        Some(true) => {
                            ui.ctx()
                                .send_viewport_cmd(egui::ViewportCommand::Visible(false));
                        }
                        Some(false) => {
                            ui.ctx()
                                .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                        }
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
            if ui.add(egui::Button::new("Yes")).clicked() {
                if let Err(e) = self.ui_message_tx.send(Message::UpdateAcknowledged) {
                    tracing::error!("Unable to send UI message: {e}");
                }
            }
            if ui.add(egui::Button::new("No")).clicked() {
                if let Err(e) = self.ui_message_tx.send(Message::UpdateCanceled) {
                    tracing::error!("Unable to send UI message: {e}");
                }
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
            let program_name = std::env::args().next().unwrap();
            let _ = std::process::Command::new(program_name).spawn();
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            self.restarting = true;
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
        if ui.add(egui::Button::new("Download")).clicked() {
            if let Err(e) = self.ui_message_tx.send(Message::DownloadAcknowledged) {
                tracing::error!("Unable to send UI message{e}");
            }
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
        self.wish_ui(ui);
        ui.separator();
        self.achievement_ui(ui, app_state);
        ui.separator();
        self.automation_ui(ui);
        ui.separator();
        self.tracker_ui(ui, app_state);
    }

    fn capture_ui(&mut self, ui: &mut egui::Ui, app_state: &AppState) {
        ui.vertical(|ui| {
            egui::Sides::new().show(
                ui,
                |ui| {
                    Self::section_header(ui, "Packet Capture");
                },
                |ui| {
                    if ui
                        .button(egui_material_icons::icons::ICON_SETTINGS)
                        .clicked()
                    {
                        self.optimizer_settings_open = true;
                    }

                    ui.add_enabled_ui(self.optimizer_export_rx.is_none(), |ui| {
                        let is_ready = app_state.updated.characters_updated.is_some()
                            && app_state.updated.items_updated.is_some()
                            && app_state.updated.achievements_updated.is_some();

                        if ui
                            .button(egui_material_icons::icons::ICON_DOWNLOAD)
                            .clicked()
                        {
                            if is_ready {
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
                                self.toasts
                                    .error("Data not found. Please open the game first.");
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
                            if is_ready {
                                self.genshin_optimizer_request_export(
                                    OptimizerExportTarget::Clipboard,
                                );
                            } else {
                                self.toasts
                                    .error("Data not found. Please open the game first.");
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
        let status_text = if let Some(updated_time) = app_state.updated.achievements_updated_time {
            if let Some(updated_instant) = app_state.updated.achievements_updated {
                ui.ctx().request_repaint(); // update timer
                let elapsed = updated_instant.elapsed().as_secs();
                let remaining = 5u64.saturating_sub(elapsed);
                RichText::new(format!("Status: Capture success [{}s]", remaining))
                    .color(Color32::from_hex("#00ab3f").unwrap())
                    .strong()
            } else {
                RichText::new(format!(
                    "Status: Ready to capture, Last capture at {}",
                    updated_time.format("%H:%M:%S")
                ))
                .strong()
            }
        } else {
            RichText::new("Status: Ready to capture").strong()
        };
        ui.label(status_text);
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

    fn wish_ui(&mut self, ui: &mut egui::Ui) {
        self.optimizer_handle_export(ui).toast_error(self);
        self.wish_handle_find_url(ui).toast_error(self);

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

    fn wish_handle_find_url(&mut self, ui: &mut egui::Ui) -> Result<()> {
        let Some(rx) = self.wish_url_rx_oneshot.take() else {
            return Ok(());
        };

        match rx.blocking_recv() {
            Ok(Ok(url)) => {
                ui.ctx().copy_text(url);
                self.toasts.info("Wish URL copied to clipboard");
                self.wish_link_failed_for = None;
                if let Some(target_url) = self.pending_open_url.take() {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(target_url));
                }
            }
            Ok(Err(_)) | Err(_) => {
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
                {
                    if let Err(e) = set_launch_on_startup(self.saved_state.start_on_startup) {
                        self.saved_state.start_on_startup = previous_startup;
                        tracing::error!("Unable to update startup behavior: {e}");
                        self.toasts.error("Unable to update startup behavior");
                    }
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

    fn want_tracker_upload(&self) -> bool {
        self.saved_state.auto_export_to_tracker
            && !self.saved_state.tracker_import_key.is_empty()
            && self.tracker_verified
    }

    fn apply_tracker_verify_result(&mut self, result: Result<(String, String, String)>) {
        match result {
            Ok(info) => {
                self.tracker_account_name = Some(info);
                self.tracker_verified = true;
            }
            Err(e) => {
                self.tracker_account_name = None;
                self.tracker_verified = false;
                self.toasts
                    .error(format!("Failed to verify tracker key: {}", e));
            }
        }
    }

    fn request_tracker_verify(&mut self) {
        let key = self.saved_state.tracker_import_key.clone();
        if key.is_empty() {
            self.tracker_account_name = None;
            self.tracker_verified = false;
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
        self.tracker_verified = false;
    }

    fn tracker_ui(&mut self, ui: &mut egui::Ui, app_state: &AppState) {
        if self.tracker_key_modal_open {
            let modal = Modal::new(Id::new("Tracker Key Modal")).show(ui.ctx(), |ui| {
                ui.set_width(360.0);
                ui.heading("Set Tracker Import Key");
                ui.separator();
                ui.label("Enter your Import Key generated from the GDT dashboard:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.saved_state.tracker_import_key)
                        .password(true),
                );
                if self.tracker_verify_rx.is_some() {
                    ui.label(RichText::new("Verifying key…").color(Color32::YELLOW));
                } else if self.tracker_verified {
                    if let Some((name, uid, server)) = &self.tracker_account_name {
                        ui.label(
                            RichText::new(format!("Valid: {} (UID {})", name, uid))
                                .color(Color32::from_hex("#00ab3f").unwrap()),
                        );
                        ui.label(RichText::new(format!("Server: {}", server)).color(Color32::GRAY));
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
                            let is_ready = app_state.updated.characters_updated.is_some()
                                && app_state.updated.items_updated.is_some()
                                && app_state.updated.achievements_updated.is_some();
                            ui.add_enabled_ui(
                                is_ready
                                    && self.tracker_verified
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
                ui.selectable_value(
                    &mut self.saved_state.tracing_level,
                    TracingLevel::VerboseTrace,
                    "Verbose Trace",
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
                        "https://github.com/konkers/irminsul/issues/new",
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

    fn optimizer_handle_export(&mut self, ui: &mut egui::Ui) -> Result<()> {
        let Some(rx) = self.optimizer_export_rx.take() else {
            return Ok(());
        };

        let json = rx.blocking_recv()??;

        match self.optimizer_export_target {
            OptimizerExportTarget::None => {
                tracing::warn!("Unexpected json export");
            }
            OptimizerExportTarget::Clipboard => {
                self.optimizer_save_to_clipboard(ui, json)?;
            }
            OptimizerExportTarget::File => {
                self.optimizer_save_to_file(json)?;
            }

            OptimizerExportTarget::TrackerManual => {
                if self.want_tracker_upload() {
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

    fn optimizer_save_to_clipboard(&mut self, ui: &mut egui::Ui, json: String) -> Result<()> {
        ui.ctx().copy_text(json);
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

    fn achievement_ui(&mut self, ui: &mut egui::Ui, app_state: &AppState) {
        self.achievements_handle_export(ui).toast_error(self);

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
                                self.toasts
                                    .error("Data not found. Please open the game first.");
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

    fn achievements_handle_export(&mut self, ui: &mut egui::Ui) -> Result<()> {
        let Some(rx) = self.achievements_export_rx.take() else {
            return Ok(());
        };

        match rx.blocking_recv() {
            Ok(Ok(achievements)) => {
                let json = serde_json::json!({ "gi_achievements": achievements }).to_string();
                ui.ctx().copy_text(json);
                self.toasts.info(format!(
                    "{} Achievements copied to clipboard",
                    achievements.len()
                ));
                self.wish_link_failed_for = None;
                if let Some(target_url) = self.pending_open_url.take() {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(target_url));
                }
            }
            Ok(Err(_)) | Err(_) => {
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
        if hwnd.is_ok() && !hwnd.clone().unwrap().0.is_null() {
            let hwnd = hwnd.unwrap();
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
        if hwnd.is_ok() && !hwnd.clone().unwrap().0.is_null() {
            let _ = PostMessageW(
                Some(hwnd.unwrap()),
                WM_CLOSE,
                windows::Win32::Foundation::WPARAM(0),
                windows::Win32::Foundation::LPARAM(0),
            );
        }
    }
}
