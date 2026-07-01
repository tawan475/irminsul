use std::collections::HashMap;
use std::fs;
use std::io::{BufWriter, Write};
use std::time::Instant;

use anime_game_data::AnimeGameData;
use anyhow::{Context, Result, anyhow};
use auto_artifactarium::{
    GameCommand, GamePacket, GameSniffer, matches_achievement_packet, matches_avatar_packet,
    matches_item_packet,
};
use base64::prelude::*;
use chrono::prelude::*;
use flate2::read::GzDecoder;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::capture::PacketCapture;
use crate::player_data::PlayerData;
use crate::{APP_ID, AppState, DataUpdated, Message, State};

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
}

pub struct Monitor {
    app_state: AppStateManager,
    ui_message_rx: mpsc::UnboundedReceiver<Message>,
    log_packet_rx: watch::Receiver<bool>,
    player_data: PlayerData,
    sniffer: GameSniffer,
    capture_cancel_token: Option<CancellationToken>,
    packet_tx: mpsc::UnboundedSender<Result<Vec<u8>>>,
    packet_rx: mpsc::UnboundedReceiver<Result<Vec<u8>>>,
    saved_state_rx: watch::Receiver<crate::app::SavedAppState>,
    toast_tx: mpsc::UnboundedSender<(String, bool)>,

    automation_pending_since: Option<Instant>,
    automation_last_signature: Option<(Option<Instant>, Option<Instant>, Option<Instant>)>,
    automation_cycle_started_at: Option<Instant>,

    ctx: egui::Context,
}

impl Monitor {
    pub async fn new(
        state_tx: watch::Sender<AppState>,
        mut ui_message_rx: mpsc::UnboundedReceiver<Message>,
        log_packet_rx: watch::Receiver<bool>,
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

        Ok(Self {
            app_state,
            player_data,
            ui_message_rx,
            log_packet_rx,
            sniffer,
            capture_cancel_token: None,
            packet_tx,
            packet_rx,
            saved_state_rx,
            toast_tx,
            automation_pending_since: None,
            automation_last_signature: None,
            automation_cycle_started_at: None,
            ctx,
        })
    }

    pub async fn run(mut self) {
        self.app_state.update_app_state(State::Main);

        loop {
            let sleep_fut = async {
                if let Some(pending_since) = self.automation_pending_since {
                    let elapsed = pending_since.elapsed();
                    let target = std::time::Duration::from_secs(5);
                    if let Some(rem) = target.checked_sub(elapsed) {
                        tokio::time::sleep(rem).await;
                    }
                } else {
                    std::future::pending::<()>().await;
                }
            };

            #[rustfmt::skip]
                tokio::select! {
                    _ = sleep_fut => {
                        self.execute_automation_export().await;
                    }
                    Some(packet_res) = self.packet_rx.recv() => {
                        match packet_res {
                            Ok(packet) => self.handle_packet(packet),
                            Err(e) => {
                                tracing::error!("Capture task encountered an error: {e}");
                                self.app_state.update_capturing_state(false);
                                self.capture_cancel_token = None;
                            }
                        }
                    },
                    Some(msg) = self.ui_message_rx.recv() => self.handle_ui_msg(msg),
                }
        }
    }

    fn handle_ui_msg(&mut self, msg: Message) {
        match msg {
            Message::StartCapture => {
                if let Some(cancel_token) = self.capture_cancel_token.take() {
                    tracing::warn!(
                        "Capture start request with an existing cancel token. Cancelling previous capture."
                    );
                    cancel_token.cancel();
                }

                // Spawn capture task.
                let cancel_token = CancellationToken::new();
                tokio::spawn(capture_task(cancel_token.clone(), self.packet_tx.clone()));
                self.capture_cancel_token = Some(cancel_token);
                self.automation_cycle_started_at = Some(Instant::now());
                self.app_state.update_capturing_state(true);
            }
            Message::StopCapture => {
                let Some(cancel_token) = self.capture_cancel_token.take() else {
                    tracing::warn!("Capture stop request with no current cancel token");
                    return;
                };
                cancel_token.cancel();
                self.app_state.update_capturing_state(false);
            }
            Message::ClearData => {
                let mut new_updated = DataUpdated::new();
                new_updated.achievements_updated_time = self
                    .app_state
                    .app_state
                    .updated
                    .achievements_updated_time
                    .clone();
                self.app_state.update_timestamps(new_updated);
                self.ctx.request_repaint();
            }
            Message::ExportGenshinOptimizer(settings, reply_tx) => {
                let _ = reply_tx.send(self.player_data.export_genshin_optimizer(&settings));
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
                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    match client.get(&url).header("x-import-key", &key).send().await {
                        Ok(res) => {
                            let status = res.status();
                            match res.text().await {
                                Ok(body) => {
                                    tracing::info!("Verify key response ({}): {}", status, body);
                                    if !status.is_success() {
                                        let _ = reply_tx.send(Err(anyhow::anyhow!(
                                            "Verify failed: HTTP {}",
                                            status
                                        )));
                                        ctx.request_repaint();
                                        return;
                                    }
                                    if let Ok(json) =
                                        serde_json::from_str::<serde_json::Value>(&body)
                                    {
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
                                        let _ = reply_tx.send(Ok((name, uid, server)));
                                        ctx.request_repaint();
                                    } else {
                                        let _ = reply_tx
                                            .send(Err(anyhow::anyhow!("Invalid JSON response")));
                                        ctx.request_repaint();
                                    }
                                }
                                Err(e) => {
                                    let _ = reply_tx.send(Err(anyhow::anyhow!(
                                        "Failed to read response: {}",
                                        e
                                    )));
                                    ctx.request_repaint();
                                }
                            }
                        }
                        Err(e) => {
                            let _ = reply_tx.send(Err(anyhow::anyhow!("Request failed: {}", e)));
                            ctx.request_repaint();
                        }
                    }
                });
            }
            Message::UploadToTracker(json, url, key, reply_tx) => {
                let ctx = self.ctx.clone();
                tokio::spawn(async move {
                    let client = reqwest::Client::new();

                    let part = reqwest::multipart::Part::bytes(json.into_bytes())
                        .file_name("irminsul_capture.json")
                        .mime_str("application/json")
                        .unwrap();

                    let form = reqwest::multipart::Form::new().part("file", part);

                    match client
                        .post(&url)
                        .header("x-import-key", &key)
                        .multipart(form)
                        .send()
                        .await
                    {
                        Ok(res) => {
                            let status = res.status();
                            let body = res.text().await.unwrap_or_default();
                            if !status.is_success() {
                                tracing::error!("Tracker upload failed ({}): {}", status, body);
                                let _ = reply_tx.send(Err(format!("HTTP {} - {}", status, body)));
                                ctx.request_repaint();
                            } else {
                                tracing::info!("Successfully uploaded data to tracker");
                                let _ = reply_tx.send(Ok(()));
                                ctx.request_repaint();
                            }
                        }
                        Err(e) => {
                            tracing::error!("Tracker upload request failed: {}", e);
                            let _ = reply_tx.send(Err(e.to_string()));
                            ctx.request_repaint();
                        }
                    }
                });
            }
            _ => (),
        }
    }

    fn handle_packet(&mut self, packet: Vec<u8>) {
        let commands = match self.sniffer.receive_packet(packet) {
            Some(GamePacket::Commands(commands)) => commands,
            Some(GamePacket::Connection(conn)) => {
                match conn {
                    auto_artifactarium::ConnectionPacket::HandshakeRequested => {
                        tracing::info!("Connection: Handshake Requested")
                    }
                    auto_artifactarium::ConnectionPacket::HandshakeEstablished => {
                        tracing::info!("Connection: Handshake Established")
                    }
                    auto_artifactarium::ConnectionPacket::Disconnected => {
                        tracing::info!("Connection: Disconnected")
                    }
                    _ => {}
                }
                return;
            }
            None => return,
        };

        let log_packets = *self.log_packet_rx.borrow_and_update();

        let mut updated = self.app_state.app_state.updated.clone();
        let mut has_new_data = false;

        for command in commands {
            let _span = tracing::info_span!("packet id {}", command.command_id);
            if log_packets {
                if let Err(e) = log_command(&command) {
                    tracing::info!("error logging command {e}");
                }
            }

            if let Some(items) = matches_item_packet(&command) {
                tracing::info!("Found item packet with {} items", items.len());
                self.player_data.process_items(&items);
                updated.items_updated = Some(Instant::now());
                has_new_data = true;
            } else if let Some(properties) =
                auto_artifactarium::matches_player_property_packet(&command)
            {
                tracing::info!("Found properties packet: {:?}", properties);
                self.player_data.process_properties(&properties);
                updated.items_updated = Some(Instant::now());
                has_new_data = true;
            } else if let Some(avatars) = matches_avatar_packet(&command) {
                tracing::info!("Found avatar packet with {} avatars", avatars.len());
                self.player_data.process_characters(&avatars);
                updated.characters_updated = Some(Instant::now());
                has_new_data = true;
            } else if let Some(achievements) = matches_achievement_packet(&command) {
                tracing::info!(
                    "Found achievement packet with {} achievements",
                    achievements.len()
                );
                self.player_data.process_achievements(&achievements);
                updated.achievements_updated = Some(Instant::now());
                updated.achievements_updated_time = Some(chrono::Local::now());
                has_new_data = true;
            }
        }

        if has_new_data {
            self.app_state.update_timestamps(updated);
            self.check_automation_trigger();
        }
    }

    fn check_automation_trigger(&mut self) {
        let saved_state = self.saved_state_rx.borrow().clone();
        let want_file = saved_state.save_result_to_file;
        let want_tracker =
            saved_state.auto_export_to_tracker && !saved_state.tracker_import_key.is_empty();

        if !want_file && !want_tracker {
            self.automation_pending_since = None;
            return;
        }

        let updated = &self.app_state.app_state.updated;

        let Some(cycle_started) = self.automation_cycle_started_at else {
            return;
        };
        let Some(items) = updated.items_updated else {
            return;
        };
        let Some(chars) = updated.characters_updated else {
            return;
        };
        let Some(achievs) = updated.achievements_updated else {
            return;
        };

        if items <= cycle_started || chars <= cycle_started || achievs <= cycle_started {
            return;
        }

        let signature = (
            updated.items_updated,
            updated.characters_updated,
            updated.achievements_updated,
        );

        if self.automation_last_signature == Some(signature) {
            return;
        }

        if self.automation_pending_since.is_none() {
            tracing::info!("All automation triggers met! Starting 5 second countdown...");
            self.automation_pending_since = Some(Instant::now());
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
        self.automation_last_signature = Some(signature);

        let json = match self
            .player_data
            .export_genshin_optimizer(&saved_state.export_settings)
        {
            Ok(j) => j,
            Err(e) => {
                let _ = self
                    .toast_tx
                    .send((format!("Failed to generate GO format: {}", e), true));
                return;
            }
        };

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
                }
            }
        }

        if saved_state.auto_export_to_tracker && !saved_state.tracker_import_key.is_empty() {
            let _ = self
                .toast_tx
                .send(("Uploading to Tracker...".to_string(), false));
            self.tracker_upload_json(&saved_state, json.clone());
        }

        // Restart capture cycle
        self.automation_cycle_started_at = Some(Instant::now());
        if let Some(cancel_token) = self.capture_cancel_token.take() {
            cancel_token.cancel();
        }
        let cancel_token = CancellationToken::new();
        tokio::spawn(capture_task(cancel_token.clone(), self.packet_tx.clone()));
        self.capture_cancel_token = Some(cancel_token);
        self.app_state.update_capturing_state(true);
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

        let file = std::fs::File::create(&path)
            .with_context(|| format!("Unable to open file {:?}", path))?;
        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(json.as_bytes())?;

        Ok(path)
    }

    fn tracker_upload_json(&self, saved_state: &crate::app::SavedAppState, json: String) {
        let key = saved_state.tracker_import_key.clone();
        let base_url = saved_state.tracker_api_url.clone();
        let url = format!(
            "{}/genshin-accounts-public/import-by-key",
            base_url.trim_end_matches('/')
        );
        let toast_tx = self.toast_tx.clone();
        let ctx = self.ctx.clone();

        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let part = reqwest::multipart::Part::bytes(json.into_bytes())
                .file_name("irminsul_capture.json")
                .mime_str("application/json")
                .unwrap();
            let form = reqwest::multipart::Form::new().part("file", part);

            match client
                .post(&url)
                .header("x-import-key", &key)
                .multipart(form)
                .send()
                .await
            {
                Ok(res) => {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    if !status.is_success() {
                        tracing::error!("Tracker auto-upload failed ({}): {}", status, body);
                        let _ = toast_tx.send((
                            format!("Tracker upload failed: HTTP {} - {}", status, body),
                            true,
                        ));
                    } else {
                        tracing::info!("Successfully uploaded data to tracker via automation");
                        let _ = toast_tx
                            .send(("Successfully auto-uploaded to Tracker".to_string(), false));
                    }
                    ctx.request_repaint();
                }
                Err(e) => {
                    tracing::error!("Tracker upload request failed: {}", e);
                    let _ = toast_tx.send((format!("Tracker upload failed: {}", e), true));
                    ctx.request_repaint();
                }
            }
        });
    }
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
    packet_tx: mpsc::UnboundedSender<Result<Vec<u8>>>,
) -> Result<()> {
    let mut capture = match PacketCapture::new() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Error creating packet capture, retrying... ({})", e);
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if cancel_token.is_cancelled() {
                return Ok(());
            }
            match PacketCapture::new() {
                Ok(c) => c,
                Err(e) => {
                    let _ = packet_tx.send(Err(anyhow!("Error creating packet capture: {e}")));
                    return Err(anyhow!("Error creating packet capture: {e}"));
                }
            }
        }
    };
    tracing::info!("starting capture");

    #[cfg(debug_assertions)]
    let mut pcapng = eframe::storage_dir(crate::APP_ID)
        .map(|mut p| {
            p.push("log");
            std::fs::create_dir_all(&p).ok()?;
            p.push("latest.pcapng");
            crate::pcapng::PcapngWriter::new(p).ok()
        })
        .flatten();
    loop {
        let packet = tokio::select!(
            packet = capture.next_packet() => packet,
            _ = cancel_token.cancelled() => break,
        );
        let packet = match packet {
            Ok(packet) => packet,
            Err(e) => {
                tracing::error!("Error receiving packet: {e}");
                let _ = packet_tx.send(Err(anyhow!("Capture stream closed or errored: {e}")));
                break;
            }
        };

        #[cfg(debug_assertions)]
        if let Some(ref mut writer) = pcapng {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            let _ = writer.write_packet(ts, &packet);
        }

        if let Err(e) = packet_tx.send(Ok(packet)) {
            tracing::error!("Error sending captured packet to monitor: {e}");
            break;
        }
    }
    tracing::info!("ending capture");
    Ok(())
}

fn log_command(command: &GameCommand) -> Result<()> {
    let mut packet_log_path = eframe::storage_dir(APP_ID).context("Storage dir not found")?;
    packet_log_path.push("packet_log");
    fs::create_dir_all(&packet_log_path)?;

    let now = Local::now();
    packet_log_path.push(format!(
        "{}-{}.bin",
        now.format("%Y-%m-%d_%H-%M-%S%.f"),
        command.command_id
    ));

    let file = fs::File::create(&packet_log_path)
        .with_context(|| format!("can't create file {packet_log_path:?}"))?;
    let mut writer = BufWriter::new(file);
    writer.write_all(&command.proto_data)?;

    Ok(())
}

fn load_keys() -> Result<HashMap<u16, Vec<u8>>> {
    let keys: HashMap<u16, String> = serde_json::from_slice(include_bytes!("../keys/gi.json"))?;

    keys.iter()
        .map(|(key, value)| -> Result<_, _> { Ok((*key, BASE64_STANDARD.decode(value)?)) })
        .collect::<Result<HashMap<_, _>>>()
}
