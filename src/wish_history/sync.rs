//! The sync task: when to run, and what the UI is told.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use super::gacha_log::{LogClient, Pacing, TokioSleeper, WishKey};
use super::run::{PAGES_PER_RUN, Partial, Run, RunError, RunReport};
use super::tracker::Tracker;
use super::{BANNERS, Banner, Trigger, credential_for};
use crate::app::SavedAppState;
use crate::signin::TrackerAuth;

/// How long after a wish its banner is synced. The history shows a wish a
/// little after it was made, and a run of single wishes then costs one sync.
pub(crate) const WISH_DELAY: Duration = Duration::from_secs(20);

/// The least time between two syncs of every banner: reopening the history
/// a few times in a row (each time with a new key) syncs once.
pub(crate) const MIN_RESYNC: Duration = Duration::from_secs(60);

/// How long after a run that stopped at its page cap the next one carries on.
pub(crate) const CONTINUE_DELAY: Duration = Duration::from_secs(30);

/// Whole-request timeout for one page of the wish history.
const LOG_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Whole-request timeout for a tracker call. An import of 2,000 records is a
/// few hundred kilobytes, stored in one batch.
const TRACKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// When each banner is next due.
#[derive(Debug, Default)]
pub(crate) struct Schedule {
    due: BTreeMap<Banner, Instant>,
    /// When every banner was last taken for a run.
    last_full: Option<Instant>,
}

impl Schedule {
    /// A new key: every banner, now -- or once [`MIN_RESYNC`] has passed since
    /// the last such run.
    pub(crate) fn on_new_key(&mut self, now: Instant) {
        let at = match self.last_full {
            Some(last) if now < last + MIN_RESYNC => last + MIN_RESYNC,
            _ => now,
        };
        for banner in BANNERS {
            self.due.insert(banner, at);
        }
    }

    /// A wish: that banner (every one when unknown), [`WISH_DELAY`] after the
    /// last wish.
    pub(crate) fn on_wish(&mut self, now: Instant, banner: Option<Banner>) {
        let banners = match banner {
            Some(banner) => vec![banner],
            None => BANNERS.to_vec(),
        };
        for banner in banners {
            self.due.insert(banner, now + WISH_DELAY);
        }
    }

    /// Carry on with unfinished banners after [`CONTINUE_DELAY`], unless
    /// they are due sooner anyway.
    pub(crate) fn on_unfinished(&mut self, now: Instant, banners: &[Banner]) {
        for &banner in banners {
            let at = now + CONTINUE_DELAY;
            self.due
                .entry(banner)
                .and_modify(|due| *due = (*due).min(at))
                .or_insert(at);
        }
    }

    pub(crate) fn next_due(&self) -> Option<Instant> {
        self.due.values().min().copied()
    }

    /// Take the banners due at `now`, in [`BANNERS`] order.
    pub(crate) fn take_due(&mut self, now: Instant) -> Vec<Banner> {
        let due: Vec<Banner> = BANNERS
            .into_iter()
            .filter(|banner| self.due.get(banner).is_some_and(|&at| at <= now))
            .collect();
        for banner in &due {
            self.due.remove(banner);
        }
        if due.len() == BANNERS.len() {
            self.last_full = Some(now);
        }
        due
    }

    pub(crate) fn clear(&mut self) {
        self.due.clear();
    }
}

/// What the sync is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Phase {
    #[default]
    Idle,
    /// Reading a banner's history.
    Syncing { banner: Banner, page: u32 },
    /// A key is held but the user's settings keep it from syncing: why.
    Off(&'static str),
}

/// How the last run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Sent `sent` records; the tracker added `added`.
    Sent {
        sent: usize,
        added: u64,
    },
    /// Nothing the tracker does not have.
    UpToDate,
    /// Part of a long history; the rest follows shortly.
    Unfinished,
    KeyExpired,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LastSync {
    pub(crate) at: chrono::DateTime<chrono::Local>,
    pub(crate) outcome: Outcome,
}

/// What the UI shows about the sync.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SyncStatus {
    pub(crate) phase: Phase,
    pub(crate) last: Option<LastSync>,
}

impl SyncStatus {
    /// One compact line, or `None` before anything happened.
    pub(crate) fn line(&self) -> Option<String> {
        match &self.phase {
            Phase::Syncing { banner, page } => {
                return Some(format!("Syncing wishes: banner {banner}, page {page}…"));
            }
            Phase::Off(why) => return Some(format!("Not synced: {why}")),
            Phase::Idle => {}
        }
        let last = self.last.as_ref()?;
        let at = last.at.format("%H:%M");
        Some(match &last.outcome {
            Outcome::Sent { added, .. } => format!("Synced {at} · added {added}"),
            Outcome::UpToDate => format!("Synced {at} · up to date"),
            Outcome::Unfinished => format!("Synced {at} · more to come"),
            Outcome::KeyExpired => format!("Sync {at}: the key expired"),
            Outcome::Failed(why) => format!("Sync failed {at}: {why}"),
        })
    }
}

/// The sync task. See the module documentation of `wish_history`.
pub(crate) struct WishSync {
    trigger_rx: mpsc::UnboundedReceiver<Trigger>,
    /// Counts logins: a run in flight stops when it moves.
    login_rx: watch::Receiver<u64>,
    key_tx: Arc<watch::Sender<Option<WishKey>>>,
    status_tx: watch::Sender<SyncStatus>,
    saved_state_rx: watch::Receiver<SavedAppState>,
    toast_tx: mpsc::UnboundedSender<(String, bool)>,
    ctx: egui::Context,
    /// The tracker sign-in, for runs while signed in.
    auth: TrackerAuth,
    log_http: reqwest::Client,
    tracker_http: reqwest::Client,
    schedule: Schedule,
    partials: BTreeMap<Banner, Partial>,
    /// Where pages are read instead of the key's own endpoint (tests).
    log_endpoint: Option<String>,
    pacing: Pacing,
}

impl WishSync {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        trigger_rx: mpsc::UnboundedReceiver<Trigger>,
        login_rx: watch::Receiver<u64>,
        key_tx: Arc<watch::Sender<Option<WishKey>>>,
        status_tx: watch::Sender<SyncStatus>,
        saved_state_rx: watch::Receiver<SavedAppState>,
        toast_tx: mpsc::UnboundedSender<(String, bool)>,
        ctx: egui::Context,
        auth: TrackerAuth,
    ) -> Self {
        // `build` only fails if the TLS backend cannot initialise, which is
        // exactly when every other HTTP request irminsul makes fails too.
        let client = |timeout| {
            crate::http_client_builder()
                .timeout(timeout)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .expect("the TLS backend must initialise for any HTTP request to work")
        };
        Self {
            trigger_rx,
            login_rx,
            key_tx,
            status_tx,
            saved_state_rx,
            toast_tx,
            ctx,
            auth,
            log_http: client(LOG_REQUEST_TIMEOUT),
            tracker_http: client(TRACKER_REQUEST_TIMEOUT),
            schedule: Schedule::default(),
            partials: BTreeMap::new(),
            log_endpoint: None,
            pacing: Pacing::default(),
        }
    }

    /// Read pages at `endpoint`, without waits between them (tests).
    #[cfg(test)]
    pub(crate) fn read_pages_at(&mut self, endpoint: String) {
        self.log_endpoint = Some(endpoint);
        self.pacing = Pacing {
            request: Duration::ZERO,
            banner: Duration::ZERO,
            backoff: Vec::new(),
        };
    }

    /// Run until the monitor's end of the channel is gone.
    pub(crate) async fn run(mut self) {
        loop {
            let due = self.schedule.next_due();
            let wait = async {
                match due {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                trigger = self.trigger_rx.recv() => match trigger {
                    Some(trigger) => self.on_trigger(trigger, Instant::now()),
                    None => break,
                },
                () = wait => self.run_due(Instant::now()).await,
            }
        }
    }

    fn fresh_key(&self, now: Instant) -> Option<WishKey> {
        self.key_tx
            .borrow()
            .as_ref()
            .filter(|key| key.is_fresh(now))
            .cloned()
    }

    fn on_trigger(&mut self, trigger: Trigger, now: Instant) {
        if trigger == Trigger::Cleared {
            self.clear();
            return;
        }
        // Only a key of this login whose UID is known syncs (the hub sends
        // `NewKey` again once the UID binds a waiting key).
        if self.fresh_key(now).is_none_or(|key| key.uid().is_none()) {
            return;
        }
        if let Some(why) = self.blocked() {
            tracing::info!("wish sync: not synced: {why}");
            self.status_tx
                .send_modify(|status| status.phase = Phase::Off(why));
            self.ctx.request_repaint();
            return;
        }
        if matches!(self.status_tx.borrow().phase, Phase::Off(_)) {
            self.status_tx
                .send_modify(|status| status.phase = Phase::Idle);
        }
        match trigger {
            Trigger::NewKey => self.schedule.on_new_key(now),
            Trigger::Wish(banner) => self.schedule.on_wish(now, banner),
            Trigger::Cleared => unreachable!("handled above"),
        }
    }

    /// Why the user's settings keep a key from syncing: the same gate as
    /// automated uploads, never overridden.
    fn blocked(&self) -> Option<&'static str> {
        let state = self.saved_state_rx.borrow();
        if !state.auto_export_to_tracker {
            return Some("uploads to the Tracker are off");
        }
        if !super::sync_enabled(&state) || credential_for(&state, &self.auth).is_none() {
            return Some("no Tracker sign-in or verified import key");
        }
        None
    }

    /// A new login: nothing of the previous one's sync is kept.
    fn clear(&mut self) {
        self.schedule.clear();
        self.partials.clear();
        self.status_tx.send_replace(SyncStatus::default());
        self.ctx.request_repaint();
    }

    async fn run_due(&mut self, now: Instant) {
        let banners = self.schedule.take_due(now);
        if banners.is_empty() {
            return;
        }
        let Some(key) = self.fresh_key(now) else {
            self.schedule.clear();
            return;
        };
        let Some(uid) = key.uid() else {
            self.schedule.clear();
            return;
        };
        let state = self.saved_state_rx.borrow().clone();
        let Some((base_url, credential)) = credential_for(&state, &self.auth) else {
            self.schedule.clear();
            return;
        };
        let tracker = Tracker {
            http: self.tracker_http.clone(),
            base_url,
            credential,
        };
        let mut log = LogClient::new(
            self.log_http.clone(),
            self.log_endpoint
                .clone()
                .unwrap_or_else(|| key.endpoint().to_owned()),
            key.clone(),
            TokioSleeper,
            self.pacing.clone(),
        );

        tracing::info!(?banners, "syncing wish history");
        let status_tx = &self.status_tx;
        let ctx = &self.ctx;
        let progress = move |banner: Banner, page: u32| {
            status_tx.send_modify(|status| status.phase = Phase::Syncing { banner, page });
            ctx.request_repaint();
        };
        // A new login while this runs stops it before it sends: the key, and
        // whatever was read with it, are the previous login's.
        let login = *self.login_rx.borrow();
        let mut login_rx = self.login_rx.clone();
        let new_login = async move {
            if login_rx.wait_for(|now| *now != login).await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        let run = Run::new(&mut log, &tracker, &progress, PAGES_PER_RUN)
            .for_uid(uid.to_string())
            .sync(&banners, &mut self.partials);
        let report = tokio::select! {
            report = run => Some(report),
            () = new_login => None,
        };
        let Some(report) = report else {
            tracing::info!("wish: a new login; stopped the sync before it sent anything");
            self.clear();
            return;
        };
        tracing::info!(
            requests = log.requests(),
            sent = report.sent,
            added = report.imported.added,
            known = report.imported.known,
            unfinished = ?report.unfinished,
            error = report.error.as_ref().map(ToString::to_string),
            "wish sync finished"
        );
        self.finish(&key, report, Instant::now());
    }

    /// Forget `key`, unless a newer key arrived during the run.
    fn drop_key(&self, key: &WishKey) {
        self.key_tx.send_if_modified(|current| {
            if current
                .as_ref()
                .is_some_and(|current| current.same_key(key))
            {
                *current = None;
                return true;
            }
            false
        });
    }

    fn finish(&mut self, key: &WishKey, report: RunReport, now: Instant) {
        let outcome = match &report.error {
            Some(RunError::KeyExpired) => {
                self.drop_key(key);
                Outcome::KeyExpired
            }
            Some(RunError::OtherAccount) => {
                tracing::info!("wish: the wish key belongs to another account; nothing sent");
                self.drop_key(key);
                Outcome::Failed(RunError::OtherAccount.to_string())
            }
            Some(error) => Outcome::Failed(error.to_string()),
            None if !report.unfinished.is_empty() => {
                self.schedule.on_unfinished(now, &report.unfinished);
                Outcome::Unfinished
            }
            None if report.sent > 0 => Outcome::Sent {
                sent: report.sent,
                added: report.imported.added,
            },
            None => Outcome::UpToDate,
        };
        if report.imported.added > 0 {
            let _ = self.toast_tx.send((
                format!("{} new wishes sent to the Tracker", report.imported.added),
                false,
            ));
        }
        self.status_tx.send_replace(SyncStatus {
            phase: Phase::Idle,
            last: Some(LastSync {
                at: chrono::Local::now(),
                outcome,
            }),
        });
        self.ctx.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_key_syncs_every_banner_now_but_not_twice_a_minute() {
        let now = Instant::now();
        let mut schedule = Schedule::default();
        schedule.on_new_key(now);
        assert_eq!(schedule.next_due(), Some(now));
        assert_eq!(schedule.take_due(now), BANNERS.to_vec());
        assert_eq!(schedule.next_due(), None);

        let soon = now + Duration::from_secs(10);
        schedule.on_new_key(soon);
        assert_eq!(schedule.take_due(soon), Vec::<Banner>::new());
        assert_eq!(schedule.next_due(), Some(now + MIN_RESYNC));
        assert_eq!(schedule.take_due(now + MIN_RESYNC), BANNERS.to_vec());
    }

    #[test]
    fn a_wish_syncs_its_banner_after_the_last_wish_settles() {
        let now = Instant::now();
        let mut schedule = Schedule::default();
        schedule.on_wish(now, Some(302));
        let later = now + Duration::from_secs(5);
        schedule.on_wish(later, Some(302));
        assert_eq!(schedule.next_due(), Some(later + WISH_DELAY));
        assert!(schedule.take_due(now + WISH_DELAY).is_empty());
        assert_eq!(schedule.take_due(later + WISH_DELAY), vec![302]);
    }

    #[test]
    fn a_wish_on_an_unknown_banner_syncs_them_all() {
        let now = Instant::now();
        let mut schedule = Schedule::default();
        schedule.on_wish(now, None);
        assert_eq!(schedule.take_due(now + WISH_DELAY), BANNERS.to_vec());
    }

    #[test]
    fn unfinished_banners_carry_on_shortly_without_postponing_a_sooner_run() {
        let now = Instant::now();
        let mut schedule = Schedule::default();
        schedule.on_wish(now, Some(301));
        schedule.on_unfinished(now, &[301, 200]);
        assert_eq!(schedule.take_due(now + WISH_DELAY), vec![301]);
        assert_eq!(schedule.take_due(now + CONTINUE_DELAY), vec![200]);
    }

    #[test]
    fn a_tracker_failure_keeps_the_key_and_an_expired_key_drops_it() {
        use auto_artifactarium::GachaAuthKey;

        use super::super::WishEvent;

        let (_state_tx, state_rx) = watch::channel(SavedAppState::default());
        let (toast_tx, _toast_rx) = mpsc::unbounded_channel();
        let auth = TrackerAuth::new(
            "https://tracker.invalid/api",
            Arc::new(crate::signin::MemoryStore::default()),
            "TEST-PC".to_owned(),
            Arc::new(|_| {}),
            Arc::new(|| {}),
        );
        let channels = super::super::channels(state_rx, toast_tx, egui::Context::default(), auth);
        channels.hub.forward(
            vec![WishEvent::Key(GachaAuthKey::new(
                "GGGG",
                "webview_gacha",
                "hk4e_global",
            ))],
            Some(811_111_111),
        );
        let now = Instant::now();
        let key = channels.view.key(now).expect("the key was captured");
        let mut sync = channels.sync;

        for error in [
            RunError::Tracker("tracker: signed out of the tracker; sign in again".to_owned()),
            RunError::Tracker("tracker: uploads are blocked for this tracker account".to_owned()),
            RunError::Api("the wish history API answered HTTP 502 Bad Gateway".to_owned()),
        ] {
            let report = RunReport {
                error: Some(error.clone()),
                ..RunReport::default()
            };
            sync.finish(&key, report, now);
            assert!(
                channels.view.key(now).is_some(),
                "{error:?} dropped the key"
            );
            let line = channels.view.sync_line(now).unwrap();
            assert!(line.contains(&error.to_string()), "{line}");
        }

        let report = RunReport {
            error: Some(RunError::KeyExpired),
            ..RunReport::default()
        };
        sync.finish(&key, report, now);
        assert!(channels.view.key(now).is_none());
    }

    #[test]
    fn the_status_line_is_compact() {
        let at = chrono::Local::now();
        let line = |outcome| {
            SyncStatus {
                phase: Phase::Idle,
                last: Some(LastSync { at, outcome }),
            }
            .line()
            .unwrap()
        };
        let hm = at.format("%H:%M").to_string();
        assert_eq!(
            line(Outcome::Sent {
                sent: 40,
                added: 37
            }),
            format!("Synced {hm} · added 37")
        );
        assert_eq!(line(Outcome::UpToDate), format!("Synced {hm} · up to date"));
        assert_eq!(
            line(Outcome::KeyExpired),
            format!("Sync {hm}: the key expired")
        );
        assert_eq!(SyncStatus::default().line(), None);
        assert_eq!(
            SyncStatus {
                phase: Phase::Syncing {
                    banner: 302,
                    page: 3
                },
                last: None,
            }
            .line()
            .as_deref(),
            Some("Syncing wishes: banner 302, page 3…")
        );
    }

    // ---- logins and the sync, against a fake API and tracker ----

    use auto_artifactarium::GachaAuthKey;
    use serde_json::json;

    use super::super::WishEvent;
    use super::super::test_server::{Reply, TestServer};

    const LOGIN_UID: u32 = 811_111_111;

    /// A fake wish history API (one record of `record_uid` per banner, each
    /// answer after `delay`) and tracker (empty cursor, imports counted).
    fn world(record_uid: &'static str, delay: Duration) -> TestServer {
        TestServer::start(move |request| {
            if request.path == "/gacha_info/api/getGachaLog" {
                std::thread::sleep(delay);
                let banner = request.param("gacha_type").unwrap_or("301").to_owned();
                let list = if request.param("end_id") == Some("0") {
                    json!([{"uid": record_uid, "gacha_type": banner, "item_id": "",
                            "count": "1", "time": "2026-10-12 21:04:11", "name": "Item",
                            "lang": "en-us", "item_type": "Weapon", "rank_type": "3",
                            "id": format!("17900000000000{banner}")}])
                } else {
                    json!([])
                };
                return Reply::json(
                    200,
                    json!({"retcode": 0, "message": "OK",
                           "data": {"region": "os_asia", "list": list}})
                    .to_string(),
                );
            }
            if request.path == "/api/wishes/cursor" {
                return Reply::json(200, r#"{"uid":"811111111","accountId":12,"newest":{}}"#);
            }
            if request.path == "/api/wishes/import" {
                return Reply::json(200, r#"{"accountId":12,"added":1,"known":0,"newest":{}}"#);
            }
            Reply::json(404, r#"{"error":{"code":"not_found"}}"#)
        })
    }

    struct Setup {
        channels: super::super::WishChannels,
        state_tx: watch::Sender<SavedAppState>,
    }

    /// Wish channels whose sync reads `server` with a verified import key and
    /// uploads on.
    fn setup(server: &TestServer) -> Setup {
        let api = format!("{}/api", server.base);
        let state = SavedAppState {
            auto_export_to_tracker: true,
            tracker_api_url: api.clone(),
            tracker_import_key: "gdt_uk_test".to_owned(),
            tracker_verified: true,
            tracker_sign_in: crate::app::TrackerSignIn::SignedOut,
            ..Default::default()
        };
        let (state_tx, state_rx) = watch::channel(state);
        let (toast_tx, _toast_rx) = mpsc::unbounded_channel();
        let auth = TrackerAuth::new(
            &api,
            Arc::new(crate::signin::MemoryStore::default()),
            "TEST-PC".to_owned(),
            Arc::new(|_| {}),
            Arc::new(|| {}),
        );
        let mut channels =
            super::super::channels(state_rx, toast_tx, egui::Context::default(), auth);
        channels
            .sync
            .read_pages_at(format!("{}/gacha_info/api/getGachaLog", server.base));
        Setup { channels, state_tx }
    }

    fn key_event(key: &str) -> WishEvent {
        WishEvent::Key(GachaAuthKey::new(key, "webview_gacha", "hk4e_global"))
    }

    /// Wait (up to 5 s) for `done`.
    async fn until(mut done: impl FnMut() -> bool) {
        for _ in 0..500 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out");
    }

    fn imports(server: &TestServer) -> Vec<serde_json::Value> {
        server
            .requests()
            .iter()
            .filter(|request| request.path == "/api/wishes/import")
            .map(|request| serde_json::from_str(&request.body).unwrap())
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_key_after_a_login_syncs_with_that_logins_uid() {
        let server = world("811111111", Duration::ZERO);
        let Setup {
            channels,
            state_tx: _state_tx,
        } = setup(&server);
        channels
            .hub
            .forward(vec![key_event("KKKK")], Some(LOGIN_UID));
        let task = tokio::spawn(channels.sync.run());
        until(|| !imports(&server).is_empty()).await;
        let body = &imports(&server)[0];
        assert_eq!(body["uid"], "811111111");
        assert_eq!(body["records"].as_array().unwrap().len(), 5);
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn records_of_another_uid_are_refused_and_the_key_dropped() {
        let server = world("899999999", Duration::ZERO);
        let Setup {
            channels,
            state_tx: _state_tx,
        } = setup(&server);
        channels
            .hub
            .forward(vec![key_event("LLLL")], Some(LOGIN_UID));
        let view = channels.view;
        let task = tokio::spawn(channels.sync.run());
        until(|| view.key(Instant::now()).is_none()).await;
        let line = view.sync_line(Instant::now()).unwrap();
        assert!(
            line.contains("the wish key belongs to another account"),
            "{line}"
        );
        assert!(imports(&server).is_empty(), "nothing sent");
        assert!(
            server
                .requests()
                .iter()
                .all(|request| request.path != "/api/wishes/cursor"),
            "refused on the first page, before even the cursor"
        );
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_new_login_stops_a_run_in_flight_before_it_sends() {
        let server = world("811111111", Duration::from_millis(800));
        let Setup {
            channels,
            state_tx: _state_tx,
        } = setup(&server);
        channels
            .hub
            .forward(vec![key_event("MMMM")], Some(LOGIN_UID));
        let view = channels.view;
        let hub = channels.hub;
        let task = tokio::spawn(channels.sync.run());
        // The first page is being read.
        until(|| !server.requests().is_empty() || view.sync_line(Instant::now()).is_some()).await;
        hub.new_login();
        assert!(view.key(Instant::now()).is_none());
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(imports(&server).is_empty(), "the run sent nothing");
        assert_eq!(
            view.sync_line(Instant::now()),
            None,
            "nothing of it is shown"
        );
        let log_requests = server
            .requests()
            .iter()
            .filter(|request| request.path == "/gacha_info/api/getGachaLog")
            .count();
        assert!(
            log_requests <= 1,
            "stopped after the page in flight: {log_requests}"
        );
        task.abort();
    }

    #[test]
    fn a_key_the_settings_keep_from_syncing_says_why() {
        let server = world("811111111", Duration::ZERO);
        let Setup {
            mut channels,
            state_tx,
        } = setup(&server);
        channels
            .hub
            .forward(vec![key_event("NNNN")], Some(LOGIN_UID));
        let now = Instant::now();

        state_tx.send_modify(|state| state.auto_export_to_tracker = false);
        channels.sync.on_trigger(Trigger::NewKey, now);
        assert_eq!(
            channels.view.sync_line(now).as_deref(),
            Some("Not synced: uploads to the Tracker are off")
        );
        assert_eq!(channels.sync.schedule.next_due(), None);

        state_tx.send_modify(|state| {
            state.auto_export_to_tracker = true;
            state.tracker_verified = false;
        });
        channels.sync.on_trigger(Trigger::NewKey, now);
        assert_eq!(
            channels.view.sync_line(now).as_deref(),
            Some("Not synced: no Tracker sign-in or verified import key")
        );

        state_tx.send_modify(|state| state.tracker_verified = true);
        channels.sync.on_trigger(Trigger::NewKey, now);
        assert_eq!(channels.view.sync_line(now), None);
        assert_eq!(channels.sync.schedule.next_due(), Some(now));
    }

    #[test]
    fn a_key_before_the_uid_waits_and_a_login_clears_the_schedule() {
        let server = world("811111111", Duration::ZERO);
        let Setup {
            mut channels,
            state_tx: _state_tx,
        } = setup(&server);
        let now = Instant::now();
        channels.hub.forward(vec![key_event("OOOO")], None);
        // Nothing to schedule: the key's account is not known.
        channels.sync.on_trigger(Trigger::NewKey, now);
        assert_eq!(channels.sync.schedule.next_due(), None);
        assert_eq!(
            channels.view.sync_line(now).as_deref(),
            Some("Sync waits for the account's UID")
        );

        channels.hub.note_uid(Some(LOGIN_UID));
        channels.sync.on_trigger(Trigger::NewKey, now);
        assert_eq!(channels.sync.schedule.next_due(), Some(now));

        channels
            .sync
            .partials
            .insert(301, crate::wish_history::run::Partial::for_tests());
        channels.sync.on_trigger(Trigger::Cleared, now);
        assert_eq!(channels.sync.schedule.next_due(), None);
        assert!(channels.sync.partials.is_empty());
    }
}
