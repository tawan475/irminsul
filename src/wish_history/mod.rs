//! Wish history from the game's own key.
//!
//! A wish history key comes from one of two places:
//!
//! * the game's traffic: when its wish history page opens, the server sends
//!   a web view key (`GetAuthkeyRsp`, recognised by auto-artifactarium);
//! * the game's web cache, where that page leaves the game's own link, key
//!   included, which works for the rest of the key's day -- see [`cache`].
//!   A key from the traffic always wins over one from the cache.
//!
//! From the key irminsul
//!
//! * gives the wish URL that paimon.moe ("Manual" import) and stardb take,
//!   for anyone to copy -- see [`WishView`]; and
//! * when a tracker credential is set and uploads are on, syncs the history
//!   to the tracker: only what the tracker does not have yet, paging no
//!   further than needed (see [`run`]). A new key syncs every banner; a wish
//!   made in game (`DoGachaRsp`) syncs that banner shortly after. Nothing
//!   polls.
//!
//! The key is a password while it lasts (about a day): it lives in memory
//! only, is never logged or persisted, and only ever goes to the game's API.
//!
//! The monitor's only hooks are [`take_wish_events`] and [`WishHub::forward`];
//! the UI reads a [`WishView`].

mod cache;
mod gacha_log;
mod run;
#[cfg(test)]
mod run_tests;
mod sync;
#[cfg(test)]
mod test_server;
mod tracker;

use std::sync::Arc;
use std::time::Instant;

use auto_artifactarium::{CommandMatch, GachaAuthKey, GachaRecordLink, GachaWish};
use tokio::sync::{mpsc, watch};

pub(crate) use self::cache::CacheSource;
use self::cache::{CacheReply, CacheState};
pub(crate) use self::gacha_log::WishKey;
use self::gacha_log::{KeySource, LinkParts};
pub(crate) use self::sync::{SyncStatus, WishSync};
use self::tracker::TrackerCredential;
use crate::app::SavedAppState;
use crate::game_watch::GameStatus;
use crate::signin::{TrackerAuth, UploadCredential};

/// A banner as the wish history API and the tracker number it (UIGF): 301
/// is both character event banners (its records say 301 or 400).
pub(crate) type Banner = u32;

/// The banners synced, in order.
pub(crate) const BANNERS: [Banner; 5] = [301, 302, 500, 200, 100];

/// The banner a wish made on the game's `gacha_type` shows up under.
pub(crate) fn banner_for_gacha_type(gacha_type: u32) -> Option<Banner> {
    match gacha_type {
        400 => Some(301),
        other if BANNERS.contains(&other) => Some(other),
        _ => None,
    }
}

/// The API base and credential a sync uses, or `None` when it must not run.
///
/// The same gate and the same choice as automated snapshot uploads: uploads
/// on ([`crate::app::want_tracker_upload`]), then the sign-in while signed
/// in, else a saved and verified import key
/// ([`crate::app::upload_credential`]).
fn credential_for(
    state: &SavedAppState,
    auth: &TrackerAuth,
) -> Option<(String, TrackerCredential)> {
    if !crate::app::want_tracker_upload(state) {
        return None;
    }
    Some(match crate::app::upload_credential(state)? {
        UploadCredential::SignedIn { base } => (
            base.clone(),
            TrackerCredential::SignedIn {
                auth: auth.clone(),
                base,
            },
        ),
        UploadCredential::ImportKey { key, .. } => (
            state.tracker_api_url.clone(),
            TrackerCredential::ImportKey(key),
        ),
    })
}

/// Whether a captured key would be synced to the tracker.
pub(crate) fn sync_enabled(state: &SavedAppState) -> bool {
    crate::app::want_tracker_upload(state)
}

/// What the monitor saw that concerns wish history.
#[derive(Debug)]
pub(crate) enum WishEvent {
    Key(GachaAuthKey),
    Wish(GachaWish),
    /// Every banner's history link, sent when the Wish screen opens.
    Banners(Vec<GachaRecordLink>),
    /// The client's version, sent at login.
    ClientVersion(String),
}

/// Take the wish history messages out of a classified batch.
///
/// They are not account data: they must not count as a batch that replaces
/// the snapshot, or reach the GOOD export.
pub(crate) fn take_wish_events(classified: &mut Vec<(u16, CommandMatch)>) -> Vec<WishEvent> {
    if classified.iter().all(|(_, found)| found.is_account_data()) {
        return Vec::new();
    }
    let mut events = Vec::new();
    let mut rest = Vec::with_capacity(classified.len());
    for (command_id, found) in std::mem::take(classified) {
        match found {
            CommandMatch::AuthKey(key) => events.push(WishEvent::Key(key)),
            CommandMatch::Wish(wish) => events.push(WishEvent::Wish(wish)),
            CommandMatch::GachaInfo(links) => events.push(WishEvent::Banners(links)),
            CommandMatch::ClientVersion(version) => events.push(WishEvent::ClientVersion(version)),
            other => rest.push((command_id, other)),
        }
    }
    *classified = rest;
    events
}

/// What the sync task is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// A new key arrived: sync every banner.
    NewKey,
    /// A wish was made on this banner (`None`: on one that could not be told).
    Wish(Option<Banner>),
}

/// What the game's wish history link is made of besides the key, as seen
/// so far this session.
#[derive(Debug, Default)]
struct Captured {
    banners: Vec<GachaRecordLink>,
    game_version: Option<String>,
}

impl Captured {
    /// The link parts for a key arriving now, for the account `uid`.
    ///
    /// The game builds the link from the history link of the banner on screen
    /// when History is pressed, which the traffic does not say. The banner
    /// the Wish screen opens on is the character event banner (`gacha_type`
    /// 301, the highest sort order); a recorded 7.1 session's link was that
    /// banner's, so that is the one taken, else the first. (The API answers
    /// the same for any banner's link, or for none.)
    fn link_parts(&self, uid: Option<u32>) -> LinkParts {
        let banner = self
            .banners
            .iter()
            .find(|banner| banner.gacha_type == Some(301))
            .or_else(|| self.banners.first());
        LinkParts {
            record_query: banner.map(|banner| banner.query.clone()),
            game_version: self.game_version.clone(),
            region: uid.and_then(region_for_uid).map(str::to_owned),
        }
    }
}

/// The server region of a UID, as the game's dispatch names it: the region
/// is in the UID's first digit (after the leading 1 of a ten-digit one).
///
/// The game learns its region from the dispatch server over HTTP, not from
/// the traffic irminsul reads, so this is how the link gets its `region`.
pub(crate) fn region_for_uid(uid: u32) -> Option<&'static str> {
    let digits = uid.to_string();
    let first = match digits.len() {
        9 => digits.as_bytes()[0],
        10 if digits.starts_with('1') => digits.as_bytes()[1],
        _ => return None,
    };
    match (digits.len(), first) {
        (_, b'6') => Some("os_usa"),
        (_, b'7') => Some("os_euro"),
        (_, b'8') => Some("os_asia"),
        (_, b'9') => Some("os_cht"),
        (9, b'1' | b'2' | b'3') => Some("cn_gf01"),
        (9, b'5') => Some("cn_qd01"),
        _ => None,
    }
}

/// What this session's traffic has shown the wish history so far: the UI's
/// "seen" list, which says why a key or a part of the link is missing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Seen {
    /// The banner list (`GetGachaInfoRsp`): the Wish screen was opened.
    pub(crate) banner_list: bool,
    /// A wish history key (`webview_gacha`) in the traffic: the game's wish
    /// history page opened.
    pub(crate) wish_key: bool,
    /// Web view keys for something else (the login's `ugc_login`), ignored.
    pub(crate) other_keys: u32,
    /// The client's version, from its login.
    pub(crate) client_version: bool,
    /// What the game's web cache showed last.
    pub(crate) cached_link: CacheState,
}

/// Asks the UI to repaint: what the monitor hands on changes what it shows.
pub(crate) type Notify = Arc<dyn Fn() + Send + Sync>;

/// The monitor's end: hands captured keys and wishes on.
#[derive(Clone)]
pub(crate) struct WishHub {
    key_tx: Arc<watch::Sender<Option<WishKey>>>,
    trigger_tx: mpsc::UnboundedSender<Trigger>,
    captured: Arc<std::sync::Mutex<Captured>>,
    seen_tx: Arc<watch::Sender<Seen>>,
    notify: Notify,
}

impl WishHub {
    /// Hand `events` on; `uid` is the account's, when captured (for the
    /// link's `region`).
    pub(crate) fn forward(&self, events: Vec<WishEvent>, uid: Option<u32>) {
        if events.is_empty() {
            return;
        }
        for event in events {
            match event {
                WishEvent::Key(key) => self.key(key, uid, Instant::now()),
                WishEvent::Banners(banners) => {
                    // Info the first time: what a user's log shows when the
                    // wish section stays empty.
                    if self.see(|seen| !std::mem::replace(&mut seen.banner_list, true)) {
                        tracing::info!(
                            banners = banners.len(),
                            "wish history: saw the banner list (the Wish screen opened)"
                        );
                    } else {
                        tracing::debug!(banners = banners.len(), "banner list");
                    }
                    self.captured.lock().unwrap().banners = banners;
                }
                WishEvent::ClientVersion(version) => {
                    if self.see(|seen| !std::mem::replace(&mut seen.client_version, true)) {
                        tracing::info!("wish history: saw the client version");
                    }
                    self.captured.lock().unwrap().game_version = Some(version);
                }
                WishEvent::Wish(wish) => {
                    let banner = wish.gacha_type.and_then(banner_for_gacha_type);
                    tracing::info!(
                        gacha_type = ?wish.gacha_type,
                        pulls = wish.pulls,
                        "a wish was made"
                    );
                    let _ = self.trigger_tx.send(Trigger::Wish(banner));
                }
            }
        }
        (self.notify)();
    }

    /// Update what was seen; `true` when `change` says it was news.
    fn see(&self, change: impl FnOnce(&mut Seen) -> bool) -> bool {
        let mut news = false;
        self.seen_tx.send_modify(|seen| news = change(seen));
        news
    }

    fn key(&self, key: GachaAuthKey, uid: Option<u32>, now: Instant) {
        if !key.is_wish_history_key() {
            // The login's keys (`ugc_login`) are for something else.
            let first = self.see(|seen| {
                seen.other_keys += 1;
                seen.other_keys == 1
            });
            if first {
                tracing::info!(app = %key.auth_appid, "wish history: ignoring a web view key for another page");
            } else {
                tracing::debug!(app = %key.auth_appid, "ignoring a web view key that is not for wishes");
            }
            return;
        }
        self.see(|seen| {
            seen.wish_key = true;
            false
        });
        let link = self.captured.lock().unwrap().link_parts(uid);
        tracing::info!(
            banner_link = link.record_query.is_some(),
            game_version = link.game_version.is_some(),
            region = link.region.as_deref(),
            "the wish history link's parts"
        );
        let key = WishKey::new(key.authkey(), &key.game_biz, now).with_link(link);
        let mut new = false;
        self.key_tx.send_if_modified(|current| match current {
            // The same key, maybe found in the cache first: no new sync, but
            // it is the game's key now, so the cache cannot replace it.
            Some(current) if current.same_key(&key) => {
                let from_cache = current.source() == KeySource::Cache;
                current.mark_from_game();
                from_cache
            }
            _ => {
                *current = Some(key);
                new = true;
                true
            }
        });
        if new {
            tracing::info!("captured a wish history key");
            let _ = self.trigger_tx.send(Trigger::NewKey);
        }
    }

    /// The key held, while it is believed to work.
    pub(crate) fn held_key(&self, now: Instant) -> Option<WishKey> {
        self.key_tx
            .borrow()
            .as_ref()
            .filter(|key| key.is_fresh(now))
            .cloned()
    }

    /// Record what the game's web cache showed.
    pub(crate) fn see_cache(&self, state: CacheState) {
        if self.see(|seen| std::mem::replace(&mut seen.cached_link, state) != state) {
            (self.notify)();
        }
    }

    /// Take a key from the game's cache, that the game's server said works,
    /// unless a key from the traffic is held (it always wins) or this key is
    /// held already. `true` when taken: every banner syncs.
    pub(crate) fn offer_cached(&self, key: WishKey, now: Instant) -> bool {
        let taken = self.key_tx.send_if_modified(|current| {
            if let Some(current) = current
                && current.is_fresh(now)
                && (current.source() == KeySource::Game || current.same_key(&key))
            {
                return false;
            }
            *current = Some(key);
            true
        });
        if taken {
            tracing::info!("took a wish history key from the game's web cache");
            let _ = self.trigger_tx.send(Trigger::NewKey);
            (self.notify)();
        }
        taken
    }
}

/// The UI's end.
pub(crate) struct WishView {
    key_rx: watch::Receiver<Option<WishKey>>,
    status_rx: watch::Receiver<SyncStatus>,
    seen_rx: watch::Receiver<Seen>,
    /// Asks the cache source to look now.
    cache_tx: mpsc::UnboundedSender<CacheReply>,
}

impl WishView {
    /// The captured key, while it is believed to work.
    pub(crate) fn key(&self, now: Instant) -> Option<WishKey> {
        self.key_rx
            .borrow()
            .as_ref()
            .filter(|key| key.is_fresh(now))
            .cloned()
    }

    /// The URL to copy: the game's link for the key held.
    pub(crate) fn wish_url(&self, now: Instant) -> Option<String> {
        self.key(now).map(|key| key.wish_url())
    }

    /// Look in the game's web cache now: answered with the wish URL, or why
    /// there is none.
    pub(crate) fn look_in_cache(&self) -> tokio::sync::oneshot::Receiver<Result<String, String>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        // A closed channel drops `tx`, which the caller sees as no answer.
        let _ = self.cache_tx.send(tx);
        rx
    }

    /// The section's status line and its tooltip, by what is really the
    /// case: see [`status_line`].
    pub(crate) fn status(&self, now: Instant, game: GameStatus, uid_known: bool) -> WishLine {
        let mut line = status_line(self.key(now).as_ref(), now, game);
        line.tooltip.push_str("\n\n");
        line.tooltip
            .push_str(&seen_summary(&self.seen_rx.borrow(), uid_known));
        line
    }

    /// One line about the tracker sync, or `None` when there is nothing to
    /// say.
    pub(crate) fn sync_line(&self) -> Option<String> {
        self.status_rx.borrow().line()
    }
}

/// The status line and what its tooltip says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WishLine {
    pub(crate) text: String,
    pub(crate) tooltip: String,
}

/// Where a key comes from, for the tooltips.
const KEY_SOURCES: &str = "A wish key comes from the game when its wish history page opens, \
     or from a link the game left in its web cache that still works. A key lasts about \
     a day.";

/// What the wish section says, by what is really the case:
///
/// * a key is held: how long it is believed to last, and where it came from;
/// * no key, and this session is not decrypting: waiting for the login
///   (with the capture's own guidance);
/// * no key, decrypting: no key yet.
///
/// Never an instruction: where keys come from is in the tooltip.
pub(crate) fn status_line(key: Option<&WishKey>, now: Instant, game: GameStatus) -> WishLine {
    if let Some(key) = key {
        let hours = key.remaining(now).as_secs().div_ceil(3600);
        let (from, tooltip) = match key.source() {
            KeySource::Game => (
                "from the game",
                "The wish history key the game sent when its history page opened. \
                 It lasts about a day; until then Copy wish URL gives the game's own \
                 link, and new wishes sync by themselves when the Tracker is set up.",
            ),
            KeySource::Cache => (
                "from the cache",
                "The game's own wish history link, found in its web cache; the game's \
                 server said it still works. Its key lasts about a day from when the game \
                 got it (counted from the cache file's time); until then Copy wish URL \
                 gives that link as it is, and new wishes sync by themselves when the \
                 Tracker is set up.",
            ),
        };
        let text = if hours <= 1 {
            format!("Key valid < 1 h · {from}")
        } else {
            format!("Key valid ~{hours} h · {from}")
        };
        return WishLine {
            text,
            tooltip: tooltip.to_owned(),
        };
    }
    if game != GameStatus::Decoding {
        return WishLine {
            text: "Waiting for the game's login".to_owned(),
            tooltip: format!("{}\n{}\n\n{KEY_SOURCES}", game.label(), game.tooltip()),
        };
    }
    WishLine {
        text: "No wish key yet".to_owned(),
        tooltip: KEY_SOURCES.to_owned(),
    }
}

/// The "seen this session" list for the tooltip.
pub(crate) fn seen_summary(seen: &Seen, uid_known: bool) -> String {
    use egui_material_icons::icons::{ICON_CHECK, ICON_CLOSE};
    let mark = |yes: bool| if yes { ICON_CHECK } else { ICON_CLOSE };
    let mut lines = vec![
        "Seen this session:".to_owned(),
        format!("{} banner list (Wish screen)", mark(seen.banner_list)),
        format!("{} wish key from the game", mark(seen.wish_key)),
        format!("{} client version", mark(seen.client_version)),
        format!("{} UID", mark(uid_known)),
        format!(
            "{} cached link: {}",
            mark(seen.cached_link == CacheState::Valid),
            seen.cached_link.label()
        ),
    ];
    if seen.other_keys > 0 {
        lines.push(format!(
            "{} other web key{} ignored",
            seen.other_keys,
            if seen.other_keys == 1 { "" } else { "s" }
        ));
    }
    lines.join("\n")
}

/// Everything the wish history needs, made together.
pub(crate) struct WishChannels {
    pub(crate) hub: WishHub,
    pub(crate) view: WishView,
    pub(crate) sync: WishSync,
    pub(crate) cache: CacheSource,
}

/// Build the hub, the view, the sync task and the cache source (neither
/// running yet).
pub(crate) fn channels(
    saved_state_rx: watch::Receiver<SavedAppState>,
    toast_tx: mpsc::UnboundedSender<(String, bool)>,
    ctx: egui::Context,
    auth: TrackerAuth,
) -> WishChannels {
    let (key_tx, key_rx) = watch::channel(None);
    let key_tx = Arc::new(key_tx);
    let (trigger_tx, trigger_rx) = mpsc::unbounded_channel();
    let (status_tx, status_rx) = watch::channel(SyncStatus::default());
    let (seen_tx, seen_rx) = watch::channel(Seen::default());
    let repaint = ctx.clone();
    let notify: Notify = Arc::new(move || repaint.request_repaint());
    let (cache_tx, cache_rx) = mpsc::unbounded_channel();
    let sync = WishSync::new(
        trigger_rx,
        Arc::clone(&key_tx),
        status_tx,
        saved_state_rx,
        toast_tx,
        ctx,
        auth,
    );
    let hub = WishHub {
        key_tx,
        trigger_tx,
        captured: Arc::default(),
        seen_tx: Arc::new(seen_tx),
        notify,
    };
    WishChannels {
        cache: CacheSource::new(hub.clone(), cache_rx),
        hub,
        view: WishView {
            key_rx,
            status_rx,
            seen_rx,
            cache_tx,
        },
        sync,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn hub() -> (
        WishHub,
        watch::Receiver<Option<WishKey>>,
        mpsc::UnboundedReceiver<Trigger>,
    ) {
        hub_with(Arc::new(|| {}))
    }

    fn hub_with(
        notify: Notify,
    ) -> (
        WishHub,
        watch::Receiver<Option<WishKey>>,
        mpsc::UnboundedReceiver<Trigger>,
    ) {
        let (key_tx, key_rx) = watch::channel(None);
        let (trigger_tx, trigger_rx) = mpsc::unbounded_channel();
        (
            WishHub {
                key_tx: Arc::new(key_tx),
                trigger_tx,
                captured: Arc::default(),
                seen_tx: Arc::new(watch::channel(Seen::default()).0),
                notify,
            },
            key_rx,
            trigger_rx,
        )
    }

    #[test]
    fn what_the_session_showed_is_counted_and_the_ui_is_repainted() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let repaints = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&repaints);
        let (hub, _key_rx, _triggers) = hub_with(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(*hub.seen_tx.borrow(), Seen::default());

        hub.forward(
            vec![
                WishEvent::ClientVersion("OSRELWin7.1.0_R1_S2_D3".to_owned()),
                WishEvent::Key(authkey("ugc_login", "IIII")),
                WishEvent::Key(authkey("ugc_login", "JJJJ")),
            ],
            None,
        );
        assert_eq!(
            *hub.seen_tx.borrow(),
            Seen {
                banner_list: false,
                wish_key: false,
                other_keys: 2,
                client_version: true,
                cached_link: CacheState::None,
            }
        );
        assert_eq!(repaints.load(Ordering::SeqCst), 1, "one repaint per batch");

        hub.forward(
            vec![
                WishEvent::Banners(vec![banner(301, "cccc")]),
                WishEvent::Key(authkey("webview_gacha", "KKKK")),
            ],
            Some(811_111_111),
        );
        let seen = hub.seen_tx.borrow().clone();
        assert!(seen.banner_list && seen.wish_key);
        assert_eq!(repaints.load(Ordering::SeqCst), 2);

        hub.forward(Vec::new(), None);
        assert_eq!(
            repaints.load(Ordering::SeqCst),
            2,
            "nothing new, no repaint"
        );
    }

    #[test]
    fn the_status_line_says_what_is_really_the_case() {
        let now = Instant::now();
        // Nothing decrypts: never "open the history".
        for game in [
            GameStatus::NotRunning,
            GameStatus::AwaitingLogin,
            GameStatus::KeyLost,
            GameStatus::LaunchMissed(crate::game_watch::MissedLaunch::AlreadyRunning),
        ] {
            let line = status_line(None, now, game);
            assert_eq!(line.text, "Waiting for the game's login", "{game:?}");
            assert!(
                line.tooltip.contains(game.tooltip()),
                "{game:?}: {}",
                line.tooltip
            );
            assert!(line.tooltip.contains("web cache"), "{game:?}");
        }
        // Decrypting, no key yet: neutral, the sources in the tooltip.
        let line = status_line(None, now, GameStatus::Decoding);
        assert_eq!(line.text, "No wish key yet");
        assert!(line.tooltip.contains("wish history page opens"));
        assert!(line.tooltip.contains("web cache that still works"));
        assert!(line.tooltip.contains("about a day"));
        // A key: how long it lasts and where from, whatever the game does now.
        let key = WishKey::new("LLLL", "hk4e_global", now);
        for game in [GameStatus::Decoding, GameStatus::NotRunning] {
            assert_eq!(
                status_line(Some(&key), now, game).text,
                "Key valid ~24 h · from the game"
            );
        }
        let late = now + gacha_log::KEY_LIFETIME - std::time::Duration::from_secs(600);
        assert_eq!(
            status_line(Some(&key), late, GameStatus::Decoding).text,
            "Key valid < 1 h · from the game"
        );
        let cached = WishKey::from_game_link(
            "https://example.invalid/getGachaLog?authkey=MMMM&game_biz=hk4e_global",
            std::time::Duration::from_secs(4 * 3600),
            now,
        )
        .unwrap();
        let line = status_line(Some(&cached), now, GameStatus::NotRunning);
        assert_eq!(line.text, "Key valid ~20 h · from the cache");
        assert!(line.tooltip.contains("web cache"));
        // Nowhere an instruction to open the history.
        for line in [
            status_line(None, now, GameStatus::Decoding),
            status_line(None, now, GameStatus::NotRunning),
            status_line(Some(&key), now, GameStatus::Decoding),
            status_line(Some(&cached), now, GameStatus::Decoding),
        ] {
            let all = format!("{} {}", line.text, line.tooltip);
            assert!(
                !all.contains("Open Wish") && !all.contains("→ History"),
                "{all}"
            );
        }
    }

    #[test]
    fn the_seen_list_marks_each_part() {
        use egui_material_icons::icons::{ICON_CHECK, ICON_CLOSE};

        let seen = Seen {
            banner_list: true,
            wish_key: false,
            other_keys: 1,
            client_version: true,
            cached_link: CacheState::Expired,
        };
        assert_eq!(
            seen_summary(&seen, false),
            format!(
                "Seen this session:\n{ICON_CHECK} banner list (Wish screen)\n\
                 {ICON_CLOSE} wish key from the game\n{ICON_CHECK} client version\n\
                 {ICON_CLOSE} UID\n{ICON_CLOSE} cached link: expired\n1 other web key ignored"
            )
        );
        assert!(!seen_summary(&Seen::default(), true).contains("ignored"));
        assert!(seen_summary(&Seen::default(), true).contains(&format!("{ICON_CHECK} UID")));
        for (state, label) in [
            (CacheState::None, "none"),
            (CacheState::Found, "found"),
            (CacheState::Valid, "valid"),
            (CacheState::Expired, "expired"),
            (CacheState::Refused, "refused"),
        ] {
            let seen = Seen {
                cached_link: state,
                ..Seen::default()
            };
            let mark = if state == CacheState::Valid {
                ICON_CHECK
            } else {
                ICON_CLOSE
            };
            assert!(
                seen_summary(&seen, true).ends_with(&format!("{mark} cached link: {label}")),
                "{state:?}"
            );
        }
    }

    fn authkey(app: &str, key: &str) -> GachaAuthKey {
        GachaAuthKey::new(key, app, "hk4e_global")
    }

    #[test]
    fn only_wish_keys_are_kept_and_a_repeat_triggers_nothing() {
        let (hub, key_rx, mut triggers) = hub();
        hub.forward(vec![WishEvent::Key(authkey("ugc_login", "AAAA"))], None);
        assert!(key_rx.borrow().is_none());
        assert!(triggers.try_recv().is_err());

        hub.forward(vec![WishEvent::Key(authkey("webview_gacha", "BBBB"))], None);
        assert!(key_rx.borrow().is_some());
        assert_eq!(triggers.try_recv(), Ok(Trigger::NewKey));

        hub.forward(vec![WishEvent::Key(authkey("webview_gacha", "BBBB"))], None);
        assert!(
            triggers.try_recv().is_err(),
            "the same key again is not new"
        );

        hub.forward(vec![WishEvent::Key(authkey("webview_gacha", "CCCC"))], None);
        assert_eq!(triggers.try_recv(), Ok(Trigger::NewKey));
    }

    #[test]
    fn a_wish_on_the_second_character_banner_syncs_the_first() {
        let (hub, _key_rx, mut triggers) = hub();
        let wish = |gacha_type| {
            WishEvent::Wish(GachaWish {
                gacha_type,
                pulls: 10,
            })
        };
        hub.forward(vec![wish(Some(400)), wish(Some(302)), wish(None)], None);
        assert_eq!(triggers.try_recv(), Ok(Trigger::Wish(Some(301))));
        assert_eq!(triggers.try_recv(), Ok(Trigger::Wish(Some(302))));
        assert_eq!(triggers.try_recv(), Ok(Trigger::Wish(None)));
    }

    #[test]
    fn regions_come_from_the_uid_like_the_dispatch_names_them() {
        assert_eq!(region_for_uid(811_111_111), Some("os_asia"));
        assert_eq!(region_for_uid(611_111_111), Some("os_usa"));
        assert_eq!(region_for_uid(711_111_111), Some("os_euro"));
        assert_eq!(region_for_uid(911_111_111), Some("os_cht"));
        assert_eq!(region_for_uid(1_811_111_111), Some("os_asia"));
        assert_eq!(region_for_uid(111_111_111), Some("cn_gf01"));
        assert_eq!(region_for_uid(511_111_111), Some("cn_qd01"));
        assert_eq!(region_for_uid(411_111_111), None);
        assert_eq!(region_for_uid(81_111_111), None);
    }

    fn banner(gacha_type: u32, gacha_id: &str) -> GachaRecordLink {
        GachaRecordLink {
            gacha_type: Some(gacha_type),
            query: format!(
                "win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2\
                 &auth_appid=webview_gacha&init_type=301&gacha_id={gacha_id}&timestamp=1790000000"
            ),
        }
    }

    #[test]
    fn the_key_carries_the_character_banners_link_the_version_and_the_region() {
        let (hub, key_rx, _triggers) = hub();
        hub.forward(
            vec![
                WishEvent::ClientVersion("OSRELWin7.1.0_R1_S2_D3".to_owned()),
                WishEvent::Banners(vec![
                    banner(200, "aaaa"),
                    banner(400, "bbbb"),
                    banner(301, "cccc"),
                ]),
                WishEvent::Key(authkey("webview_gacha", "HHHH")),
            ],
            Some(811_111_111),
        );
        let url = key_rx.borrow().as_ref().unwrap().wish_url();
        assert_eq!(
            url,
            "https://public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog\
             ?win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2\
             &auth_appid=webview_gacha&init_type=301&gacha_id=cccc&timestamp=1790000000\
             &lang=en&device_type=pc&game_version=OSRELWin7.1.0_R1_S2_D3&region=os_asia\
             &authkey=HHHH&game_biz="
        );
    }

    #[test]
    fn without_a_character_banner_the_first_banners_link_is_taken() {
        let captured = Captured {
            banners: vec![banner(200, "aaaa"), banner(302, "dddd")],
            game_version: None,
        };
        let parts = captured.link_parts(None);
        assert!(parts.record_query.unwrap().contains("gacha_id=aaaa"));
        assert_eq!(parts.region, None);
        assert_eq!(Captured::default().link_parts(None), LinkParts::default());
    }

    #[test]
    fn banner_types_map_to_the_synced_banners() {
        assert_eq!(banner_for_gacha_type(400), Some(301));
        for banner in BANNERS {
            assert_eq!(banner_for_gacha_type(banner), Some(banner));
        }
        assert_eq!(banner_for_gacha_type(303), None);
    }

    #[test]
    fn wish_messages_are_taken_out_of_the_batch() {
        let mut classified = vec![
            (1, CommandMatch::DeletedItems(vec![1])),
            (2, CommandMatch::AuthKey(authkey("webview_gacha", "DDDD"))),
            (
                3,
                CommandMatch::Wish(GachaWish {
                    gacha_type: Some(301),
                    pulls: 1,
                }),
            ),
            (4, CommandMatch::GachaInfo(vec![banner(301, "cccc")])),
            (
                5,
                CommandMatch::ClientVersion("OSRELWin7.1.0_R1_S2_D3".to_owned()),
            ),
        ];
        let events = take_wish_events(&mut classified);
        assert_eq!(events.len(), 4);
        assert_eq!(classified.len(), 1);
        assert!(matches!(classified[0], (1, CommandMatch::DeletedItems(_))));
    }

    #[test]
    fn the_view_gives_the_held_keys_link_and_says_how_long_it_lasts() {
        let (key_tx, key_rx) = watch::channel(None);
        let (_status_tx, status_rx) = watch::channel(SyncStatus::default());
        let (_seen_tx, seen_rx) = watch::channel(Seen::default());
        let (cache_tx, _cache_rx) = mpsc::unbounded_channel();
        let view = WishView {
            key_rx,
            status_rx,
            seen_rx,
            cache_tx,
        };
        let status = |at| view.status(at, GameStatus::Decoding, true).text;
        let now = Instant::now();
        assert_eq!(view.wish_url(now), None);
        assert_eq!(status(now), "No wish key yet");

        key_tx.send_replace(Some(WishKey::new("EEEE", "hk4e_global", now)));
        let url = view.wish_url(now).unwrap();
        assert!(url.contains("authkey=EEEE"), "{url}");
        assert_eq!(status(now), "Key valid ~24 h · from the game");
        assert!(
            view.status(now, GameStatus::Decoding, true)
                .tooltip
                .contains("Seen this session:")
        );

        // A cached link is given as it is.
        let link = "https://example.invalid/getGachaLog?authkey=FFFF&game_biz=hk4e_global";
        key_tx.send_replace(WishKey::from_game_link(
            link,
            std::time::Duration::ZERO,
            now,
        ));
        assert_eq!(view.wish_url(now).as_deref(), Some(link));

        // A day later the key is gone.
        let later = now + gacha_log::KEY_LIFETIME;
        assert_eq!(view.wish_url(later), None);
        assert_eq!(status(later), "No wish key yet");
    }

    #[test]
    fn looking_in_the_cache_without_a_cache_source_is_no_answer() {
        let (_key_tx, key_rx) = watch::channel(None);
        let (_status_tx, status_rx) = watch::channel(SyncStatus::default());
        let (_seen_tx, seen_rx) = watch::channel(Seen::default());
        let (cache_tx, cache_rx) = mpsc::unbounded_channel();
        drop(cache_rx);
        let view = WishView {
            key_rx,
            status_rx,
            seen_rx,
            cache_tx,
        };
        let mut answer = view.look_in_cache();
        assert!(matches!(
            answer.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
    }

    #[test]
    fn syncing_is_gated_and_authenticated_like_automated_uploads() {
        use crate::app::TrackerSignIn;

        let auth = TrackerAuth::new(
            "https://tracker.invalid/api",
            Arc::new(crate::signin::MemoryStore::default()),
            "TEST-PC".to_owned(),
            Arc::new(|_| {}),
            Arc::new(|| {}),
        );
        let mut state = SavedAppState {
            auto_export_to_tracker: true,
            tracker_api_url: "https://tracker.invalid/api".to_owned(),
            tracker_import_key: "gdt_uk_test".to_owned(),
            tracker_verified: true,
            tracker_sign_in: TrackerSignIn::SignedOut,
            ..Default::default()
        };
        let credential = |state: &SavedAppState| {
            credential_for(state, &auth).map(|(base, credential)| (base, format!("{credential:?}")))
        };

        // Not signed in: the verified import key.
        assert!(sync_enabled(&state));
        assert_eq!(
            credential(&state),
            Some((
                "https://tracker.invalid/api".to_owned(),
                "ImportKey(<redacted>)".to_owned()
            ))
        );
        state.tracker_verified = false;
        assert_eq!(credential(&state), None);

        // Signed in: the sign-in, whatever the key says.
        state.tracker_sign_in = TrackerSignIn::SignedIn;
        assert_eq!(
            credential(&state),
            Some((
                "https://tracker.invalid/api".to_owned(),
                "SignedIn(https://tracker.invalid/api)".to_owned()
            ))
        );

        // Uploads off, or the sign-in not read yet: nothing syncs.
        state.auto_export_to_tracker = false;
        assert!(!sync_enabled(&state));
        assert_eq!(credential(&state), None);
        state.auto_export_to_tracker = true;
        state.tracker_sign_in = TrackerSignIn::Unknown;
        assert_eq!(credential(&state), None);
    }
}
