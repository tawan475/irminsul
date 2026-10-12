//! Wish history from the game's own traffic.
//!
//! Opening Wish -> History in game makes the server send a web view key
//! (`GetAuthkeyRsp`, recognised by auto-artifactarium). From it irminsul
//!
//! * builds the wish URL that paimon.moe ("Manual" import) and stardb take,
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

use auto_artifactarium::{CommandMatch, GachaAuthKey, GachaWish};
use tokio::sync::{mpsc, watch};

pub(crate) use self::gacha_log::WishKey;
pub(crate) use self::sync::{SyncStatus, WishSync};
use self::tracker::TrackerCredential;
use crate::app::SavedAppState;
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
}

/// Take the wish history messages out of a classified batch.
///
/// They are not account data: they must not count as a batch that replaces
/// the snapshot, or reach the GOOD export.
pub(crate) fn take_wish_events(classified: &mut Vec<(u16, CommandMatch)>) -> Vec<WishEvent> {
    if !classified
        .iter()
        .any(|(_, found)| matches!(found, CommandMatch::AuthKey(_) | CommandMatch::Wish(_)))
    {
        return Vec::new();
    }
    let mut events = Vec::new();
    let mut rest = Vec::with_capacity(classified.len());
    for (command_id, found) in std::mem::take(classified) {
        match found {
            CommandMatch::AuthKey(key) => events.push(WishEvent::Key(key)),
            CommandMatch::Wish(wish) => events.push(WishEvent::Wish(wish)),
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

/// The monitor's end: hands captured keys and wishes on.
#[derive(Clone)]
pub(crate) struct WishHub {
    key_tx: Arc<watch::Sender<Option<WishKey>>>,
    trigger_tx: mpsc::UnboundedSender<Trigger>,
}

impl WishHub {
    pub(crate) fn forward(&self, events: Vec<WishEvent>) {
        for event in events {
            match event {
                WishEvent::Key(key) => self.key(key, Instant::now()),
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
    }

    fn key(&self, key: GachaAuthKey, now: Instant) {
        if !key.is_wish_history_key() {
            // The login's keys (`ugc_login`) are for something else.
            tracing::debug!(app = %key.auth_appid, "ignoring a web view key that is not for wishes");
            return;
        }
        let key = WishKey::new(key.authkey(), &key.game_biz, now);
        let new = self.key_tx.send_if_modified(|current| {
            if current
                .as_ref()
                .is_some_and(|current| current.same_key(&key))
            {
                return false;
            }
            *current = Some(key);
            true
        });
        if new {
            tracing::info!("captured a wish history key");
            let _ = self.trigger_tx.send(Trigger::NewKey);
        }
    }
}

/// The UI's end.
pub(crate) struct WishView {
    key_rx: watch::Receiver<Option<WishKey>>,
    status_rx: watch::Receiver<SyncStatus>,
    /// The URL the web-cache scraper found (`crate::wish`), the fallback while
    /// no key has been captured.
    scraped_url_rx: watch::Receiver<Option<String>>,
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

    /// The URL to copy: built from the captured key, else the scraped one.
    pub(crate) fn wish_url(&self, now: Instant) -> Option<String> {
        match self.key(now) {
            Some(key) => Some(key.wish_url()),
            None => self.scraped_url_rx.borrow().clone(),
        }
    }

    /// "Open Wish → History in game" until a key exists, then how long it
    /// lasts.
    pub(crate) fn key_line(&self, now: Instant) -> String {
        match self.key(now) {
            None => "Open Wish → History in game".to_owned(),
            Some(key) => {
                let hours = key.remaining(now).as_secs().div_ceil(3600);
                if hours <= 1 {
                    "Wish key valid for less than an hour".to_owned()
                } else {
                    format!("Wish key valid about {hours} h")
                }
            }
        }
    }

    /// One line about the tracker sync, or `None` when there is nothing to
    /// say.
    pub(crate) fn sync_line(&self) -> Option<String> {
        self.status_rx.borrow().line()
    }
}

/// Everything the wish history needs, made together.
pub(crate) struct WishChannels {
    pub(crate) hub: WishHub,
    pub(crate) view: WishView,
    pub(crate) sync: WishSync,
}

/// Build the hub, the view and the sync task (not yet running).
pub(crate) fn channels(
    scraped_url_rx: watch::Receiver<Option<String>>,
    saved_state_rx: watch::Receiver<SavedAppState>,
    toast_tx: mpsc::UnboundedSender<(String, bool)>,
    ctx: egui::Context,
    auth: TrackerAuth,
) -> WishChannels {
    let (key_tx, key_rx) = watch::channel(None);
    let key_tx = Arc::new(key_tx);
    let (trigger_tx, trigger_rx) = mpsc::unbounded_channel();
    let (status_tx, status_rx) = watch::channel(SyncStatus::default());
    let sync = WishSync::new(
        trigger_rx,
        Arc::clone(&key_tx),
        status_tx,
        saved_state_rx,
        toast_tx,
        ctx,
        auth,
    );
    WishChannels {
        hub: WishHub { key_tx, trigger_tx },
        view: WishView {
            key_rx,
            status_rx,
            scraped_url_rx,
        },
        sync,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub() -> (
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
            },
            key_rx,
            trigger_rx,
        )
    }

    fn authkey(app: &str, key: &str) -> GachaAuthKey {
        GachaAuthKey::new(key, app, "hk4e_global")
    }

    #[test]
    fn only_wish_keys_are_kept_and_a_repeat_triggers_nothing() {
        let (hub, key_rx, mut triggers) = hub();
        hub.forward(vec![WishEvent::Key(authkey("ugc_login", "AAAA"))]);
        assert!(key_rx.borrow().is_none());
        assert!(triggers.try_recv().is_err());

        hub.forward(vec![WishEvent::Key(authkey("webview_gacha", "BBBB"))]);
        assert!(key_rx.borrow().is_some());
        assert_eq!(triggers.try_recv(), Ok(Trigger::NewKey));

        hub.forward(vec![WishEvent::Key(authkey("webview_gacha", "BBBB"))]);
        assert!(
            triggers.try_recv().is_err(),
            "the same key again is not new"
        );

        hub.forward(vec![WishEvent::Key(authkey("webview_gacha", "CCCC"))]);
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
        hub.forward(vec![wish(Some(400)), wish(Some(302)), wish(None)]);
        assert_eq!(triggers.try_recv(), Ok(Trigger::Wish(Some(301))));
        assert_eq!(triggers.try_recv(), Ok(Trigger::Wish(Some(302))));
        assert_eq!(triggers.try_recv(), Ok(Trigger::Wish(None)));
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
        ];
        let events = take_wish_events(&mut classified);
        assert_eq!(events.len(), 2);
        assert_eq!(classified.len(), 1);
        assert!(matches!(classified[0], (1, CommandMatch::DeletedItems(_))));
    }

    #[test]
    fn the_view_prefers_the_captured_key_and_says_how_long_it_lasts() {
        let (key_tx, key_rx) = watch::channel(None);
        let (_status_tx, status_rx) = watch::channel(SyncStatus::default());
        let (scraped_tx, scraped_url_rx) = watch::channel(None);
        let view = WishView {
            key_rx,
            status_rx,
            scraped_url_rx,
        };
        let now = Instant::now();
        assert_eq!(view.wish_url(now), None);
        assert_eq!(view.key_line(now), "Open Wish → History in game");

        scraped_tx.send_replace(Some("https://example.invalid/scraped".to_owned()));
        assert_eq!(
            view.wish_url(now).as_deref(),
            Some("https://example.invalid/scraped")
        );

        key_tx.send_replace(Some(WishKey::new("EEEE", "hk4e_global", now)));
        let url = view.wish_url(now).unwrap();
        assert!(url.contains("authkey=EEEE"), "{url}");
        assert_eq!(view.key_line(now), "Wish key valid about 24 h");

        // A day later the key is gone and the scraper's URL is back.
        let later = now + gacha_log::KEY_LIFETIME;
        assert_eq!(
            view.wish_url(later).as_deref(),
            Some("https://example.invalid/scraped")
        );
        assert_eq!(view.key_line(later), "Open Wish → History in game");
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
