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
            Phase::Idle => {}
        }
        let last = self.last.as_ref()?;
        let at = last.at.format("%H:%M");
        Some(match &last.outcome {
            Outcome::Sent { added, .. } => format!("Synced {at} · added {added}"),
            Outcome::UpToDate => format!("Synced {at} · up to date"),
            Outcome::Unfinished => format!("Synced {at} · more to come"),
            Outcome::KeyExpired => format!("Sync {at}: the key expired; open Wish → History"),
            Outcome::Failed(why) => format!("Sync failed {at}: {why}"),
        })
    }
}

/// The sync task. See the module documentation of `wish_history`.
pub(crate) struct WishSync {
    trigger_rx: mpsc::UnboundedReceiver<Trigger>,
    key_tx: Arc<watch::Sender<Option<WishKey>>>,
    status_tx: watch::Sender<SyncStatus>,
    saved_state_rx: watch::Receiver<SavedAppState>,
    toast_tx: mpsc::UnboundedSender<(String, bool)>,
    ctx: egui::Context,
    log_http: reqwest::Client,
    tracker_http: reqwest::Client,
    schedule: Schedule,
    partials: BTreeMap<Banner, Partial>,
}

impl WishSync {
    pub(super) fn new(
        trigger_rx: mpsc::UnboundedReceiver<Trigger>,
        key_tx: Arc<watch::Sender<Option<WishKey>>>,
        status_tx: watch::Sender<SyncStatus>,
        saved_state_rx: watch::Receiver<SavedAppState>,
        toast_tx: mpsc::UnboundedSender<(String, bool)>,
        ctx: egui::Context,
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
            key_tx,
            status_tx,
            saved_state_rx,
            toast_tx,
            ctx,
            log_http: client(LOG_REQUEST_TIMEOUT),
            tracker_http: client(TRACKER_REQUEST_TIMEOUT),
            schedule: Schedule::default(),
            partials: BTreeMap::new(),
        }
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
        if self.fresh_key(now).is_none() {
            return;
        }
        if !super::sync_enabled(&self.saved_state_rx.borrow()) {
            tracing::debug!("wish sync is off (no tracker credential, or uploads are off)");
            return;
        }
        match trigger {
            Trigger::NewKey => self.schedule.on_new_key(now),
            Trigger::Wish(banner) => self.schedule.on_wish(now, banner),
        }
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
        let state = self.saved_state_rx.borrow().clone();
        let Some((base_url, credential)) = credential_for(&state) else {
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
            key.endpoint().to_owned(),
            key.clone(),
            TokioSleeper,
            Pacing::default(),
        );

        tracing::info!(?banners, "syncing wish history");
        let status_tx = &self.status_tx;
        let ctx = &self.ctx;
        let progress = move |banner: Banner, page: u32| {
            status_tx.send_modify(|status| status.phase = Phase::Syncing { banner, page });
            ctx.request_repaint();
        };
        let report = Run::new(&mut log, &tracker, &progress, PAGES_PER_RUN)
            .sync(&banners, &mut self.partials)
            .await;
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

    fn finish(&mut self, key: &WishKey, report: RunReport, now: Instant) {
        let outcome = match &report.error {
            Some(RunError::KeyExpired) => {
                // Only if no newer key arrived during the run.
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
                Outcome::KeyExpired
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
}
