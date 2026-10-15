//! Live sync: between two snapshots, send the tracker what changed.
//!
//! Plan: the tracker's `docs/plans/live-sync.md` (§4.3 sending rules, §6
//! irminsul, §13 the contract as built). The game sends the whole account at
//! login and at every world change; each of those is a snapshot, as before,
//! tagged with `gi_capture`. In between, this sends batches of changes
//! (`delta.rs`) to `POST /irminsul/changes`, adaptively in time and amount,
//! and nothing at all while nothing changes.
//!
//! [`LiveSync`] is the policy and the bookkeeping only: no I/O, no clock of
//! its own (every call takes `now` in milliseconds), so the monitor and
//! `--replay-journal` (simulated time) run exactly the same decisions.
//!
//! Live mode needs the tracker's consent: the answer to a snapshot upload
//! names the journal's `live.base`. Without it (an older tracker, live sync
//! off for the account, the switch off here) irminsul stays in snapshot mode,
//! today's behaviour: every change uploads the whole account after the 5 s
//! debounce, tagged `reason: "change"`.

use serde::Deserialize;

use crate::delta::{self, GoodDelta, Keyed, Sum};
use crate::good::{GiCapture, GiCaptureJournal, Good};

/// No batch sooner than this after the previous one (except a big one).
pub const BATCH_SPACING_MS: u64 = 15_000;
/// A lone change waits at most this long.
pub const LONE_CHANGE_MS: u64 = 120_000;
/// Changes at once that send a batch straight away.
pub const BIG_BATCH: usize = 2_000;
/// Changes that make a batch worth sending after [`BATCH_SPACING_MS`].
pub const NORMAL_BATCH: usize = 5;
/// The first retry after a failed request; doubled up to [`MAX_BACKOFF_MS`].
pub const FIRST_BACKOFF_MS: u64 = 15_000;
pub const MAX_BACKOFF_MS: u64 = 120_000;
/// Items in one item packet for it to be a full send of the account (the
/// game's own login and world-change sends hold thousands; the matcher
/// itself needs ten).
pub const FULL_SEND_MIN_ITEMS: usize = 100;

/// Why a snapshot is taken (`gi_capture.reason`; contract, append only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Login,
    World,
    Manual,
    Collapse,
    Logout,
    Resync,
    Change,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::World => "world",
            Self::Manual => "manual",
            Self::Collapse => "collapse",
            Self::Logout => "logout",
            Self::Resync => "resync",
            Self::Change => "change",
        }
    }

    /// Whether this snapshot waits for the debounced automation export (the
    /// game's full sends arrive over several seconds) rather than going now.
    fn debounced(self) -> bool {
        matches!(self, Self::Login | Self::World)
    }

    /// Whether live sync retries this snapshot itself when it fails (the
    /// automation retries its own, by releasing its signature).
    fn retried_here(self) -> bool {
        matches!(self, Self::Collapse | Self::Logout | Self::Resync)
    }
}

/// Whether an item packet is the game sending the whole inventory (login, or
/// a world change), as opposed to a change to a few items.
pub fn is_full_send(items_in_packet: usize, items_held: usize) -> bool {
    items_in_packet >= FULL_SEND_MIN_ITEMS && items_in_packet * 2 >= items_held
}

/// A new id for one game login: 16 characters of `[A-Za-z0-9_-]`.
pub fn new_session_id() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        // Unique enough for one PC's logins: the time, spread over the bytes.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (nanos >> ((i % 16) * 8)) as u8 ^ (i as u8).wrapping_mul(37);
        }
    }
    bytes
        .iter()
        .map(|byte| ALPHABET[usize::from(byte & 63)] as char)
        .collect()
}

/// The game login the data belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Login {
    session: String,
    /// Full sends seen in this connection: 1 = the login's own.
    world: u32,
}

/// The tracker's journal this follows: what it has acknowledged.
#[derive(Clone, Debug)]
struct Journal {
    base: String,
    /// The last batch the tracker stored on it (0: none yet).
    seq: u64,
    /// The state it holds: the snapshot plus every stored batch.
    keyed: Keyed,
}

/// A snapshot upload in flight.
#[derive(Clone, Debug)]
struct SnapshotFlight {
    ticket: u64,
    reason: Reason,
    keyed: Keyed,
}

/// A batch in flight.
#[derive(Clone, Debug)]
struct BatchFlight {
    delta: GoodDelta,
    keyed: Keyed,
    /// Changes noted when its export was built: what it covers.
    pending_at_build: usize,
}

/// What the monitor should do now.
#[derive(Debug, PartialEq)]
pub enum Action {
    Nothing,
    /// Upload the current state as a snapshot, tagged with this capture.
    Snapshot(Reason),
    /// POST this batch.
    Batch(Box<GoodDelta>),
}

/// The tracker's answer to a snapshot upload, as far as live sync cares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportAnswer {
    /// `live.base` when the tracker now follows this snapshot with a journal.
    pub base: Option<String>,
    pub watching: bool,
}

impl ImportAnswer {
    /// Read the import's answer: the hosted tracker's `ImportResponse`, or
    /// the old backend's `{status, message, data}` wrapper. Anything else
    /// means no live sync.
    pub fn parse(body: &str) -> Self {
        #[derive(Deserialize)]
        struct Live {
            base: String,
            #[serde(default)]
            watching: bool,
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return Self::default();
        };
        let live = value
            .get("live")
            .or_else(|| value.get("data").and_then(|data| data.get("live")))
            .cloned()
            .and_then(|live| serde_json::from_value::<Live>(live).ok())
            .filter(|live| !live.base.is_empty() && live.base.len() <= 32);
        match live {
            Some(live) => Self {
                base: Some(live.base),
                watching: live.watching,
            },
            None => Self::default(),
        }
    }
}

/// What the tracker said to a batch (§13's answer table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchAnswer {
    Stored {
        collapse: bool,
        watching: bool,
    },
    /// A retry of a batch it already stored.
    Duplicate,
    /// Live sync is off for the account.
    LiveOff,
    /// 409 `resync`, or the batch was too big: send a snapshot.
    Resync,
    /// 429 `daily_live_limit`: snapshots until the next UTC day.
    DailyLimit,
    /// Rate limited, a server error, no connection: keep the changes, retry.
    Retry,
    /// 401 / 403 and the like: snapshot mode; the next snapshot upload shows
    /// the user what is wrong, as uploads always have.
    Refused,
}

impl BatchAnswer {
    /// `status` 0 = the request never got an answer.
    pub fn of(status: u16, body: &str) -> Self {
        let value: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
        let code = value
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        match status {
            200..=299 => {
                if value.get("ok") == Some(&serde_json::Value::Bool(false)) {
                    Self::LiveOff
                } else if value.get("duplicate") == Some(&serde_json::Value::Bool(true)) {
                    Self::Duplicate
                } else if value.get("ok") == Some(&serde_json::Value::Bool(true)) {
                    Self::Stored {
                        collapse: value.get("collapse") == Some(&serde_json::Value::Bool(true)),
                        watching: value.get("watching") == Some(&serde_json::Value::Bool(true)),
                    }
                } else {
                    // A 2xx that is not this API (an old tracker's app page).
                    Self::LiveOff
                }
            }
            409 if code == "resync" => Self::Resync,
            409 => Self::Refused,
            413 | 422 => Self::Resync,
            429 if code == "daily_live_limit" => Self::DailyLimit,
            404 | 405 => Self::LiveOff,
            0 | 429 | 500..=599 => Self::Retry,
            _ => Self::Refused,
        }
    }
}

/// Live sync's state for one running irminsul.
#[derive(Debug, Default)]
pub struct LiveSync {
    login: Option<Login>,
    journal: Option<Journal>,
    snapshot_flight: Option<SnapshotFlight>,
    batch_flight: Option<BatchFlight>,
    tickets: u64,
    /// A batch that failed to get an answer: resent unchanged, so a retry
    /// the tracker already stored is a duplicate of exactly it.
    unacked: Option<BatchFlight>,
    /// A snapshot that must be uploaded.
    wanted: Option<Reason>,
    /// The capture a wanted logout snapshot carries (the login is over).
    logout_login: Option<(Login, u64)>,
    /// Account changes noted since the last batch was built (an estimate:
    /// the diff decides what is sent).
    pending: usize,
    last_sent_ms: u64,
    watching: bool,
    retry_at_ms: u64,
    backoff_ms: u64,
    /// Snapshot mode until this UTC day is over (the daily batch limit).
    off_day: Option<u64>,
}

const DAY_MS: u64 = 86_400_000;

impl LiveSync {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether batches go to the tracker now (else snapshot mode).
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.journal.is_some() && self.off_day.is_none_or(|day| now_ms / DAY_MS > day)
    }

    /// The journal's last stored batch.
    #[cfg(test)]
    pub fn seq(&self) -> Option<u64> {
        self.journal.as_ref().map(|journal| journal.seq)
    }

    /// The game sent the whole inventory: a login (the first of a
    /// connection) or a world change.
    pub fn note_full_send(&mut self) {
        match &mut self.login {
            Some(login) => {
                login.world += 1;
                self.wanted = Some(Reason::World);
            }
            None => {
                self.login = Some(Login {
                    session: new_session_id(),
                    world: 1,
                });
                self.wanted = Some(Reason::Login);
            }
        }
    }

    /// Some account data changed (`count` entries, an estimate).
    pub fn note_change(&mut self, count: usize) {
        self.pending = self.pending.saturating_add(count.max(1));
    }

    /// The game connection ended (a logout, the game closing, a reconnect).
    /// When the journal holds anything, a logout snapshot of the data as it
    /// is goes up first, with the login that is ending.
    pub fn note_connection_ended(&mut self) {
        let Some(login) = self.login.take() else {
            return;
        };
        let journal_open = self.journal.as_ref().is_some_and(|journal| journal.seq > 0)
            || self.unacked.is_some()
            || self.pending > 0
            || self.batch_flight.is_some();
        if journal_open && self.journal.is_some() {
            let seq = self.journal.as_ref().map_or(0, |journal| journal.seq);
            self.logout_login = Some((login, seq));
            self.wanted = Some(Reason::Logout);
        }
    }

    /// The captured data was replaced (a new connection's first data, or the
    /// user cleared it): nothing journals against the old state any more.
    pub fn note_data_replaced(&mut self) {
        self.journal = None;
        self.unacked = None;
        self.pending = 0;
        self.logout_login = None;
        if self.wanted == Some(Reason::Logout) {
            self.wanted = None;
        }
    }

    /// The reason the debounced automation export uploads a snapshot with,
    /// or `None` when it should not upload one (live mode: batches carry the
    /// changes). `live_enabled`: the switch here and the tracker upload on.
    pub fn automation_reason(&self, live_enabled: bool, now_ms: u64) -> Option<Reason> {
        if live_enabled && self.is_live(now_ms) {
            return self.wanted.filter(|reason| reason.debounced());
        }
        Some(match self.wanted {
            Some(reason) => reason,
            None => Reason::Change,
        })
    }

    /// The `gi_capture` for a snapshot uploaded now for `reason`.
    pub fn capture(&self, reason: Reason) -> Option<GiCapture> {
        let (login, seq) = match (reason, &self.logout_login) {
            (Reason::Logout, Some((login, seq))) => (login, *seq),
            _ => (
                self.login.as_ref()?,
                self.journal.as_ref().map_or(0, |journal| journal.seq),
            ),
        };
        Some(GiCapture {
            v: 1,
            reason: reason.as_str().to_string(),
            session: login.session.clone(),
            world: login.world,
            journal: GiCaptureJournal {
                seq: if reason == Reason::Login { 0 } else { seq },
            },
        })
    }

    /// A snapshot of `keyed` went up for `reason`; the ticket names it in
    /// [`Self::snapshot_answered`] (a newer snapshot supersedes it).
    pub fn snapshot_started(&mut self, reason: Reason, keyed: Keyed) -> u64 {
        if self.wanted == Some(reason) || reason == Reason::Manual {
            self.wanted = None;
        }
        self.tickets += 1;
        self.snapshot_flight = Some(SnapshotFlight {
            ticket: self.tickets,
            reason,
            keyed,
        });
        self.tickets
    }

    /// Whether a request is in flight (the sender sends one at a time).
    pub fn busy(&self) -> bool {
        self.snapshot_flight.is_some() || self.batch_flight.is_some()
    }

    /// The snapshot upload `ticket` finished: `Some(answer)` when it was
    /// stored.
    pub fn snapshot_answered(&mut self, ticket: u64, answer: Option<ImportAnswer>, now_ms: u64) {
        if self.snapshot_flight.as_ref().map(|flight| flight.ticket) != Some(ticket) {
            return;
        }
        let Some(SnapshotFlight { reason, keyed, .. }) = self.snapshot_flight.take() else {
            return;
        };
        match answer {
            Some(answer) => {
                self.backoff_ms = 0;
                self.retry_at_ms = 0;
                self.unacked = None;
                self.watching = answer.watching;
                self.last_sent_ms = now_ms;
                if reason == Reason::Logout {
                    self.logout_login = None;
                }
                // What came in while it was in flight is in the next diff.
                self.journal = answer.base.map(|base| Journal {
                    base,
                    seq: 0,
                    keyed,
                });
            }
            None => {
                // The debounced ones are retried by the automation (its
                // signature is released); the others from here, after a wait.
                if reason.retried_here() {
                    self.wanted.get_or_insert(reason);
                    self.back_off(now_ms);
                }
            }
        }
    }

    fn back_off(&mut self, now_ms: u64) {
        self.backoff_ms = if self.backoff_ms == 0 {
            FIRST_BACKOFF_MS
        } else {
            (self.backoff_ms * 2).min(MAX_BACKOFF_MS)
        };
        self.retry_at_ms = now_ms + self.backoff_ms;
    }

    /// When [`Self::tick`] next has something to decide, or `None` when only
    /// new data (or an answer) can change that.
    pub fn next_tick_ms(&self, live_enabled: bool, now_ms: u64) -> Option<u64> {
        if self.busy() {
            return None;
        }
        if let Some(reason) = self.wanted
            && !reason.debounced()
        {
            return Some(self.retry_at_ms.max(now_ms));
        }
        if !live_enabled || !self.is_live(now_ms) || self.wanted.is_some() {
            return None;
        }
        if self.unacked.is_some() {
            return Some(self.retry_at_ms.max(now_ms));
        }
        if self.pending == 0 {
            return None;
        }
        if self.pending >= BIG_BATCH {
            return Some(self.retry_at_ms.max(now_ms));
        }
        Some(
            (self.last_sent_ms + BATCH_SPACING_MS)
                .max(self.retry_at_ms)
                .max(now_ms),
        )
    }

    /// Decide what to send now. `export` builds the current state when a
    /// batch may be due: the export (for its `sum` and UID) and its keyed
    /// form.
    pub fn tick(
        &mut self,
        live_enabled: bool,
        now_ms: u64,
        export: impl FnOnce() -> Option<(Good, Keyed)>,
    ) -> Action {
        if self.busy() || now_ms < self.retry_at_ms {
            return Action::Nothing;
        }
        if let Some(reason) = self.wanted
            && !reason.debounced()
        {
            return Action::Snapshot(reason);
        }
        if !live_enabled || !self.is_live(now_ms) || self.wanted.is_some() {
            return Action::Nothing;
        }
        if let Some(flight) = self.unacked.take() {
            let delta = flight.delta.clone();
            self.batch_flight = Some(flight);
            return Action::Batch(Box::new(delta));
        }
        if self.pending == 0 {
            return Action::Nothing;
        }
        let since = now_ms.saturating_sub(self.last_sent_ms);
        if self.pending < BIG_BATCH && since < BATCH_SPACING_MS {
            return Action::Nothing;
        }
        let Some((good, keyed)) = export() else {
            return Action::Nothing;
        };
        let journal = self.journal.as_ref().expect("is_live checked it");
        let changes = delta::diff(&journal.keyed, &keyed);
        if changes.is_empty() {
            self.pending = 0;
            return Action::Nothing;
        }
        let due = changes.len() >= BIG_BATCH
            || changes.len() >= NORMAL_BATCH
            || self.watching
            || since >= LONE_CHANGE_MS
            || delta::is_important(&changes, &keyed);
        if !due {
            return Action::Nothing;
        }
        let Some(uid) = good.gi_player.as_ref().and_then(|player| player.uid) else {
            // The tracker routes a batch by its UID; without one, snapshots.
            self.journal = None;
            return Action::Nothing;
        };
        let Some(login) = &self.login else {
            return Action::Nothing;
        };
        let mut batch = GoodDelta::new(uid, &login.session, journal.seq + 1, &journal.base, now_ms);
        batch.changes = changes;
        batch.sum = Some(Sum::of(&good));
        if batch.changes.len() > delta::MAX_CHANGES
            || serde_json::to_vec(&batch).map_or(usize::MAX, |json| json.len()) > delta::MAX_BYTES
        {
            // Too much for a batch: the whole state is cheaper.
            self.wanted = Some(Reason::Collapse);
            return Action::Snapshot(Reason::Collapse);
        }
        self.batch_flight = Some(BatchFlight {
            delta: batch.clone(),
            keyed,
            pending_at_build: self.pending,
        });
        Action::Batch(Box::new(batch))
    }

    /// The batch request finished with `answer`.
    pub fn batch_answered(&mut self, answer: BatchAnswer, now_ms: u64) {
        let Some(BatchFlight {
            delta,
            keyed,
            pending_at_build,
        }) = self.batch_flight.take()
        else {
            return;
        };
        // A snapshot since started a new journal: this batch's is gone.
        if self.journal.as_ref().map(|journal| journal.base.as_str()) != Some(delta.base.as_str()) {
            return;
        }
        match answer {
            BatchAnswer::Stored { collapse, watching } => {
                self.watching = watching;
                if collapse {
                    self.wanted = Some(Reason::Collapse);
                }
                self.stored(delta.seq, keyed, pending_at_build, now_ms);
            }
            BatchAnswer::Duplicate => self.stored(delta.seq, keyed, pending_at_build, now_ms),
            BatchAnswer::LiveOff => {
                self.journal = None;
                self.wanted = Some(Reason::Change);
                self.backoff_ms = 0;
                self.retry_at_ms = 0;
            }
            BatchAnswer::Resync => {
                self.journal = None;
                self.wanted = Some(Reason::Resync);
                self.backoff_ms = 0;
                self.retry_at_ms = 0;
            }
            BatchAnswer::DailyLimit => {
                self.off_day = Some(now_ms / DAY_MS);
                self.journal = None;
                self.wanted = Some(Reason::Change);
                self.backoff_ms = 0;
                self.retry_at_ms = 0;
            }
            BatchAnswer::Retry => {
                self.unacked = Some(BatchFlight {
                    delta,
                    keyed,
                    pending_at_build,
                });
                self.back_off(now_ms);
            }
            BatchAnswer::Refused => {
                // Snapshot mode: the next change uploads whole, and that
                // upload's failure is what the user sees.
                self.journal = None;
            }
        }
    }

    fn stored(&mut self, seq: u64, keyed: Keyed, pending_at_build: usize, now_ms: u64) {
        if let Some(journal) = &mut self.journal {
            journal.seq = seq;
            journal.keyed = keyed;
        }
        self.pending = self.pending.saturating_sub(pending_at_build);
        self.last_sent_ms = now_ms;
        self.backoff_ms = 0;
        self.retry_at_ms = 0;
    }

    /// Everything not sent yet as one batch, taken as stored at once:
    /// `--replay-journal` uses it before each snapshot and at the end, so
    /// the snapshot plus the batches can be checked against the whole state.
    /// `None` when not live or nothing changed.
    pub fn flush(&mut self, now_ms: u64, good: &Good, keyed: Keyed) -> Option<GoodDelta> {
        if self.busy() || !self.is_live(now_ms) {
            return None;
        }
        let journal = self.journal.as_ref()?;
        let changes = delta::diff(&journal.keyed, &keyed);
        if changes.is_empty() {
            return None;
        }
        let uid = good.gi_player.as_ref().and_then(|player| player.uid)?;
        let session = self
            .login
            .as_ref()
            .or(self.logout_login.as_ref().map(|(login, _)| login))?
            .session
            .clone();
        let mut batch = GoodDelta::new(uid, &session, journal.seq + 1, &journal.base, now_ms);
        batch.changes = changes;
        batch.sum = Some(Sum::of(good));
        self.unacked = None;
        let pending = self.pending;
        self.stored(batch.seq, keyed, pending, now_ms);
        Some(batch)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::delta::Change;
    use crate::good::GiPlayer;

    fn good(mora: u32) -> Good {
        let mut good: Good = serde_json::from_value(serde_json::json!({
            "format": "GOOD", "version": 3, "source": "Irminsul",
            "characters": [], "artifacts": [], "weapons": [], "materials": {}
        }))
        .unwrap();
        good.materials = HashMap::from([("Mora".to_string(), mora)]);
        good.gi_player = Some(GiPlayer {
            uid: Some(812_345_678),
            ..Default::default()
        });
        good
    }

    fn with_materials(count: usize) -> Good {
        let mut good = good(1);
        for i in 0..count {
            good.materials.insert(format!("Thing{i}"), 1);
        }
        good
    }

    fn keyed(good: &Good) -> Keyed {
        Keyed::of(good, |_| None)
    }

    fn export(good: Good) -> impl FnOnce() -> Option<(Good, Keyed)> {
        move || {
            let keyed = keyed(&good);
            Some((good, keyed))
        }
    }

    /// Logged in, snapshot stored with a journal; the clock at `t`.
    fn live_at(t: u64) -> LiveSync {
        let mut live = LiveSync::new();
        live.note_full_send();
        assert_eq!(live.automation_reason(true, t), Some(Reason::Login));
        let ticket = live.snapshot_started(Reason::Login, keyed(&good(100)));
        live.snapshot_answered(
            ticket,
            Some(ImportAnswer {
                base: Some("k1".into()),
                watching: false,
            }),
            t,
        );
        assert!(live.is_live(t));
        live
    }

    fn sent(action: Action) -> GoodDelta {
        match action {
            Action::Batch(delta) => *delta,
            other => panic!("expected a batch, got {other:?}"),
        }
    }

    #[test]
    fn afk_sends_nothing() {
        let mut live = live_at(0);
        assert_eq!(live.next_tick_ms(true, 1_000), None);
        assert_eq!(
            live.tick(true, 10_000_000, || panic!("no export")),
            Action::Nothing
        );
    }

    #[test]
    fn a_normal_batch_waits_15_s_for_5_changes() {
        let mut live = live_at(0);
        live.note_change(5);
        assert_eq!(live.next_tick_ms(true, 1_000), Some(BATCH_SPACING_MS));
        assert_eq!(
            live.tick(true, 14_999, export(with_materials(5))),
            Action::Nothing
        );
        let batch = sent(live.tick(true, 15_000, export(with_materials(5))));
        assert_eq!(batch.seq, 1);
        assert_eq!(batch.base, "k1");
        assert_eq!(batch.uid, 812_345_678);
        assert_eq!(batch.sum.unwrap().materials, 6);
        assert!(live.busy());
        live.batch_answered(
            BatchAnswer::Stored {
                collapse: false,
                watching: false,
            },
            15_100,
        );
        assert_eq!(live.seq(), Some(1));
        assert_eq!(live.next_tick_ms(true, 15_200), None);
    }

    #[test]
    fn a_few_changes_wait_for_two_minutes() {
        let mut live = live_at(0);
        live.note_change(1);
        assert_eq!(live.tick(true, 20_000, export(good(101))), Action::Nothing);
        assert_eq!(live.tick(true, 119_999, export(good(101))), Action::Nothing);
        let batch = sent(live.tick(true, 120_000, export(good(101))));
        assert_eq!(batch.changes.len(), 1);
    }

    #[test]
    fn someone_watching_gets_every_change_after_15_s() {
        let mut live = LiveSync::new();
        live.note_full_send();
        let ticket = live.snapshot_started(Reason::Login, keyed(&good(100)));
        live.snapshot_answered(
            ticket,
            Some(ImportAnswer {
                base: Some("k1".into()),
                watching: true,
            }),
            0,
        );
        live.note_change(1);
        assert_eq!(live.tick(true, 14_000, export(good(101))), Action::Nothing);
        assert_eq!(
            sent(live.tick(true, 15_000, export(good(101))))
                .changes
                .len(),
            1
        );
    }

    #[test]
    fn an_important_change_goes_after_15_s() {
        let mut live = live_at(0);
        let mut levelled = good(100);
        levelled.characters.push(crate::good::Character {
            key: "Furina".into(),
            level: 90,
            constellation: 0,
            ascension: 6,
            talent: crate::good::TalentLevel {
                auto: 1,
                skill: 1,
                burst: 1,
            },
        });
        live.note_change(1);
        let batch = sent(live.tick(true, 15_000, export(levelled)));
        assert!(matches!(batch.changes[0], Change::Add(..)));
    }

    #[test]
    fn a_big_burst_goes_at_once() {
        let mut live = live_at(0);
        live.note_change(BIG_BATCH);
        assert_eq!(live.next_tick_ms(true, 1_000), Some(1_000));
        // 2,000 distinct changes is a whole snapshot's worth: a collapse.
        assert_eq!(
            live.tick(true, 1_000, export(with_materials(2_001))),
            Action::Snapshot(Reason::Collapse)
        );
    }

    #[test]
    fn nothing_changed_after_all_clears_the_estimate() {
        let mut live = live_at(0);
        live.note_change(3);
        assert_eq!(live.tick(true, 200_000, export(good(100))), Action::Nothing);
        assert_eq!(live.next_tick_ms(true, 200_000), None);
    }

    #[test]
    fn a_failed_batch_is_resent_unchanged_with_backoff() {
        let mut live = live_at(0);
        live.note_change(5);
        let first = sent(live.tick(true, 15_000, export(with_materials(5))));
        live.batch_answered(BatchAnswer::Retry, 15_000);
        assert_eq!(live.next_tick_ms(true, 15_001), Some(30_000));
        // More changes meanwhile: the retry is still exactly the first batch.
        live.note_change(5);
        assert_eq!(
            live.tick(true, 29_999, export(with_materials(9))),
            Action::Nothing
        );
        let again = sent(live.tick(true, 30_000, || panic!("the retry needs no export")));
        assert_eq!(again, first);
        live.batch_answered(BatchAnswer::Retry, 30_000);
        assert_eq!(live.next_tick_ms(true, 30_000), Some(60_000));
        sent(live.tick(true, 60_000, || None));
        live.batch_answered(BatchAnswer::Retry, 60_000);
        assert_eq!(live.next_tick_ms(true, 60_000), Some(120_000));
        sent(live.tick(true, 120_000, || None));
        live.batch_answered(BatchAnswer::Retry, 120_000);
        // Capped at two minutes.
        assert_eq!(live.next_tick_ms(true, 120_000), Some(240_000));
        sent(live.tick(true, 240_000, || None));
        live.batch_answered(BatchAnswer::Duplicate, 240_000);
        assert_eq!(live.seq(), Some(1));
        // The changes made meanwhile follow as seq 2 (four: a lone-change wait).
        assert_eq!(
            live.tick(true, 255_000, export(with_materials(9))),
            Action::Nothing
        );
        let next = sent(live.tick(true, 360_000, export(with_materials(9))));
        assert_eq!(next.seq, 2);
        assert_eq!(next.changes.len(), 4);
    }

    #[test]
    fn the_trackers_answers_steer_the_sender() {
        // collapse: true asks for a snapshot now.
        let mut live = live_at(0);
        live.note_change(5);
        sent(live.tick(true, 15_000, export(with_materials(5))));
        live.batch_answered(
            BatchAnswer::Stored {
                collapse: true,
                watching: false,
            },
            15_000,
        );
        assert_eq!(
            live.tick(true, 15_001, || None),
            Action::Snapshot(Reason::Collapse)
        );

        // resync: a snapshot, and no batches until its answer.
        let mut live = live_at(0);
        live.note_change(5);
        sent(live.tick(true, 15_000, export(with_materials(5))));
        live.batch_answered(BatchAnswer::Resync, 15_000);
        assert!(!live.is_live(15_000));
        assert_eq!(
            live.tick(true, 15_001, || None),
            Action::Snapshot(Reason::Resync)
        );
        let ticket = live.snapshot_started(Reason::Resync, keyed(&with_materials(5)));
        live.snapshot_answered(
            ticket,
            Some(ImportAnswer {
                base: Some("k2".into()),
                watching: false,
            }),
            16_000,
        );
        assert!(live.is_live(16_000));

        // live: false means snapshot mode, starting with a snapshot.
        let mut live = live_at(0);
        live.note_change(5);
        sent(live.tick(true, 15_000, export(with_materials(5))));
        live.batch_answered(BatchAnswer::LiveOff, 15_000);
        assert!(!live.is_live(15_000));
        assert_eq!(
            live.tick(true, 15_001, || None),
            Action::Snapshot(Reason::Change)
        );
        live.snapshot_started(Reason::Change, keyed(&with_materials(5)));
        assert_eq!(live.automation_reason(true, 15_000), Some(Reason::Change));

        // The daily limit: snapshot mode for the rest of the UTC day.
        let mut live = live_at(0);
        live.note_change(5);
        sent(live.tick(true, 15_000, export(with_materials(5))));
        live.batch_answered(BatchAnswer::DailyLimit, 15_000);
        let ticket = live.snapshot_started(Reason::Change, keyed(&with_materials(5)));
        live.snapshot_answered(
            ticket,
            Some(ImportAnswer {
                base: Some("k3".into()),
                watching: false,
            }),
            16_000,
        );
        assert!(!live.is_live(16_000));
        assert!(live.is_live(DAY_MS + 1));
    }

    #[test]
    fn snapshot_mode_without_the_trackers_consent() {
        let mut live = LiveSync::new();
        live.note_full_send();
        let ticket = live.snapshot_started(Reason::Login, keyed(&good(100)));
        // An older tracker: no `live` in the answer.
        live.snapshot_answered(ticket, Some(ImportAnswer::default()), 0);
        assert!(!live.is_live(0));
        live.note_change(5);
        assert_eq!(
            live.tick(true, 100_000, || panic!("no batches")),
            Action::Nothing
        );
        assert_eq!(live.automation_reason(true, 100_000), Some(Reason::Change));
        // The switch off: always snapshot mode.
        let live = live_at(0);
        assert_eq!(live.automation_reason(false, 1), Some(Reason::Change));
    }

    #[test]
    fn the_capture_reasons_of_a_session() {
        let mut live = LiveSync::new();
        // Login.
        live.note_full_send();
        let login = live.capture(Reason::Login).unwrap();
        assert_eq!(
            (login.reason.as_str(), login.world, login.journal.seq),
            ("login", 1, 0)
        );
        assert!(login.session.len() >= 16);
        assert!(
            login
                .session
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        let ticket = live.snapshot_started(Reason::Login, keyed(&good(1)));
        live.snapshot_answered(
            ticket,
            Some(ImportAnswer {
                base: Some("k1".into()),
                watching: false,
            }),
            0,
        );
        // Two world changes in the same connection.
        for world in [2, 3] {
            live.note_full_send();
            assert_eq!(live.automation_reason(true, 1), Some(Reason::World));
            let capture = live.capture(Reason::World).unwrap();
            assert_eq!((capture.reason.as_str(), capture.world), ("world", world));
            assert_eq!(capture.session, login.session);
            let ticket = live.snapshot_started(Reason::World, keyed(&good(world)));
            live.snapshot_answered(
                ticket,
                Some(ImportAnswer {
                    base: Some(format!("k{world}")),
                    watching: false,
                }),
                0,
            );
            assert_eq!(live.automation_reason(true, 1), None);
        }
        // A batch, then the tracker asks for a collapse.
        live.note_change(5);
        sent(live.tick(true, 20_000, export(with_materials(5))));
        live.batch_answered(
            BatchAnswer::Stored {
                collapse: true,
                watching: false,
            },
            20_000,
        );
        assert_eq!(
            live.tick(true, 20_001, || None),
            Action::Snapshot(Reason::Collapse)
        );
        let collapse = live.capture(Reason::Collapse).unwrap();
        assert_eq!(
            (collapse.reason.as_str(), collapse.journal.seq),
            ("collapse", 1)
        );
        let ticket = live.snapshot_started(Reason::Collapse, keyed(&with_materials(5)));
        live.snapshot_answered(
            ticket,
            Some(ImportAnswer {
                base: Some("k4".into()),
                watching: false,
            }),
            21_000,
        );
        // A change, then the game closes: a logout snapshot with this login.
        live.note_change(1);
        live.note_connection_ended();
        assert_eq!(
            live.tick(true, 21_001, || None),
            Action::Snapshot(Reason::Logout)
        );
        let logout = live.capture(Reason::Logout).unwrap();
        assert_eq!((logout.reason.as_str(), logout.world), ("logout", 3));
        assert_eq!(logout.session, login.session);
        let ticket = live.snapshot_started(Reason::Logout, keyed(&with_materials(6)));
        live.snapshot_answered(ticket, Some(ImportAnswer::default()), 22_000);
        // The next full send is a new login.
        live.note_full_send();
        let next = live.capture(Reason::Login).unwrap();
        assert_ne!(next.session, login.session);
        assert_eq!(next.world, 1);
    }

    #[test]
    fn an_idle_logout_sends_nothing() {
        let mut live = live_at(0);
        live.note_connection_ended();
        assert_eq!(live.tick(true, 1, || None), Action::Nothing);
    }

    #[test]
    fn a_failed_logout_snapshot_is_retried_after_a_wait() {
        let mut live = live_at(0);
        live.note_change(1);
        live.note_connection_ended();
        assert_eq!(
            live.tick(true, 1, || None),
            Action::Snapshot(Reason::Logout)
        );
        let ticket = live.snapshot_started(Reason::Logout, keyed(&good(101)));
        live.snapshot_answered(ticket, None, 1);
        assert_eq!(live.tick(true, 2, || None), Action::Nothing);
        assert_eq!(live.next_tick_ms(true, 2), Some(1 + FIRST_BACKOFF_MS));
        assert_eq!(
            live.tick(true, 1 + FIRST_BACKOFF_MS, || None),
            Action::Snapshot(Reason::Logout)
        );
    }

    #[test]
    fn replaced_data_ends_the_journal() {
        let mut live = live_at(0);
        live.note_change(5);
        live.note_data_replaced();
        assert!(!live.is_live(0));
        assert_eq!(live.tick(true, 100_000, || None), Action::Nothing);
    }

    #[test]
    fn full_sends_are_told_from_item_changes() {
        assert!(is_full_send(5_543, 5_543));
        assert!(is_full_send(5_543, 0));
        assert!(!is_full_send(12, 5_543));
        assert!(!is_full_send(99, 0));
        assert!(!is_full_send(1_000, 5_543));
    }

    #[test]
    fn the_answers_are_read_leniently() {
        assert_eq!(
            ImportAnswer::parse(
                r#"{"status":"created","snapshotId":3,"contentKey":"x","live":{"base":"k9","watching":true}}"#
            ),
            ImportAnswer {
                base: Some("k9".into()),
                watching: true
            }
        );
        assert_eq!(
            ImportAnswer::parse(r#"{"status":"created","snapshotId":3}"#),
            ImportAnswer::default()
        );
        assert_eq!(ImportAnswer::parse("<html>"), ImportAnswer::default());
        assert_eq!(
            BatchAnswer::of(
                200,
                r#"{"ok":true,"seq":3,"collapse":false,"watching":true}"#
            ),
            BatchAnswer::Stored {
                collapse: false,
                watching: true
            }
        );
        assert_eq!(
            BatchAnswer::of(200, r#"{"ok":true,"duplicate":true,"seq":3}"#),
            BatchAnswer::Duplicate
        );
        assert_eq!(
            BatchAnswer::of(200, r#"{"ok":false,"live":false}"#),
            BatchAnswer::LiveOff
        );
        assert_eq!(
            BatchAnswer::of(
                409,
                r#"{"error":{"code":"resync","message":"Send a snapshot first"}}"#
            ),
            BatchAnswer::Resync
        );
        assert_eq!(
            BatchAnswer::of(
                429,
                r#"{"error":{"code":"daily_live_limit","message":"x"}}"#
            ),
            BatchAnswer::DailyLimit
        );
        assert_eq!(
            BatchAnswer::of(429, r#"{"error":{"code":"rate_limited","message":"x"}}"#),
            BatchAnswer::Retry
        );
        assert_eq!(BatchAnswer::of(0, ""), BatchAnswer::Retry);
        assert_eq!(BatchAnswer::of(503, ""), BatchAnswer::Retry);
        assert_eq!(BatchAnswer::of(413, ""), BatchAnswer::Resync);
        assert_eq!(BatchAnswer::of(404, "<html>"), BatchAnswer::LiveOff);
        assert_eq!(
            BatchAnswer::of(401, r#"{"error":{"code":"session_revoked","message":"x"}}"#),
            BatchAnswer::Refused
        );
    }
}
