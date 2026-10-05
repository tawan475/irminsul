//! Whether Genshin is running, and -- the part that actually matters -- whether
//! Irminsul was capturing when it started.
//!
//! Irminsul can only read a game session it watched *begin*. The XOR key every
//! packet is encrypted with is recovered from the login handshake, and nothing
//! after it carries the key again, so a session that started before Irminsul
//! launched -- or while packet capture was stopped -- yields nothing at all, for
//! as long as it lasts. Until now the UI said "Capture: running" throughout,
//! which is true and useless: it is the app's most common failure mode and it
//! was completely invisible.
//!
//! The useful signal is therefore not "is Genshin running" but "did Irminsul
//! watch this game session start, with capture active". That is a transition,
//! not a snapshot, so [`GameWatch`] keeps the previous observation and judges
//! the change. It is deliberately pure -- fed only "is the process there?" and
//! "is capture running?" -- so every interesting case is unit-testable without a
//! game. [`ProcessDetector`] is the seam the real scan hides behind.
//!
//! # What this does not prove
//!
//! The process appearing is a *proxy* for the moment that actually matters.
//! The key comes from the `GetPlayerTokenRsp` exchanged when the client
//! connects to the game server -- "entering the door", in the quickstart's
//! words -- which is some way after the executable starts. Watching the
//! process appear inside the capture window therefore guarantees the exchange
//! is inside it too, but *not* watching it appear guarantees nothing: a client
//! parked on the title screen has not had that exchange yet, and neither has
//! one about to be logged into a second time. Both of those recover on their
//! own, which is why [`GameStatus::Decoding`] outranks every process verdict
//! and why the two red states' tooltips offer entering the world before they
//! offer a restart.
//!
//! Seeing the process appear inside the capture window is likewise *necessary*
//! for the key, not *sufficient*: the exchange still has to be on an interface
//! Irminsul is capturing, and the seed search still has to succeed. The one
//! state here backed by evidence is [`GameStatus::Decoding`], which is only
//! ever set by game commands that actually decrypted -- and even that proves
//! the login was seen rather than that every later packet will decode. The
//! wording of each state is picked to claim exactly that much and no more.

/// Names the game process runs under.
///
/// The `.exe` forms are what Windows reports and also what a Proton/Wine prefix
/// reports on Linux; the bare forms cover a native-ish launcher that strips the
/// extension. Matching is case-insensitive.
const GAME_PROCESS_NAMES: &[&str] = &[
    // Global client.
    "GenshinImpact.exe",
    // CN client.
    "YuanShen.exe",
    "GenshinImpact",
    "YuanShen",
];

/// How much of a process name Linux keeps.
///
/// `/proc/<pid>/comm` -- where the name comes from on Linux, sysinfo included --
/// is `TASK_COMM_LEN` = 16 bytes *including* the NUL, so the longest name that
/// survives is 15 characters and "GenshinImpact.exe" is only ever seen as
/// "GenshinImpact.e". Without this the Proton case silently never matches.
const LINUX_COMM_LEN: usize = 15;

/// Is `name` one of the game's process names?
///
/// Truncation is honoured only for an exact 15-character prefix of a longer
/// known name, so this cannot start matching launchers or crash handlers that
/// merely begin the same way.
pub fn is_game_process_name(name: &str) -> bool {
    GAME_PROCESS_NAMES.iter().any(|known| {
        if name.eq_ignore_ascii_case(known) {
            return true;
        }
        name.len() == LINUX_COMM_LEN
            && known.len() > LINUX_COMM_LEN
            && known.is_char_boundary(LINUX_COMM_LEN)
            && known[..LINUX_COMM_LEN].eq_ignore_ascii_case(name)
    })
}

/// Why a running game cannot be captured.
///
/// The fix is the same in both cases -- restart Genshin -- but the cause is not,
/// and a user who just pressed Stop deserves to be told that is what did it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissedLaunch {
    /// The game was already running the first time Irminsul looked, i.e.
    /// Irminsul was started second.
    AlreadyRunning,
    /// The game started, or kept running, while packet capture was stopped.
    CaptureStopped,
}

/// How loudly the UI should say it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    /// Nothing to report.
    Neutral,
    /// Working as intended.
    Good,
    /// Actionable: nothing will be captured until the user does something.
    Problem,
}

/// What Irminsul can honestly say about the game.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GameStatus {
    /// No game process found.
    #[default]
    NotRunning,
    /// The process appeared while capture was running, so the login handshake
    /// fell inside the capture window. Nothing has decoded yet.
    LaunchCaptured,
    /// Game commands are decrypting. The only state here backed by packets
    /// rather than by process bookkeeping.
    ///
    /// Set only by commands that decrypted under the *session* key, so it
    /// proves the key for the current connection was recovered. Login messages
    /// decrypted under the baked-in dispatch key do not count: every connection
    /// gets that far, including one whose session key is then never found (see
    /// [`GameStatus::KeyLost`]). The per-category ticks above the line are what
    /// confirm which data actually arrived.
    Decoding,
    /// The game is running but the capture backend is not up.
    ///
    /// Neutral rather than red because it is normally transient: capture is
    /// always-on and supervised, so this covers the seconds before the backend
    /// reports itself started, and the backoff between restart attempts. A real
    /// failure is reported as an error toast and in the log, and shows here as
    /// this state simply never clearing.
    CaptureOff,
    /// The game was already open when Irminsul started, and nothing says yet
    /// whether its login is behind it or still to come.
    ///
    /// The common, working case: Genshin parked on the title screen, Irminsul
    /// opened, then the door clicked. The key comes from the token exchange as
    /// the client enters the world, so that session captures normally. Only
    /// game traffic with no login in it (a session already in the world, see
    /// [`IN_WORLD_GRACE`]) turns this into [`MissedLaunch::AlreadyRunning`].
    AwaitingLogin,
    /// The game is running and Irminsul cannot have seen it start.
    LaunchMissed(MissedLaunch),
    /// A connection's login was seen, but its session key was not recovered,
    /// so nothing from it decrypts. Reached when the search gave up, or when
    /// no session-key data followed the login within [`KEY_RECOVERY_GRACE`].
    KeyLost,
}

impl GameStatus {
    /// The short line shown next to "Capture:" and "Status:".
    pub fn label(self) -> &'static str {
        match self {
            GameStatus::NotRunning => "Game: not running",
            GameStatus::LaunchCaptured => "Game: running, launch captured",
            GameStatus::Decoding => "Game: data decrypting",
            GameStatus::CaptureOff => "Game: running, capture starting",
            GameStatus::AwaitingLogin => "Game: running — enter the world to capture",
            GameStatus::LaunchMissed(MissedLaunch::AlreadyRunning) => {
                "Game: already running — restart Genshin to capture"
            }
            GameStatus::LaunchMissed(MissedLaunch::CaptureStopped) => {
                "Game: capture was off — restart Genshin to capture"
            }
            GameStatus::KeyLost => "Game: key not recovered — relog to capture",
        }
    }

    /// The long explanation, shown on hover so the line itself stays short.
    pub fn tooltip(self) -> &'static str {
        match self {
            GameStatus::NotRunning => "Start Genshin while Irminsul is running.",
            GameStatus::LaunchCaptured => {
                "Login seen. Says \"data decrypting\" once your data arrives."
            }
            GameStatus::Decoding => {
                "Reading this session. Inventory, characters and achievements arrive by \
                 themselves as you enter the world."
            }
            GameStatus::CaptureOff => {
                "Capture isn't running; it restarts itself within seconds. If this stays, run \
                 Irminsul as administrator and check the log."
            }
            GameStatus::AwaitingLogin => "Fine if you're on the title screen: enter the world now.",
            GameStatus::LaunchMissed(MissedLaunch::AlreadyRunning) => {
                "Irminsul started after you entered the world. Return to the title screen and \
                 enter again, or restart Genshin."
            }
            GameStatus::LaunchMissed(MissedLaunch::CaptureStopped) => {
                "Capture was off when you logged in. Return to the title screen and enter the \
                 world again, or restart Genshin."
            }
            GameStatus::KeyLost => {
                "Couldn't read this login. Return to the title screen and enter again. Data \
                 captured before is kept."
            }
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            GameStatus::NotRunning | GameStatus::CaptureOff | GameStatus::AwaitingLogin => {
                Severity::Neutral
            }
            GameStatus::LaunchCaptured | GameStatus::Decoding => Severity::Good,
            GameStatus::LaunchMissed(_) | GameStatus::KeyLost => Severity::Problem,
        }
    }
}

/// The live process scan, kept behind a trait so [`GameWatch`] can be driven
/// from tests with no game and no process list.
pub trait ProcessDetector {
    /// Is a game process present right now?
    fn game_running(&mut self) -> bool;
}

use std::time::{Duration, Instant};

/// How long a decoded batch keeps the line on "data decrypting".
///
/// Long enough to ride out a loading screen without flicker, short enough that
/// closing the game clears the claim while the user is still looking at it.
const DECODING_TTL: Duration = Duration::from_secs(10);

/// How long a connection's login traffic may go without session-key data
/// before the key is reported as not recovered.
///
/// A normal login recovers the key within a second or two of the token
/// exchange, and a search that gives up says so directly (see
/// [`GameWatch::note_key_recovery_failed`]), so this only has to catch what
/// slips past both while staying clear of a slow but working login.
pub const KEY_RECOVERY_GRACE: Duration = Duration::from_secs(30);

/// How long game traffic may flow, for a game that was already open when
/// Irminsul started, with no login seen in it before the session is judged to
/// have begun before Irminsul.
///
/// A client on the title screen sends nothing to the game server; entering the
/// world opens the connection with a handshake that the sniffer reports (see
/// [`GameWatch::note_login_seen`]) well within this. A session already in the
/// world keeps pinging, so it crosses this quickly and is reported missed.
pub const IN_WORLD_GRACE: Duration = Duration::from_secs(8);

/// The transition logic. See the module docs.
#[derive(Debug, Default)]
pub struct GameWatch {
    /// Presence at the previous poll; `None` until the first one, which is
    /// exactly what makes "it was already there when we opened our eyes"
    /// distinguishable from "we watched it start".
    previous: Option<bool>,
    /// The verdict reached from process transitions alone. Never holds
    /// [`GameStatus::Decoding`]: that one is packet evidence, tracked
    /// separately, so a session that stops decoding falls back to the
    /// process verdict instead of to nothing.
    process_status: GameStatus,
    /// When game data last decoded.
    ///
    /// A timestamp rather than a flag so the claim expires on its own. "Data
    /// decrypting" is a statement about *now*; a sticky boolean left the line
    /// asserting it long after the game had closed, because the only thing that
    /// cleared it was a process scan that cannot be relied on (a Proton prefix
    /// may report a name this build does not know, and a replayed savefile has
    /// no game process at all). Expiry makes the line self-correcting whatever
    /// the scan does.
    decoded_at: Option<Instant>,
    /// Whether any game data decoded since the last poll.
    ///
    /// The tie-breaker that makes a scan's "gone" trustworthy without letting it
    /// start a flap: an absence is believed only when no packets arrived to
    /// contradict it. See [`Self::poll`].
    decoded_since_poll: bool,
    /// Why this game session cannot be captured, once that is established.
    ///
    /// Remembered rather than recomputed so that stopping capture can stay
    /// visually quiet while still surfacing the truth when capture resumes.
    holed_cause: Option<MissedLaunch>,
    /// When the current connection's login traffic (dispatch-key commands)
    /// was first seen with no session-key data since.
    ///
    /// The evidence for [`GameStatus::KeyLost`]: a login that was watched and
    /// then led nowhere. Cleared by session-key data, a reset, or the process
    /// going away.
    awaiting_key_since: Option<Instant>,
    /// The sniffer gave up recovering the current connection's session key.
    key_recovery_failed: bool,
    /// For a game that was already open when Irminsul started: when its game
    /// traffic was first seen with no login watched since. See
    /// [`IN_WORLD_GRACE`] and [`GameStatus::AwaitingLogin`].
    traffic_without_login_since: Option<Instant>,
    /// Has the scan ever actually found the game?
    ///
    /// Until it has, an absence proves nothing. The process names here are a
    /// guess on anything but Windows -- a Proton prefix may report something
    /// this build does not know, and a replayed savefile has no game process at
    /// all -- and a scan that has never once seen the game must not be allowed
    /// to withdraw evidence that packets are decoding. See [`Self::observe`].
    scan_found_game: bool,
}

impl GameWatch {
    /// What the UI should show.
    pub fn status(&self) -> GameStatus {
        if self.is_decoding() {
            GameStatus::Decoding
        } else if self.key_lost()
            && matches!(
                self.process_status,
                GameStatus::LaunchCaptured | GameStatus::LaunchMissed(_)
            )
        {
            // Only over a running game with capture up: "not running" and
            // "capture starting" are the more basic truths when they apply.
            GameStatus::KeyLost
        } else if self.process_status == GameStatus::LaunchMissed(MissedLaunch::AlreadyRunning)
            && !self.missed_in_world()
        {
            GameStatus::AwaitingLogin
        } else {
            self.process_status
        }
    }

    /// Has game traffic flowed long enough, with no login in it, to say the
    /// already-open game's session began before Irminsul?
    fn missed_in_world(&self) -> bool {
        self.traffic_without_login_since
            .is_some_and(|at| at.elapsed() >= IN_WORLD_GRACE)
    }

    /// Was a login seen whose session key has not arrived, and is not coming?
    fn key_lost(&self) -> bool {
        self.key_recovery_failed
            || self
                .awaiting_key_since
                .is_some_and(|at| at.elapsed() >= KEY_RECOVERY_GRACE)
    }

    /// Has game data decoded recently enough to still say so?
    fn is_decoding(&self) -> bool {
        self.decoded_at
            .is_some_and(|at| at.elapsed() < DECODING_TTL)
    }

    /// Has the process scan ever matched the game?
    ///
    /// Diagnostic only. A permanent `false` while the game is plainly running
    /// means this build does not know the process name on this machine, which
    /// is the difference between the line correcting itself instantly and it
    /// waiting out [`DECODING_TTL`].
    pub fn scan_ever_found_game(&self) -> bool {
        self.scan_found_game
    }

    /// How long ago game data last decoded, if ever.
    pub fn decoded_age(&self) -> Option<Duration> {
        self.decoded_at.map(|at| at.elapsed())
    }

    /// Did the last scan find the game running?
    pub fn game_running(&self) -> bool {
        self.previous == Some(true)
    }

    /// Has the process list been looked at even once?
    ///
    /// Used to fire the startup toast on the first poll only.
    pub fn has_polled(&self) -> bool {
        self.previous.is_some()
    }

    /// Scan, then judge.
    pub fn poll(&mut self, detector: &mut dyn ProcessDetector, capturing: bool) -> GameStatus {
        let running = detector.game_running();
        let quiet = !std::mem::take(&mut self.decoded_since_poll);

        // A game the scan saw last time and cannot see now, with no packet in
        // between to argue otherwise, really has gone: drop the decrypting
        // claim at once rather than waiting out `DECODING_TTL`.
        //
        // The "no packet in between" half is what keeps this from bringing back
        // the flap. A scan that intermittently loses a *running* game is
        // contradicted by the packets still arriving from it, so its absence is
        // ignored; only a silence the packets agree with is acted on.
        if !running && matches!(self.previous, Some(true)) && quiet {
            self.decoded_at = None;
        }

        self.observe(running, capturing)
    }

    /// Judge one observation against the previous one.
    pub fn observe(&mut self, running: bool, capturing: bool) -> GameStatus {
        let previous = self.previous.replace(running);
        // Diagnostic only now: a permanent `false` while the game is plainly
        // running says this build cannot name the process on this machine.
        self.scan_found_game |= running;

        // Packet evidence is withdrawn only by things that cannot be wrong:
        // capture being off (nothing is arriving to decode) and a launch (a new
        // session, whose evidence has to be earned again).
        //
        // The process scan deliberately does NOT get a vote. It used to: an
        // absence was allowed to clear the evidence once the scan had matched at
        // least once. On a real machine the scan turned out to miss the running
        // game on most ticks, and the result was the line flipping
        // Decoding -> NotRunning -> Decoding every two seconds, forever, while
        // packets were plainly decoding the whole time. A heuristic that can
        // report a running game as absent must not be able to overrule the one
        // signal that is direct evidence. Staleness is handled by `DECODING_TTL`
        // instead, which needs no scan to be right.
        let launched = running && matches!(previous, Some(false));
        if !capturing || launched {
            self.decoded_at = None;
        }
        if !running || launched {
            // Whatever connection the key was missing for is gone with it.
            self.awaiting_key_since = None;
            self.key_recovery_failed = false;
            self.traffic_without_login_since = None;
        }

        if !running {
            // The process is gone. Whatever it was doing is over, and the next
            // launch gets judged on its own merits.
            self.holed_cause = None;
            self.process_status = GameStatus::NotRunning;
            return self.status();
        }

        // A launch watched with capture already up is a clean session, whatever
        // was concluded about the one before it.
        if launched && capturing {
            self.holed_cause = None;
        } else if self.holed_cause.is_none() {
            // Record why this session is unrecoverable, the first time it is.
            self.holed_cause = match (previous, capturing) {
                // Already there the first time we looked: Irminsul cannot have
                // watched a process that predates it, so the login exchange the
                // key comes from is behind us.
                (None, _) => Some(MissedLaunch::AlreadyRunning),
                // Started while capture was off: the handshake happened outside
                // the capture window, so there is no key for this session.
                (Some(false), false) => Some(MissedLaunch::CaptureStopped),
                // Capture stopped part-way through a session Irminsul *did*
                // watch begin. Deliberately NOT written off. The session key was
                // recovered at login and the sniffer still holds it -- stopping
                // capture does not throw it away. The only thing a gap can cost
                // is KCP sequence continuity, and only if traffic actually flowed
                // while capture was down; stop and start at a menu and nothing
                // is missed at all. Predicting death here cried wolf on a
                // session that goes on working, so the line now waits to be
                // shown rather than guessing: if the stream really did stall,
                // the symptom is that no data arrives and the line simply never
                // reaches "data decrypting".
                (Some(true), false) => None,
                (Some(_), true) => None,
            };
        }

        self.process_status = if !capturing {
            // Quiet on purpose -- see `GameStatus::CaptureOff`.
            GameStatus::CaptureOff
        } else if let Some(cause) = self.holed_cause {
            GameStatus::LaunchMissed(cause)
        } else {
            GameStatus::LaunchCaptured
        };

        self.status()
    }

    /// Re-derive the verdict from the presence already observed.
    ///
    /// Capture starting or stopping changes the answer without the process list
    /// changing at all, and waiting out a poll interval before a red line
    /// appears makes the UI look like it missed the click.
    pub fn recheck(&mut self, capturing: bool) -> GameStatus {
        match self.previous {
            Some(running) => self.observe(running, capturing),
            // Nothing observed yet: there is no verdict to revise, and
            // inventing a presence here would fabricate a transition.
            None => self.status(),
        }
    }

    /// Game data decoded, so the session key was recovered.
    ///
    /// Returns whether the user-visible status changed.
    pub fn note_decoded_data(&mut self) -> bool {
        let before = self.status();
        self.decoded_at = Some(Instant::now());
        self.decoded_since_poll = true;
        self.awaiting_key_since = None;
        self.key_recovery_failed = false;

        // Packets outrank the process scan. Something decoded, so the login
        // exchange for *this* session was inside the capture window, whatever
        // the scan concluded from process timing -- returning to the title
        // screen and logging in again re-handshakes inside a process that was
        // already running. Promoting the remembered verdict is what stops the
        // line falling back to red when the decoding claim later expires.
        self.holed_cause = None;
        if matches!(self.process_status, GameStatus::LaunchMissed(_)) {
            self.process_status = GameStatus::LaunchCaptured;
        }

        self.status() != before
    }

    /// Captured data was dropped -- a new game connection, or the user pressing
    /// Clear -- so nothing has decoded for what follows.
    ///
    /// Returns whether the user-visible status changed.
    pub fn note_data_cleared(&mut self) -> bool {
        let before = self.status();
        self.decoded_at = None;
        self.status() != before
    }

    /// Login traffic decoded -- commands under the dispatch key -- with no
    /// session key yet. Starts the [`KEY_RECOVERY_GRACE`] clock for this
    /// connection, unless it is already running.
    ///
    /// Deliberately *not* evidence for [`GameStatus::Decoding`]: the dispatch
    /// key decrypts the login exchange of any connection, including one whose
    /// session key is then never recovered.
    ///
    /// Returns whether the user-visible status changed.
    pub fn note_login_traffic(&mut self) -> bool {
        let before = self.status();
        self.awaiting_key_since.get_or_insert_with(Instant::now);
        self.login_watched();
        self.status() != before
    }

    /// Game traffic arrived (any captured frame on the game's ports).
    ///
    /// Only matters for a game that was already open when Irminsul started:
    /// it starts the [`IN_WORLD_GRACE`] clock, which a login seen in time
    /// stops. The verdict itself changes at the next poll, so this does not
    /// report a change.
    pub fn note_game_traffic(&mut self) {
        if self.holed_cause == Some(MissedLaunch::AlreadyRunning) {
            self.traffic_without_login_since
                .get_or_insert_with(Instant::now);
        }
    }

    /// A login was watched -- a connection handshake or login traffic -- so
    /// the current session's start fell inside the capture window, whatever
    /// the process timing suggested.
    ///
    /// Returns whether the user-visible status changed.
    pub fn note_login_seen(&mut self) -> bool {
        let before = self.status();
        self.login_watched();
        self.status() != before
    }

    fn login_watched(&mut self) {
        self.traffic_without_login_since = None;
        if self.holed_cause.take().is_some()
            && matches!(self.process_status, GameStatus::LaunchMissed(_))
        {
            self.process_status = GameStatus::LaunchCaptured;
        }
    }

    /// The sniffer gave up recovering the current connection's session key.
    ///
    /// Returns whether the user-visible status changed.
    pub fn note_key_recovery_failed(&mut self) -> bool {
        let before = self.status();
        self.key_recovery_failed = true;
        self.status() != before
    }

    /// The game connection restarted: the previous connection's decrypting
    /// claim and key verdict end, and the new one is judged on its own.
    ///
    /// Returns whether the user-visible status changed.
    pub fn note_session_reset(&mut self) -> bool {
        let before = self.status();
        self.decoded_at = None;
        self.awaiting_key_since = None;
        self.key_recovery_failed = false;
        // A reset is the sniffer seeing a connection handshake: a login.
        self.login_watched();
        self.status() != before
    }
}

/// The real detector: a process-name scan through `sysinfo`.
///
/// One [`sysinfo::System`] is kept for the life of the app rather than rebuilt
/// per tick. On Windows sysinfo opens a handle the first time it sees a process
/// and caches it, so a fresh `System` every two seconds would re-`OpenProcess`
/// every process on the machine.
pub struct SystemProcessDetector {
    system: sysinfo::System,
}

impl SystemProcessDetector {
    pub fn new() -> Self {
        Self {
            // Not `new_all`: that eagerly reads CPU, memory, disks and networks,
            // none of which this app ever asks for.
            system: sysinfo::System::new(),
        }
    }
}

impl Default for SystemProcessDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemProcessDetector {
    /// Refresh the process list and count the names `matches` accepts.
    ///
    /// The predicate exists so a test can drive the real scan -- the one thing
    /// the fake detector cannot cover -- without needing the game installed.
    fn count_matching(&mut self, matches: impl Fn(&str) -> bool) -> usize {
        // `ProcessRefreshKind::nothing()` is load-bearing, not tidiness: the
        // plain `refresh_processes` helper asks for memory, CPU, disk usage,
        // the executable path and per-thread tasks, and `everything()` adds the
        // full command line and environment of every process on the machine.
        // Doing any of that twice a second, on a box that is also running a
        // game, is a real cost for a question that the process *name* answers.
        // With `nothing()` a tick is one toolhelp snapshot walk on Windows, and
        // a `/proc` `stat` read per pid on Linux.
        self.system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );

        self.system
            .processes()
            .values()
            .filter_map(|process| process.name().to_str())
            .filter(|name| matches(name))
            .count()
    }
}

impl SystemProcessDetector {
    /// Terminate every running game process, returning how many were stopped.
    ///
    /// There is no graceful shutdown to ask for -- the game exposes no such
    /// affordance to another process -- so this is an outright kill. Genshin is
    /// server-authoritative, so account progress is safe; anything in flight
    /// (a domain run, a boss fight) is not. The UI says so before offering it.
    ///
    /// A zero return is a real outcome, not an error: the process may have
    /// exited between the scan and the kill, or the kill may have been refused.
    /// Irminsul runs elevated, so a refusal is unlikely but not impossible.
    pub fn kill_game_processes(&mut self) -> usize {
        self.system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );

        self.system
            .processes()
            .values()
            .filter(|process| process.name().to_str().is_some_and(is_game_process_name))
            .filter(|process| process.kill())
            .count()
    }
}

impl ProcessDetector for SystemProcessDetector {
    fn game_running(&mut self) -> bool {
        self.count_matching(is_game_process_name) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process list the test drives directly.
    #[derive(Default)]
    struct FakeDetector {
        running: bool,
    }

    impl ProcessDetector for FakeDetector {
        fn game_running(&mut self) -> bool {
            self.running
        }
    }

    const CAPTURING: bool = true;
    const STOPPED: bool = false;

    /// A watch that has already seen the game absent once, i.e. Irminsul was
    /// started first and is waiting for the user to launch the game.
    fn watching_before_launch(capturing: bool) -> GameWatch {
        let mut watch = GameWatch::default();
        assert_eq!(watch.observe(false, capturing), GameStatus::NotRunning);
        watch
    }

    #[test]
    fn process_names_cover_both_clients_and_linux_truncation() {
        assert!(is_game_process_name("GenshinImpact.exe"));
        assert!(is_game_process_name("YuanShen.exe"));
        assert!(is_game_process_name("GenshinImpact"));
        assert!(is_game_process_name("YuanShen"));
        // Case is not guaranteed by any of the platforms.
        assert!(is_game_process_name("genshinimpact.exe"));
        assert!(is_game_process_name("YUANSHEN.EXE"));
        // `/proc/<pid>/comm` keeps 15 characters, so this is what a Proton run
        // looks like on Linux. Missing it made the whole feature dead on Linux.
        assert!(is_game_process_name("GenshinImpact.e"));

        assert!(!is_game_process_name(""));
        assert!(!is_game_process_name("launcher.exe"));
        assert!(!is_game_process_name("UnityCrashHandler64.exe"));
        assert!(!is_game_process_name("GenshinImpact.exe.bak"));
        // A prefix that is not the truncation length must not match, or every
        // "Genshin*" helper process counts as the game.
        assert!(!is_game_process_name("GenshinImpact."));
        assert!(!is_game_process_name("Genshin"));
    }

    #[test]
    fn nothing_running_is_neutral() {
        let mut watch = GameWatch::default();
        assert_eq!(watch.observe(false, CAPTURING), GameStatus::NotRunning);
        assert_eq!(watch.status().severity(), Severity::Neutral);
    }

    #[test]
    fn a_launch_watched_while_capturing_is_the_working_case() {
        let mut watch = watching_before_launch(CAPTURING);
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
        assert_eq!(watch.status().severity(), Severity::Good);
    }

    /// Ages the "traffic with no login" clock past [`IN_WORLD_GRACE`], i.e. a
    /// session that was already in the world. Returns false (and the caller
    /// skips) on the rare clock that cannot go back that far.
    fn age_traffic_past_grace(watch: &mut GameWatch) -> bool {
        watch.note_game_traffic();
        match Instant::now().checked_sub(IN_WORLD_GRACE + Duration::from_secs(1)) {
            Some(stale) => {
                watch.traffic_without_login_since = Some(stale);
                true
            }
            None => false,
        }
    }

    #[test]
    fn a_game_already_open_at_the_first_poll_waits_for_the_login() {
        // Genshin on the title screen, Irminsul opened, door not clicked yet:
        // the common working order. Nothing is missed until the client
        // connects, so this must not be red.
        let mut watch = GameWatch::default();
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::AwaitingLogin);
        assert_eq!(watch.status().severity(), Severity::Neutral);
        // Some traffic, but not yet long enough to call it a session in progress.
        watch.note_game_traffic();
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::AwaitingLogin);
    }

    #[test]
    fn a_login_seen_after_opening_irminsul_is_a_captured_session() {
        let mut watch = GameWatch::default();
        watch.observe(true, CAPTURING);
        watch.note_game_traffic();
        assert!(watch.note_login_seen());
        assert_eq!(watch.status(), GameStatus::LaunchCaptured);
        // The traffic clock went with it: later traffic is not held against it.
        if age_traffic_past_grace(&mut watch) {
            assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
        }

        // A connection handshake arriving as a session reset counts the same.
        let mut watch = GameWatch::default();
        watch.observe(true, CAPTURING);
        assert!(watch.note_session_reset());
        assert_eq!(watch.status(), GameStatus::LaunchCaptured);

        // So does login traffic under the dispatch key.
        let mut watch = GameWatch::default();
        watch.observe(true, CAPTURING);
        assert!(watch.note_login_traffic());
        assert_eq!(watch.status(), GameStatus::LaunchCaptured);
    }

    #[test]
    fn game_traffic_with_no_login_means_the_session_was_already_running() {
        // Irminsul opened while already in the world: the game keeps talking to
        // the server, but the login that carried the key is behind us.
        let mut watch = GameWatch::default();
        watch.observe(true, CAPTURING);
        if age_traffic_past_grace(&mut watch) {
            assert_eq!(
                watch.observe(true, CAPTURING),
                GameStatus::LaunchMissed(MissedLaunch::AlreadyRunning)
            );
            assert_eq!(watch.status().severity(), Severity::Problem);
            // Going back to the title screen and in again recovers.
            assert!(watch.note_login_seen());
            assert_eq!(watch.status(), GameStatus::LaunchCaptured);
        }
    }

    #[test]
    fn traffic_only_counts_for_a_game_that_was_already_open() {
        // A launch Irminsul watched has nothing to prove: its traffic must not
        // start the clock.
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        watch.note_game_traffic();
        assert_eq!(watch.traffic_without_login_since, None);
        assert_eq!(watch.status(), GameStatus::LaunchCaptured);
    }

    #[test]
    fn a_launch_while_capture_was_stopped_is_flagged_with_its_own_cause() {
        let mut watch = watching_before_launch(STOPPED);
        // Quiet while capture is off -- the capture line says that already.
        assert_eq!(watch.observe(true, STOPPED), GameStatus::CaptureOff);
        // Restarting capture does not recover the handshake that was missed,
        // and that is when saying so is useful rather than redundant.
        assert_eq!(
            watch.observe(true, CAPTURING),
            GameStatus::LaunchMissed(MissedLaunch::CaptureStopped)
        );
    }

    #[test]
    fn stopping_capture_mid_session_keeps_the_session() {
        // Stopping capture does NOT throw the session key away -- it was
        // recovered at login and the sniffer still holds it. A gap can cost KCP
        // sequence continuity, but only if traffic actually flowed while
        // capture was down, so predicting death here cried wolf on sessions
        // that go on working. Off is quiet, back on is green again.
        let mut watch = watching_before_launch(CAPTURING);
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
        assert_eq!(watch.observe(true, STOPPED), GameStatus::CaptureOff);
        assert_eq!(watch.status().severity(), Severity::Neutral);
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
        assert_eq!(watch.status().severity(), Severity::Good);
    }

    #[test]
    fn a_settled_verdict_does_not_flap_across_polls() {
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        for _ in 0..10 {
            assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
        }

        let mut watch = GameWatch::default();
        watch.observe(true, CAPTURING);
        for _ in 0..10 {
            assert_eq!(watch.observe(true, CAPTURING), GameStatus::AwaitingLogin);
        }
        if age_traffic_past_grace(&mut watch) {
            for _ in 0..10 {
                assert_eq!(
                    watch.observe(true, CAPTURING),
                    GameStatus::LaunchMissed(MissedLaunch::AlreadyRunning)
                );
            }
        }
    }

    #[test]
    fn restarting_the_game_clears_the_verdict_and_is_judged_fresh() {
        // The actual fix being recommended to the user has to work.
        let mut watch = GameWatch::default();
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::AwaitingLogin);
        if age_traffic_past_grace(&mut watch) {
            assert_eq!(
                watch.observe(true, CAPTURING),
                GameStatus::LaunchMissed(MissedLaunch::AlreadyRunning)
            );
        }
        assert_eq!(watch.observe(false, CAPTURING), GameStatus::NotRunning);
        assert_eq!(watch.traffic_without_login_since, None);
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
    }

    #[test]
    fn decoded_data_beats_a_missed_launch() {
        // Returning to the title screen and logging in again re-handshakes
        // inside the same process, so a game that was already running when
        // Irminsul started can still become capturable without the process ever
        // going away. Packets outrank the process heuristic.
        let mut watch = GameWatch::default();
        watch.observe(true, CAPTURING);
        assert!(watch.note_decoded_data());
        assert_eq!(watch.status(), GameStatus::Decoding);
        // A second batch is not a change, so it must not churn the watch
        // channel and repaint on every packet.
        assert!(!watch.note_decoded_data());
        // And the next poll must not overwrite the stronger evidence.
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::Decoding);
    }

    #[test]
    fn decoded_data_does_not_survive_the_next_launch() {
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        watch.note_decoded_data();
        // Closing the game no longer withdraws the claim on the spot -- only
        // time does, so a scan that cannot see the game cannot start a flap.
        assert_eq!(watch.observe(false, CAPTURING), GameStatus::Decoding);
        // A launch is a new session, and its evidence has to be earned again.
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
    }

    #[test]
    fn decoded_data_does_not_survive_capture_stopping() {
        // Otherwise the line would still read "data decrypting" while the
        // capture backend is down and nothing is arriving at all.
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        watch.note_decoded_data();
        assert_eq!(watch.observe(true, STOPPED), GameStatus::CaptureOff);
    }

    #[test]
    fn a_scan_that_has_never_found_the_game_cannot_withdraw_the_packets() {
        // The process names are a guess off Windows, and a replayed savefile
        // has no game process at all. If a scan that has never once seen the
        // game were allowed to clear the packet evidence, it would fight every
        // decoded batch for the line and flip it between "not running" and
        // "data decrypting" about once a second for the whole session.
        let mut watch = GameWatch::default();
        assert_eq!(watch.observe(false, CAPTURING), GameStatus::NotRunning);
        assert!(watch.note_decoded_data());
        for _ in 0..5 {
            assert_eq!(watch.observe(false, CAPTURING), GameStatus::Decoding);
        }
        // Capture stopping still withdraws it: nothing is arriving to decode,
        // whatever the scan can or cannot see.
        assert_eq!(watch.observe(false, STOPPED), GameStatus::NotRunning);
    }

    #[test]
    fn a_quiet_disappearance_clears_the_claim_at_once() {
        // The complement of `a_scan_saying_gone_never_overrules_live_packets`:
        // when the packets agree with the scan by stopping, the absence is
        // believed immediately instead of waiting out DECODING_TTL, so closing
        // the game updates the line on the next poll rather than ten seconds
        // later.
        let mut detector = FakeDetector::default();
        let mut watch = GameWatch::default();

        detector.running = true;
        assert_eq!(
            watch.poll(&mut detector, CAPTURING),
            GameStatus::AwaitingLogin
        );
        assert!(watch.note_decoded_data());
        assert_eq!(watch.status(), GameStatus::Decoding);

        // Still running and still decoding: nothing is withdrawn.
        assert_eq!(watch.poll(&mut detector, CAPTURING), GameStatus::Decoding);

        // Game closes and the packets stop with it.
        detector.running = false;
        assert_eq!(watch.poll(&mut detector, CAPTURING), GameStatus::NotRunning);
    }

    #[test]
    fn a_flaky_scan_cannot_clear_a_claim_the_packets_keep_alive() {
        // The same path, but with packets still arriving between polls: the
        // scan losing sight of a live game must not be believed, or the line
        // flaps every poll for the whole session.
        let mut detector = FakeDetector::default();
        let mut watch = GameWatch::default();

        detector.running = true;
        watch.poll(&mut detector, CAPTURING);
        watch.note_decoded_data();

        for _ in 0..10 {
            detector.running = false;
            watch.note_decoded_data();
            assert_eq!(watch.poll(&mut detector, CAPTURING), GameStatus::Decoding);
        }
    }

    #[test]
    fn a_scan_saying_gone_never_overrules_live_packets() {
        // The regression this replaces, seen in a real capture: the scan missed
        // the running game on most ticks, and because an absence was allowed to
        // withdraw the packet evidence the line flipped Decoding -> NotRunning
        // -> Decoding every two seconds for the whole session while data was
        // decoding perfectly. Direct evidence outranks the heuristic, always.
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        watch.note_decoded_data();
        for _ in 0..10 {
            assert_eq!(watch.observe(false, CAPTURING), GameStatus::Decoding);
        }
        // The process verdict underneath still tracks the scan, so once the
        // claim expires the line lands on it rather than on nothing.
        if let Some(stale) = Instant::now().checked_sub(DECODING_TTL + Duration::from_secs(1)) {
            watch.decoded_at = Some(stale);
            assert_eq!(watch.status(), GameStatus::NotRunning);
        }
    }

    #[test]
    fn clearing_captured_data_drops_the_decoding_claim() {
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        watch.note_decoded_data();
        assert!(watch.note_data_cleared());
        assert_eq!(watch.status(), GameStatus::LaunchCaptured);
        assert!(!watch.note_data_cleared());
    }

    #[test]
    fn recheck_reacts_to_the_stop_button_without_waiting_for_a_poll() {
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        assert_eq!(watch.recheck(STOPPED), GameStatus::CaptureOff);
        // Re-deriving from the same presence must not look like a launch, and
        // must not invent a problem: this session was watched from its start.
        assert_eq!(watch.recheck(CAPTURING), GameStatus::LaunchCaptured);
    }

    #[test]
    fn the_decoding_claim_expires_on_its_own() {
        // The bug this replaces: the claim was a sticky boolean cleared only by
        // a process scan, so on a machine where the scan cannot name the game
        // the line went on saying "data decrypting" long after the game closed.
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        assert!(watch.note_decoded_data());
        assert_eq!(watch.status(), GameStatus::Decoding);

        let stale = Instant::now().checked_sub(DECODING_TTL + Duration::from_secs(1));
        // `Instant` has no guaranteed epoch; if the process has not been up
        // long enough to subtract, there is nothing to assert.
        if let Some(stale) = stale {
            watch.decoded_at = Some(stale);
            assert_eq!(watch.status(), GameStatus::LaunchCaptured);
        }
    }

    #[test]
    fn an_expired_decoding_claim_never_falls_back_to_red() {
        // Going back to the title screen and logging in again re-handshakes
        // inside a process that was already running, so a session that started
        // red can legitimately decode. When the claim later expires it must
        // land on the green verdict the packets proved, not on the red one the
        // process timing guessed -- otherwise the line flaps on every lull.
        let mut watch = GameWatch::default();
        watch.observe(true, CAPTURING);
        if age_traffic_past_grace(&mut watch) {
            assert_eq!(
                watch.observe(true, CAPTURING),
                GameStatus::LaunchMissed(MissedLaunch::AlreadyRunning)
            );
        }
        assert!(watch.note_decoded_data());
        assert_eq!(watch.status(), GameStatus::Decoding);

        if let Some(stale) = Instant::now().checked_sub(DECODING_TTL + Duration::from_secs(1)) {
            watch.decoded_at = Some(stale);
            assert_eq!(watch.status(), GameStatus::LaunchCaptured);
            assert_eq!(watch.status().severity(), Severity::Good);
        }
    }

    #[test]
    fn closing_the_game_clears_the_claim_once_it_goes_stale() {
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        watch.note_decoded_data();
        assert_eq!(watch.status(), GameStatus::Decoding);

        // The scan sees it go, which settles the verdict underneath; the claim
        // itself is left to expire, because the scan is not trustworthy enough
        // to take it away.
        assert_eq!(watch.observe(false, CAPTURING), GameStatus::Decoding);
        if let Some(stale) = Instant::now().checked_sub(DECODING_TTL + Duration::from_secs(1)) {
            watch.decoded_at = Some(stale);
            assert_eq!(watch.status(), GameStatus::NotRunning);
        }
        // And the next launch is judged clean rather than inheriting anything.
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
    }

    #[test]
    fn a_capture_gap_does_not_condemn_a_watched_session() {
        // Stop, poll a few times while stopped, start again. The line must go
        // quiet and then come back green, never red: this is the sequence a
        // user reported working perfectly in-game while the UI called it dead.
        let mut watch = watching_before_launch(CAPTURING);
        watch.observe(true, CAPTURING);
        for _ in 0..5 {
            assert_eq!(watch.observe(true, STOPPED), GameStatus::CaptureOff);
        }
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
    }

    #[test]
    fn a_launch_inside_a_capture_gap_is_still_condemned() {
        // The distinction that makes the above safe: a session that *started*
        // while capture was off never had its handshake seen, so there is no
        // key for it and saying so is not a guess.
        let mut watch = GameWatch::default();
        assert_eq!(watch.observe(false, STOPPED), GameStatus::NotRunning);
        assert_eq!(watch.observe(true, STOPPED), GameStatus::CaptureOff);
        assert_eq!(
            watch.observe(true, CAPTURING),
            GameStatus::LaunchMissed(MissedLaunch::CaptureStopped)
        );
    }

    #[test]
    fn recheck_before_the_first_poll_invents_nothing() {
        // `start_capture` reports `capturing = false` while the backend comes
        // up, which happens before the first poll. That must not fabricate a
        // presence and flag a game nobody has looked for yet.
        let mut watch = GameWatch::default();
        assert_eq!(watch.recheck(STOPPED), GameStatus::NotRunning);
        assert!(!watch.has_polled());
        assert_eq!(watch.recheck(CAPTURING), GameStatus::NotRunning);
    }

    #[test]
    fn the_startup_toast_fires_on_the_first_poll_only() {
        let mut watch = GameWatch::default();
        let mut detector = FakeDetector { running: true };

        assert!(!watch.has_polled());
        assert_eq!(
            watch.poll(&mut detector, CAPTURING),
            GameStatus::AwaitingLogin
        );
        assert!(watch.has_polled());

        // The game stays up; the toast condition must not come back.
        for _ in 0..5 {
            watch.poll(&mut detector, CAPTURING);
            assert!(watch.has_polled());
        }
    }

    #[test]
    fn polling_goes_through_the_detector() {
        let mut watch = GameWatch::default();
        let mut detector = FakeDetector::default();

        assert_eq!(watch.poll(&mut detector, CAPTURING), GameStatus::NotRunning);
        detector.running = true;
        assert_eq!(
            watch.poll(&mut detector, CAPTURING),
            GameStatus::LaunchCaptured
        );
        detector.running = false;
        assert_eq!(watch.poll(&mut detector, CAPTURING), GameStatus::NotRunning);
    }

    #[test]
    fn the_real_scan_reaches_a_named_process_list() {
        // The one thing `FakeDetector` cannot cover: that a refresh with every
        // expensive switch turned off still yields processes *with names* to
        // match against. If sysinfo ever stops populating `name()` under
        // `ProcessRefreshKind::nothing()`, the feature would silently report
        // "not running" forever and every test above would still pass.
        let mut detector = SystemProcessDetector::new();
        assert!(
            detector.count_matching(|name| !name.is_empty()) > 0,
            "the process scan returned no named processes"
        );
        // Whether the game itself is running is deliberately not asserted: a
        // developer may well have Genshin open while running the tests.
    }

    // -- key recovery ------------------------------------------------------------

    /// A watch on a game it saw launch with capture running.
    fn launched() -> GameWatch {
        let mut watch = watching_before_launch(CAPTURING);
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
        watch
    }

    /// Pretend `at` happened `ago` in the past, if the clock allows it.
    fn backdate(at: &mut Option<Instant>, ago: Duration) -> bool {
        match Instant::now().checked_sub(ago) {
            Some(past) => {
                *at = Some(past);
                true
            }
            None => false,
        }
    }

    #[test]
    fn login_traffic_alone_does_not_claim_decrypting() {
        // 05:11 on 2026-10-04: the reconnect's dispatch-key messages decoded,
        // the line went green "data decrypting", and nothing else decoded for
        // an hour and three quarters.
        let mut watch = launched();
        assert!(!watch.note_login_traffic());
        assert_eq!(watch.status(), GameStatus::LaunchCaptured);
    }

    #[test]
    fn a_login_whose_key_never_arrives_is_flagged() {
        let mut watch = launched();
        watch.note_login_traffic();
        assert_eq!(watch.status(), GameStatus::LaunchCaptured, "still in grace");

        if backdate(
            &mut watch.awaiting_key_since,
            KEY_RECOVERY_GRACE + Duration::from_secs(1),
        ) {
            assert_eq!(watch.status(), GameStatus::KeyLost);
            assert_eq!(watch.status().severity(), Severity::Problem);
            // The poll keeps it up: it is not a process verdict.
            assert_eq!(watch.observe(true, CAPTURING), GameStatus::KeyLost);
        }
    }

    #[test]
    fn a_key_search_given_up_on_is_flagged_at_once() {
        let mut watch = launched();
        watch.note_login_traffic();
        assert!(watch.note_key_recovery_failed());
        assert_eq!(watch.status(), GameStatus::KeyLost);
        assert!(!watch.note_key_recovery_failed(), "no churn on repeats");
    }

    #[test]
    fn a_normal_login_never_shows_the_problem() {
        let mut watch = launched();
        watch.note_login_traffic();
        assert!(watch.note_decoded_data());
        assert_eq!(watch.status(), GameStatus::Decoding);

        // Long after, with the claim expired, it is green, not red.
        if backdate(
            &mut watch.decoded_at,
            DECODING_TTL + KEY_RECOVERY_GRACE + Duration::from_secs(1),
        ) {
            assert_eq!(watch.status(), GameStatus::LaunchCaptured);
        }
    }

    #[test]
    fn session_data_clears_the_problem() {
        let mut watch = launched();
        watch.note_login_traffic();
        watch.note_key_recovery_failed();
        assert!(watch.note_decoded_data());
        assert_eq!(watch.status(), GameStatus::Decoding);
    }

    #[test]
    fn a_new_connection_is_judged_afresh() {
        let mut watch = launched();
        watch.note_login_traffic();
        watch.note_key_recovery_failed();
        assert_eq!(watch.status(), GameStatus::KeyLost);

        assert!(watch.note_session_reset());
        assert_eq!(watch.status(), GameStatus::LaunchCaptured);

        // And a reset ends the previous connection's decrypting claim.
        watch.note_decoded_data();
        watch.note_session_reset();
        assert_eq!(watch.status(), GameStatus::LaunchCaptured);
    }

    #[test]
    fn closing_the_game_or_stopping_capture_outranks_the_problem() {
        let mut watch = launched();
        watch.note_login_traffic();
        watch.note_key_recovery_failed();

        assert_eq!(watch.observe(true, STOPPED), GameStatus::CaptureOff);
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::KeyLost);
        assert_eq!(watch.observe(false, CAPTURING), GameStatus::NotRunning);
        // A relaunch starts clean.
        assert_eq!(watch.observe(true, CAPTURING), GameStatus::LaunchCaptured);
    }

    #[test]
    fn every_state_has_its_own_line_and_explanation() {
        let states = [
            GameStatus::NotRunning,
            GameStatus::LaunchCaptured,
            GameStatus::Decoding,
            GameStatus::LaunchMissed(MissedLaunch::AlreadyRunning),
            GameStatus::LaunchMissed(MissedLaunch::CaptureStopped),
            GameStatus::KeyLost,
        ];
        for (i, state) in states.iter().enumerate() {
            assert!(state.label().starts_with("Game: "), "{state:?}");
            assert!(!state.tooltip().is_empty(), "{state:?}");
            for other in &states[i + 1..] {
                assert_ne!(state.label(), other.label());
                assert_ne!(state.tooltip(), other.tooltip());
            }
        }
        assert!(GameStatus::KeyLost.label().contains("relog"));
        assert!(GameStatus::KeyLost.tooltip().contains("kept"));

        // The two unrecoverable states must name the fix, since that is the
        // entire point of the line.
        for cause in [MissedLaunch::AlreadyRunning, MissedLaunch::CaptureStopped] {
            let state = GameStatus::LaunchMissed(cause);
            assert!(state.label().contains("restart Genshin"), "{state:?}");
            assert_eq!(state.severity(), Severity::Problem);
            // ...but the tooltip must not present that as the only way out.
            // The session key comes from the connect-to-server exchange, not
            // from the executable starting, so a client still sitting on the
            // title screen recovers by simply going in. Telling that user to
            // close and relaunch Genshin costs them minutes for nothing, and
            // the quickstart explicitly blesses starting Irminsul second.
            assert!(state.tooltip().contains("world"), "{state:?}");
        }
    }
}
