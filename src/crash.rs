//! Evidence for a run that ends without saying why.
//!
//! The log of 2026-10-06 stopped fourteen and a half hours into a session: no
//! shutdown lines, no panic line, and nothing from Windows Error Reporting.
//! Three things were missing, and this module adds them.
//!
//! - **A crash report that cannot be lost.** The panic hook used to log only
//!   through the non-blocking tracing appender, whose worker thread never gets
//!   to write the line when the panic ends in an abort (a panic inside an
//!   `extern "C"` callback, during unwinding, or in a `Drop`). Panics now go to
//!   `crash.log` first, with a blocking write. On Windows, `native.rs` adds what
//!   no panic hook sees: native crashes (an access violation, a stack overflow,
//!   a fault inside a driver) and an `ExitProcess` that skipped Irminsul's
//!   shutdown, each with a minidump.
//! - **A clean-exit marker.** Every orderly shutdown ends `latest.log` with a
//!   [`CLEAN_EXIT_MARKER`] line ([`mark_clean_exit`]), so a log without one
//!   ended some other way.
//! - **A look back at startup.** [`examine_previous_run`] reads the previous
//!   run's log and `crash.log` and says how that run ended. A run that ended
//!   abruptly, or with a crash report, has its log kept longer (`main.rs`) and
//!   is mentioned once in the UI.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use chrono::{DateTime, Datelike, Local, Timelike, Utc};

#[cfg(windows)]
mod native;

/// The file every crash report is appended to, in the log directory.
pub const CRASH_LOG: &str = "crash.log";

/// `crash.log` past this size is moved aside to [`CRASH_LOG_OLD`] at startup,
/// replacing the one there, so a crash loop cannot fill the disk.
const CRASH_LOG_LIMIT: u64 = 1024 * 1024;
const CRASH_LOG_OLD: &str = "crash.log.old";

/// In the first line of every run's log. A previous log whose first line lacks
/// it was written by a build that did not mark its exits, and says nothing
/// about how that run ended: without this, the first start after an update
/// would report the old version's perfectly normal exit as abrupt.
pub const RUN_START_MARKER: &str = "[run-start]";

/// In the last line every orderly shutdown writes to `latest.log`.
pub const CLEAN_EXIT_MARKER: &str = "[clean-exit]";

/// How much of the end of the previous log is searched for the marker and the
/// time of its last line. The marker is written after the last thing the
/// shutdown logs, so only lines still queued in the tracing worker can follow
/// it.
const TAIL_BYTES: u64 = 256 * 1024;

/// How much earlier than the run's first log line a crash report's file time
/// may be and still belong to that run (see [`classify`]).
const CLOCK_SLACK: chrono::TimeDelta = chrono::TimeDelta::seconds(2);

struct Paths {
    latest_log: PathBuf,
    crash_log: PathBuf,
}

static PATHS: OnceLock<Paths> = OnceLock::new();

/// Set by the first [`mark_clean_exit`]. `native.rs` reads it to tell an exit
/// Irminsul chose from one something else forced.
static CLEAN_EXIT: AtomicBool = AtomicBool::new(false);

/// Start this run's `latest.log`, opened for appending, and write its first
/// line.
///
/// Append mode is load bearing: [`mark_clean_exit`] writes its marker through a
/// second handle, and a handle that writes at its own offset (what
/// `File::create` returns) would write its next line over the marker.
pub fn create_run_log(log_dir: &Path) -> std::io::Result<File> {
    let path = log_dir.join("latest.log");
    // Truncates whatever rotation failed to move away.
    File::create(&path)?;
    let mut file = OpenOptions::new().append(true).open(&path)?;
    let line = log_line(
        "INFO",
        &format!(
            "{RUN_START_MARKER} Irminsul {} (pid {})",
            env!("CARGO_PKG_VERSION"),
            std::process::id()
        ),
    );
    file.write_all(line.as_bytes())?;
    Ok(file)
}

/// Start recording crashes into `log_dir`. Called once, after tracing is up.
pub fn install(log_dir: &Path) {
    let paths = PATHS.get_or_init(|| Paths {
        latest_log: log_dir.join("latest.log"),
        crash_log: log_dir.join(CRASH_LOG),
    });
    if std::fs::metadata(&paths.crash_log).is_ok_and(|metadata| metadata.len() > CRASH_LOG_LIMIT) {
        let _ = std::fs::rename(&paths.crash_log, log_dir.join(CRASH_LOG_OLD));
    }
    install_panic_hook();
    #[cfg(windows)]
    native::install(log_dir, &paths.crash_log);
}

/// End `latest.log` with the clean-exit marker. Only the first call writes.
///
/// A blocking write of its own rather than a tracing line: the update path
/// starts the replacement process before this one's tracing worker has
/// flushed, and the replacement reads this log at startup.
pub fn mark_clean_exit(reason: &str) {
    if CLEAN_EXIT.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(paths) = PATHS.get() else {
        return;
    };
    let line = log_line("INFO", &format!("{CLEAN_EXIT_MARKER} {reason}"));
    if let Ok(mut file) = OpenOptions::new().append(true).open(&paths.latest_log) {
        let _ = file.write_all(line.as_bytes());
        let _ = file.sync_all();
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn clean_exit_marked() -> bool {
    CLEAN_EXIT.load(Ordering::SeqCst)
}

/// One line in the shape tracing's default format writes, so the lines this
/// module writes itself read like the rest of the log.
fn log_line(level: &str, message: &str) -> String {
    format!(
        "{} {level:>5} irminsul::crash: {message}\n",
        Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ")
    )
}

/// The first line of a `crash.log` report. Allocation free, because the native
/// crash handler writes it from a process whose heap may be what broke.
fn write_report_header(out: &mut impl std::fmt::Write, kind: &str) {
    let now = Utc::now();
    let _ = writeln!(
        out,
        "==== {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z {kind} | Irminsul {} | pid {} ====",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );
}

/// Append to `crash.log` and push it to disk before returning.
///
/// The file is opened for each report and never held, so nothing is shared
/// with whatever panicked -- not even the logger.
fn append_crash_report(text: &str) {
    let Some(paths) = PATHS.get() else {
        return;
    };
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.crash_log)
    {
        let _ = file.write_all(text.as_bytes());
        let _ = file.sync_data();
    }
}

/// Route panics into `crash.log` and the log file.
///
/// Release builds set `windows_subsystem = "windows"`, so the default hook's
/// stderr goes nowhere and every panic in this app used to be invisible --
/// including panics inside egui's own update loop, which take the window with
/// them.
///
/// `--replay-export` installs this alone: without [`install`] there is no
/// `crash.log` to write, so a replay never touches the data directory.
pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
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
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");

        // On disk before anything else is tried. A panic that ends in an abort
        // (inside an `extern "C"` callback, during unwinding, in a `Drop`)
        // never lets the tracing worker write the line below, and capturing
        // the backtrace takes a lock of its own.
        let mut report = String::new();
        write_report_header(&mut report, "panic");
        let _ = writeln!(
            report,
            "thread '{thread_name}' panicked at {location}:\n{message}"
        );
        append_crash_report(&report);

        let backtrace = std::backtrace::Backtrace::force_capture();
        append_crash_report(&format!("backtrace:\n{backtrace}\n"));

        tracing::error!("panic in thread '{thread_name}' at {location}: {message}\n{backtrace}");

        // Debug builds keep their console, so leave the usual output in place.
        default_hook(info);
    }));
}

/// How the previous run ended, as far as its log and `crash.log` can say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEnd {
    /// No previous log, or one written by a build that did not mark its
    /// exits.
    Unknown,
    /// It shut down normally, or Windows ended the session.
    Clean,
    /// No clean exit, and `crash.log` was written to while it ran.
    Crashed { last_line: Option<DateTime<Utc>> },
    /// No clean exit and no crash report: killed from outside, or a crash
    /// nothing in the process lived to report.
    Abrupt { last_line: Option<DateTime<Utc>> },
}

impl RunEnd {
    /// What the previous log's rotated name gets, so a log worth keeping is
    /// pruned on a budget of its own (`main.rs::prune_rotated`).
    pub fn kept_suffix(&self) -> &'static str {
        match self {
            RunEnd::Crashed { .. } => KEPT_CRASHED_SUFFIX,
            RunEnd::Abrupt { .. } => KEPT_ABRUPT_SUFFIX,
            RunEnd::Unknown | RunEnd::Clean => "",
        }
    }
}

pub const KEPT_ABRUPT_SUFFIX: &str = "-abrupt";
pub const KEPT_CRASHED_SUFFIX: &str = "-crashed";

/// Read how the run that wrote `latest.log` ended. Call before rotation moves
/// that log aside.
pub fn examine_previous_run(log_dir: &Path) -> RunEnd {
    let Ok(mut file) = File::open(log_dir.join("latest.log")) else {
        return RunEnd::Unknown;
    };
    let head = read_head(&mut file, 4096);
    let tail = read_tail(&mut file, TAIL_BYTES);
    // Empty is no report: `native.rs` creates the file at startup, so its
    // time alone would date a report that was never written into that run.
    let crash_log_modified = std::fs::metadata(log_dir.join(CRASH_LOG))
        .ok()
        .filter(|metadata| metadata.len() > 0)
        .and_then(|metadata| metadata.modified().ok());
    classify(&head, &tail, crash_log_modified)
}

/// The pure half of [`examine_previous_run`].
fn classify(head: &str, tail: &str, crash_log_modified: Option<SystemTime>) -> RunEnd {
    let first_line = head.lines().next().unwrap_or_default();
    if !first_line.contains(RUN_START_MARKER) {
        return RunEnd::Unknown;
    }
    if tail.contains(CLEAN_EXIT_MARKER) {
        return RunEnd::Clean;
    }

    let started = line_time(first_line);
    // Backtraces and other multi-line messages put lines without a time at
    // the end; the last line that has one is when the log went quiet.
    let last_line = tail.lines().rev().find_map(line_time).or(started);
    // File times come from a coarser clock than the log's timestamps and can
    // land a few milliseconds before the run's first line when the report is
    // written right after it starts, so allow a little slack. A report from
    // an earlier run can't be that close to this run's start.
    let reported = match (started, crash_log_modified) {
        (Some(started), Some(modified)) => DateTime::<Utc>::from(modified) + CLOCK_SLACK >= started,
        _ => false,
    };
    if reported {
        RunEnd::Crashed { last_line }
    } else {
        RunEnd::Abrupt { last_line }
    }
}

/// The time at the start of a log line, if it has one.
fn line_time(line: &str) -> Option<DateTime<Utc>> {
    let stamp = line.split_whitespace().next()?;
    DateTime::parse_from_rfc3339(stamp)
        .ok()
        .map(|time| time.with_timezone(&Utc))
}

fn read_head(file: &mut File, limit: u64) -> String {
    let mut buf = Vec::new();
    let _ = Read::take(&mut *file, limit).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// The last `limit` bytes. The first line may be cut, which `classify`
/// tolerates: it only looks for a marker and for well-formed times.
fn read_tail(file: &mut File, limit: u64) -> String {
    let Ok(len) = file.seek(SeekFrom::End(0)) else {
        return String::new();
    };
    if file
        .seek(SeekFrom::Start(len.saturating_sub(limit)))
        .is_err()
    {
        return String::new();
    }
    let mut buf = Vec::new();
    let _ = Read::take(&mut *file, limit).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// What may have ended a run that left no trace, in the WARN line.
#[cfg(windows)]
const ABRUPT_CAUSES: &str = "killed from outside, or a crash Windows didn't report";
/// Without `native.rs` a system shutdown leaves no marker either.
#[cfg(not(windows))]
const ABRUPT_CAUSES: &str =
    "killed from outside, the system shut down while it ran, or a crash it didn't report";

/// Log how the previous run ended, and return the notice for the UI when it
/// did not end cleanly. `kept_log` is where rotation moved its log.
pub fn report_previous_run(end: &RunEnd, kept_log: Option<&Path>) -> Option<String> {
    let kept = kept_log
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "nowhere (it could not be moved)".to_string());
    match end {
        RunEnd::Unknown => None,
        RunEnd::Clean => {
            tracing::info!("the previous run exited cleanly");
            None
        }
        RunEnd::Abrupt { last_line } => {
            tracing::warn!(
                "the previous run ended abruptly at {} without a crash report ({ABRUPT_CAUSES}); \
                 its log is kept as {kept}",
                long_time(*last_line)
            );
            Some(format!(
                "Irminsul stopped unexpectedly last time ({}) and left no crash report. Its log \
                 was kept as {kept}.",
                short_time(*last_line)
            ))
        }
        RunEnd::Crashed { last_line } => {
            tracing::warn!(
                "the previous run did not shut down cleanly (its last log line is from {}); \
                 {CRASH_LOG} has a report from it, and its log is kept as {kept}",
                long_time(*last_line)
            );
            Some(format!(
                "Irminsul crashed last time ({}). The report is in {CRASH_LOG}, next to its log \
                 ({kept}).",
                short_time(*last_line)
            ))
        }
    }
}

fn long_time(time: Option<DateTime<Utc>>) -> String {
    match time {
        Some(time) => format!(
            "{} ({})",
            time.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S %:z"),
            time.format("%H:%M:%SZ")
        ),
        None => "an unknown time".to_string(),
    }
}

fn short_time(time: Option<DateTime<Utc>>) -> String {
    match time {
        Some(time) => time
            .with_timezone(&Local)
            .format("%b %-d, %H:%M")
            .to_string(),
        None => "time unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const START: &str =
        "2026-10-05T17:15:11.851244Z  INFO irminsul::crash: [run-start] Irminsul 0.2.2 (pid 7)";

    fn time(stamp: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(stamp).unwrap().into()
    }

    #[test]
    fn a_log_from_a_build_that_marks_no_exits_says_nothing() {
        // The first start after updating from such a build must not call that
        // build's normal exit abrupt.
        let head = "2026-10-05T17:15:11.851244Z  INFO irminsul: Tracing initialized and logging \
                    to file.\n";
        assert_eq!(classify(head, head, None), RunEnd::Unknown);
        assert_eq!(classify("", "", None), RunEnd::Unknown);
    }

    #[test]
    fn a_log_that_ends_with_the_marker_was_a_clean_exit() {
        let tail = "2026-10-06T07:39:41.6Z  INFO irminsul::monitor: sniffer thread exiting\n\
                    2026-10-06T07:39:41.7Z  INFO irminsul::crash: [clean-exit] window closed\n\
                    2026-10-06T07:39:41.8Z  INFO irminsul: relaunched after update\n";
        assert_eq!(classify(START, tail, None), RunEnd::Clean);
    }

    #[test]
    fn a_log_that_just_stops_ended_abruptly_at_its_last_line() {
        // The 2026-10-06 log: minute stats, then nothing.
        let tail = "ats (last minute) frames=879\n\
                    2026-10-06T07:39:41.635185Z  INFO irminsul::monitor: capture stats (last \
                    minute) frames=3648\n";
        assert_eq!(
            classify(START, tail, None),
            RunEnd::Abrupt {
                last_line: Some(time("2026-10-06T07:39:41.635185Z"))
            }
        );
    }

    #[test]
    fn the_last_line_is_the_last_one_with_a_time() {
        let tail = "2026-10-06T07:39:41Z ERROR irminsul: something\n   0: frame\n   1: frame\n";
        assert_eq!(
            classify(START, tail, None),
            RunEnd::Abrupt {
                last_line: Some(time("2026-10-06T07:39:41Z"))
            }
        );
        // Nothing after the first line: the start is all there is.
        assert_eq!(
            classify(START, START, None),
            RunEnd::Abrupt {
                last_line: Some(time("2026-10-05T17:15:11.851244Z"))
            }
        );
    }

    #[test]
    fn a_crash_report_written_during_the_run_makes_it_a_crash() {
        let started: SystemTime = time("2026-10-05T17:15:11.851244Z").into();
        let tail = "2026-10-06T07:39:41Z  INFO irminsul::monitor: capture stats\n";
        let last_line = Some(time("2026-10-06T07:39:41Z"));

        let during = started + Duration::from_secs(3600);
        assert_eq!(
            classify(START, tail, Some(during)),
            RunEnd::Crashed { last_line }
        );

        // Written right after the start, its file time can read a few
        // milliseconds before the log's clock: still this run.
        let just_after_start = started - Duration::from_millis(15);
        assert_eq!(
            classify(START, tail, Some(just_after_start)),
            RunEnd::Crashed { last_line }
        );

        // A report from an earlier run says nothing about this one.
        let before = started - Duration::from_secs(60);
        assert_eq!(
            classify(START, tail, Some(before)),
            RunEnd::Abrupt { last_line }
        );
    }

    #[test]
    fn only_runs_that_did_not_exit_cleanly_keep_their_logs_longer() {
        assert_eq!(RunEnd::Unknown.kept_suffix(), "");
        assert_eq!(RunEnd::Clean.kept_suffix(), "");
        assert_eq!(
            RunEnd::Abrupt { last_line: None }.kept_suffix(),
            KEPT_ABRUPT_SUFFIX
        );
        assert_eq!(
            RunEnd::Crashed { last_line: None }.kept_suffix(),
            KEPT_CRASHED_SUFFIX
        );
    }

    #[test]
    fn the_run_log_starts_with_the_marker_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("latest.log"),
            "left over by a failed rotation\n",
        )
        .unwrap();

        let mut file = create_run_log(dir.path()).unwrap();
        // A second handle appends, as `mark_clean_exit`'s does ...
        let mut other = OpenOptions::new()
            .append(true)
            .open(dir.path().join("latest.log"))
            .unwrap();
        other.write_all(b"from the other handle\n").unwrap();
        // ... and the first one's next line lands after it, not over it.
        file.write_all(b"from the log handle\n").unwrap();

        let text = std::fs::read_to_string(dir.path().join("latest.log")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].contains(RUN_START_MARKER), "{text}");
        assert!(line_time(lines[0]).is_some(), "{text}");
        assert_eq!(
            &lines[1..],
            ["from the other handle", "from the log handle"]
        );
    }

    #[test]
    fn the_previous_run_is_read_from_the_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(examine_previous_run(dir.path()), RunEnd::Unknown);

        // A run long enough that its start is far outside the tail.
        let mut log = create_run_log(dir.path()).unwrap();
        let filler = "2026-10-06T07:00:00Z  INFO irminsul::monitor: capture stats\n";
        for _ in 0..(2 * TAIL_BYTES as usize / filler.len()) {
            log.write_all(filler.as_bytes()).unwrap();
        }
        log.write_all(b"2026-10-06T07:39:41Z  INFO irminsul::monitor: last words\n")
            .unwrap();
        let abrupt = RunEnd::Abrupt {
            last_line: Some(time("2026-10-06T07:39:41Z")),
        };
        assert_eq!(examine_previous_run(dir.path()), abrupt);

        // The empty crash.log every start creates is not a report.
        File::create(dir.path().join(CRASH_LOG)).unwrap();
        assert_eq!(examine_previous_run(dir.path()), abrupt);

        std::fs::write(dir.path().join(CRASH_LOG), "==== a report ====\n").unwrap();
        assert!(matches!(
            examine_previous_run(dir.path()),
            RunEnd::Crashed { .. }
        ));

        log.write_all(log_line("INFO", "[clean-exit] window closed").as_bytes())
            .unwrap();
        assert_eq!(examine_previous_run(dir.path()), RunEnd::Clean);
    }

    #[test]
    fn the_report_header_is_one_line() {
        let mut header = String::new();
        write_report_header(&mut header, "panic");
        assert!(header.starts_with("==== "), "{header}");
        assert!(header.ends_with("====\n"), "{header}");
        assert_eq!(header.lines().count(), 1, "{header}");
        assert!(
            header.contains(&format!("pid {}", std::process::id())),
            "{header}"
        );
    }

    #[test]
    fn the_notice_and_warning_only_come_for_an_unclean_end() {
        assert_eq!(report_previous_run(&RunEnd::Unknown, None), None);
        assert_eq!(report_previous_run(&RunEnd::Clean, None), None);

        let kept = Path::new("log/2026-10-06_14-39-41-abrupt.log");
        let notice = report_previous_run(&RunEnd::Abrupt { last_line: None }, Some(kept)).unwrap();
        assert!(
            notice.contains("2026-10-06_14-39-41-abrupt.log"),
            "{notice}"
        );
        let notice = report_previous_run(&RunEnd::Crashed { last_line: None }, None).unwrap();
        assert!(notice.contains(CRASH_LOG), "{notice}");
    }
}
