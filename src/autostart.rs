//! "Start Irminsul on startup".
//!
//! On Windows this is a Task Scheduler task, [`TASK_NAME`] in the root folder,
//! that starts Irminsul at the user's sign-in with highest privileges. It used
//! to be a `HKCU\...\CurrentVersion\Run` value, which never did anything: the
//! executable's manifest requires administrator rights (`build.rs`), and
//! Windows silently skips Run entries that need elevation at sign-in. A logon
//! task with `RunLevel` `HighestAvailable` starts elevated without a UAC
//! prompt. Registering one needs elevation, which Irminsul always has. The old
//! Run value is moved to a task on the first launch that finds it.
//!
//! The checkbox shows what Task Scheduler holds rather than a saved
//! preference. That is read on a background thread after every change, when
//! the window regains focus, and otherwise at most every [`REFRESH_INTERVAL`] --
//! never per frame. When the task starts a different copy of Irminsul, or a
//! file that is gone, an amber icon next to the checkbox says so and offers to
//! point it at the running copy.
//!
//! Everything that builds or reads text is a plain function, tested on every
//! platform; only `windows_impl` touches the system. Elsewhere the checkbox
//! fails the way it always has.

// The text helpers are only called from `windows_impl` outside the tests.
#![cfg_attr(not(windows), allow(dead_code))]

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use egui::{Button, Color32, Context, Id, Label, Modal, RichText, Ui};
use egui_notify::Toasts;

/// The task's name in Task Scheduler's root folder.
pub const TASK_NAME: &str = "Irminsul";

/// How long after sign-in the task waits before starting Irminsul, so the
/// desktop and the tray are up first.
const LOGON_DELAY: &str = "PT15S";

/// The longest a shown state may go unchecked while the window is in use.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Focus regained sooner than this after the last read does not read again.
const FOCUS_REFRESH_MIN: Duration = Duration::from_secs(2);

const CHECKBOX_LABEL: &str = "Start Irminsul on startup";

/// Escape text for an XML element's content.
///
/// `"` and `'` only need escaping inside attribute values, and leaving them
/// alone keeps a quoted `Command` readable in Task Scheduler's own XML view.
fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Undo XML escaping: the five named entities and numeric character references.
/// Anything unrecognised is kept as written.
fn xml_unescape(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        plain.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let decoded = after.find(';').and_then(|semi| {
            let entity = &after[..semi];
            let c = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => {
                    if let Some(hex) = entity
                        .strip_prefix("#x")
                        .or_else(|| entity.strip_prefix("#X"))
                    {
                        u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                    } else {
                        entity
                            .strip_prefix('#')
                            .and_then(|decimal| decimal.parse().ok())
                            .and_then(char::from_u32)
                    }
                }
            };
            c.map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                plain.push(c);
                rest = &after[semi + 1..];
            }
            None => {
                plain.push('&');
                rest = after;
            }
        }
    }
    plain.push_str(rest);
    plain
}

/// The contents of every `<name …>…</name>` element in `xml`, in order; a
/// self-closing `<name/>` is empty.
///
/// Enough for the XML Task Scheduler writes, which has no CDATA, no comments
/// and no element nested in one of the same name. Not a general XML parser.
fn elements<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after_name = &rest[start + open.len()..];
        // `<Settings` must not match `<SettingsFoo`.
        let ends_name = after_name
            .chars()
            .next()
            .is_some_and(|c| c == '>' || c == '/' || c.is_whitespace());
        if !ends_name {
            rest = after_name;
            continue;
        }
        let Some(tag_end) = after_name.find('>') else {
            break;
        };
        if after_name[..tag_end].ends_with('/') {
            found.push("");
            rest = &after_name[tag_end + 1..];
            continue;
        }
        let body = &after_name[tag_end + 1..];
        let Some(end) = body.find(&close) else {
            break;
        };
        found.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    found
}

/// The contents of the first `<name>` element in `xml`.
fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    elements(xml, name).into_iter().next()
}

/// An `xs:boolean`.
fn xml_bool(text: &str) -> Option<bool> {
    match text.trim() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

/// The task definition for starting `exe` at `user_id`'s sign-in.
///
/// - `HighestAvailable` with an `InteractiveToken`: elevated, on the user's
///   desktop, without a stored password or a UAC prompt.
/// - `ExecutionTimeLimit` `PT0S`: no limit. The default of 72 hours would
///   stop Irminsul three days into a session.
/// - Batteries never stop or prevent it, and a second trigger while it runs
///   is ignored (`IgnoreNew`); Irminsul is single-instance anyway.
/// - `Priority` 5 is a normal-priority process. Task Scheduler's default of 7
///   would start the capture below normal priority, behind the game.
/// - The command is quoted; the working directory is the exe's folder, where
///   a debug build keeps its `irminsul-data` (release builds use `%APPDATA%`).
pub fn task_xml(exe: &str, working_dir: &str, user_id: &str) -> String {
    let command = xml_escape(&format!("\"{exe}\""));
    let user_id = xml_escape(user_id);
    let working_dir = if working_dir.is_empty() {
        String::new()
    } else {
        format!(
            "\n      <WorkingDirectory>{}</WorkingDirectory>",
            xml_escape(working_dir)
        )
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Starts Irminsul when you sign in. Set by its "{CHECKBOX_LABEL}" option.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user_id}</UserId>
      <Delay>{LOGON_DELAY}</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user_id}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>{working_dir}
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// `text` as UTF-16 LE with a byte order mark: the only encoding
/// `schtasks /Create /XML` reads non-ASCII paths from correctly.
pub fn utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// Decode a task definition: the UTF-16 file in Task Scheduler's store, or
/// what `schtasks /Query /XML` prints, which is 8-bit when piped despite its
/// `encoding="UTF-16"` declaration.
pub fn decode_task_xml(bytes: &[u8]) -> String {
    fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
        let units = bytes.chunks_exact(2).map(|pair| unit([pair[0], pair[1]]));
        char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }

    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        // UTF-16 LE without a BOM: `<` followed by a zero byte.
        [first, 0, ..] if *first != 0 => utf16(bytes, u16::from_le_bytes),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// What a registered task does, as far as this feature cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredTask {
    /// The program it runs, as written in `Exec/Command` (quotes included).
    pub command: Option<String>,
    /// Whether it will run at sign-in: the task is enabled, and so is one of
    /// its logon triggers.
    pub enabled: bool,
}

/// Read a task definition (see [`decode_task_xml`] for the bytes).
pub fn parse_task_xml(xml: &str) -> RegisteredTask {
    // Disabling a task in Task Scheduler sets this one; elements left out
    // default to true.
    let task_enabled = element(xml, "Settings")
        .and_then(|settings| element(settings, "Enabled"))
        .and_then(xml_bool)
        .unwrap_or(true);
    let logon_enabled = element(xml, "Triggers").is_some_and(|triggers| {
        elements(triggers, "LogonTrigger").iter().any(|trigger| {
            element(trigger, "Enabled")
                .and_then(xml_bool)
                .unwrap_or(true)
        })
    });
    let command = element(xml, "Actions")
        .and_then(|actions| element(actions, "Exec"))
        .and_then(|exec| element(exec, "Command"))
        .map(|command| xml_unescape(command.trim()))
        .filter(|command| !command.is_empty());

    RegisteredTask {
        command,
        enabled: task_enabled && logon_enabled,
    }
}

/// `path` without surrounding whitespace and quotes (a `Command` may be
/// quoted) and without a `\\?\` verbatim prefix, as `canonicalize` returns.
pub fn clean_exe_path(path: &str) -> String {
    let path = path.trim().trim_matches('"').trim();
    if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(local) = path.strip_prefix(r"\\?\") {
        local.to_string()
    } else {
        path.to_string()
    }
}

/// Whether two exe paths name the same file, as far as their text can tell:
/// quotes, `\\?\` prefixes, slash direction and case aside (Windows paths are
/// case-insensitive). The caller canonicalizes first where the files exist,
/// which settles `..`, 8.3 names and links.
pub fn same_exe(a: &str, b: &str) -> bool {
    fn comparable(path: &str) -> String {
        clean_exe_path(&path.replace('/', "\\")).to_lowercase()
    }
    comparable(a) == comparable(b)
}

/// Why the startup task deserves a second look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupWarning {
    /// It starts an Irminsul other than the running one.
    OtherCopy,
    /// It starts a file that is not there any more.
    MissingFile,
}

impl StartupWarning {
    pub fn title(self) -> &'static str {
        match self {
            StartupWarning::OtherCopy => "Startup opens another copy",
            StartupWarning::MissingFile => "Startup points to a file that no longer exists",
        }
    }
}

/// Whether to warn about the startup task, given whether it runs at sign-in,
/// the exe it starts (`None` when it names none) and whether that file
/// exists.
pub fn startup_warning(
    enabled: bool,
    registered: Option<&str>,
    current: &str,
    registered_exists: bool,
) -> Option<StartupWarning> {
    let registered = registered?;
    if !enabled || same_exe(registered, current) {
        None
    } else if registered_exists {
        Some(StartupWarning::OtherCopy)
    } else {
        Some(StartupWarning::MissingFile)
    }
}

/// What was last read from Task Scheduler.
#[derive(Clone, Debug, Default)]
struct Snapshot {
    /// The task exists and runs at sign-in.
    enabled: bool,
    warning: Option<StartupWarning>,
    /// The exe the task starts, unquoted, when there is a task.
    registered: Option<String>,
    /// When that file was last modified, for telling copies apart.
    registered_modified: Option<String>,
    /// The running exe.
    current: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Job {
    /// Move an old Run entry to a task, then read the state.
    Migrate,
    /// Read the state.
    Refresh,
    /// Register the task for the running exe.
    Enable,
    /// Remove the task.
    Disable,
    /// Register the task for the running exe instead of another copy.
    Repoint,
}

impl Job {
    /// Whether the job changes the task, during which the checkbox waits.
    fn changes(self) -> bool {
        !matches!(self, Job::Refresh)
    }
}

struct JobResult {
    job: Job,
    /// For [`Job::Migrate`], the Run entry that was moved, if there was one.
    outcome: Result<Option<String>, String>,
    snapshot: Snapshot,
}

#[cfg(windows)]
fn run(job: Job) -> JobResult {
    windows_impl::run(job)
}

#[cfg(not(windows))]
fn run(job: Job) -> JobResult {
    let outcome = match job {
        Job::Migrate | Job::Refresh => Ok(None),
        Job::Enable | Job::Disable | Job::Repoint => {
            Err("Start on startup is only supported on Windows".to_string())
        }
    };
    JobResult {
        job,
        outcome,
        snapshot: Snapshot::default(),
    }
}

/// The checkbox, its warning and its modal, with the state behind them.
pub struct Startup {
    ctx: Context,
    snapshot: Option<Snapshot>,
    job: Option<(Job, Receiver<JobResult>)>,
    checked_at: Option<Instant>,
    was_focused: bool,
    modal_open: bool,
}

impl Startup {
    /// On Windows, also moves an old Run entry to a task and reads the state.
    pub fn new(ctx: &Context) -> Self {
        let mut startup = Self {
            ctx: ctx.clone(),
            snapshot: None,
            job: None,
            checked_at: None,
            was_focused: false,
            modal_open: false,
        };
        if cfg!(windows) {
            startup.start(Job::Migrate);
        }
        startup
    }

    /// Collect a finished job into `saved_on`, and read the state again when
    /// the window regains focus or the last read is [`REFRESH_INTERVAL`] old.
    /// Cheap: called every frame.
    pub fn poll(&mut self, ctx: &Context, saved_on: &mut bool, toasts: &mut Toasts) {
        if let Some((_, rx)) = &self.job {
            match rx.try_recv() {
                Ok(result) => {
                    self.job = None;
                    self.apply(result, saved_on, toasts);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.job = None;
                    tracing::error!("the startup task job ended without an answer");
                }
            }
        }

        let focused = ctx.input(|input| input.focused);
        let regained = focused && !self.was_focused;
        self.was_focused = focused;

        if !cfg!(windows) || self.job.is_some() {
            return;
        }
        let age = self.checked_at.map(|at| at.elapsed());
        let stale = age.is_none_or(|age| age >= REFRESH_INTERVAL);
        let refocused = regained && age.is_some_and(|age| age >= FOCUS_REFRESH_MIN);
        if stale || refocused {
            self.start(Job::Refresh);
        }
    }

    fn start(&mut self, job: Job) {
        let (tx, rx) = mpsc::channel();
        let ctx = self.ctx.clone();
        let spawned = thread::Builder::new()
            .name("startup-task".to_string())
            .spawn(move || {
                let _ = tx.send(run(job));
                ctx.request_repaint();
            });
        match spawned {
            // Replaces a pending refresh, whose answer is then dropped. A
            // change never replaces a change: the controls wait for it.
            Ok(_) => self.job = Some((job, rx)),
            Err(e) => tracing::error!("could not start the startup task job: {e}"),
        }
    }

    fn apply(&mut self, result: JobResult, saved_on: &mut bool, toasts: &mut Toasts) {
        let JobResult {
            job,
            outcome,
            snapshot,
        } = result;

        match (job, outcome) {
            (Job::Migrate, Ok(Some(old))) => tracing::info!(
                "moved Start on startup from the Run entry ({old}) to the {TASK_NAME} scheduled task"
            ),
            (Job::Migrate, Err(e)) => {
                tracing::error!("could not move Start on startup to Task Scheduler: {e}");
                toasts.error("Could not move Start on startup to Task Scheduler");
            }
            (Job::Enable | Job::Disable, Err(e)) => {
                tracing::error!("Unable to update startup behavior: {e}");
                toasts.error("Unable to update startup behavior");
            }
            (Job::Repoint, Ok(_)) => {
                toasts.success("Startup now opens this copy");
            }
            (Job::Repoint, Err(e)) => {
                tracing::error!("could not point startup at this copy: {e}");
                toasts.error("Could not point startup at this copy");
            }
            (Job::Refresh, Err(e)) => tracing::warn!("could not read the startup task: {e}"),
            (Job::Migrate | Job::Refresh | Job::Enable | Job::Disable, Ok(_)) => {}
        }

        if job == Job::Enable && !snapshot.enabled {
            tracing::warn!("the {TASK_NAME} task was registered but does not read back as enabled");
        }
        // Once per change, not per refresh.
        let previous = self
            .snapshot
            .as_ref()
            .map(|previous| (previous.warning, previous.registered.as_deref()));
        if let Some(warning) = snapshot.warning
            && previous != Some((Some(warning), snapshot.registered.as_deref()))
        {
            tracing::info!(
                ?warning,
                registered = snapshot.registered.as_deref().unwrap_or(""),
                current = snapshot.current.as_deref().unwrap_or(""),
                "the startup task starts another file"
            );
        }

        // What Task Scheduler holds wins over what was saved or clicked.
        *saved_on = snapshot.enabled;
        if snapshot.warning.is_none() {
            self.modal_open = false;
        }
        self.snapshot = Some(snapshot);
        self.checked_at = Some(Instant::now());
    }

    fn changing(&self) -> bool {
        self.job.as_ref().is_some_and(|(job, _)| job.changes())
    }

    fn warning(&self, saved_on: bool) -> Option<StartupWarning> {
        let snapshot = self.snapshot.as_ref()?;
        if saved_on && snapshot.enabled {
            snapshot.warning
        } else {
            None
        }
    }

    /// The "Start Irminsul on startup" row: the checkbox, and the warning
    /// icon when the task starts another file.
    pub fn checkbox_ui(&mut self, ui: &mut Ui, saved_on: &mut bool) {
        ui.horizontal(|ui| {
            let checkbox = egui::Checkbox::new(saved_on, CHECKBOX_LABEL);
            if ui.add_enabled(!self.changing(), checkbox).changed() {
                // Shown at once; the job's read-back corrects it if needed.
                self.start(if *saved_on { Job::Enable } else { Job::Disable });
            }

            if let Some(warning) = self.warning(*saved_on) {
                let icon = RichText::new(egui_material_icons::icons::ICON_WARNING)
                    .color(ui.visuals().warn_fg_color);
                if ui
                    .add(Button::new(icon).frame(false))
                    .on_hover_text(warning.title())
                    .clicked()
                {
                    self.modal_open = true;
                }
            }
        });
    }

    /// The modal behind the warning icon, when it is open.
    pub fn modal_ui(&mut self, ctx: &Context, saved_on: bool) {
        if !self.modal_open {
            return;
        }
        let (Some(warning), Some(snapshot)) = (self.warning(saved_on), self.snapshot.clone())
        else {
            self.modal_open = false;
            return;
        };

        enum Choice {
            Repoint,
            Reveal(String),
            Close,
        }
        let mut choice = None;
        let changing = self.changing();

        let modal = Modal::new(Id::new("Startup Path")).show(ctx, |ui| {
            ui.set_width(460.0);
            ui.heading(warning.title());
            ui.separator();

            ui.label("At sign-in Windows starts:");
            path_label(ui, "registered", snapshot.registered.as_deref());
            if warning == StartupWarning::OtherCopy
                && let Some(modified) = &snapshot.registered_modified
            {
                ui.indent("registered_modified", |ui| {
                    ui.label(
                        RichText::new(format!("modified {modified}"))
                            .small()
                            .color(Color32::GRAY),
                    );
                });
            }
            ui.add_space(4.0);
            ui.label("You are running:");
            path_label(ui, "current", snapshot.current.as_deref());
            ui.separator();

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!changing, Button::new("Start this copy instead"))
                    .clicked()
                {
                    choice = Some(Choice::Repoint);
                }
                if warning == StartupWarning::OtherCopy
                    && let Some(registered) = &snapshot.registered
                    && ui.button("Open its folder").clicked()
                {
                    choice = Some(Choice::Reveal(registered.clone()));
                }
                if ui.button("Close").clicked() {
                    choice = Some(Choice::Close);
                }
            });
        });

        match choice {
            Some(Choice::Repoint) => {
                self.start(Job::Repoint);
                self.modal_open = false;
            }
            Some(Choice::Reveal(path)) => reveal_in_explorer(&path),
            Some(Choice::Close) => self.modal_open = false,
            None => {}
        }
        if modal.should_close() {
            self.modal_open = false;
        }
    }
}

/// A path on its own indented line, selectable so it can be copied.
fn path_label(ui: &mut Ui, id: &str, path: Option<&str>) {
    ui.indent(id, |ui| {
        ui.add(Label::new(RichText::new(path.unwrap_or("unknown")).monospace()).selectable(true));
    });
}

#[cfg(windows)]
fn reveal_in_explorer(path: &str) {
    windows_impl::reveal_in_explorer(path);
}

#[cfg(not(windows))]
fn reveal_in_explorer(path: &str) {
    let folder = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new(path));
    if let Err(e) = open::that(folder) {
        tracing::error!("could not open {folder:?}: {e}");
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Output};

    use anyhow::{Context as _, Result, bail};
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        HKEY_CURRENT_USER, RRF_NOEXPAND, RRF_RT_ANY, RegDeleteKeyValueW, RegGetValueW,
    };
    use windows::core::{PCWSTR, w};

    use super::{
        Job, JobResult, RegisteredTask, Snapshot, TASK_NAME, clean_exe_path, decode_task_xml,
        parse_task_xml, startup_warning, task_xml, utf16le_with_bom,
    };

    /// `CREATE_NO_WINDOW`: schtasks and whoami are console programs, and a
    /// GUI process starting one would otherwise flash a console window.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// Where versions before the scheduled task put the entry.
    const RUN_KEY: PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    /// Task Manager's enabled/disabled flag for that entry.
    const STARTUP_APPROVED_KEY: PCWSTR =
        w!("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run");
    const RUN_VALUE: PCWSTR = w!("Irminsul");

    fn hidden(program: &str) -> Command {
        let mut command = Command::new(program);
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }

    /// What a finished console program said, for an error message.
    fn describe(output: &Output) -> String {
        let said = format!(
            "{} {}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        format!("{} ({})", said.trim(), output.status)
    }

    pub fn run(job: Job) -> JobResult {
        let outcome = match job {
            Job::Refresh => Ok(None),
            Job::Migrate => migrate(),
            Job::Enable | Job::Repoint => create_task().map(|()| None),
            Job::Disable => delete_task().map(|()| None),
        }
        .map_err(|e| format!("{e:#}"));

        JobResult {
            job,
            outcome,
            snapshot: snapshot(),
        }
    }

    fn snapshot() -> Snapshot {
        let task = query_task().unwrap_or_else(|e| {
            tracing::warn!("could not read the {TASK_NAME} task: {e:#}");
            None
        });
        let enabled = task.as_ref().is_some_and(|task| task.enabled);
        let registered = task
            .and_then(|task| task.command)
            .map(|command| clean_exe_path(&command));
        let current = std::env::current_exe()
            .ok()
            .map(|exe| clean_exe_path(&exe.display().to_string()));

        let registered_modified = registered
            .as_deref()
            .and_then(|path| std::fs::metadata(path).ok())
            .filter(|metadata| metadata.is_file())
            .and_then(|metadata| metadata.modified().ok())
            .map(|modified| {
                chrono::DateTime::<chrono::Local>::from(modified)
                    .format("%Y-%m-%d %H:%M")
                    .to_string()
            });
        let registered_exists = registered
            .as_deref()
            .is_some_and(|path| Path::new(path).is_file());
        let warning = current.as_deref().and_then(|current| {
            startup_warning(
                enabled,
                registered.as_deref().map(canonical).as_deref(),
                &canonical(current),
                registered_exists,
            )
        });

        Snapshot {
            enabled,
            warning,
            registered,
            registered_modified,
            current,
        }
    }

    /// The final path of an existing file (links and 8.3 names resolved), or
    /// the path as given.
    fn canonical(path: &str) -> String {
        std::fs::canonicalize(path)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| path.to_string())
    }

    /// The registered task, or `None` when there is none.
    ///
    /// Read from the task's file in Task Scheduler's store: UTF-16, so paths
    /// outside the console code page survive, readable by the user who
    /// registered it, and no process to start. `schtasks /Query /XML` is the
    /// fallback; piped, it prints the console code page, which loses them.
    fn query_task() -> Result<Option<RegisteredTask>> {
        let store = std::env::var_os("SystemRoot").or_else(|| std::env::var_os("windir"));
        if let Some(root) = store {
            let file = Path::new(&root)
                .join("System32")
                .join("Tasks")
                .join(TASK_NAME);
            match std::fs::read(&file) {
                Ok(bytes) => return Ok(Some(parse_task_xml(&decode_task_xml(&bytes)))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => tracing::debug!("could not read {file:?} ({e}); asking schtasks"),
            }
        }

        let output = hidden("schtasks")
            .args(["/Query", "/TN", TASK_NAME, "/XML"])
            .output()
            .context("could not run schtasks")?;
        if output.status.success() {
            Ok(Some(parse_task_xml(&decode_task_xml(&output.stdout))))
        } else {
            // "Not found" is the usual reason, and it is worded in the
            // system language, so it is not told apart from the others.
            tracing::debug!("schtasks /Query: {}", describe(&output));
            Ok(None)
        }
    }

    /// `DOMAIN\user` for the task's principal and logon trigger.
    ///
    /// From the environment, which holds the elevated token's user and keeps
    /// non-ASCII names intact; `whoami` prints in the console code page.
    fn current_user() -> Result<String> {
        let var = |name| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        match (var("USERDOMAIN"), var("USERNAME")) {
            (Some(domain), Some(user)) => return Ok(format!("{domain}\\{user}")),
            (None, Some(user)) => return Ok(user),
            _ => {}
        }

        let output = hidden("whoami").output().context("could not run whoami")?;
        let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() || user.is_empty() {
            bail!("could not tell who is signed in: {}", describe(&output));
        }
        Ok(user)
    }

    /// Register the task for the running exe, replacing any other.
    fn create_task() -> Result<()> {
        let exe = std::env::current_exe().context("could not find the running executable")?;
        let exe = clean_exe_path(&exe.display().to_string());
        let working_dir = Path::new(&exe)
            .parent()
            .map(|dir| dir.display().to_string())
            .unwrap_or_default();
        let xml = task_xml(&exe, &working_dir, &current_user()?);

        // A directory rather than a `NamedTempFile`, so schtasks can open the
        // file however it likes; both go when `dir` is dropped.
        let dir = tempfile::Builder::new()
            .prefix("irminsul-task")
            .tempdir()
            .context("could not create a temporary directory")?;
        let file = dir.path().join("task.xml");
        std::fs::write(&file, utf16le_with_bom(&xml))
            .with_context(|| format!("could not write {file:?}"))?;

        let output = hidden("schtasks")
            .args(["/Create", "/TN", TASK_NAME, "/XML"])
            .arg(&file)
            .arg("/F")
            .output()
            .context("could not run schtasks")?;
        if !output.status.success() {
            bail!("schtasks /Create failed: {}", describe(&output));
        }
        tracing::info!("registered the {TASK_NAME} scheduled task for {exe}");
        Ok(())
    }

    /// Remove the task. One that is not there is fine.
    fn delete_task() -> Result<()> {
        let output = hidden("schtasks")
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .output()
            .context("could not run schtasks")?;
        if output.status.success() {
            tracing::info!("removed the {TASK_NAME} scheduled task");
            return Ok(());
        }
        // schtasks says "not found" in the system language, so look instead.
        if query_task()?.is_none() {
            return Ok(());
        }
        bail!("schtasks /Delete failed: {}", describe(&output))
    }

    /// The old Run entry's command, if there is one.
    fn read_run_value() -> Result<Option<String>> {
        let mut size = 0u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                RUN_KEY,
                RUN_VALUE,
                RRF_RT_ANY | RRF_NOEXPAND,
                None,
                None,
                Some(&mut size),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            bail!("could not read the Run entry: {status:?}");
        }

        let mut data = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut size = (data.len() * 2) as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                RUN_KEY,
                RUN_VALUE,
                RRF_RT_ANY | RRF_NOEXPAND,
                None,
                Some(data.as_mut_ptr().cast()),
                Some(&mut size),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            bail!("could not read the Run entry: {status:?}");
        }
        data.truncate((size as usize) / 2);
        let text = String::from_utf16_lossy(&data);
        Ok(Some(text.trim_end_matches('\0').to_string()))
    }

    /// Remove the Run entry and Task Manager's flag for it.
    fn delete_run_values() {
        for (key, name) in [
            (RUN_KEY, "Run"),
            (STARTUP_APPROVED_KEY, "StartupApproved\\Run"),
        ] {
            let status = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key, RUN_VALUE) };
            if status == ERROR_SUCCESS {
                tracing::info!("removed the {name} entry for Irminsul");
            } else if status != ERROR_FILE_NOT_FOUND {
                tracing::warn!("could not remove the {name} entry for Irminsul: {status:?}");
            }
        }
    }

    /// Move a Run entry left by an older version to a task for the running
    /// exe. The entry only exists when startup was turned on, so a task is
    /// always made for it; it is removed once that worked, and otherwise kept
    /// so the next launch tries again. `Some(command)` when one was moved.
    fn migrate() -> Result<Option<String>> {
        let Some(old) = read_run_value()? else {
            return Ok(None);
        };
        tracing::info!(
            "found Start on startup as a Run entry ({old}), which Windows does not run for an \
             exe that needs elevation; replacing it with a scheduled task"
        );
        create_task().context("the Run entry is kept so the next launch tries again")?;
        delete_run_values();
        Ok(Some(old))
    }

    /// Open Explorer at `path`, selected.
    pub fn reveal_in_explorer(path: &str) {
        // Explorer reads its own command line: `/select,` and the quoted path
        // must reach it as written, which `arg` quoting would not do.
        if let Err(e) = Command::new("explorer")
            .raw_arg(format!("/select,\"{path}\""))
            .spawn()
        {
            tracing::error!("could not open Explorer at {path}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = r"D:\Apps\Irminsul\irminsul.exe";
    const DIR: &str = r"D:\Apps\Irminsul";
    const USER: &str = r"TAWAN475\tawan475";

    /// `schtasks /Query /TN RTSS /XML` on a real machine: a logon task made
    /// by another program, with an unquoted command and its arguments.
    const FOREIGN_TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\RTSS</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
      <UserId>TAWAN475\tawan475</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <StopOnIdleEnd>false</StopOnIdleEnd>
    </IdleSettings>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Program Files (x86)\RivaTuner Statistics Server\RTSS.exe</Command>
      <Arguments>/s</Arguments>
    </Exec>
  </Actions>
</Task>
"#;

    #[test]
    fn the_task_starts_this_exe_elevated_at_sign_in_and_never_times_out() {
        let xml = task_xml(EXE, DIR, USER);

        for expected in [
            "<RunLevel>HighestAvailable</RunLevel>",
            "<LogonType>InteractiveToken</LogonType>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
            "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
            "<Delay>PT15S</Delay>",
            r#"<Command>"D:\Apps\Irminsul\irminsul.exe"</Command>"#,
            r"<WorkingDirectory>D:\Apps\Irminsul</WorkingDirectory>",
        ] {
            assert!(xml.contains(expected), "missing {expected} in\n{xml}");
        }
        // The logon trigger and the principal are both this user.
        assert_eq!(
            xml.matches(r"<UserId>TAWAN475\tawan475</UserId>").count(),
            2,
            "{xml}"
        );
        assert_eq!(elements(&xml, "LogonTrigger").len(), 1);
        assert!(xml.starts_with(r#"<?xml version="1.0" encoding="UTF-16"?>"#));
    }

    #[test]
    fn paths_and_names_are_escaped_in_the_task() {
        let exe = r"C:\Tom & Jerry\<odd>\irminsul.exe";
        let xml = task_xml(exe, r"C:\Tom & Jerry\<odd>", r"R&D\a<b");

        assert!(
            xml.contains(r#"<Command>"C:\Tom &amp; Jerry\&lt;odd&gt;\irminsul.exe"</Command>"#),
            "{xml}"
        );
        assert!(
            xml.contains(r"<WorkingDirectory>C:\Tom &amp; Jerry\&lt;odd&gt;</WorkingDirectory>"),
            "{xml}"
        );
        assert!(xml.contains(r"<UserId>R&amp;D\a&lt;b</UserId>"), "{xml}");
        assert!(!xml.contains("Tom & Jerry"), "{xml}");

        // And it reads back as written.
        let task = parse_task_xml(&xml);
        assert_eq!(
            task.command.as_deref().map(clean_exe_path).as_deref(),
            Some(exe)
        );
    }

    #[test]
    fn the_task_reads_back_as_enabled_for_this_exe() {
        let task = parse_task_xml(&task_xml(EXE, DIR, USER));
        assert!(task.enabled);
        assert_eq!(
            task.command.as_deref(),
            Some(r#""D:\Apps\Irminsul\irminsul.exe""#)
        );
    }

    #[test]
    fn the_task_file_is_utf16_with_a_bom_and_non_ascii_paths_survive() {
        let exe = r"C:\Users\ธวัช\下载\irminsul.exe";
        let xml = task_xml(exe, r"C:\Users\ธวัช\下载", USER);
        let bytes = utf16le_with_bom(&xml);

        assert_eq!(&bytes[..4], &[0xFF, 0xFE, b'<', 0]);
        assert_eq!(decode_task_xml(&bytes), xml);
        let task = parse_task_xml(&decode_task_xml(&bytes));
        assert_eq!(
            task.command.as_deref().map(clean_exe_path).as_deref(),
            Some(exe)
        );
    }

    #[test]
    fn task_xml_is_decoded_from_every_encoding_schtasks_and_the_store_use() {
        let utf16_le_no_bom: Vec<u8> = FOREIGN_TASK
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut utf16_be = vec![0xFE, 0xFF];
        utf16_be.extend(FOREIGN_TASK.encode_utf16().flat_map(u16::to_be_bytes));
        let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
        utf8_bom.extend_from_slice(FOREIGN_TASK.as_bytes());

        for bytes in [
            utf16le_with_bom(FOREIGN_TASK),
            utf16_le_no_bom,
            utf16_be,
            utf8_bom,
            FOREIGN_TASK.as_bytes().to_vec(),
        ] {
            assert_eq!(decode_task_xml(&bytes), FOREIGN_TASK);
        }

        // Piped, schtasks prints 8-bit text with `\r\r\n` line ends.
        let piped = FOREIGN_TASK.replace('\n', "\r\r\n");
        let task = parse_task_xml(&decode_task_xml(piped.as_bytes()));
        assert_eq!(
            task.command.as_deref(),
            Some(r"C:\Program Files (x86)\RivaTuner Statistics Server\RTSS.exe")
        );
        assert!(task.enabled);
    }

    #[test]
    fn a_disabled_task_or_logon_trigger_does_not_run_at_sign_in() {
        let xml = task_xml(EXE, DIR, USER);

        // Task Scheduler's "Disable" sets the task-level flag, not the
        // trigger's, and the two must not be confused.
        let disabled = xml.replace(
            "<Enabled>true</Enabled>\n    <Hidden>",
            "<Enabled>false</Enabled>\n    <Hidden>",
        );
        assert_ne!(disabled, xml);
        let task = parse_task_xml(&disabled);
        assert!(!task.enabled);
        assert!(task.command.is_some());

        let trigger_off = xml.replace(
            "<LogonTrigger>\n      <Enabled>true</Enabled>",
            "<LogonTrigger>\n      <Enabled>false</Enabled>",
        );
        assert_ne!(trigger_off, xml);
        assert!(!parse_task_xml(&trigger_off).enabled);

        // A task that runs on a schedule rather than at sign-in.
        let no_logon = FOREIGN_TASK.replace("LogonTrigger", "TimeTrigger");
        assert!(!parse_task_xml(&no_logon).enabled);

        // Elements left out default to enabled.
        let minimal = "<Task><Triggers><LogonTrigger/></Triggers><Actions><Exec>\
                       <Command>a.exe</Command><Arguments /></Exec></Actions></Task>";
        let task = parse_task_xml(minimal);
        assert!(task.enabled);
        assert_eq!(task.command.as_deref(), Some("a.exe"));
    }

    #[test]
    fn entities_in_a_registered_command_are_decoded() {
        assert_eq!(
            xml_unescape("&quot;C:\\A &amp; B\\&#x6E2C;&#35;&lt;&gt;&apos;.exe&quot;"),
            "\"C:\\A & B\\測#<>'.exe\""
        );
        // Not an entity: kept as written.
        assert_eq!(xml_unescape("A & B &bogus; &"), "A & B &bogus; &");
    }

    #[test]
    fn element_lookup_does_not_match_longer_names() {
        let xml = "<IdleSettings><Enabled>x</Enabled></IdleSettings><Settings a=\"1\">\
                   <Enabled>false</Enabled></Settings><SettingsMore>y</SettingsMore>";
        assert_eq!(elements(xml, "Settings"), vec!["<Enabled>false</Enabled>"]);
        assert_eq!(element(xml, "Missing"), None);
    }

    #[test]
    fn exe_paths_compare_without_case_quotes_or_verbatim_prefixes() {
        for other in [
            r"d:\apps\irminsul\IRMINSUL.EXE",
            r#""D:\Apps\Irminsul\irminsul.exe""#,
            r#""D:\Apps\Irminsul\irminsul.exe"#,
            r#"D:\Apps\Irminsul\irminsul.exe""#,
            r#"  "D:\Apps\Irminsul\irminsul.exe"  "#,
            r"\\?\D:\Apps\Irminsul\irminsul.exe",
            r"D:/Apps/Irminsul/irminsul.exe",
        ] {
            assert!(same_exe(EXE, other), "{other}");
            assert!(same_exe(other, EXE), "{other}");
        }
        assert!(same_exe(
            r"\\?\UNC\nas\share\irminsul.exe",
            r"\\nas\share\irminsul.exe"
        ));

        for other in [
            r"C:\Users\tawan475\Downloads\irminsul-windows.exe",
            r"D:\Apps\Irminsul\irminsul.exe.old",
            r"D:\Apps\Irminsul2\irminsul.exe",
        ] {
            assert!(!same_exe(EXE, other), "{other}");
        }
    }

    #[test]
    fn the_warning_names_another_copy_or_a_missing_file_only_when_startup_is_on() {
        let downloads = r"C:\Users\tawan475\Downloads\irminsul-windows.exe";

        // Startup opens this copy, however the path is spelled.
        assert_eq!(startup_warning(true, Some(EXE), EXE, true), None);
        assert_eq!(
            startup_warning(true, Some(r"\\?\d:\apps\irminsul\irminsul.exe"), EXE, true),
            None
        );

        // Another copy, present or gone.
        assert_eq!(
            startup_warning(true, Some(downloads), EXE, true),
            Some(StartupWarning::OtherCopy)
        );
        assert_eq!(
            startup_warning(true, Some(downloads), EXE, false),
            Some(StartupWarning::MissingFile)
        );

        // Off, or nothing registered: nothing to say.
        assert_eq!(startup_warning(false, Some(downloads), EXE, true), None);
        assert_eq!(startup_warning(false, Some(downloads), EXE, false), None);
        assert_eq!(startup_warning(true, None, EXE, false), None);
    }

    #[test]
    fn the_warning_titles_are_the_approved_wording() {
        assert_eq!(
            StartupWarning::OtherCopy.title(),
            "Startup opens another copy"
        );
        assert_eq!(
            StartupWarning::MissingFile.title(),
            "Startup points to a file that no longer exists"
        );
    }
}
