//! What the panic hook cannot see, on Windows.
//!
//! Three ways for the process to end that leave nothing behind otherwise:
//!
//! - **A native crash** -- an access violation, a stack overflow, a fault
//!   inside a graphics driver. [`on_unhandled_exception`] appends the exception
//!   code, address, faulting module and the stack to `crash.log` and writes a
//!   minidump (`crash-<UTC time>.dmp`) next to it, then lets Windows Error
//!   Reporting carry on as it would have.
//!
//!   `__fastfail`, which is how Rust aborts (a panic that cannot unwind, a
//!   double panic, an allocation failure), bypasses this filter entirely: the
//!   kernel ends the process without running any user-mode handler. That is why
//!   the panic hook writes `crash.log` itself, synchronously, *before* the
//!   abort can happen -- for a panic that aborts, that line is all there is.
//!   There is deliberately no vectored handler either: it would also see every
//!   first-chance exception a driver raises and handles itself, and report
//!   crashes that never happened.
//! - **`ExitProcess` without Irminsul's shutdown**: a library calling `exit()`,
//!   or the main thread panicking out of `main`. No exception is involved, so
//!   no filter sees it. [`on_tls_callback`] does: the loader calls it as the
//!   process detaches, and it reports the exit unless [`super::mark_clean_exit`]
//!   ran first.
//! - **Windows ending the session** (shut down, restart, sign out). Windows
//!   asks every top-level window and then terminates the process without
//!   running anything else, which would look exactly like a kill. A hidden
//!   window on its own thread hears it and writes the clean-exit marker.
//!
//! What still leaves no trace: `TerminateProcess` from another process (Task
//! Manager, an antivirus), a fail-fast that was not a panic, a power cut, a
//! blue screen. The next start reports those as an abrupt end.
//!
//! Code that runs inside a crashed process must not allocate: the heap may be
//! what broke, and its lock may be held by the thread that crashed. Lines are
//! formatted into a [`LineBuf`] on the stack and written through a `crash.log`
//! handle opened at startup.

use std::ffi::c_void;
use std::fmt::{self, Write as _};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use chrono::Utc;
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HMODULE, HWND, LPARAM, LRESULT, MAX_PATH, WAIT_OBJECT_0, WPARAM,
};
use windows::Win32::System::Diagnostics::Debug::{
    EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, LPTOP_LEVEL_EXCEPTION_FILTER,
    MINIDUMP_EXCEPTION_INFORMATION, MINIDUMP_TYPE, MiniDumpWithThreadInfo,
    MiniDumpWithUnloadedModules, MiniDumpWriteDump, RtlCaptureStackBackTrace,
    SetUnhandledExceptionFilter,
};
use windows::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW,
};
use windows::Win32::System::Threading::{
    CreateThread, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
    THREAD_CREATION_FLAGS, WaitForSingleObject,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, ENDSESSION_CLOSEAPP, ENDSESSION_LOGOFF,
    GetMessageW, MSG, RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WM_ENDSESSION,
    WM_QUERYENDSESSION, WNDCLASSW, WS_OVERLAPPED,
};
use windows::core::{PCWSTR, w};

use super::write_report_header;

/// Minidumps kept in the log directory. Pruned at startup, because deleting
/// files is not something a crashed process should attempt; a crash adds one
/// more until the next start.
const DUMP_RETENTION: usize = 3;

/// How long the crashed thread waits for its minidump before giving up and
/// letting the process end anyway.
const DUMP_TIMEOUT_MS: u32 = 30_000;

/// Stack frames written to `crash.log`. The exception dispatcher's own frames
/// come first, so a crash gets a few more than an exit.
const CRASH_FRAMES: usize = 48;
const EXIT_FRAMES: usize = 32;

/// Normal plus thread times and start addresses, and the modules that had
/// already been unloaded (a crash in an unloaded DLL shows up as an address
/// in none of the loaded ones). No heap memory: the dump is small, and a user
/// sending one does not send the account data and tracker key in the heap.
const DUMP_TYPE: MINIDUMP_TYPE =
    MINIDUMP_TYPE(MiniDumpWithThreadInfo.0 | MiniDumpWithUnloadedModules.0);

/// `crash.log`, opened for appending at startup. Writing through it needs
/// neither the heap nor a path conversion.
static CRASH_FILE: OnceLock<File> = OnceLock::new();
static DUMP_DIR: OnceLock<PathBuf> = OnceLock::new();
/// Whichever filter was installed before ours, called after it.
static PREVIOUS_FILTER: OnceLock<LPTOP_LEVEL_EXCEPTION_FILTER> = OnceLock::new();
/// The first report wins. A second exception inside the handler, or the exit
/// that follows a reported crash, adds nothing.
static REPORTED: AtomicBool = AtomicBool::new(false);
static EXIT_HOOK_ARMED: AtomicBool = AtomicBool::new(false);
static MAIN_THREAD: AtomicU32 = AtomicU32::new(0);
/// Handed to the thread that writes the dump.
static DUMP_EXCEPTION: AtomicPtr<EXCEPTION_POINTERS> = AtomicPtr::new(std::ptr::null_mut());
static DUMP_THREAD: AtomicU32 = AtomicU32::new(0);
/// The session-end window, once it exists. Read by the tests.
static SESSION_WINDOW: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Install everything in this file. Called once, on the main thread.
pub(super) fn install(log_dir: &Path, crash_log: &Path) {
    match OpenOptions::new().create(true).append(true).open(crash_log) {
        Ok(file) => {
            let _ = CRASH_FILE.set(file);
        }
        Err(e) => tracing::warn!("cannot open {crash_log:?} for native crash reports: {e}"),
    }
    let _ = DUMP_DIR.set(log_dir.to_path_buf());
    prune_dumps(log_dir, DUMP_RETENTION);

    // SAFETY: plain Win32 calls; the filter is a valid `extern "system"`
    // function for the life of the process.
    unsafe {
        MAIN_THREAD.store(GetCurrentThreadId(), Ordering::SeqCst);
        let previous = SetUnhandledExceptionFilter(Some(on_unhandled_exception));
        let _ = PREVIOUS_FILTER.set(previous);
    }
    arm_exit_hook();
    start_session_watcher();
}

/// A line (or a few) formatted without allocating; whatever does not fit is
/// cut off.
struct LineBuf {
    buf: [u8; 4096],
    len: usize,
}

impl LineBuf {
    fn new() -> Self {
        Self {
            buf: [0; 4096],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Append to `crash.log` and push it to disk.
fn append(bytes: &[u8]) {
    if let Some(mut file) = CRASH_FILE.get() {
        let _ = file.write_all(bytes);
        let _ = file.sync_data();
    }
}

/// The unhandled-exception filter: report the crash, then hand it on.
///
/// Returns what the previous filter says, or `EXCEPTION_CONTINUE_SEARCH`, so
/// Windows Error Reporting still gets the crash and the event log still
/// records it.
unsafe extern "system" fn on_unhandled_exception(info: *const EXCEPTION_POINTERS) -> i32 {
    if !REPORTED.swap(true, Ordering::SeqCst) {
        // SAFETY: `info` is the system's, valid for this call.
        unsafe { report_exception(info) };
    }
    match PREVIOUS_FILTER.get().copied().flatten() {
        // SAFETY: a filter someone installed, called as Windows would have.
        Some(previous) => unsafe { previous(info) },
        None => EXCEPTION_CONTINUE_SEARCH,
    }
}

/// Write the crash to `crash.log`, then the minidump.
///
/// # Safety
///
/// `info` must be null or point to valid exception pointers.
unsafe fn report_exception(info: *const EXCEPTION_POINTERS) {
    // SAFETY: plain Win32 call.
    let thread = unsafe { GetCurrentThreadId() };
    let mut line = LineBuf::new();
    write_report_header(&mut line, "native crash");

    // SAFETY: the caller's contract; both pointers are null-checked.
    let record = unsafe { info.as_ref().and_then(|info| info.ExceptionRecord.as_ref()) };
    match record {
        Some(record) => {
            let code = record.ExceptionCode.0 as u32;
            let address = record.ExceptionAddress as usize;
            let mut name = [0u16; MAX_PATH as usize];
            // SAFETY: `name` is a valid buffer.
            let module = unsafe { module_at(address, &mut name) }
                .map(|(len, offset)| (&name[..len], offset));
            let access = (code == ACCESS_VIOLATION && record.NumberParameters >= 2).then(|| {
                (
                    record.ExceptionInformation[0],
                    record.ExceptionInformation[1],
                )
            });
            describe_exception(&mut line, code, address, module, access);
        }
        None => {
            let _ = line.write_str("an unhandled exception without an exception record");
        }
    }
    describe_thread(&mut line, thread);
    let _ = line.write_str("\nstack (the exception dispatcher's frames first):\n");
    // SAFETY: walks this thread's own stack.
    unsafe { write_stack::<CRASH_FRAMES>(&mut line) };
    append(line.as_bytes());

    // On a thread of its own: this one may have no stack left (an overflow),
    // and if the dump deadlocks on a lock the crash left held, only the
    // helper hangs -- this thread stops waiting and lets the process end.
    DUMP_EXCEPTION.store(info.cast_mut(), Ordering::SeqCst);
    DUMP_THREAD.store(thread, Ordering::SeqCst);
    // SAFETY: `dump_thread` is a valid thread routine taking no parameter.
    let helper = unsafe {
        CreateThread(
            None,
            0,
            Some(dump_thread),
            None,
            THREAD_CREATION_FLAGS(0),
            None,
        )
    };
    match helper {
        Ok(handle) => {
            // SAFETY: a handle this function owns.
            unsafe {
                if WaitForSingleObject(handle, DUMP_TIMEOUT_MS) != WAIT_OBJECT_0 {
                    append(b"minidump: not finished after 30 s; gave up waiting\n");
                }
                let _ = CloseHandle(handle);
            }
        }
        Err(_) => append(b"minidump: could not start a thread to write it\n"),
    }
}

/// The helper thread [`report_exception`] starts.
unsafe extern "system" fn dump_thread(_: *mut c_void) -> u32 {
    let exception = DUMP_EXCEPTION.load(Ordering::SeqCst);
    let thread = DUMP_THREAD.load(Ordering::SeqCst);
    write_minidump(Some((exception, thread)));
    0
}

/// Write `crash-<UTC time>.dmp` and say so in `crash.log`.
///
/// Allocates (the path, the outcome line): it only runs on the helper thread,
/// whose wait is bounded.
fn write_minidump(exception: Option<(*mut EXCEPTION_POINTERS, u32)>) {
    let Some(dir) = DUMP_DIR.get() else {
        return;
    };
    // UTC, like every time in `crash.log`; and no local time zone lookup in a
    // crashed process.
    let name = format!("crash-{}.dmp", Utc::now().format("%Y-%m-%d_%H-%M-%SZ"));
    let path = dir.join(&name);
    let outcome = match File::create(&path) {
        Ok(file) => {
            let info = exception.map(|(pointers, thread)| MINIDUMP_EXCEPTION_INFORMATION {
                ThreadId: thread,
                ExceptionPointers: pointers,
                ClientPointers: false.into(),
            });
            // SAFETY: a file handle this function owns, and exception pointers
            // the system gave the filter, which is still waiting on this.
            let written = unsafe {
                MiniDumpWriteDump(
                    GetCurrentProcess(),
                    GetCurrentProcessId(),
                    HANDLE(file.as_raw_handle()),
                    DUMP_TYPE,
                    info.as_ref().map(|info| info as *const _),
                    None,
                    None,
                )
            };
            drop(file);
            match written {
                Ok(()) => format!("minidump: {name}\n"),
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    format!("minidump: failed ({e})\n")
                }
            }
        }
        Err(e) => format!("minidump: could not create {name} ({e})\n"),
    };
    append(outcome.as_bytes());
}

const ACCESS_VIOLATION: u32 = 0xC000_0005;

/// What the common exception codes mean.
fn exception_name(code: u32) -> &'static str {
    match code {
        ACCESS_VIOLATION => "access violation",
        0xC000_00FD => "stack overflow",
        0xC000_0374 => "heap corruption",
        0xC000_0409 => "fail fast / stack buffer overrun",
        0xC000_001D => "illegal instruction",
        0xC000_0094 => "integer division by zero",
        0xC000_0095 => "integer overflow",
        0xC000_0096 => "privileged instruction",
        0xC000_0006 => "in-page error",
        0xC000_0008 => "invalid handle",
        0x8000_0003 => "breakpoint",
        0xE06D_7363 => "C++ exception",
        _ => "unknown exception",
    }
}

/// `exception 0xC0000005 (access violation) at 0x... in module+0x..., writing
/// address 0x...`. `module` is the module's path and the address's offset in
/// it; `access` is an access violation's operation and target.
fn describe_exception(
    out: &mut impl fmt::Write,
    code: u32,
    address: usize,
    module: Option<(&[u16], usize)>,
    access: Option<(usize, usize)>,
) {
    let _ = write!(
        out,
        "exception 0x{code:08X} ({}) at 0x{address:016X}",
        exception_name(code)
    );
    if let Some((path, offset)) = module {
        let _ = out.write_str(" in ");
        write_file_name(out, path);
        let _ = write!(out, "+0x{offset:X}");
    }
    if let Some((operation, target)) = access {
        let verb = match operation {
            0 => "reading",
            1 => "writing",
            8 => "executing",
            _ => "accessing",
        };
        let _ = write!(out, ", {verb} address 0x{target:016X}");
    }
}

fn describe_thread(out: &mut impl fmt::Write, thread: u32) {
    let _ = write!(out, " on thread {thread}");
    if thread == MAIN_THREAD.load(Ordering::SeqCst) {
        let _ = out.write_str(" (the main thread)");
    }
}

/// The last component of a UTF-16 path.
fn write_file_name(out: &mut impl fmt::Write, path: &[u16]) {
    let separator = |c: &u16| *c == u16::from(b'\\') || *c == u16::from(b'/');
    let name = path.rsplit(separator).next().unwrap_or(path);
    for c in char::decode_utf16(name.iter().copied()) {
        let _ = out.write_char(c.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
}

/// The module `address` lies in: the length of its path, written to `name`,
/// and the address's offset into it.
///
/// # Safety
///
/// Only reads loader state; safe for any `address`.
unsafe fn module_at(address: usize, name: &mut [u16; MAX_PATH as usize]) -> Option<(usize, usize)> {
    let mut module = HMODULE::default();
    // SAFETY: with FROM_ADDRESS the "name" is any address, and
    // UNCHANGED_REFCOUNT leaves nothing to release.
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(address as *const u16),
            &mut module,
        )
        .ok()?;
    }
    // SAFETY: `name` is a valid buffer.
    let len = unsafe { GetModuleFileNameW(Some(module), name) } as usize;
    Some((len.min(name.len()), address.wrapping_sub(module.0 as usize)))
}

/// Up to `N` return addresses of the calling thread, one per line as
/// `module+0xoffset`, which the module's symbols turn into names.
///
/// # Safety
///
/// Walks the calling thread's stack; needs nothing from the caller.
unsafe fn write_stack<const N: usize>(out: &mut LineBuf) {
    let mut frames = [std::ptr::null_mut::<c_void>(); N];
    // SAFETY: `frames` is a valid buffer; skips this function's own frame.
    let count = unsafe { RtlCaptureStackBackTrace(1, &mut frames, None) } as usize;
    for &frame in frames.iter().take(count) {
        let address = frame as usize;
        let mut name = [0u16; MAX_PATH as usize];
        let _ = write!(out, "  0x{address:016X}");
        // SAFETY: `name` is a valid buffer.
        if let Some((len, offset)) = unsafe { module_at(address, &mut name) } {
            let _ = out.write_str(" ");
            write_file_name(out, &name[..len]);
            let _ = write!(out, "+0x{offset:X}");
        }
        let _ = out.write_str("\n");
    }
}

/// Called by the loader at every thread start and exit, and once more as the
/// process exits through `ExitProcess` -- which is the call this is for.
///
/// A TLS callback is the only code an executable gets to run on that path;
/// std uses the same mechanism (`.CRT$XLB`) for thread-local destructors.
/// The loader calls the callbacks in section-name order, so this one runs
/// after std's.
#[used]
#[unsafe(link_section = ".CRT$XLY")]
static EXIT_HOOK: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) = on_tls_callback;

/// Keep the TLS directory and [`EXIT_HOOK`] in the image, and let the hook
/// report from now on.
fn arm_exit_hook() {
    // The TLS directory the loader reads the callbacks from. The linker drops
    // it (and with it every callback) unless something refers to it.
    unsafe extern "C" {
        #[link_name = "_tls_used"]
        static TLS_USED: u8;
    }
    // SAFETY: one-byte reads of two statics that exist for the life of the
    // process; volatile, so the references survive optimisation.
    unsafe {
        std::ptr::from_ref(&TLS_USED).read_volatile();
        std::ptr::from_ref(&EXIT_HOOK).read_volatile();
    }
    EXIT_HOOK_ARMED.store(true, Ordering::SeqCst);
}

/// See [`EXIT_HOOK`].
///
/// By the time this runs every other thread is gone and the heap's lock may
/// have died with one of them, so it neither allocates nor touches
/// thread-locals (std's callback destroyed them just before this one). No
/// minidump either, for the same reason: the stack it writes says who called
/// `ExitProcess`, which is what a dump of this lone thread would show.
unsafe extern "system" fn on_tls_callback(
    _module: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) {
    const DLL_PROCESS_DETACH: u32 = 0;
    if reason != DLL_PROCESS_DETACH
        || !EXIT_HOOK_ARMED.load(Ordering::SeqCst)
        || super::clean_exit_marked()
        || REPORTED.swap(true, Ordering::SeqCst)
    {
        return;
    }
    let mut line = LineBuf::new();
    write_report_header(&mut line, "exit without shutdown");
    let _ = line.write_str("the process is exiting through ExitProcess");
    // SAFETY: plain Win32 call.
    describe_thread(&mut line, unsafe { GetCurrentThreadId() });
    let _ = line.write_str(
        " without Irminsul's shutdown: the main thread panicked (see above), or code called \
         exit()\nstack:\n",
    );
    // SAFETY: walks this thread's own stack.
    unsafe { write_stack::<EXIT_FRAMES>(&mut line) };
    append(line.as_bytes());
}

/// Delete all but the newest `keep` minidumps. Their names are fixed-width
/// UTC stamps, so name order is time order.
fn prune_dumps(dir: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut dumps: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("crash-") && name.ends_with(".dmp"))
        })
        .collect();
    dumps.sort_unstable_by(|a, b| b.file_name().cmp(&a.file_name()));
    for path in dumps.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
}

/// Class of the window that hears Windows end the session.
const SESSION_WINDOW_CLASS: PCWSTR = w!("IrminsulSessionEndWatcher");

fn start_session_watcher() {
    let spawned = std::thread::Builder::new()
        .name("session-end-watcher".into())
        .spawn(|| {
            // SAFETY: creates and pumps a window owned by this thread.
            if let Err(e) = unsafe { run_session_watcher() } {
                tracing::warn!("cannot watch for Windows ending the session: {e}");
            }
        });
    if let Err(e) = spawned {
        tracing::warn!("cannot start the thread that watches for Windows ending the session: {e}");
    }
}

/// Create the hidden window and pump its messages for the life of the
/// process.
///
/// A top-level window, because Windows sends `WM_QUERYENDSESSION` and
/// `WM_ENDSESSION` to top-level windows only (a message-only window gets
/// neither), and one of its own on its own thread, because winit ignores both
/// and a busy UI thread must not delay the marker. Never shown, and not titled
/// "Irminsul": `app.rs` finds the main window by that exact title.
///
/// # Safety
///
/// Call on a thread that does nothing else.
unsafe fn run_session_watcher() -> windows::core::Result<()> {
    // SAFETY: the window class and window live as long as the process; the
    // message loop is this thread's.
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = WNDCLASSW {
            lpfnWndProc: Some(session_window_proc),
            hInstance: instance.into(),
            lpszClassName: SESSION_WINDOW_CLASS,
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err(windows::core::Error::from_win32());
        }
        let window = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            SESSION_WINDOW_CLASS,
            w!("Irminsul session-end watcher"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        )?;
        SESSION_WINDOW.store(window.0, Ordering::SeqCst);

        let mut message = MSG::default();
        // -1 is an error, 0 is WM_QUIT; neither should ever come.
        while GetMessageW(&mut message, None, 0, 0).0 > 0 {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    Ok(())
}

unsafe extern "system" fn session_window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        // Irminsul has nothing to save and never stands in the way.
        WM_QUERYENDSESSION => LRESULT(1),
        // Non-zero: the session really is ending, and Windows will terminate
        // the process once every window has answered.
        WM_ENDSESSION if wparam.0 != 0 => {
            super::mark_clean_exit(session_end_reason(lparam.0 as u32));
            LRESULT(0)
        }
        // SAFETY: the arguments Windows passed in.
        _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
}

/// The clean-exit reason for `WM_ENDSESSION`'s flags.
fn session_end_reason(flags: u32) -> &'static str {
    if flags & ENDSESSION_CLOSEAPP != 0 {
        "Windows asked Irminsul to close (an installer or update needed it closed)"
    } else if flags & ENDSESSION_LOGOFF != 0 {
        "Windows is signing the user out"
    } else {
        "Windows is shutting down or restarting"
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Output};
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::NTSTATUS;
    use windows::Win32::System::Diagnostics::Debug::{
        CONTEXT, EXCEPTION_RECORD, RtlCaptureContext, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };
    use windows::Win32::UI::WindowsAndMessaging::SendMessageW;

    use super::*;
    use crate::crash::{CRASH_LOG, RunEnd, create_run_log, examine_previous_run};

    /// Set in a child this test binary starts of itself: the log directory the
    /// child installs everything into. The process-wide hooks can only be
    /// installed once per process, and some of these tests end theirs.
    const CHILD_DIR: &str = "IRMINSUL_CRASH_TEST_DIR";

    /// In a child, install everything into its log directory and return it.
    fn child_setup() -> Option<PathBuf> {
        let dir = PathBuf::from(std::env::var_os(CHILD_DIR)?);
        create_run_log(&dir).unwrap();
        crate::crash::install(&dir);
        Some(dir)
    }

    /// Run the test `name` of this module in a child with `dir` as its log
    /// directory.
    fn run_child(name: &str, dir: &Path) -> Output {
        // The path libtest knows the test by: no crate name in a binary.
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, rest)| rest);
        Command::new(std::env::current_exe().unwrap())
            .args([
                &format!("{module}::{name}"),
                "--exact",
                // The test's own `#[ignore]` was for the parent to decide.
                "--include-ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_DIR, dir)
            .output()
            .unwrap()
    }

    fn read(dir: &Path, name: &str) -> String {
        std::fs::read_to_string(dir.join(name)).unwrap_or_default()
    }

    fn dumps(dir: &Path) -> Vec<PathBuf> {
        let mut dumps: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "dmp"))
            .collect();
        dumps.sort();
        dumps
    }

    /// A minidump file starts with this signature.
    fn assert_is_minidump(path: &Path) {
        let bytes = std::fs::read(path).unwrap();
        assert!(bytes.starts_with(b"MDMP"), "{path:?} is not a minidump");
    }

    #[test]
    fn a_native_crash_is_reported_with_its_module_stack_and_a_dump() {
        if child_setup().is_some() {
            // A write to 0x10 from a function of this executable, handed to
            // the filter the way Windows would: no real crash, so no Windows
            // Error Reporting event for a test.
            #[repr(C, align(16))]
            struct Aligned(CONTEXT);
            let mut context = Aligned(CONTEXT::default());
            let mut record = EXCEPTION_RECORD {
                ExceptionCode: NTSTATUS(ACCESS_VIOLATION as i32),
                ExceptionAddress: report_exception as *mut c_void,
                NumberParameters: 2,
                ..Default::default()
            };
            record.ExceptionInformation[0] = 1;
            record.ExceptionInformation[1] = 0x10;
            unsafe {
                RtlCaptureContext(&mut context.0);
                let pointers = EXCEPTION_POINTERS {
                    ExceptionRecord: &mut record,
                    ContextRecord: &mut context.0,
                };
                on_unhandled_exception(&pointers);
            }
            // Reported once: the exit that follows adds nothing.
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let output = run_child(
            "a_native_crash_is_reported_with_its_module_stack_and_a_dump",
            dir.path(),
        );
        assert!(output.status.success(), "{output:?}");

        let report = read(dir.path(), CRASH_LOG);
        assert_eq!(report.matches("==== ").count(), 1, "{report}");
        assert!(report.contains(" native crash | Irminsul "), "{report}");
        assert!(
            report.contains("exception 0xC0000005 (access violation) at 0x"),
            "{report}"
        );
        let exe = std::env::current_exe().unwrap();
        let exe = exe.file_name().unwrap().to_str().unwrap();
        assert!(report.contains(&format!(" in {exe}+0x")), "{report}");
        assert!(
            report.contains(", writing address 0x0000000000000010 on thread "),
            "{report}"
        );
        assert!(report.contains("\nstack (the exception"), "{report}");
        assert!(report.contains("  0x"), "{report}");
        assert!(report.contains("minidump: crash-"), "{report}");

        let dumps = dumps(dir.path());
        assert_eq!(dumps.len(), 1, "{dumps:?}");
        assert_is_minidump(&dumps[0]);
    }

    #[test]
    fn an_exit_that_skips_the_shutdown_is_reported_with_who_called_it() {
        if child_setup().is_some() {
            std::process::exit(3);
        }

        let dir = tempfile::tempdir().unwrap();
        let output = run_child(
            "an_exit_that_skips_the_shutdown_is_reported_with_who_called_it",
            dir.path(),
        );
        assert_eq!(output.status.code(), Some(3), "{output:?}");

        let report = read(dir.path(), CRASH_LOG);
        assert!(report.contains(" exit without shutdown | "), "{report}");
        assert!(report.contains("exiting through ExitProcess"), "{report}");
        let exe = std::env::current_exe().unwrap();
        let exe = exe.file_name().unwrap().to_str().unwrap();
        assert!(report.contains(&format!(" {exe}+0x")), "{report}");
        // And the next start calls it a crash, not a mystery.
        assert!(matches!(
            examine_previous_run(dir.path()),
            RunEnd::Crashed { .. }
        ));
    }

    #[test]
    fn a_clean_exit_reports_nothing() {
        if child_setup().is_some() {
            crate::crash::mark_clean_exit("window closed");
            std::process::exit(0);
        }

        let dir = tempfile::tempdir().unwrap();
        let output = run_child("a_clean_exit_reports_nothing", dir.path());
        assert!(output.status.success(), "{output:?}");
        assert_eq!(read(dir.path(), CRASH_LOG), "");
        assert!(read(dir.path(), "latest.log").contains("[clean-exit] window closed"));
        assert_eq!(examine_previous_run(dir.path()), RunEnd::Clean);
    }

    #[test]
    fn windows_ending_the_session_is_a_clean_exit() {
        if child_setup().is_some() {
            let deadline = Instant::now() + Duration::from_secs(10);
            let window = loop {
                let window = SESSION_WINDOW.load(Ordering::SeqCst);
                if !window.is_null() {
                    break HWND(window);
                }
                assert!(Instant::now() < deadline, "the window never appeared");
                std::thread::sleep(Duration::from_millis(10));
            };
            let logoff = Some(LPARAM(ENDSESSION_LOGOFF as isize));
            unsafe {
                assert_eq!(
                    SendMessageW(window, WM_QUERYENDSESSION, Some(WPARAM(0)), logoff),
                    LRESULT(1)
                );
                SendMessageW(window, WM_ENDSESSION, Some(WPARAM(1)), logoff);
            }
            // Windows would terminate the process now; an exit is the
            // nearest thing that runs the exit hook.
            std::process::exit(0);
        }

        let dir = tempfile::tempdir().unwrap();
        let output = run_child("windows_ending_the_session_is_a_clean_exit", dir.path());
        assert!(output.status.success(), "{output:?}");
        assert!(
            read(dir.path(), "latest.log").contains("[clean-exit] Windows is signing the user out"),
            "{output:?}"
        );
        assert_eq!(read(dir.path(), CRASH_LOG), "");
        assert_eq!(examine_previous_run(dir.path()), RunEnd::Clean);
    }

    #[test]
    fn a_panic_is_written_to_crash_log_synchronously() {
        if child_setup().is_some() {
            let _ = std::thread::Builder::new()
                .name("doomed".into())
                .spawn(|| panic!("the decoder fell over"))
                .unwrap()
                .join();
            crate::crash::mark_clean_exit("window closed");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let output = run_child("a_panic_is_written_to_crash_log_synchronously", dir.path());
        assert!(output.status.success(), "{output:?}");
        let report = read(dir.path(), CRASH_LOG);
        assert!(report.contains(" panic | Irminsul "), "{report}");
        assert!(report.contains("thread 'doomed' panicked at "), "{report}");
        assert!(
            report.contains("the decoder fell over\nbacktrace:\n"),
            "{report}"
        );
    }

    /// The real thing: a panic that aborts. Ignored because the abort is a
    /// fail-fast, which Windows Error Reporting records as a crash of the
    /// test binary every time it runs; `cargo test -- --ignored` runs it.
    #[test]
    #[ignore]
    fn a_panic_that_aborts_still_reaches_crash_log() {
        if child_setup().is_some() {
            unsafe { SetErrorMode(SEM_NOGPFAULTERRORBOX) };
            extern "C" fn callback() {
                panic!("panicked in a callback that cannot unwind");
            }
            callback();
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let output = run_child("a_panic_that_aborts_still_reaches_crash_log", dir.path());
        assert!(!output.status.success(), "{output:?}");
        let report = read(dir.path(), CRASH_LOG);
        assert!(
            report.contains("panicked in a callback that cannot unwind"),
            "{report}"
        );
    }

    /// The real thing: an access violation, caught by the installed filter.
    /// Ignored for the same reason as the abort above.
    #[test]
    #[ignore]
    fn a_real_access_violation_is_reported_with_a_dump() {
        if child_setup().is_some() {
            unsafe {
                SetErrorMode(SEM_NOGPFAULTERRORBOX);
                std::ptr::write_volatile(0x10 as *mut u8, 1);
            }
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let output = run_child(
            "a_real_access_violation_is_reported_with_a_dump",
            dir.path(),
        );
        assert_eq!(
            output.status.code().map(|code| code as u32),
            Some(ACCESS_VIOLATION),
            "{output:?}"
        );
        let report = read(dir.path(), CRASH_LOG);
        assert!(
            report.contains("(access violation)")
                && report.contains("writing address 0x0000000000000010"),
            "{report}"
        );
        assert!(
            report.contains("(the main thread)") || report.contains("on thread "),
            "{report}"
        );
        let dumps = dumps(dir.path());
        assert_eq!(dumps.len(), 1, "{report}");
        assert_is_minidump(&dumps[0]);
    }

    #[test]
    fn exceptions_are_described_with_their_module_and_access() {
        let path: Vec<u16> = r"C:\Windows\System32\DriverStore\nvoglv64.dll"
            .encode_utf16()
            .collect();
        let mut line = LineBuf::new();
        describe_exception(
            &mut line,
            ACCESS_VIOLATION,
            0x7FF6_A1B2_C3D4,
            Some((&path, 0x12_3456)),
            Some((0, 0)),
        );
        assert_eq!(
            std::str::from_utf8(line.as_bytes()).unwrap(),
            "exception 0xC0000005 (access violation) at 0x00007FF6A1B2C3D4 in \
             nvoglv64.dll+0x123456, reading address 0x0000000000000000"
        );

        let mut line = LineBuf::new();
        describe_exception(&mut line, 0xC000_00FD, 0x1000, None, None);
        assert_eq!(
            std::str::from_utf8(line.as_bytes()).unwrap(),
            "exception 0xC00000FD (stack overflow) at 0x0000000000001000"
        );
    }

    #[test]
    fn a_line_that_does_not_fit_is_cut_not_a_panic() {
        let mut line = LineBuf::new();
        for _ in 0..1000 {
            let _ = line.write_str("0123456789");
        }
        assert_eq!(line.as_bytes().len(), 4096);
    }

    #[test]
    fn only_the_newest_dumps_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        for day in 1..=5 {
            std::fs::write(
                dir.path()
                    .join(format!("crash-2026-10-0{day}_12-00-00Z.dmp")),
                b"MDMP",
            )
            .unwrap();
        }
        std::fs::write(dir.path().join(CRASH_LOG), "kept").unwrap();
        std::fs::write(dir.path().join("other.dmp"), "not ours").unwrap();

        prune_dumps(dir.path(), DUMP_RETENTION);

        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "crash-2026-10-03_12-00-00Z.dmp",
                "crash-2026-10-04_12-00-00Z.dmp",
                "crash-2026-10-05_12-00-00Z.dmp",
                "crash.log",
                "other.dmp",
            ]
        );
    }

    #[test]
    fn the_session_end_reason_follows_the_flags() {
        assert_eq!(
            session_end_reason(ENDSESSION_LOGOFF),
            "Windows is signing the user out"
        );
        assert!(session_end_reason(ENDSESSION_CLOSEAPP).contains("asked Irminsul to close"));
        assert!(session_end_reason(0).contains("shutting down"));
    }
}
