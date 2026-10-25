//! The minidump writer, in a process of its own.
//!
//! A process cannot safely dump itself. `MiniDumpWriteDump` called from
//! inside suspends every other thread first, and then loads modules of its
//! own; when one of the suspended threads was holding the loader lock (a
//! thread loading a DLL, the session-end watcher creating its window), the
//! dump waits for that lock forever. The crashed thread's bounded wait does
//! not help either: it is one of the threads the dump suspended. The test
//! child of 2026-10-25 sat like that for 1.7 hours.
//!
//! So [`start`] launches a second copy of the executable at startup
//! ([`HANDLER_ARG`], or a test of this module in a test binary), which waits
//! on the app's process handle and a request event. On a crash the app only
//! writes two numbers into memory both share and sets the event, neither of
//! which allocates or takes a lock, and waits for the answer;
//! [`run`] dumps the app from outside, where the app's own locks cannot hold
//! it, appends the outcome to `crash.log` and answers. When the app exits,
//! the handler sees its process handle signalled and exits too.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::windows::io::{AsRawHandle, IntoRawHandle};
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use chrono::Utc;
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, MINIDUMP_EXCEPTION_INFORMATION, MiniDumpWriteDump,
};
use windows::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_ALL_ACCESS, MapViewOfFile, OpenFileMappingW, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateEventW, EVENT_MODIFY_STATE, INFINITE, OpenEventW, OpenProcess,
    PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_VM_READ, SYNCHRONIZATION_SYNCHRONIZE,
    SetEvent, WaitForMultipleObjects,
};
use windows::core::HSTRING;

use super::DUMP_TYPE;

/// The first argument that makes the executable a dump handler instead of the
/// app. `main` checks it before anything else runs.
pub const HANDLER_ARG: &str = "--crash-dump-handler";

/// What the handler is told, in its environment: the app's process id, the
/// prefix of the shared objects' names, and where the dump and the outcome
/// line go.
const ENV_PARENT: &str = "IRMINSUL_DUMP_HANDLER_PARENT";
const ENV_NAMES: &str = "IRMINSUL_DUMP_HANDLER_NAMES";
const ENV_DIR: &str = "IRMINSUL_DUMP_HANDLER_DIR";
const ENV_LOG: &str = "IRMINSUL_DUMP_HANDLER_LOG";

/// The memory both processes map.
#[repr(C)]
struct Shared {
    /// The thread that crashed.
    thread: AtomicU32,
    _padding: u32,
    /// The address of its `EXCEPTION_POINTERS`, in the app's address space;
    /// 0 for a report without them.
    exception: AtomicU64,
}

/// The app's end of the handler, once it is running.
struct Handler {
    request: HANDLE,
    done: HANDLE,
    process: HANDLE,
    shared: *const Shared,
    pid: u32,
}

// SAFETY: handles and a mapping that live as long as the process; the shared
// fields are atomics.
unsafe impl Send for Handler {}
unsafe impl Sync for Handler {}

static HANDLER: OnceLock<Handler> = OnceLock::new();

/// The handler's process id, once it runs. Read by the tests.
#[cfg(test)]
pub(super) fn pid() -> Option<u32> {
    HANDLER.get().map(|handler| handler.pid)
}

/// Create the shared objects and launch the handler. Without it a native
/// crash is still reported, just without a dump.
pub(super) fn start(dump_dir: &Path, crash_log: &Path) {
    if HANDLER.get().is_some() {
        return;
    }
    match launch(dump_dir, crash_log) {
        Ok(handler) => {
            // A second Irminsul process in Task Manager is this one.
            tracing::info!("crash dump handler running as process {}", handler.pid);
            let _ = HANDLER.set(handler);
        }
        Err(e) => {
            tracing::warn!("cannot start the crash dump handler, so a crash gets no dump: {e}")
        }
    }
}

fn launch(dump_dir: &Path, crash_log: &Path) -> anyhow::Result<Handler> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("no random bytes: {e}"))?;
    let names = format!(
        "Local\\irminsul-crash-{}-{:016x}",
        std::process::id(),
        u64::from_le_bytes(nonce)
    );
    // SAFETY: plain Win32 calls; every handle is kept for the life of the
    // process, which is what the crash path needs.
    let handler = unsafe {
        let request = CreateEventW(
            None,
            false,
            false,
            &HSTRING::from(format!("{names}-request")),
        )?;
        let done = CreateEventW(None, true, false, &HSTRING::from(format!("{names}-done")))?;
        let mapping = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_READWRITE,
            0,
            size_of::<Shared>() as u32,
            &HSTRING::from(format!("{names}-shared")),
        )?;
        let view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size_of::<Shared>());
        if view.Value.is_null() {
            return Err(windows::core::Error::from_win32().into());
        }

        let child = handler_command()?
            .env(ENV_PARENT, std::process::id().to_string())
            .env(ENV_NAMES, &names)
            .env(ENV_DIR, dump_dir)
            .env(ENV_LOG, crash_log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW.0)
            .spawn()?;
        let pid = child.id();
        Handler {
            request,
            done,
            process: HANDLE(child.into_raw_handle()),
            shared: view.Value.cast(),
            pid,
        }
    };
    Ok(handler)
}

/// The command line that makes a dump handler of this executable.
fn handler_command() -> std::io::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    #[cfg(not(test))]
    command.arg(HANDLER_ARG);
    // A test binary has no `main` of ours: the handler is a test there.
    #[cfg(test)]
    command.args([
        "crash::native::dump_handler::tests::handler_process",
        "--exact",
        "--include-ignored",
        "--test-threads=1",
    ]);
    Ok(command)
}

/// What [`request`] got back.
pub(super) enum Outcome {
    /// The handler answered; it wrote the outcome to `crash.log` itself.
    Answered,
    /// No handler is running (it never started, or it is gone).
    NoHandler,
    /// It did not answer within `timeout_ms`.
    TimedOut,
}

/// Ask the handler to dump this process. For the crash path: no allocation,
/// no lock, only memory writes and waits.
///
/// # Safety
///
/// `exception` must be null or valid until this returns.
pub(super) unsafe fn request(
    exception: *const EXCEPTION_POINTERS,
    thread: u32,
    timeout_ms: u32,
) -> Outcome {
    let Some(handler) = HANDLER.get() else {
        return Outcome::NoHandler;
    };
    // SAFETY: the mapping lives as long as the process.
    let shared = unsafe { &*handler.shared };
    shared.thread.store(thread, Ordering::SeqCst);
    shared.exception.store(exception as u64, Ordering::SeqCst);
    // SAFETY: handles this process owns for its whole life.
    unsafe {
        if SetEvent(handler.request).is_err() {
            return Outcome::NoHandler;
        }
        // The handler has this thread suspended while it writes the dump,
        // which takes well under a second.
        match WaitForMultipleObjects(&[handler.done, handler.process], false, timeout_ms) {
            WAIT_OBJECT_0 => Outcome::Answered,
            WAIT_TIMEOUT => Outcome::TimedOut,
            // The handler exited without answering, or the wait failed.
            _ => Outcome::NoHandler,
        }
    }
}

/// The handler process: wait for the app to crash or exit. Returns the exit
/// code.
///
/// Nobody reads a handler's output: when it fails, the app finds no answer
/// at its crash and says so in `crash.log` itself.
pub fn run() -> i32 {
    serve().map_or(1, |()| 0)
}

fn serve() -> anyhow::Result<()> {
    let var = |name: &str| -> anyhow::Result<OsString> {
        std::env::var_os(name).ok_or_else(|| anyhow::anyhow!("{name} is not set"))
    };
    let parent: u32 = var(ENV_PARENT)?.to_string_lossy().parse()?;
    let names = var(ENV_NAMES)?.to_string_lossy().into_owned();
    let dump_dir = PathBuf::from(var(ENV_DIR)?);
    let crash_log = PathBuf::from(var(ENV_LOG)?);

    // SAFETY: plain Win32 calls on objects the app created for this process.
    unsafe {
        let process = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SYNCHRONIZE,
            false,
            parent,
        )?;
        let access = EVENT_MODIFY_STATE | SYNCHRONIZATION_SYNCHRONIZE;
        let request = OpenEventW(access, false, &HSTRING::from(format!("{names}-request")))?;
        let done = OpenEventW(access, false, &HSTRING::from(format!("{names}-done")))?;
        let mapping = OpenFileMappingW(
            FILE_MAP_ALL_ACCESS.0,
            false,
            &HSTRING::from(format!("{names}-shared")),
        )?;
        let view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size_of::<Shared>());
        if view.Value.is_null() {
            return Err(windows::core::Error::from_win32().into());
        }
        let shared = &*view.Value.cast::<Shared>();

        // The app exiting (first, so an exit wins a tie) or its request.
        let woken = WaitForMultipleObjects(&[process, request], false, INFINITE);
        if woken.0 != WAIT_OBJECT_0.0 + 1 {
            return Ok(());
        }
        let thread = shared.thread.load(Ordering::SeqCst);
        let exception = shared.exception.load(Ordering::SeqCst);
        let outcome = write_dump(&dump_dir, process, parent, thread, exception);
        append_line(&crash_log, &outcome);
        let _ = SetEvent(done);
        let _ = CloseHandle(process);
    }
    Ok(())
}

/// Write `crash-<UTC time>.dmp` of the app and return the line for
/// `crash.log`.
fn write_dump(dir: &Path, process: HANDLE, pid: u32, thread: u32, exception: u64) -> String {
    let name = format!("crash-{}.dmp", Utc::now().format("%Y-%m-%d_%H-%M-%SZ"));
    let path = dir.join(&name);
    let file = match File::create(&path) {
        Ok(file) => file,
        Err(e) => return format!("minidump: could not create {name} ({e})\n"),
    };
    let info = (exception != 0).then(|| MINIDUMP_EXCEPTION_INFORMATION {
        ThreadId: thread,
        ExceptionPointers: exception as *mut _,
        // The pointers are the app's, read out of its memory.
        ClientPointers: true.into(),
    });
    // SAFETY: a process handle with the access the dump needs, and a file
    // handle this function owns.
    let written = unsafe {
        MiniDumpWriteDump(
            process,
            pid,
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

fn append_line(crash_log: &Path, line: &str) {
    if let Ok(mut file) = OpenOptions::new().append(true).open(crash_log) {
        let _ = file.write_all(line.as_bytes());
        let _ = file.sync_data();
    }
}

#[cfg(test)]
mod tests {
    /// The handler, in a test binary: [`super::handler_command`] starts this
    /// test with the handler's environment. Run any other way, it has nothing
    /// to do.
    #[test]
    fn handler_process() {
        if std::env::var_os(super::ENV_PARENT).is_some() {
            std::process::exit(super::run());
        }
    }
}
