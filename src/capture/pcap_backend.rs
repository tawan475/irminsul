use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use async_trait::async_trait;
use pcap::{Activated, Active, BreakLoop, Capture, ConnectionStatus, Device, Offline, Savefile};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::capture::{CaptureBackend, CaptureError, CaptureSource, PORT_RANGE, Result};

/// How long a blocking read waits before returning `TimeoutExpired`. This is
/// what gives each packet loop a chance to notice the stop flag; without it a
/// quiet interface blocks in libpcap forever and the thread can never be
/// reclaimed.
const READ_TIMEOUT_MS: i32 = 250;

/// Flush the savefile every this many packets, so an abrupt exit loses at most
/// this much of the tail instead of everything buffered by libpcap.
const SAVEFILE_FLUSH_INTERVAL: u32 = 64;

/// Upper bound on how long dropping the backend waits for its capture threads.
/// Reaching it means a driver honoured neither `pcap_breakloop` nor the read
/// timeout; we then leak the thread rather than hang the application.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Longest device-derived fragment allowed in a per-device savefile name.
const MAX_DEVICE_FILENAME_FRAGMENT: usize = 64;

pub struct PcapBackend {
    packet_rx: UnboundedReceiver<Result<Vec<u8>>>,
    /// Held purely for its `Drop`, which stops the capture threads when this
    /// backend goes away.
    #[allow(dead_code)]
    running: RunningCaptures,
}

/// Handles for the threads started by one `PcapBackend`, and the machinery to
/// stop them again. Dropping this stops every capture thread; without it each
/// restarted capture stranded one thread and one open device handle per
/// interface for the lifetime of the process.
struct RunningCaptures {
    stop: Arc<AtomicBool>,
    live_threads: Arc<AtomicUsize>,
    breakloops: Vec<BreakLoop>,
    threads: Vec<JoinHandle<()>>,
}

impl RunningCaptures {
    fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            live_threads: Arc::new(AtomicUsize::new(0)),
            breakloops: Vec::new(),
            threads: Vec::new(),
        }
    }
}

impl Drop for RunningCaptures {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);

        // Wake anything parked inside libpcap. The read timeout alone would
        // also do it, just up to READ_TIMEOUT_MS later.
        for breakloop in &self.breakloops {
            breakloop.breakloop();
        }

        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        while self.live_threads.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
            std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
        }

        let stragglers = self.live_threads.load(Ordering::Acquire);
        if stragglers > 0 {
            // Joining now could block forever. The threads own a clone of the
            // stop flag, so they still exit on their own; detach them.
            tracing::warn!(
                "{stragglers} pcap capture thread(s) did not stop within {SHUTDOWN_TIMEOUT:?}; \
                 detaching them"
            );
            self.threads.clear();
            return;
        }

        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                tracing::warn!("A pcap capture thread panicked");
            }
        }
    }
}

struct CaptureInfo<T: Activated> {
    device_identifier: String,
    capture: Capture<T>,
    savefile: Option<Savefile>,
}

/// Why one device's packet loop stopped, handed back to the thread that owns the
/// `packet_tx` clone instead of being pushed onto the shared channel.
struct LoopOutcome {
    /// Whether this device ever yielded a packet.
    has_captured: bool,
    /// `None` when the loop stopped for an ordinary reason: the stop flag, or
    /// the receiver going away.
    error: Option<anyhow::Error>,
}

impl PcapBackend {
    fn get_device_identifier(device: &Device) -> String {
        format!(
            "{} (desc {})",
            device.name,
            device.desc.as_deref().unwrap_or("None")
        )
    }

    fn should_capture_on_device(device: &Device) -> bool {
        let flags = &device.flags;
        flags.is_up()
            && flags.is_running()
            && !flags.is_loopback()
            && !device.addresses.is_empty()
            && flags.connection_status != ConnectionStatus::Disconnected
    }

    pub fn new(source: CaptureSource) -> Result<Self> {
        let filter_expression = format!("udp and portrange {}-{}", PORT_RANGE.0, PORT_RANGE.1);
        let (packet_tx, packet_rx) = mpsc::unbounded_channel();

        let running = match source {
            CaptureSource::Device(savefile_path) => {
                // 1. Find all devices
                let devices = Device::list().map_err(|e| CaptureError::Capture {
                    has_captured: false,
                    error: e.into(),
                })?;

                tracing::info!("Found {} available devices", devices.len());
                for (i, device) in devices.iter().enumerate() {
                    tracing::info!(
                        "Available device {}/{}: {}, details: {:?}",
                        i + 1,
                        devices.len(),
                        PcapBackend::get_device_identifier(device),
                        device
                    );
                }

                // 2. Try to set up capture on all of them (we expect some of them to fail)
                let mut successful_captures = Vec::new();
                let mut failures: Vec<(String, CaptureError)> = Vec::new();
                for device in devices {
                    // Computed up front: `setup_device_capture` consumes the device.
                    let device_identifier = Self::get_device_identifier(&device);

                    if !Self::should_capture_on_device(&device) {
                        tracing::info!("Excluded device {device_identifier} from capture");
                        continue;
                    }

                    match Self::setup_device_capture(
                        device,
                        &filter_expression,
                        savefile_path.as_deref(),
                    ) {
                        Ok(capture) => {
                            successful_captures.push(capture);
                        }
                        // A savefile that cannot be opened is a problem with the
                        // path the user gave, not with this device. Fail fast and
                        // distinctly instead of letting it look like "no device".
                        Err(err @ CaptureError::SavefileError(_)) => return Err(err),
                        Err(err) => {
                            // Previously discarded, which left one generic error
                            // for permission problems, busy devices and bad
                            // filters alike.
                            tracing::warn!("Could not capture on {device_identifier}: {err}");
                            failures.push((device_identifier, err));
                        }
                    }
                }

                // 3. Process results
                Self::handle_results(successful_captures, &failures, packet_tx)?
            }

            CaptureSource::File(savefile_path) => {
                // 1. Read capture savefile
                let mut successful_captures = Vec::new();
                let capture = Self::setup_file_capture(&savefile_path, &filter_expression)?;
                successful_captures.push(capture);

                // 2. Process results
                Self::handle_results(successful_captures, &[], packet_tx)?
            }
        };

        Ok(Self { packet_rx, running })
    }

    fn setup_device_capture(
        device: Device,
        filter_expression: &str,
        savefile_path: Option<&Path>,
    ) -> Result<CaptureInfo<Active>> {
        let device_identifier = Self::get_device_identifier(&device);
        let device_name = device.name.clone();

        let mut capture = Capture::from_device(device)
            .map_err(|e| CaptureError::Capture {
                has_captured: false,
                error: e.into(),
            })?
            .immediate_mode(true)
            // Bounded reads are what let the packet loop observe its stop flag.
            .timeout(READ_TIMEOUT_MS)
            .open()
            .map_err(|e| CaptureError::Capture {
                has_captured: false,
                error: e.into(),
            })?;

        capture
            .filter(filter_expression, true)
            .map_err(|e| CaptureError::Filter(e.into()))?;

        let savefile = match savefile_path {
            Some(base) => {
                let path = next_savefile_path(base, &device_name);
                tracing::info!(
                    "Recording {device_identifier} to savefile {}",
                    path.display()
                );
                Some(
                    capture
                        .savefile(&path)
                        .map_err(|err| CaptureError::SavefileError(err.into()))?,
                )
            }
            None => None,
        };

        Ok(CaptureInfo {
            device_identifier,
            capture,
            savefile,
        })
    }

    fn setup_file_capture(
        savefile_path: &PathBuf,
        filter_expression: &str,
    ) -> Result<CaptureInfo<Offline>> {
        let device_identifier = String::from("FILE");

        let mut capture = Capture::from_file(savefile_path).map_err(|e| CaptureError::Capture {
            has_captured: false,
            error: e.into(),
        })?;

        capture
            .filter(filter_expression, true)
            .map_err(|e| CaptureError::Filter(e.into()))?;

        Ok(CaptureInfo {
            device_identifier,
            capture,
            savefile: None,
        })
    }

    /// Pump one device's packets into `packet_tx` until it is asked to stop or
    /// the device fails.
    ///
    /// Failures are *returned*, never sent: `packet_tx` is shared with every
    /// other device's loop, and an `Err` on it ends capture everywhere. Whether
    /// this device dying is worth ending capture over is [`finish_thread`]'s
    /// call to make, because only it knows how many devices are left.
    fn packet_loop(
        mut capture: Capture<impl Activated>,
        packet_tx: &UnboundedSender<Result<Vec<u8>>>,
        device_identifier: &str,
        mut savefile: Option<Savefile>,
        stop: &AtomicBool,
    ) -> LoopOutcome {
        let mut has_captured = false;
        let mut unflushed: u32 = 0;
        let mut error = None;

        while !stop.load(Ordering::Relaxed) {
            match capture.next_packet() {
                Ok(packet) => {
                    has_captured = true;

                    if let Some(savefile) = savefile.as_mut() {
                        // `Savefile::write` returns nothing and swallows errors,
                        // so flushing periodically is the only way to notice a
                        // full or unwritable disk -- and to bound how much of
                        // the recording an abrupt exit loses.
                        savefile.write(&packet);
                        unflushed += 1;
                        if unflushed >= SAVEFILE_FLUSH_INTERVAL {
                            unflushed = 0;
                            if let Err(err) = savefile.flush() {
                                tracing::warn!(
                                    "Could not flush savefile for device {device_identifier}: {err}"
                                );
                            }
                        }
                    }

                    if packet_tx.send(Ok(packet.data.to_vec())).is_err() {
                        tracing::info!(
                            "Packet loop for device {} ending (has_captured: {}): channel closed",
                            device_identifier,
                            has_captured
                        );
                        break;
                    }
                }
                // Not an error: this is the loop's opportunity to re-check the
                // stop flag. Treating it as fatal would kill capture the first
                // time an interface went quiet for READ_TIMEOUT_MS.
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(err) => {
                    if stop.load(Ordering::Relaxed) {
                        // `pcap_breakloop` during shutdown surfaces here; it is
                        // not worth reporting upstream.
                        break;
                    }

                    tracing::info!(
                        "Packet loop for device {} ending (has_captured: {}): capture error: {}",
                        device_identifier,
                        has_captured,
                        err
                    );
                    error = Some(err.into());
                    break;
                }
            }
        }

        if let Some(savefile) = savefile.as_mut()
            && let Err(err) = savefile.flush()
        {
            tracing::warn!(
                "Could not flush savefile for device {device_identifier} while stopping: {err}"
            );
        }
        // Explicit for clarity: this closes the dump file. Before the loop had a
        // stop signal it never ran, which is why recordings ended mid-packet.
        drop(savefile);

        tracing::debug!(
            "Packet loop for device {device_identifier} exited (has_captured: {has_captured})"
        );

        LoopOutcome {
            has_captured,
            error,
        }
    }

    fn handle_results(
        successful_captures: Vec<CaptureInfo<impl Activated + 'static>>,
        failures: &[(String, CaptureError)],
        packet_tx: UnboundedSender<Result<Vec<u8>>>,
    ) -> Result<RunningCaptures> {
        // 1. Handle capture results
        if successful_captures.is_empty() {
            return Err(CaptureError::Capture {
                has_captured: false,
                error: no_device_error(failures),
            });
        }

        tracing::info!("Capturing on {} devices:", successful_captures.len());
        for (i, capture_info) in successful_captures.iter().enumerate() {
            tracing::info!(
                "Capture device {}/{}: {}",
                i + 1,
                successful_captures.len(),
                capture_info.device_identifier
            );
        }

        // 2. Set up packet loops for each successful capture
        let mut running = RunningCaptures::new();
        running.threads.reserve(successful_captures.len());
        running.breakloops.reserve(successful_captures.len());

        // Shared so the fatal error can say whether capture ever worked on
        // *any* device, not just on whichever one happened to stop last.
        let any_captured = Arc::new(AtomicBool::new(false));

        for mut capture_info in successful_captures {
            running
                .breakloops
                .push(capture_info.capture.breakloop_handle());

            let CaptureInfo {
                device_identifier,
                capture,
                savefile,
            } = capture_info;

            let packet_tx = packet_tx.clone();
            let stop = running.stop.clone();
            let live_threads = running.live_threads.clone();
            let any_captured = any_captured.clone();
            live_threads.fetch_add(1, Ordering::Release);

            running.threads.push(std::thread::spawn(move || {
                let outcome =
                    Self::packet_loop(capture, &packet_tx, &device_identifier, savefile, &stop);

                if let Some(error) =
                    finish_thread(&live_threads, &any_captured, &device_identifier, outcome)
                {
                    let _ = packet_tx.send(Err(error));
                }

                // Dropping the final clone is what closes the channel and makes
                // `next_packet` return `CaptureClosed`, so hold it until the
                // report above has gone out.
                drop(packet_tx);
            }));
        }

        Ok(running)
    }
}

/// Build the error returned when no device could be opened, naming the reason
/// each candidate was rejected.
fn no_device_error(failures: &[(String, CaptureError)]) -> anyhow::Error {
    if failures.is_empty() {
        return anyhow!("No capture device available");
    }

    let details = failures
        .iter()
        .map(|(device, err)| format!("{device}: {err}"))
        .collect::<Vec<_>>()
        .join("; ");

    anyhow!(
        "No capture device available ({} device(s) could not be opened: {details})",
        failures.len()
    )
}

/// Retire one finished packet loop, and decide what it reports upstream.
///
/// One device failing must not end capture on the others. Capture runs on every
/// eligible interface precisely because only one of them carries the game's
/// traffic, so a VPN adapter going down, a USB NIC being unplugged or a Wi-Fi
/// reset must not take the interface the game is on with it. Such an error is
/// logged and swallowed.
///
/// Only the thread that takes `live_threads` from 1 to 0 -- the last device
/// still capturing -- turns its error into the fatal `CaptureError` that stops
/// `next_packet`. A last device that stopped *without* an error reports nothing:
/// dropping the final `packet_tx` clone closes the channel and `next_packet`
/// returns `CaptureClosed` by itself.
fn finish_thread(
    live_threads: &AtomicUsize,
    any_captured: &AtomicBool,
    device_identifier: &str,
    outcome: LoopOutcome,
) -> Option<CaptureError> {
    if outcome.has_captured {
        any_captured.store(true, Ordering::Release);
    }

    // Sequenced after the store above, so the last thread's `Acquire` load below
    // sees what every earlier device recorded.
    let was_last = live_threads.fetch_sub(1, Ordering::AcqRel) == 1;

    let Some(error) = outcome.error else {
        tracing::debug!("Capture on {device_identifier} stopped");
        return None;
    };

    if !was_last {
        tracing::warn!(
            "Capture on {device_identifier} stopped: {error}. Still capturing on other device(s)."
        );
        return None;
    }

    tracing::error!("Capture on {device_identifier} stopped: {error}. No devices left.");
    Some(CaptureError::Capture {
        has_captured: any_captured.load(Ordering::Acquire),
        error: anyhow!("{device_identifier}: {error}"),
    })
}

/// How many savefiles this process has already opened per device path.
///
/// `pcap_dump_open` truncates, so a second open of a path this process is
/// already recording to throws the first recording away. `Monitor::start_capture`
/// is documented to replace a capture that is still running, which rebuilds the
/// backend; and `RunningCaptures::drop` detaches any thread that outlived
/// `SHUTDOWN_TIMEOUT` rather than hanging, so an outgoing dumper can still be
/// flushing while the incoming one opens its own. `pcap_dump_open_append` is
/// gated behind `libpcap_1_7_2` and so is not always available, so instead each
/// re-open gets its own file.
///
/// Today the UI sends `StartCapture` only at startup, so in practice the
/// generation is always 0 -- this keeps the guarantee from resting on that.
fn savefile_generations() -> &'static Mutex<HashMap<PathBuf, u32>> {
    static GENERATIONS: OnceLock<Mutex<HashMap<PathBuf, u32>>> = OnceLock::new();
    GENERATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Pick the savefile path for one device, never returning a path this process
/// has already handed out.
fn next_savefile_path(base: &Path, device_name: &str) -> PathBuf {
    let root = savefile_path_for_device(base, device_name);

    let generation = {
        let mut generations = savefile_generations()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let counter = generations.entry(root.clone()).or_insert(0);
        let generation = *counter;
        *counter += 1;
        generation
    };

    savefile_path_for_generation(&root, generation)
}

/// Derive a per-device savefile path from the path the user asked for.
///
/// One `Savefile` is opened per device, and libpcap gives each its own file
/// handle with its own header. Pointing them all at one path made every dumper
/// truncate the file the others were writing, producing a capture Wireshark
/// rejects. `session.pcap` on `eth0` therefore becomes `session-eth0.pcap`.
fn savefile_path_for_device(base: &Path, device_name: &str) -> PathBuf {
    let mut fragment: String = device_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    fragment.truncate(MAX_DEVICE_FILENAME_FRAGMENT);
    let fragment = fragment.trim_matches('_');
    let fragment = if fragment.is_empty() {
        "device"
    } else {
        fragment
    };

    let stem = base
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("capture");

    let mut file_name = format!("{stem}-{fragment}");
    if let Some(extension) = base.extension().and_then(|ext| ext.to_str()) {
        file_name.push('.');
        file_name.push_str(extension);
    }

    base.with_file_name(file_name)
}

/// Disambiguate repeated opens of the same per-device path: the first capture
/// of a session writes `session-eth0.pcap`, the next `session-eth0.2.pcap`.
fn savefile_path_for_generation(root: &Path, generation: u32) -> PathBuf {
    if generation == 0 {
        return root.to_path_buf();
    }

    let stem = root
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("capture");

    let mut file_name = format!("{stem}.{}", generation + 1);
    if let Some(extension) = root.extension().and_then(|ext| ext.to_str()) {
        file_name.push('.');
        file_name.push_str(extension);
    }

    root.with_file_name(file_name)
}

#[async_trait]
impl CaptureBackend for PcapBackend {
    async fn next_packet(&mut self) -> Result<Vec<u8>> {
        match self.packet_rx.recv().await {
            Some(Ok(packet)) => Ok(packet),
            Some(Err(err)) => Err(err),
            None => Err(CaptureError::CaptureClosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_device_savefile_names_keep_the_stem_and_extension() {
        let path = savefile_path_for_device(Path::new("session.pcap"), "eth0");
        assert_eq!(path.file_name().unwrap(), "session-eth0.pcap");
    }

    #[test]
    fn per_device_savefile_names_stay_in_the_requested_directory() {
        let base = Path::new("captures").join("session.pcap");
        let path = savefile_path_for_device(&base, "eth0");

        assert_eq!(path.parent(), Some(Path::new("captures")));
        assert_eq!(path.file_name().unwrap(), "session-eth0.pcap");
    }

    #[test]
    fn windows_device_names_are_sanitised() {
        let path = savefile_path_for_device(
            Path::new("session.pcap"),
            r"\Device\NPF_{2CD1B2C4-1A2B-3C4D}",
        );
        assert_eq!(
            path.file_name().unwrap(),
            "session-Device_NPF__2CD1B2C4-1A2B-3C4D.pcap"
        );
    }

    #[test]
    fn distinct_devices_never_share_a_savefile() {
        // The whole point of the fix: two dumpers must not target one path.
        let a = savefile_path_for_device(Path::new("session.pcap"), "eth0");
        let b = savefile_path_for_device(Path::new("session.pcap"), "wlan0");
        assert_ne!(a, b);
    }

    #[test]
    fn a_path_without_an_extension_keeps_having_none() {
        let path = savefile_path_for_device(Path::new("session"), "eth0");
        assert_eq!(path.file_name().unwrap(), "session-eth0");
        assert_eq!(path.extension(), None);
    }

    #[test]
    fn an_unusable_device_name_falls_back_to_a_placeholder() {
        let path = savefile_path_for_device(Path::new("session.pcap"), "///");
        assert_eq!(path.file_name().unwrap(), "session-device.pcap");
    }

    #[test]
    fn long_device_names_are_truncated() {
        let path = savefile_path_for_device(Path::new("session.pcap"), &"a".repeat(200));
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(
            name.len(),
            "session-".len() + MAX_DEVICE_FILENAME_FRAGMENT + ".pcap".len()
        );
    }

    #[test]
    fn the_first_capture_of_a_session_uses_the_plain_per_device_path() {
        let root = Path::new("session-eth0.pcap");
        assert_eq!(savefile_path_for_generation(root, 0), root);
    }

    #[test]
    fn later_captures_never_reuse_an_earlier_path() {
        let root = Path::new("session-eth0.pcap");
        let mut seen = std::collections::HashSet::new();

        for generation in 0..5 {
            let path = savefile_path_for_generation(root, generation);
            assert!(seen.insert(path), "generation {generation} reused a path");
        }

        assert_eq!(
            savefile_path_for_generation(root, 1).file_name().unwrap(),
            "session-eth0.2.pcap"
        );
        assert_eq!(
            savefile_path_for_generation(root, 4).file_name().unwrap(),
            "session-eth0.5.pcap"
        );
    }

    #[test]
    fn generation_suffixes_survive_a_missing_extension() {
        let path = savefile_path_for_generation(Path::new("session-eth0"), 1);
        assert_eq!(path.file_name().unwrap(), "session-eth0.2");
    }

    #[test]
    fn next_savefile_path_hands_out_a_fresh_path_every_time() {
        // The registry is process-wide, so use a device name no other test uses.
        let base = Path::new("registry-test.pcap");
        let first = next_savefile_path(base, "unique-device-for-this-test");
        let second = next_savefile_path(base, "unique-device-for-this-test");
        let other_device = next_savefile_path(base, "another-unique-device");

        assert_eq!(
            first.file_name().unwrap(),
            "registry-test-unique-device-for-this-test.pcap"
        );
        assert_ne!(first, second);
        assert_ne!(first, other_device);
        assert_ne!(second, other_device);
    }

    fn outcome(has_captured: bool, error: Option<&str>) -> LoopOutcome {
        LoopOutcome {
            has_captured,
            error: error.map(|message| anyhow!("{message}")),
        }
    }

    #[test]
    fn one_device_failing_does_not_end_capture_on_the_others() {
        // The regression this guards: a single device's `Err` used to go
        // straight onto the shared channel, so `next_packet` returned it, the
        // backend was dropped, and every *other* interface stopped with it.
        let live = AtomicUsize::new(3);
        let any_captured = AtomicBool::new(false);

        assert!(
            finish_thread(
                &live,
                &any_captured,
                "vpn0",
                outcome(false, Some("device removed"))
            )
            .is_none()
        );
        assert!(
            finish_thread(
                &live,
                &any_captured,
                "usb0",
                outcome(false, Some("device removed"))
            )
            .is_none()
        );
        assert_eq!(live.load(Ordering::Acquire), 1);
    }

    #[test]
    fn the_last_device_left_reports_the_fatal_error() {
        let live = AtomicUsize::new(1);
        let any_captured = AtomicBool::new(false);

        let error = finish_thread(
            &live,
            &any_captured,
            "eth0",
            outcome(true, Some("read failed")),
        )
        .expect("the last device must end capture");

        match error {
            CaptureError::Capture {
                has_captured,
                error,
            } => {
                assert!(has_captured);
                let message = error.to_string();
                assert!(message.contains("eth0"), "{message}");
                assert!(message.contains("read failed"), "{message}");
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(live.load(Ordering::Acquire), 0);
    }

    #[test]
    fn the_fatal_error_reports_traffic_seen_on_any_device() {
        // eth0 saw packets and died first; wlan0 never saw any and dies last.
        // "has_captured: false" would misreport that as a capture that never
        // worked at all.
        let live = AtomicUsize::new(2);
        let any_captured = AtomicBool::new(false);

        assert!(finish_thread(&live, &any_captured, "eth0", outcome(true, Some("boom"))).is_none());
        let error = finish_thread(&live, &any_captured, "wlan0", outcome(false, Some("boom")))
            .expect("the last device must end capture");

        match error {
            CaptureError::Capture { has_captured, .. } => assert!(has_captured),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_clean_stop_reports_nothing_and_lets_the_channel_close() {
        // Shutdown and "receiver went away" both land here. Reporting an error
        // would turn an orderly stop into a toast about a broken capture.
        let live = AtomicUsize::new(1);
        let any_captured = AtomicBool::new(false);

        assert!(finish_thread(&live, &any_captured, "eth0", outcome(true, None)).is_none());
        assert_eq!(live.load(Ordering::Acquire), 0);
    }

    #[test]
    fn exactly_one_thread_reports_when_every_device_fails_at_once() {
        const DEVICES: usize = 8;

        let live = AtomicUsize::new(DEVICES);
        let any_captured = AtomicBool::new(false);
        let reports = AtomicUsize::new(0);
        // Shared by reference, so each `move` closure copies the borrow rather
        // than trying to take the atomic itself.
        let (live, any_captured, reports) = (&live, &any_captured, &reports);

        std::thread::scope(|scope| {
            for i in 0..DEVICES {
                scope.spawn(move || {
                    let device = format!("device{i}");
                    if finish_thread(live, any_captured, &device, outcome(true, Some("boom")))
                        .is_some()
                    {
                        reports.fetch_add(1, Ordering::AcqRel);
                    }
                });
            }
        });

        assert_eq!(reports.load(Ordering::Acquire), 1);
        assert_eq!(live.load(Ordering::Acquire), 0);
    }

    #[test]
    fn no_device_error_lists_every_rejection_reason() {
        let failures = vec![
            (
                "eth0 (desc None)".to_string(),
                CaptureError::Capture {
                    has_captured: false,
                    error: anyhow!("permission denied"),
                },
            ),
            (
                "wlan0 (desc None)".to_string(),
                CaptureError::Filter(anyhow!("bad filter")),
            ),
        ];

        let message = no_device_error(&failures).to_string();
        assert!(message.contains("2 device(s)"), "{message}");
        assert!(message.contains("eth0 (desc None)"), "{message}");
        assert!(message.contains("permission denied"), "{message}");
        assert!(message.contains("wlan0 (desc None)"), "{message}");
        assert!(message.contains("bad filter"), "{message}");
    }

    #[test]
    fn no_device_error_without_failures_keeps_the_original_message() {
        assert_eq!(
            no_device_error(&[]).to_string(),
            "No capture device available"
        );
    }
}
