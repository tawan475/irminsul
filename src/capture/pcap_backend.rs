use std::path::PathBuf;

use anyhow::anyhow;
use async_trait::async_trait;
use pcap::{Activated, Active, Capture, ConnectionStatus, Device, Offline, Savefile};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::capture::{CaptureBackend, CaptureError, CaptureSource, PORT_RANGE, Result};

pub struct PcapBackend {
    packet_rx: UnboundedReceiver<Result<Vec<u8>>>,
}

struct CaptureInfo<T: Activated> {
    device_identifier: String,
    capture: Capture<T>,
    savefile: Option<Savefile>,
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

        match source {
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
                for device in devices {
                    if !Self::should_capture_on_device(&device) {
                        tracing::info!(
                            "Excluded device {} from capture",
                            PcapBackend::get_device_identifier(&device)
                        );
                        continue;
                    }

                    match Self::setup_device_capture(device, &filter_expression, &savefile_path) {
                        Ok(capture) => {
                            successful_captures.push(capture);
                        }
                        Err(_) => {
                            // Ignore; we probably shouldn't have captured on that device anyways
                        }
                    }
                }

                // 3. Process results
                Self::handle_results(successful_captures, packet_tx)?;
            }

            CaptureSource::File(savefile_path) => {
                // 1. Read capture savefile
                let mut successful_captures = Vec::new();
                let capture = Self::setup_file_capture(&savefile_path, &filter_expression)?;
                successful_captures.push(capture);

                // 2. Process results
                Self::handle_results(successful_captures, packet_tx)?;
            }
        }

        Ok(Self { packet_rx })
    }

    fn setup_device_capture(
        device: Device,
        filter_expression: &str,
        savefile_path: &Option<PathBuf>,
    ) -> Result<CaptureInfo<Active>> {
        let device_identifier = Self::get_device_identifier(&device);

        let mut capture = Capture::from_device(device)
            .map_err(|e| CaptureError::Capture {
                has_captured: false,
                error: e.into(),
            })?
            .immediate_mode(true)
            .open()
            .map_err(|e| CaptureError::Capture {
                has_captured: false,
                error: e.into(),
            })?;

        capture
            .filter(filter_expression, true)
            .map_err(|e| CaptureError::Filter(e.into()))?;

        let savefile = if let Some(savefile_path) = savefile_path {
            Some(
                capture
                    .savefile(savefile_path)
                    .map_err(|err| CaptureError::SavefileError(err.into()))?,
            )
        } else {
            None
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

    fn packet_loop(
        mut capture: Capture<impl Activated>,
        packet_tx: UnboundedSender<Result<Vec<u8>>>,
        device_identifier: String,
        mut savefile: Option<Savefile>,
    ) {
        let mut has_captured = false;

        loop {
            match capture.next_packet() {
                Ok(packet) => {
                    has_captured = true;

                    if let Some(ref mut savefile) = savefile {
                        savefile.write(&packet);
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
                Err(err) => {
                    tracing::info!(
                        "Packet loop for device {} ending (has_captured: {}): capture error: {}",
                        device_identifier,
                        has_captured,
                        err
                    );
                    let _ = packet_tx.send(Err(CaptureError::Capture {
                        has_captured,
                        error: err.into(),
                    }));
                    break;
                }
            }
        }
    }

    fn handle_results(
        successful_captures: Vec<CaptureInfo<impl Activated + 'static>>,
        packet_tx: UnboundedSender<Result<Vec<u8>>>,
    ) -> Result<()> {
        // 1. Handle capture results
        if successful_captures.is_empty() {
            return Err(CaptureError::Capture {
                has_captured: false,
                error: anyhow!("No capture device available"),
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
        for capture_info in successful_captures {
            let packet_tx = packet_tx.clone();
            std::thread::spawn(move || {
                Self::packet_loop(
                    capture_info.capture,
                    packet_tx,
                    capture_info.device_identifier,
                    capture_info.savefile,
                )
            });
        }

        Ok(())
    }
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
