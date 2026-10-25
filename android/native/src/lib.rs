//! Native side of irminsul's Android app (phase 0 spike).
//!
//! The app's `VpnService` routes only the game's package into a tun device
//! and hands its file descriptor here. Every packet the game sends is read
//! from the tun, every reply is written back to it, and in between a
//! userspace stack (`ipstack`) turns them into TCP and UDP flows that go out
//! through ordinary sockets. The app itself is not in the VPN's allowed list,
//! so those sockets bypass the tunnel without `protect()`.
//!
//! The game's KCP traffic (UDP 22101–22102, both directions) is copied aside
//! as it passes, unchanged, into a pcap file (`LINKTYPE_RAW`), which
//! `irminsul --replay-export` reads. Nothing is altered on the way through.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

/// The game server's KCP ports (irminsul's `capture::PORT_RANGE`).
const GAME_PORTS: (u16, u16) = (22101, 22102);
/// `LINKTYPE_RAW`: bare IPv4/IPv6 packets, what the tee writes.
const LINKTYPE_RAW: u32 = 101;
const MTU: u16 = 1500;

#[derive(Default)]
struct Stats {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    game_packets: AtomicU64,
    game_bytes: AtomicU64,
    tcp_flows: AtomicU64,
    udp_flows: AtomicU64,
    flow_errors: AtomicU64,
}

impl Stats {
    fn line(&self) -> String {
        format!(
            "in={} out={} game_packets={} game_bytes={} tcp_flows={} udp_flows={} flow_errors={}",
            self.packets_in.load(Ordering::Relaxed),
            self.packets_out.load(Ordering::Relaxed),
            self.game_packets.load(Ordering::Relaxed),
            self.game_bytes.load(Ordering::Relaxed),
            self.tcp_flows.load(Ordering::Relaxed),
            self.udp_flows.load(Ordering::Relaxed),
            self.flow_errors.load(Ordering::Relaxed),
        )
    }
}

struct Running {
    runtime: tokio::runtime::Runtime,
    stop: oneshot::Sender<()>,
    stats: Arc<Stats>,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

/// UDP source/destination ports of a bare IP packet, or `None` when it is
/// not UDP. IPv6 extension headers are not walked (the game sends none).
fn udp_ports(packet: &[u8]) -> Option<(u16, u16)> {
    let (proto, offset) = match packet.first()? >> 4 {
        4 => (*packet.get(9)?, usize::from(packet[0] & 0x0f) * 4),
        6 => (*packet.get(6)?, 40),
        _ => return None,
    };
    if proto != 17 {
        return None;
    }
    let ports = packet.get(offset..offset + 4)?;
    Some((
        u16::from_be_bytes([ports[0], ports[1]]),
        u16::from_be_bytes([ports[2], ports[3]]),
    ))
}

fn is_game_packet(packet: &[u8]) -> bool {
    let in_range = |p: u16| (GAME_PORTS.0..=GAME_PORTS.1).contains(&p);
    udp_ports(packet).is_some_and(|(src, dst)| in_range(src) || in_range(dst))
}

/// The tun file descriptor as the async device `ipstack` reads and writes,
/// one packet per call, copying game packets to the tee on the way.
struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    tee: mpsc::UnboundedSender<(SystemTime, Vec<u8>)>,
    stats: Arc<Stats>,
}

impl TunDevice {
    fn new(fd: OwnedFd, tee: mpsc::UnboundedSender<(SystemTime, Vec<u8>)>, stats: Arc<Stats>) -> io::Result<Self> {
        let raw = fd.as_raw_fd();
        // SAFETY: `raw` is the open tun descriptor we own.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor is owned by the `AsyncFd` from here on and
        // closed only when it is dropped.
        let fd = unsafe { AsyncFd::register(fd) }.map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Self { fd, tee, stats })
    }

    fn copy_if_game(&self, packet: &[u8]) {
        if is_game_packet(packet) {
            self.stats.game_packets.fetch_add(1, Ordering::Relaxed);
            self.stats.game_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
            let _ = self.tee.send((SystemTime::now(), packet.to_vec()));
        }
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is valid for `buf.len()` bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is valid for `buf.len()` bytes.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

impl AsyncRead for TunDevice {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = ready!(this.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| read_fd(fd.as_raw_fd(), unfilled)) {
                Ok(Ok(n)) => {
                    this.stats.packets_out.fetch_add(1, Ordering::Relaxed);
                    this.copy_if_game(&buf.initialize_unfilled()[..n]);
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = ready!(this.fd.poll_write_ready(cx))?;
            match guard.try_io(|fd| write_fd(fd.as_raw_fd(), packet)) {
                Ok(Ok(n)) => {
                    this.stats.packets_in.fetch_add(1, Ordering::Relaxed);
                    this.copy_if_game(packet);
                    return Poll::Ready(Ok(n));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Writes the tee's packets as a classic pcap file, flushed every second so
/// a capture pulled while the VPN still runs is readable up to then.
async fn write_pcap(path: String, mut packets: mpsc::UnboundedReceiver<(SystemTime, Vec<u8>)>) -> io::Result<()> {
    let mut out = BufWriter::new(File::create(&path)?);
    out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
    out.write_all(&2u16.to_le_bytes())?;
    out.write_all(&4u16.to_le_bytes())?;
    out.write_all(&0i32.to_le_bytes())?;
    out.write_all(&0u32.to_le_bytes())?;
    out.write_all(&u32::from(MTU).max(65535).to_le_bytes())?;
    out.write_all(&LINKTYPE_RAW.to_le_bytes())?;
    out.flush()?;
    let mut flush = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            packet = packets.recv() => {
                let Some((at, data)) = packet else { break };
                let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
                out.write_all(&(since.as_secs() as u32).to_le_bytes())?;
                out.write_all(&since.subsec_micros().to_le_bytes())?;
                out.write_all(&(data.len() as u32).to_le_bytes())?;
                out.write_all(&(data.len() as u32).to_le_bytes())?;
                out.write_all(&data)?;
            }
            _ = flush.tick() => out.flush()?,
        }
    }
    out.flush()
}

async fn forward_tcp(mut flow: IpStackTcpStream, stats: Arc<Stats>) {
    let peer = flow.peer_addr();
    let upstream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(peer)).await;
    let mut upstream = match upstream {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            stats.flow_errors.fetch_add(1, Ordering::Relaxed);
            log::debug!("tcp connect {peer}: {e}");
            return;
        }
        Err(_) => {
            stats.flow_errors.fetch_add(1, Ordering::Relaxed);
            log::debug!("tcp connect {peer}: timed out");
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    if let Err(e) = tokio::io::copy_bidirectional(&mut flow, &mut upstream).await {
        log::debug!("tcp {peer}: {e}");
    }
    let _ = upstream.shutdown().await;
    let _ = flow.shutdown().await;
}

async fn forward_udp(mut flow: IpStackUdpStream, stats: Arc<Stats>) {
    let peer = flow.peer_addr();
    let bind: SocketAddr = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let socket = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            stats.flow_errors.fetch_add(1, Ordering::Relaxed);
            log::debug!("udp bind for {peer}: {e}");
            return;
        }
    };
    if let Err(e) = socket.connect(peer).await {
        stats.flow_errors.fetch_add(1, Ordering::Relaxed);
        log::debug!("udp connect {peer}: {e}");
        return;
    }
    let mut from_game = vec![0u8; usize::from(MTU)];
    let mut from_server = vec![0u8; 65535];
    loop {
        tokio::select! {
            read = flow.read(&mut from_game) => match read {
                // ipstack yields 0 at the end of the flow (an empty
                // datagram reads the same; the game sends none).
                Ok(0) | Err(_) => break,
                Ok(n) => if socket.send(&from_game[..n]).await.is_err() { break },
            },
            recv = socket.recv(&mut from_server) => match recv {
                Ok(n) => if flow.write_all(&from_server[..n]).await.is_err() { break },
                Err(e) => {
                    log::debug!("udp {peer}: {e}");
                    break;
                }
            },
        }
    }
}

async fn run(fd: OwnedFd, pcap_path: String, stats: Arc<Stats>, stop: oneshot::Receiver<()>) -> anyhow::Result<()> {
    let (tee, packets) = mpsc::unbounded_channel();
    let writer = tokio::spawn(write_pcap(pcap_path, packets));
    let device = TunDevice::new(fd, tee, stats.clone())?;

    let mut config = IpStackConfig::default();
    config.mtu(MTU)?;
    // The game keeps its KCP flow busy; a minute of silence means it is gone.
    config.udp_timeout(Duration::from_secs(60));
    let mut stack = IpStack::new(config, device);

    let mut report = tokio::time::interval(Duration::from_secs(10));
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = report.tick() => log::info!("{}", stats.line()),
            flow = stack.accept() => match flow? {
                IpStackStream::Tcp(flow) => {
                    stats.tcp_flows.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(forward_tcp(flow, stats.clone()));
                }
                IpStackStream::Udp(flow) => {
                    stats.udp_flows.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(forward_udp(flow, stats.clone()));
                }
                IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {}
            },
        }
    }
    // Dropping the stack closes the tun (the VPN ends); the tee's sender goes
    // with it, so the writer drains and flushes.
    drop(stack);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    log::info!("stopped: {}", stats.line());
    Ok(())
}

fn start(fd: RawFd, pcap_path: String) -> anyhow::Result<()> {
    let mut running = RUNNING.lock().unwrap();
    if running.is_some() {
        anyhow::bail!("already running");
    }
    // SAFETY: the app hands over the tun descriptor with `detachFd()`, so it
    // is ours to own and close.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("irminsul-vpn")
        .build()?;
    let stats = Arc::new(Stats::default());
    let (stop, stopped) = oneshot::channel();
    let task_stats = stats.clone();
    runtime.spawn(async move {
        if let Err(e) = run(fd, pcap_path, task_stats, stopped).await {
            log::error!("forwarder ended: {e:#}");
        }
    });
    *running = Some(Running { runtime, stop, stats });
    Ok(())
}

fn stop() {
    let Some(running) = RUNNING.lock().unwrap().take() else { return };
    let _ = running.stop.send(());
    running.runtime.shutdown_timeout(Duration::from_secs(3));
}

fn init_logging() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("irminsul")
            .with_max_level(log::LevelFilter::Info),
    );
}

/// `NativeBridge.start(fd, pcapPath)`: 0 on success, -1 on failure (logged).
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_tawan475_irminsul_NativeBridge_start(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    pcap_path: JString,
) -> jint {
    init_logging();
    let path: String = match env.get_string(&pcap_path) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("start: bad path: {e}");
            return -1;
        }
    };
    match start(fd, path.clone()) {
        Ok(()) => {
            log::info!("forwarder started, game packets to {path}");
            0
        }
        Err(e) => {
            log::error!("start: {e:#}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_tawan475_irminsul_NativeBridge_stop(_env: JNIEnv, _class: JClass) {
    stop();
}

/// `NativeBridge.stats()`: one line of counters, or "" when not running.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_tawan475_irminsul_NativeBridge_stats(env: JNIEnv, _class: JClass) -> jstring {
    let line = RUNNING.lock().unwrap().as_ref().map(|r| r.stats.line()).unwrap_or_default();
    env.new_string(line).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(src: u16, dst: u16) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8];
        p.extend_from_slice(&src.to_be_bytes());
        p.extend_from_slice(&dst.to_be_bytes());
        p.extend_from_slice(&[0, 8, 0, 0]);
        p
    }

    #[test]
    fn game_packets_are_udp_on_the_kcp_ports_either_way() {
        assert!(is_game_packet(&ipv4_udp(40000, 22101)));
        assert!(is_game_packet(&ipv4_udp(22102, 40000)));
        assert!(!is_game_packet(&ipv4_udp(40000, 53)));
        let mut tcp = ipv4_udp(40000, 22101);
        tcp[9] = 6;
        assert!(!is_game_packet(&tcp));
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        v6.extend_from_slice(&[0; 32]);
        v6.extend_from_slice(&40000u16.to_be_bytes());
        v6.extend_from_slice(&22101u16.to_be_bytes());
        assert!(is_game_packet(&v6));
        assert!(!is_game_packet(&[0x45, 0]));
        assert!(!is_game_packet(&[]));
    }
}
