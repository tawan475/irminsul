//! Parse network packets transmitted between the game and the server
//!
//! Packets are built up in following layers depending on the purpose of the packet:
//!
//! - Packets for connection management ([`GamePacket::Connection`])
//!     - **Ethernet/IP/UDP**, handled using [`etherparse`]
//!     - **[`ConnectionPacket`]**, containing events for connection establishment/disconnection
//! - Packets for game commands ([`GamePacket::Commands`])
//!     - **Ethernet/IP/UDP**, handled using [`etherparse`]
//!     - **KCP**, handled using [mhy-kcp](https://github.com/hashblen/mhy-kcp)
//!         - The KCP header contains an extra field that needs to be removed
//!           to be compatible with the regular KCP protocol
//!     - **[`GameCommand`]**, encrypted using XOR
//!     - **Protobuf**, payload, needs to be parsed into using the types generated in
//!       [`gen::protos`]
//!
//! [`GameCommand`]s are encrypted using an XOR-key.
//! One of the first packets sent is a request for a new key from a seed.
//! That key is used for the rest of the packets.
//! This means the recording for packets needs to start before the game starts (train hyperdrive).
//!
//! ## Trust boundary
//!
//! Everything below [`GameSniffer::receive_packet`] is attacker-reachable: the
//! caller hands over whatever landed on UDP 22101/22102, which any local process
//! or LAN host can write to. Nothing in a datagram is authenticated, so no
//! length, offset or connection event coming off the wire may be trusted to be
//! consistent, and none of them may panic the caller's capture thread.
//!
//! ## Example
//! ```
//! use auto_artifactarium::{GamePacket, GameSniffer, ConnectionPacket};
//!
//! let packets: Vec<Vec<u8>> = vec![/**/];
//!
//! let mut sniffer = GameSniffer::new();
//! for packet in packets {
//!     match sniffer.receive_packet(packet) {
//!         Some(GamePacket::Connection(ConnectionPacket::Disconnected)) => {
//!             println!("Disconnected!");
//!             break;
//!         }
//!         Some(GamePacket::Commands(commands)) => {
//!             for command in commands {
//!                 println!("{:?}", command);
//!             }
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use protobuf::Message;
use protobuf::UnknownValueRef::{Fixed32, Fixed64, LengthDelimited, Varint};
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};
use tracing::{debug, info, info_span, instrument, trace, warn};

use crate::Key::Dispatch;
use crate::connection::parse_connection_packet;
use crate::crypto::{bruteforce, decrypt_command, guess, lookup_initial_key};
use crate::r#gen::protos::{AvatarInfo, Item, PacketHead, PropValue, Unk, prop_value};
use crate::kcp::KcpSniffer;
pub use crate::unk_util::{
    Achievement, AchievementMatchError, matches_achievement_all_data_notify,
    matches_avatars_all_data_notify, matches_get_player_token_rsp, matches_items_all_data_notify,
    try_match_achievement_all_data_notify,
};

fn bytes_as_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

pub mod r#gen;

mod connection;
mod crypto;
mod cs_rand;
mod kcp;
mod unk_util;

const PORTS: [u16; 2] = [22101, 22102];

/// Consecutive messages a live session key may fail to decrypt before the key is
/// treated as suspect.
///
/// A key that has been working is worth more than any single message: dropping
/// the message keeps the rest of the session decodable, whereas throwing the key
/// away ends the capture until the game is restarted.
const MAX_SESSION_FAILURES: u32 = 3;

/// How many *failed* [`bruteforce`] runs are spent on one set of session seeds.
///
/// A run takes seconds and blocks the caller's capture thread. If the key is
/// recoverable at all the first message recovers it, so repeating the search for
/// every undecryptable message only turns a dead session into a frozen one.
///
/// Only failures are counted. A run that recovered a key was not futile work,
/// and one login can legitimately need several re-derivations; charging those to
/// the budget froze recovery for the rest of the session, because inside one
/// login no new `GetPlayerTokenRsp` ever arrives to clear the counter.
const MAX_BRUTEFORCE_ATTEMPTS: u32 = 5;

/// Client-seed draws tried against a retained time seed.
///
/// The retained anchor is a cheap first probe: one time seed, no sweep around
/// it. That is strictly narrower than [`bruteforce`], which covers +/-1499 ms of
/// candidate send times -- but nothing is lost by probing the anchor first,
/// because a miss falls straight through to the full
/// `bruteforce(session.sent_ms, ..)` pass, and the anchor is by construction
/// inside that pass's own window.
const RETAINED_SEED_DEPTH: i32 = 1000;

/// Entries a store notify needs before it is believed.
///
/// Mirrors the floor already applied inside `matches_items_all_data_notify`; it
/// is not a new restriction, it just counts entries that carry real inventory
/// evidence instead of anything that happened to parse.
const MIN_REAL_ITEMS: usize = 10;

/// Entries a property notify needs before it is believed.
///
/// Deliberately unchanged. Lowering it to catch single-property delta notifies
/// does not work -- the delta arrives under a different command id with a
/// different shape -- and would trade a known limitation for false positives.
const MIN_PROPERTIES: usize = 5;

/// Ceiling used when ranking raw values recovered from an unrecognised
/// `PropValue` layout, so a float bit pattern can never outrank a real counter.
/// The largest real player property is Mora, capped at 9,999,999,999.
const MAX_PLAUSIBLE_PROPERTY: u64 = 1_000_000_000_000;

/// Playable avatars live in one contiguous block of ids (`10000002` upwards);
/// monsters and NPCs are two orders of magnitude away. The block is left
/// deliberately wide so a new release cannot age this check out.
const PLAYER_AVATAR_IDS: std::ops::RangeInclusive<u32> = 10_000_000..=10_999_999;

/// One-shot flags for the "this is what that command id is" discovery lines, so
/// a long capture logs each discovery once instead of once per packet.
static STORE_NOTIFY_LOGGED: AtomicBool = AtomicBool::new(false);
static PROPERTY_NOTIFY_LOGGED: AtomicBool = AtomicBool::new(false);
static AVATAR_NOTIFY_LOGGED: AtomicBool = AtomicBool::new(false);
static ACHIEVEMENT_NOTIFY_LOGGED: AtomicBool = AtomicBool::new(false);

/// `true` the first time it is called for a given flag.
fn first_time(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::Relaxed)
}

/// Top-level packet sent by the game
pub enum GamePacket {
    Connection(ConnectionPacket),
    Commands(Vec<GameCommand>),
}

/// Packet for connection management
pub enum ConnectionPacket {
    HandshakeRequested,
    Disconnected,
    HandshakeEstablished,
    SegmentData(PacketDirection, Vec<u8>),
}

/// Game command header.
///
/// Contains the type of the command in `command_id`, the `PacketHead` in
/// `proto_header` and the payload encoded in protobuf in `proto_data`.
///
/// ## Bit Layout
/// | Bit indices     |  Type |  Name |
/// | - | - | - |
/// |   0..2      |  `u16`  |  Header (magic constant) |
/// |   2..4      |  `u16`  |  command_id |
/// |   4..6      |  `u16`  |  header_len |
/// |   6..10     |  `u32`  |  data_len |
/// |  10..10+header_len |  variable  |  proto_header |
/// |  10+header_len..10+header_len+data_len |  variable  |  proto_data |
/// | ..+2  |  `u16`  |  Tail (magic constant) |
#[derive(Clone)]
pub struct GameCommand {
    pub command_id: u16,
    pub header_len: u16,
    pub data_len: u32,
    /// Serialised [`PacketHead`]. Envelope metadata only -- matchers must run on
    /// `proto_data`, or header fields turn up as top-level payload fields.
    pub proto_header: Vec<u8>,
    /// Serialised payload, without the header.
    pub proto_data: Vec<u8>,
}

impl GameCommand {
    const HEADER_LEN: usize = 10;
    const TAIL_LEN: usize = 2;

    /// Parse every command in one decrypted KCP message.
    ///
    /// A single transport message may carry more than one command. The framing
    /// declares each command's lengths inline for exactly that reason, and
    /// Grasscutter's own receiver (`GameSession.handleReceive`) walks a
    /// decrypted message in a `while readableBytes > 0` loop rather than
    /// parsing it once. Returning only the first command -- which is what
    /// upstream hashblen does -- silently drops the rest, and losing a
    /// `GetPlayerTokenRsp` because it shared a message with a neighbour is the
    /// difference between a working capture and one that stays empty while
    /// looking healthy.
    ///
    /// A trailing run of bytes that is not a command ends the walk; everything
    /// parsed before it is still returned.
    #[instrument(skip(bytes), fields(len = bytes.len()))]
    pub fn parse_message(bytes: &[u8]) -> Vec<Self> {
        let mut commands = Vec::new();
        let mut offset = 0usize;

        while offset < bytes.len() {
            // `parse_prefix` never reports fewer than `HEADER_LEN + TAIL_LEN`
            // consumed bytes, so this walk always advances.
            let Some((command, consumed)) = Self::parse_prefix(&bytes[offset..]) else {
                if !commands.is_empty() {
                    warn!(
                        offset,
                        len = bytes.len(),
                        commands = commands.len(),
                        "trailing bytes after the last command in this kcp message"
                    );
                }
                break;
            };

            commands.push(command);
            offset += consumed;
        }

        commands
    }

    /// Parse the first command in a decrypted KCP message.
    ///
    /// Kept for callers holding a buffer they know carries exactly one command.
    /// The sniffer uses [`GameCommand::parse_message`], because a message may
    /// carry several; like upstream hashblen, this ignores anything after the
    /// first command's tail rather than rejecting the message.
    pub fn try_new(bytes: Vec<u8>) -> Option<Self> {
        Self::parse_prefix(&bytes).map(|(command, _)| command)
    }

    /// Split the command at the front of `bytes` into its header and payload,
    /// with the number of bytes it consumed.
    ///
    /// `header_len` and `data_len` are read straight out of an attacker-supplied
    /// buffer, so every offset derived from them is computed with `checked_add`
    /// and checked against the buffer before anything is sliced. The tail magic
    /// is required *where the declared lengths say the command ends*, not at the
    /// end of the buffer: that is what tells a command followed by another one
    /// apart from a length that overran into whatever came next.
    fn parse_prefix(bytes: &[u8]) -> Option<(Self, usize)> {
        let header_overhead = Self::HEADER_LEN + Self::TAIL_LEN;
        if bytes.len() < header_overhead {
            warn!(len = bytes.len(), "game command header incomplete");
            return None;
        }

        if bytes[0] != 0x45 || bytes[1] != 0x67 {
            debug!("game command did not carry the magic bytes");
            return None;
        }

        // skip header magic const
        let command_id = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let header_len = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let data_len = u32::from_be_bytes(bytes[6..10].try_into().unwrap());

        let data_start = Self::HEADER_LEN.checked_add(header_len as usize);
        let data_end = data_start.and_then(|start| start.checked_add(data_len as usize));
        let total = data_end.and_then(|end| end.checked_add(Self::TAIL_LEN));

        // `checked_add` first, compare second: computing `end + TAIL_LEN <= len`
        // would overflow on exactly the lengths this guard exists to reject.
        let (Some(data_start), Some(data_end), Some(total)) = (data_start, data_end, total) else {
            warn!(
                header_len,
                data_len,
                len = bytes.len(),
                "game command lengths overflow the address space"
            );
            return None;
        };

        if total > bytes.len() {
            warn!(
                header_len,
                data_len,
                total,
                len = bytes.len(),
                "game command lengths overrun the kcp message"
            );
            return None;
        }

        // `total == data_end + TAIL_LEN <= bytes.len()`, so both indices are in
        // bounds.
        if bytes[data_end] != 0x89 || bytes[data_end + 1] != 0xAB {
            debug!(
                header_len,
                data_len, "game command did not end where its lengths said it would"
            );
            return None;
        }

        Some((
            GameCommand {
                command_id,
                header_len,
                data_len,
                proto_header: bytes[Self::HEADER_LEN..data_start].to_vec(),
                proto_data: bytes[data_start..data_end].to_vec(),
            },
            total,
        ))
    }

    /// Parse the payload as `T`.
    pub fn parse_proto<T: protobuf::Message>(&self) -> protobuf::Result<T> {
        T::parse_from_bytes(&self.proto_data)
    }

    /// Parse the envelope as `T`, normally [`PacketHead`].
    pub fn parse_header<T: protobuf::Message>(&self) -> protobuf::Result<T> {
        T::parse_from_bytes(&self.proto_header)
    }
}

impl fmt::Debug for GameCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GameCommand")
            .field("command_id", &self.command_id)
            .field("header_len", &self.header_len)
            .field("data_len", &self.data_len)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum PacketDirection {
    Sent,
    Received,
}

pub enum Key {
    Dispatch(Vec<u8>),
    Session(Vec<u8>),
}

/// Session seeds recovered from a `GetPlayerTokenRsp`, with the send time of the
/// packet that carried them.
///
/// The two are worthless apart: recovering the session key needs a server seed to
/// XOR against *and* a send time to anchor the client-seed search on. Holding
/// them in one `Option` makes "seeds installed, send time unknown" -- the state
/// that used to be reached whenever the header failed to parse, and that then
/// panicked the capture thread on the next undecryptable packet -- impossible to
/// represent.
#[derive(Debug, Clone)]
struct SessionSeeds {
    seeds: Vec<u64>,
    sent_ms: u64,
}

/// Whether XOR-decrypting `data` with `key` would reveal a [`GameCommand`].
///
/// Only the four bytes the check actually reads are decrypted, instead of
/// cloning and XOR-ing the whole message to look at two bytes at each end.
///
/// Both the dispatch and the session key are probed on all four magic bytes.
/// The session probe used to check only the leading two, which meant a message
/// whose tail was wrong got decrypted, handed to the command parser and rejected
/// there instead -- the same outcome by a noisier route, since
/// [`GameCommand::parse_message`] requires a tail as well. The tail checked here
/// is the *message's* last two bytes, which belong to the last command in it; a
/// message carrying several commands still ends on one.
fn magic_matches(key: &[u8], data: &[u8]) -> bool {
    if key.is_empty() || data.len() < GameCommand::HEADER_LEN + GameCommand::TAIL_LEN {
        return false;
    }

    let plain = |i: usize| data[i] ^ key[i % key.len()];
    let last = data.len() - 1;

    plain(0) == 0x45 && plain(1) == 0x67 && plain(last - 1) == 0x89 && plain(last) == 0xAB
}

/// Protocol version a command claims, i.e. the key version to look up.
fn protocol_version(data: &[u8]) -> Option<u16> {
    data.first_chunk::<2>()
        .map(|bytes| u16::from_be_bytes(*bytes) ^ 0x4567)
}

/// Conversation id of a raw game KCP segment.
fn segment_conv_id(kcp_seg: &[u8]) -> Option<u32> {
    (kcp_seg.len() >= 4).then(|| ::kcp::get_conv(kcp_seg))
}

/// What the currently installed key can do with the message in hand.
enum KeyState {
    /// No key at all yet.
    Absent,
    /// The dispatch key decrypts this message.
    DispatchOk,
    /// The dispatch key no longer decrypts, which is the normal end of the login
    /// handshake: the session key has taken over.
    DispatchStale,
    /// The session key decrypts this message.
    SessionOk,
    /// The session key did not decrypt this message.
    SessionStale,
}

#[derive(Default)]
pub struct GameSniffer {
    sent_kcp: Option<KcpSniffer>,
    recv_kcp: Option<KcpSniffer>,
    /// The send time that produced the live session key. Named for what it holds
    /// -- it is a timestamp, not a seed the client chose.
    last_time_seed: Option<u64>,
    key: Option<Key>,
    initial_keys: HashMap<u16, Vec<u8>>,
    rsa_keys: Vec<RsaPrivateKey>,
    session_seeds: Option<SessionSeeds>,
    /// Consecutive messages the live session key failed to decrypt.
    session_failures: u32,
    /// A re-derivation attempt has already failed for the current failure burst,
    /// so do not pay for another one until something decrypts again.
    session_rederive_exhausted: bool,
    /// Full bruteforce runs already spent on the current [`SessionSeeds`].
    bruteforce_attempts: u32,
    /// A handshake request arrived while a session key was live. Nothing about
    /// that datagram is authenticated, so the reset it asks for waits for
    /// corroboration.
    pending_reset: bool,
    /// Protocol version the last "no key for this version" complaint was about,
    /// so the complaint is made once per version and not once per message.
    unknown_key_version: Option<u16>,
    /// Times `reset_session` has run. Published by
    /// [`GameSniffer::session_generation`] so a consumer can latch on a reset
    /// this library actually concluded, rather than on a raw handshake datagram
    /// anyone can forge.
    session_generation: u64,
}

impl GameSniffer {
    pub fn new() -> Self {
        let pem_data_4 = include_str!("../keys/private_key_4.pem");
        let pem_data_5 = include_str!("../keys/private_key_5.pem");

        let rsa_4 = RsaPrivateKey::from_pkcs1_pem(pem_data_4);
        let rsa_5 = RsaPrivateKey::from_pkcs1_pem(pem_data_5);

        GameSniffer {
            rsa_keys: [rsa_4, rsa_5].into_iter().filter_map(Result::ok).collect(),
            ..Default::default()
        }
    }

    pub fn set_initial_keys(mut self, initial_keys: HashMap<u16, Vec<u8>>) -> Self {
        self.initial_keys = initial_keys;
        self
    }

    /// How many times this sniffer has torn down its per-connection state.
    ///
    /// Starts at 0 and only ever increases. It changes when *this library* has
    /// concluded that the game connection restarted, which is one of:
    ///
    /// * a handshake request seen while no session key was live (nothing worth
    ///   protecting is installed at that point), or
    /// * a handshake request that was deferred because a session key *was* live,
    ///   and has since been corroborated -- by a KCP segment on a different
    ///   conversation, by a segment opening a conversation in a direction that
    ///   had no sniffer, or by the live key going dead.
    ///
    /// It never changes on a bare [`ConnectionPacket::HandshakeRequested`], which
    /// is unauthenticated: any local process can put a 20-byte datagram on a game
    /// port and produce one.
    ///
    /// A consumer that clears captured player data on reconnect should key off
    /// this instead of the connection packet: read it after each
    /// [`GameSniffer::receive_packet`] and act when the value changed, *before*
    /// processing the commands that same call returned -- those already belong to
    /// the new connection.
    pub fn session_generation(&self) -> u64 {
        self.session_generation
    }

    #[instrument(skip_all, fields(len = bytes.len()))]
    pub fn receive_packet(&mut self, bytes: Vec<u8>) -> Option<GamePacket> {
        let packet = parse_connection_packet(&PORTS, bytes)?;
        match packet {
            ConnectionPacket::HandshakeRequested => {
                // Any process able to put a 20-byte datagram on a game port
                // reaches this arm: nothing in `parse_connection_packet` is
                // authenticated, and the direction does not discriminate either
                // (a datagram sent *to* 22102 classifies as `Sent`, exactly like
                // a real client handshake). Wiping a live session key on that
                // alone hands anyone a one-packet kill switch, so while a
                // session key is live the reset waits for corroboration: a
                // segment on a different KCP conversation, or the live key going
                // dead. A spoofed handshake then costs one log line, because the
                // next message that still decrypts clears the flag again.
                if matches!(self.key, Some(Key::Session(_))) {
                    if !self.pending_reset {
                        warn!(
                            "handshake requested while a session key is live; deferring the reset \
                             until a new conversation or a dead key corroborates it"
                        );
                    }
                    self.pending_reset = true;
                } else {
                    self.reset_session("handshake requested");
                }
                Some(GamePacket::Connection(packet))
            }
            ConnectionPacket::HandshakeEstablished | ConnectionPacket::Disconnected => {
                Some(GamePacket::Connection(packet))
            }

            ConnectionPacket::SegmentData(direction, kcp_seg) => {
                let commands = self.receive_kcp_segment(direction, &kcp_seg);
                match commands {
                    Some(commands) => Some(GamePacket::Commands(commands)),
                    None => Some(GamePacket::Connection(ConnectionPacket::SegmentData(
                        direction, kcp_seg,
                    ))),
                }
            }
        }
    }

    /// Drop everything tied to one game connection.
    ///
    /// Every caller has already corroborated the reset (see
    /// [`GameSniffer::session_generation`]), so this is also where the
    /// generation counter is bumped.
    fn reset_session(&mut self, reason: &str) {
        info!(reason, "resetting session state");
        self.session_generation = self.session_generation.saturating_add(1);
        self.recv_kcp = None;
        self.sent_kcp = None;
        self.key = None;
        self.session_seeds = None;
        // Keeping this across connections is what made the first message of
        // every reconnect burn a full failing bruteforce against the *previous*
        // connection's anchor before it got anywhere.
        self.last_time_seed = None;
        self.session_failures = 0;
        self.session_rederive_exhausted = false;
        self.bruteforce_attempts = 0;
        self.pending_reset = false;
    }

    fn receive_kcp_segment(
        &mut self,
        direction: PacketDirection,
        kcp_seg: &[u8],
    ) -> Option<Vec<GameCommand>> {
        let current_conv = match direction {
            PacketDirection::Sent => self.sent_kcp.as_ref(),
            PacketDirection::Received => self.recv_kcp.as_ref(),
        }
        .map(|kcp| kcp.conv_id);

        // A new conversation id is the corroboration a deferred reset was
        // waiting for: the game really did reconnect.
        if self.pending_reset
            && let (Some(current), Some(incoming)) = (current_conv, segment_conv_id(kcp_seg))
            && current != incoming
        {
            self.reset_session("handshake request confirmed by a new kcp conversation");
        }

        let segments = {
            let has_sniffer = match direction {
                PacketDirection::Sent => self.sent_kcp.is_some(),
                PacketDirection::Received => self.recv_kcp.is_some(),
            };

            if !has_sniffer {
                // No sniffer in this direction means no conv id to compare, so
                // the branch above cannot have fired: a genuine reconnect whose
                // first segment lands in a direction the previous connection
                // never used (capture started mid-session, or an earlier
                // `try_new` failed) would otherwise wait for the key to die,
                // silently eating the first two messages -- one of which is the
                // `GetPlayerTokenRsp` the whole session depends on.
                //
                // The segment is turned into a sniffer *first*, so a datagram
                // that is not even a valid KCP segment cannot corroborate
                // anything; once it is one, a conversation is opening here, and
                // an attacker cannot open a conversation the real game is not
                // using either.
                let fresh = KcpSniffer::try_new(kcp_seg)?;
                if self.pending_reset {
                    self.reset_session(
                        "handshake request confirmed by a new kcp conversation in a direction \
                         with no sniffer",
                    );
                }
                match direction {
                    PacketDirection::Sent => self.sent_kcp = Some(fresh),
                    PacketDirection::Received => self.recv_kcp = Some(fresh),
                }
            }

            let kcp = match direction {
                PacketDirection::Sent => &mut self.sent_kcp,
                PacketDirection::Received => &mut self.recv_kcp,
            };

            kcp.as_mut()?.receive_segments(kcp_seg)
        };

        Some(
            segments
                .into_iter()
                .flat_map(|data| self.receive_commands(data))
                .collect(),
        )
    }

    /// Decrypt one KCP message and parse every command it carries.
    #[instrument(skip_all, fields(len = data.len()))]
    fn receive_commands(&mut self, mut data: Vec<u8>) -> Vec<GameCommand> {
        // Every key branch below reads `data[0]`, `data[1]`, `data[len - 2]` and
        // `data[len - 1]`, and a real command carries a 10-byte header plus a
        // 2-byte tail anyway, so a runt message is dropped before it can index
        // out of bounds.
        if data.len() < GameCommand::HEADER_LEN + GameCommand::TAIL_LEN {
            debug!(
                len = data.len(),
                "kcp message too short to be a game command"
            );
            return Vec::new();
        }

        if !self.ensure_key(&data) {
            return Vec::new();
        }

        let Some(key) = self.key.as_ref() else {
            return Vec::new();
        };
        let key_bytes = match key {
            Dispatch(bytes) | Key::Session(bytes) => bytes,
        };
        decrypt_command(key_bytes, &mut data);

        let commands = GameCommand::parse_message(&data);

        for command in &commands {
            let span = info_span!("command", ?command);
            let _enter = span.enter();

            // The span above already renders command_id/header_len/data_len on
            // every event below, so this line carries no information of its own;
            // it is kept at debug purely as a "a command got this far" marker.
            debug!("received");
            // Trace-level only, and the payload alone rather than header first:
            // this is a base64 dump of the account's game data, so it must never
            // reach a log a user is asked to send in as a bug report.
            trace!(data = BASE64_STANDARD.encode(&command.proto_data), "data");

            self.install_session_seeds(command);
        }

        commands
    }

    /// Make sure `self.key` holds something that decrypts `data`, deriving or
    /// re-deriving it when it does not. `false` means the message has to be
    /// dropped.
    fn ensure_key(&mut self, data: &[u8]) -> bool {
        let state = match &self.key {
            None => KeyState::Absent,
            Some(Dispatch(key)) => {
                if magic_matches(key, data) {
                    KeyState::DispatchOk
                } else {
                    KeyState::DispatchStale
                }
            }
            Some(Key::Session(key)) => {
                if magic_matches(key, data) {
                    KeyState::SessionOk
                } else {
                    KeyState::SessionStale
                }
            }
        };

        match state {
            KeyState::Absent => self.install_dispatch_key(data),
            KeyState::DispatchOk => true,
            KeyState::SessionOk => {
                self.session_failures = 0;
                self.session_rederive_exhausted = false;
                // The session this key belongs to is demonstrably still alive,
                // so whatever asked for a reset was not this game.
                self.pending_reset = false;
                true
            }
            KeyState::DispatchStale => {
                debug!("dispatch key no longer decrypts; looking for the session key");
                self.recover_session_key(data)
            }
            KeyState::SessionStale => self.handle_session_key_reject(data),
        }
    }

    fn install_dispatch_key(&mut self, data: &[u8]) -> bool {
        if let Some(key) = lookup_initial_key(&self.initial_keys, data) {
            self.unknown_key_version = None;
            self.key = Some(Dispatch(key));
            return true;
        }

        // When the running game is newer than this build, *every* message of
        // the session misses. Complain once per version rather than once per
        // message, and as a warning rather than an error: a missing key is a
        // stale build, not a fault.
        let version = protocol_version(data);
        if self.unknown_key_version != version {
            self.unknown_key_version = version;
            warn!(
                ?version,
                "no dispatch key is baked in for this protocol version; this build is probably \
                 older than the running game"
            );
        } else {
            debug!(?version, "still no dispatch key for this protocol version");
        }
        false
    }

    /// Recover the session key from the retained seeds.
    fn recover_session_key(&mut self, data: &[u8]) -> bool {
        let Some(session) = self.session_seeds.clone() else {
            debug!("no session seeds retained yet; dropping the message");
            return false;
        };

        // Cheap pass first. Inside one connection the retained time seed is the
        // exact anchor that already worked, so the draw depth alone is worth
        // probing before paying for a full search. This is a narrower search
        // than `bruteforce` -- one time seed instead of the +/-1499 ms sweep
        // around it -- but nothing is lost by trying it first: a miss falls
        // through to the `bruteforce(session.sent_ms, ..)` pass below, whose own
        // window already contains the anchor.
        if let Some(anchor) = self.last_time_seed {
            for &seed in &session.seeds {
                if let Some(key) = guess(anchor as i64, seed, RETAINED_SEED_DEPTH, data) {
                    debug!("recovered the session key from the retained send time");
                    self.install_session_key(key, anchor);
                    return true;
                }
            }
        }

        if self.bruteforce_attempts >= MAX_BRUTEFORCE_ATTEMPTS {
            debug!(
                attempts = self.bruteforce_attempts,
                "session key bruteforce budget for these seeds is spent; dropping the message"
            );
            return false;
        }

        for &seed in &session.seeds {
            if let Some((time_seed, key)) = bruteforce(session.sent_ms, seed, data.to_vec()) {
                self.install_session_key(key, time_seed);
                return true;
            }
        }

        // Charged only now, on the way out. The budget caps *futile* work, and a
        // run that recovered a key was not futile; counting successes too meant
        // five legitimate re-derivations inside one login exhausted it, after
        // which nothing could be recovered until a new `GetPlayerTokenRsp` --
        // which, inside one login, never arrives.
        self.bruteforce_attempts = self.bruteforce_attempts.saturating_add(1);

        warn!(
            seeds = session.seeds.len(),
            attempt = self.bruteforce_attempts,
            "could not recover the session key from the retained seeds"
        );
        false
    }

    fn install_session_key(&mut self, key: Vec<u8>, time_seed: u64) {
        self.last_time_seed = Some(time_seed);
        self.key = Some(Key::Session(key));
        self.session_failures = 0;
        self.session_rederive_exhausted = false;
    }

    /// A message the live session key could not decrypt.
    fn handle_session_key_reject(&mut self, data: &[u8]) -> bool {
        self.session_failures = self.session_failures.saturating_add(1);

        // A key that has been decrypting the session is worth more than one
        // message. This used to throw the key away and fall back to
        // `lookup_initial_key`, which cannot succeed on session-encrypted bytes,
        // so a single reject silently ended the capture for the rest of the game
        // session.
        if self.session_failures < MAX_SESSION_FAILURES {
            debug!(
                failures = self.session_failures,
                "session key did not decrypt this message; dropping the message, keeping the key"
            );
            return false;
        }

        if self.pending_reset {
            // A handshake was seen while this key was live, and now the key is
            // dead too. Two independent signals agreeing is the corroboration
            // the deferred reset was waiting for.
            self.reset_session("handshake request confirmed by a dead session key");
            return self.install_dispatch_key(data);
        }

        if self.session_rederive_exhausted {
            debug!("session key still failing and re-derivation is already spent");
            return false;
        }
        self.session_rederive_exhausted = true;
        warn!(
            failures = self.session_failures,
            "session key stopped decrypting; trying to re-derive it from the retained seeds"
        );
        self.recover_session_key(data)
    }

    /// Pick up the session seeds from a `GetPlayerTokenRsp`.
    ///
    /// The seeds and the send time are only usable together, so they are parsed
    /// first and committed together. Publishing the seeds before parsing the
    /// header is what left seeds live with no send time whenever the header
    /// failed to parse, and the next undecryptable packet then panicked.
    fn install_session_seeds(&mut self, command: &GameCommand) {
        if !matches!(self.key, Some(Dispatch(_))) {
            return;
        }

        let Some(seeds) = matches_get_player_token_rsp(&command.proto_data, &self.rsa_keys) else {
            return;
        };

        match command.parse_header::<PacketHead>() {
            Ok(header) => {
                debug!(
                    seeds = seeds.len(),
                    sent_ms = header.sent_ms,
                    "installed new session seeds"
                );
                self.session_seeds = Some(SessionSeeds {
                    seeds,
                    sent_ms: header.sent_ms,
                });
                // A new token response means a new session key is coming, so the
                // previous connection's anchor and search budget go with it.
                self.last_time_seed = None;
                self.bruteforce_attempts = 0;
            }
            Err(e) => {
                warn!(
                    %e,
                    header_len = command.proto_header.len(),
                    "token response header did not parse; session seeds not installed"
                );
            }
        }
    }
}

/// Everything this library can recognise inside a decrypted command.
#[derive(Debug)]
#[non_exhaustive]
pub enum CommandMatch {
    Items(Vec<Item>),
    Properties(HashMap<u32, u64>),
    Avatars(Vec<AvatarInfo>),
    Achievements(Vec<Achievement>),
}

impl CommandMatch {
    /// Name of the packet kind, for logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Items(_) => "items",
            Self::Properties(_) => "properties",
            Self::Avatars(_) => "avatars",
            Self::Achievements(_) => "achievements",
        }
    }
}

/// Run every matcher over one command and report what it is.
///
/// The individual `matches_*_packet` functions stay available, but a caller that
/// tries them in an `else if` chain can never notice that two of them claimed the
/// same command -- which is exactly how a shape collision turns into silently
/// missing data. This runs all four and logs when more than one claims a command,
/// then returns the first claim in the historical priority order.
pub fn classify_command(game_command: &GameCommand) -> Option<CommandMatch> {
    let mut claims = Vec::new();
    if let Some(items) = matches_item_packet(game_command) {
        claims.push(CommandMatch::Items(items));
    }
    if let Some(properties) = matches_player_property_packet(game_command) {
        claims.push(CommandMatch::Properties(properties));
    }
    if let Some(avatars) = matches_avatar_packet(game_command) {
        claims.push(CommandMatch::Avatars(avatars));
    }
    if let Some(achievements) = matches_achievement_packet(game_command) {
        claims.push(CommandMatch::Achievements(achievements));
    }

    if claims.len() > 1 {
        let kinds: Vec<&str> = claims.iter().map(CommandMatch::kind).collect();
        warn!(
            command_id = game_command.command_id,
            ?kinds,
            "more than one matcher claimed this command; taking the first"
        );
    }

    claims.into_iter().next()
}

/// Recover the achievement list from a command, or `None` if it is not one.
///
/// Observed command id: `AchievementAllDataNotify` was 5619 in 7.0. It is
/// recorded here as documentation only -- matching on it would break on every
/// game version, which is why the matchers inspect shape instead.
pub fn matches_achievement_packet(game_command: &GameCommand) -> Option<Vec<Achievement>> {
    let achievements = matches_achievement_all_data_notify(&game_command.proto_data)?;

    if first_time(&ACHIEVEMENT_NOTIFY_LOGGED) {
        info!(
            command_id = game_command.command_id,
            count = achievements.len(),
            "discovered AchievementAllDataNotify"
        );
    }
    Some(achievements)
}

/// Recover the achievement list from a command, reporting why it did not match.
///
/// Lets a caller tell "some other packet" apart from "the achievement packet,
/// but its fields could not be read", which is worth surfacing in a UI.
pub fn try_matches_achievement_packet(
    game_command: &GameCommand,
) -> Result<Vec<Achievement>, AchievementMatchError> {
    try_match_achievement_all_data_notify(&game_command.proto_data)
}

/// Recover the inventory from a `PlayerStoreNotify`, or `None` if this is not one.
///
/// Observed command id: `PlayerStoreNotify` was 8132 in 7.0, kept as
/// documentation only.
///
/// The packet is identified by payload-intrinsic evidence: enough entries at
/// field 5 that carry both a guid and one of the material/equip/furniture
/// detail arms. The previous second discriminator ("field 1 or 3 is a varint")
/// only ever matched `PacketHead`'s `packet_id`/`client_sequence_id`, so it
/// filtered nothing while the header was being fed to the matcher, and would
/// have rejected every store notify the moment the header was split off.
pub fn matches_item_packet(game_command: &GameCommand) -> Option<Vec<Item>> {
    let items = matches_items_all_data_notify(&game_command.proto_data)?;

    // A `map<uint32, PropValue>` entry parses as an `Item` too -- its field 2 is
    // a submessage where `guid` wants a varint, so the mismatch lands in the
    // unknown fields and `guid` reads back as 0, and none of the detail arms are
    // set. Real inventory entries have both. Counting rather than requiring a
    // majority keeps this from rejecting an inventory that is mostly virtual
    // items, and irminsul already discards entries with no detail arm anyway.
    let real = items
        .iter()
        .filter(|item| {
            item.guid != 0 && (item.has_material() || item.has_equip() || item.has_furniture())
        })
        .count();
    if real < MIN_REAL_ITEMS {
        trace!(
            command_id = game_command.command_id,
            total = items.len(),
            real,
            "field 5 parsed as items, but too few carry a guid and a detail arm"
        );
        return None;
    }

    if first_time(&STORE_NOTIFY_LOGGED) {
        info!(
            command_id = game_command.command_id,
            count = items.len(),
            "discovered PlayerStoreNotify"
        );
    } else {
        debug!(
            command_id = game_command.command_id,
            count = items.len(),
            "item packet"
        );
    }
    Some(items)
}

/// Recover the character roster from an `AvatarDataNotify`, or `None` if this is
/// not one.
///
/// Observed command id: `AvatarDataNotify` was 6586 in 7.0, kept as
/// documentation only.
///
/// The previous shape test was "some field 6 is length-delimited", which any
/// repeated submessage satisfies. The discriminator used here instead is that
/// `AvatarInfo` carries a `prop_map`; a plain `{varint, varint}` list does not.
/// There is deliberately **no** minimum roster size: a new account owns fewer
/// than ten characters and still has to export.
pub fn matches_avatar_packet(game_command: &GameCommand) -> Option<Vec<AvatarInfo>> {
    let avatars = matches_avatars_all_data_notify(&game_command.proto_data)?;

    let plausible = avatars
        .iter()
        .filter(|avatar| {
            !avatar.prop_map.is_empty() && PLAYER_AVATAR_IDS.contains(&avatar.avatar_id)
        })
        .count();
    if plausible * 2 <= avatars.len() {
        trace!(
            command_id = game_command.command_id,
            total = avatars.len(),
            plausible,
            "field 6 parsed as avatars, but too few look like playable characters"
        );
        return None;
    }

    if first_time(&AVATAR_NOTIFY_LOGGED) {
        info!(
            command_id = game_command.command_id,
            count = avatars.len(),
            "discovered AvatarDataNotify"
        );
    } else {
        debug!(
            command_id = game_command.command_id,
            count = avatars.len(),
            "avatar packet"
        );
    }
    Some(avatars)
}

/// One entry of a `map<uint32, PropValue>`, if `bytes` is exactly that.
///
/// A protobuf map entry has field 1 (the key, a varint here) and field 2 (the
/// value, a submessage here) and nothing else. Insisting on that exact shape is
/// what separates a property map from the other repeated submessages in the
/// protocol: an `Item` puts a varint at field 2, an `Achievement` is varints
/// throughout, an `AvatarInfo` has many more fields.
fn parse_prop_map_entry(bytes: &[u8]) -> Option<(u32, PropValue)> {
    let entry = Unk::parse_from_bytes(bytes).ok()?;

    let mut key = None;
    let mut value = None;
    let mut fields = 0usize;
    for (field_number, field_data) in entry.unknown_fields().iter() {
        fields += 1;
        match (field_number, field_data) {
            (1, Varint(k)) => key = u32::try_from(k).ok(),
            (2, LengthDelimited(v)) => value = PropValue::parse_from_bytes(v).ok(),
            _ => return None,
        }
    }

    if fields != 2 {
        return None;
    }
    Some((key?, value?))
}

/// A float as a property counter: rounded, with the non-finite cases pinned to 0
/// rather than left to a saturating cast.
fn round_float(value: f64) -> i64 {
    if value.is_finite() {
        value.round() as i64
    } else {
        0
    }
}

/// A signed protocol value as the non-negative counter the export format wants.
fn as_counter(value: i64) -> u64 {
    if value < 0 {
        debug!(value, "negative player property clamped to 0");
        return 0;
    }
    value as u64
}

/// The value a `PropValue` carries.
///
/// `val` (field 4) and the `value` oneof (`ival` field 2, `fval` field 3) hold
/// the same number in the packets this was written against, so either serves.
/// `fval` is a float and is read as one: its four bytes read as an integer are
/// the IEEE-754 bit pattern, which turned `1.0` into 1065353216 and, being
/// larger than any real player stat, then outranked the correct value sitting
/// beside it.
///
/// `None` means nothing in the message was recognisable as a value *and* it
/// carried fields this build does not know, i.e. the schema drifted and the
/// caller should fall back to [`drifted_prop_value`]. A `PropValue` whose value
/// fields are simply absent is a property whose value is 0, and is reported as
/// such -- proto3 omits zeros, and dropping them is what made a snapshot keep
/// yesterday's resin count after the resin was spent.
pub fn prop_value(prop: &PropValue) -> Option<u64> {
    if prop.val != 0 {
        return Some(as_counter(prop.val));
    }
    match &prop.value {
        Some(prop_value::Value::Ival(value)) => Some(as_counter(*value)),
        Some(prop_value::Value::Fval(value)) => Some(as_counter(round_float(f64::from(*value)))),
        None => {
            if prop.unknown_fields().iter().next().is_some() {
                return None;
            }
            Some(0)
        }
    }
}

/// The number a `PropValue` carries, however this game version chose to encode
/// it.
///
/// The one entry point a consumer should use. `irminsul` reads avatar levels and
/// ascensions out of `AvatarInfo::prop_map`, which is the same
/// `map<uint32, PropValue>` shape as the player properties this module decodes,
/// and reading only field 4 there silently dropped every character whose value
/// arrived in the `ival` oneof instead.
pub fn prop_value_any(prop: &PropValue) -> Option<u64> {
    prop_value(prop).or_else(|| drifted_prop_value(prop))
}

/// Last-resort read of a `PropValue` whose field numbers this build does not
/// recognise, kept because the game reshuffles them between major versions.
///
/// Fixed-width fields are floats on the wire, so they are decoded as floats; the
/// ceiling keeps a stray bit pattern from outranking a plausible counter.
fn drifted_prop_value(prop: &PropValue) -> Option<u64> {
    let mut best: Option<u64> = None;
    for (_, field_data) in prop.unknown_fields().iter() {
        let candidate = match field_data {
            Varint(value) => value,
            Fixed32(bits) => as_counter(round_float(f64::from(f32::from_bits(bits)))),
            Fixed64(bits) => as_counter(round_float(f64::from_bits(bits))),
            LengthDelimited(_) => continue,
        };
        if candidate <= MAX_PLAUSIBLE_PROPERTY && best.is_none_or(|best| candidate > best) {
            best = Some(candidate);
        }
    }
    best
}

/// Recover the player properties from a `PlayerPropertyNotify`, or `None` if this
/// is not one.
///
/// Observed command id: `PlayerPropertyNotify` was 2643 in 7.0, kept as
/// documentation only.
///
/// Values used to be guessed as "the largest varint in the submessage that is
/// not the map key", which dropped every property whose value was 0 (routine --
/// resin gets spent), dropped any value that happened to equal its own property
/// id, and mistook a float's bit pattern for a huge integer. `PropValue` is
/// declared in `protos.proto`, so it is parsed rather than guessed.
pub fn matches_player_property_packet(game_command: &GameCommand) -> Option<HashMap<u32, u64>> {
    let msg = Unk::parse_from_bytes(&game_command.proto_data).ok()?;

    let mut properties: HashMap<u32, u64> = HashMap::new();
    // `PropValue.type` is the property id by definition, so it corroborates the
    // map key. It is counted rather than required: a server that simply leaves
    // the field unset must not be locked out, but a "map" whose inner ids
    // consistently disagree with its keys is not a property map at all.
    let mut agreeing = 0usize;
    let mut disagreeing = 0usize;

    for (_, field_data) in msg.unknown_fields().iter() {
        let LengthDelimited(entry_bytes) = field_data else {
            continue;
        };
        let Some((key, prop)) = parse_prop_map_entry(entry_bytes) else {
            continue;
        };
        if key == 0 {
            continue;
        }

        if prop.type_ == key {
            agreeing += 1;
        } else if prop.type_ != 0 {
            disagreeing += 1;
        }

        let Some(value) = prop_value(&prop).or_else(|| drifted_prop_value(&prop)) else {
            trace!(key, "property value could not be read");
            continue;
        };
        properties.insert(key, value);
    }

    if disagreeing > agreeing {
        trace!(
            command_id = game_command.command_id,
            agreeing, disagreeing, "inner property ids disagree with the map keys"
        );
        return None;
    }

    // A property notify carries a whole page of properties. Anything smaller is
    // more likely a coincidence than a delta -- real deltas arrive under a
    // different command id with a different shape, so lowering this floor buys
    // false positives and no live tracking.
    if properties.len() < MIN_PROPERTIES {
        return None;
    }

    if first_time(&PROPERTY_NOTIFY_LOGGED) {
        info!(
            command_id = game_command.command_id,
            count = properties.len(),
            "discovered PlayerPropertyNotify"
        );
    } else {
        debug!(
            command_id = game_command.command_id,
            count = properties.len(),
            "property packet"
        );
    }
    Some(properties)
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;
    use crate::crypto::new_key_from_seed;
    use crate::cs_rand::Random;

    const PROP_MAP_TAG: u32 = 4;
    const ITEM_LIST_TAG: u32 = 5;
    const AVATAR_LIST_TAG: u32 = 6;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn field_varint(tag: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(tag) << 3);
        out.extend(varint(value));
        out
    }

    fn field_bytes(tag: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = varint((u64::from(tag) << 3) | 2);
        out.extend(varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn field_fixed32(tag: u32, bits: u32) -> Vec<u8> {
        let mut out = varint((u64::from(tag) << 3) | 5);
        out.extend_from_slice(&bits.to_le_bytes());
        out
    }

    /// A plaintext `GameCommand` on the wire.
    fn command_bytes(command_id: u16, header: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x45, 0x67];
        out.extend(command_id.to_be_bytes());
        out.extend((header.len() as u16).to_be_bytes());
        out.extend((payload.len() as u32).to_be_bytes());
        out.extend_from_slice(header);
        out.extend_from_slice(payload);
        out.extend([0x89, 0xAB]);
        out
    }

    fn command(payload: Vec<u8>) -> GameCommand {
        GameCommand::try_new(command_bytes(1234, &field_varint(1, 7), &payload))
            .expect("fixture should be a well formed command")
    }

    fn udp_frame(src_port: u16, dest_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .udp(src_port, dest_port);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn handshake_frame() -> Vec<u8> {
        let mut payload = vec![0u8; 20];
        payload[..4].copy_from_slice(&0xFFu32.to_be_bytes());
        udp_frame(50000, 22102, &payload)
    }

    /// One segment in the game's KCP framing:
    /// `conv(4) extra(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4)
    /// extra(4) content`.
    fn game_segment(conv: u32, content: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&conv.to_le_bytes());
        s.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        s.push(81); // cmd: push
        s.push(0); // frg
        s.extend_from_slice(&128u16.to_le_bytes()); // wnd
        s.extend_from_slice(&0u32.to_le_bytes()); // ts
        s.extend_from_slice(&0u32.to_le_bytes()); // sn
        s.extend_from_slice(&0u32.to_le_bytes()); // una
        s.extend_from_slice(&(content.len() as u32).to_le_bytes());
        s.extend_from_slice(&0xFEED_FACEu32.to_le_bytes());
        s.extend_from_slice(content);
        s
    }

    fn segment_frame(direction: PacketDirection, conv: u32, content: &[u8]) -> Vec<u8> {
        let segment = game_segment(conv, content);
        match direction {
            PacketDirection::Received => udp_frame(22102, 50000, &segment),
            PacketDirection::Sent => udp_frame(50000, 22102, &segment),
        }
    }

    /// A `map<uint32, PropValue>` entry.
    fn prop_entry(key: u32, prop: &[u8]) -> Vec<u8> {
        let mut out = field_varint(1, u64::from(key));
        out.extend(field_bytes(2, prop));
        out
    }

    /// A `PropValue` with `type` and `val` set, the shape the server sends.
    fn prop_val(key: u32, value: i64) -> Vec<u8> {
        let mut out = field_varint(1, u64::from(key));
        out.extend(field_varint(4, value as u64));
        out
    }

    fn property_packet(entries: &[(u32, Vec<u8>)]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|(key, prop)| field_bytes(PROP_MAP_TAG, &prop_entry(*key, prop)))
            .collect()
    }

    /// One `Item` with a guid and a `Material` detail arm.
    fn item_entry(item_id: u32, guid: u64) -> Vec<u8> {
        let mut out = field_varint(1, u64::from(item_id));
        out.extend(field_varint(2, guid));
        out.extend(field_bytes(5, &field_varint(1, 3)));
        out
    }

    fn item_packet(count: u32) -> Vec<u8> {
        (0..count)
            .flat_map(|i| field_bytes(ITEM_LIST_TAG, &item_entry(1000 + i, u64::from(i) + 1)))
            .collect()
    }

    /// One `AvatarInfo` with an id, a guid and a one-entry `prop_map`.
    fn avatar_entry(avatar_id: u32, guid: u64) -> Vec<u8> {
        let mut out = field_varint(1, u64::from(avatar_id));
        out.extend(field_varint(2, guid));
        out.extend(field_bytes(3, &prop_entry(4001, &prop_val(4001, 90))));
        out
    }

    fn avatar_packet(count: u32) -> Vec<u8> {
        (0..count)
            .flat_map(|i| {
                field_bytes(
                    AVATAR_LIST_TAG,
                    &avatar_entry(10_000_002 + i, u64::from(i) + 1),
                )
            })
            .collect()
    }

    // -- GameCommand::try_new --------------------------------------------------

    #[test]
    fn try_new_rejects_lengths_that_overflow_the_buffer() {
        // The crafted datagram from the audit: 62 bytes carrying the magic
        // bytes and the largest lengths the header can express.
        let mut bytes = vec![0x45, 0x67];
        bytes.extend(1234u16.to_be_bytes());
        bytes.extend(u16::MAX.to_be_bytes());
        bytes.extend(u32::MAX.to_be_bytes());
        bytes.resize(60, 0);
        bytes.extend([0x89, 0xAB]);
        assert_eq!(bytes.len(), 62);

        assert!(GameCommand::try_new(bytes).is_none());
    }

    #[test]
    fn try_new_rejects_every_length_pair_without_panicking() {
        for header_len in [0u16, 1, 12, u16::MAX] {
            for data_len in [0u32, 1, 40, u32::MAX] {
                let mut bytes = vec![0x45, 0x67];
                bytes.extend(1u16.to_be_bytes());
                bytes.extend(header_len.to_be_bytes());
                bytes.extend(data_len.to_be_bytes());
                bytes.resize(50, 0);
                bytes.extend([0x89, 0xAB]);

                let expected = 10 + header_len as usize + data_len as usize + 2 == bytes.len();
                assert_eq!(
                    GameCommand::try_new(bytes).is_some(),
                    expected,
                    "header_len {header_len}, data_len {data_len}"
                );
            }
        }
    }

    #[test]
    fn try_new_splits_the_header_off_the_payload() {
        let header = field_varint(6, 1_756_400_000_000);
        let payload = field_varint(9, 42);
        let command = GameCommand::try_new(command_bytes(7, &header, &payload)).expect("valid");

        assert_eq!(command.command_id, 7);
        assert_eq!(command.proto_header, header);
        assert_eq!(command.proto_data, payload);
        assert_eq!(
            command.parse_header::<PacketHead>().unwrap().sent_ms,
            1_756_400_000_000
        );
    }

    #[test]
    fn try_new_requires_the_tail_where_the_lengths_put_it() {
        let base = command_bytes(7, &[1, 2], &[3, 4, 5]);
        assert!(GameCommand::try_new(base.clone()).is_some());

        // a byte inserted before the tail: the declared lengths no longer point
        // at the magic
        let mut shifted = base.clone();
        shifted.insert(base.len() - 2, 0);
        assert!(GameCommand::try_new(shifted).is_none());

        // one byte short: the declared lengths overrun the message
        let mut short = base;
        short.remove(11);
        assert!(GameCommand::try_new(short).is_none());
    }

    #[test]
    fn try_new_ignores_bytes_after_the_first_command() {
        // Requiring the lengths to account for the message *exactly* was
        // stricter than both the previous code and upstream hashblen, and it
        // rejected -- with nothing but a `warn!` to show for it -- the whole
        // message rather than the padding.
        let mut padded = command_bytes(7, &[1, 2], &[3, 4, 5]);
        padded.extend([0, 0, 0]);

        let command = GameCommand::try_new(padded).expect("the command is complete");
        assert_eq!(command.command_id, 7);
        assert_eq!(command.proto_data, vec![3, 4, 5]);
    }

    #[test]
    fn parse_message_recovers_every_command_in_one_kcp_message() {
        // The mhy framing lets one transport message carry several commands --
        // Grasscutter parses a decrypted message in a loop for that reason. A
        // parser that insists on exactly one loses all of them, including a
        // `GetPlayerTokenRsp` that happens to share a message with a neighbour.
        let mut message = command_bytes(11, &field_varint(1, 1), &field_varint(2, 2));
        message.extend(command_bytes(22, &[], &field_varint(3, 3)));
        message.extend(command_bytes(33, &field_varint(4, 4), &[]));

        let commands = GameCommand::parse_message(&message);

        let ids: Vec<u16> = commands.iter().map(|c| c.command_id).collect();
        assert_eq!(ids, vec![11, 22, 33]);
        assert_eq!(commands[0].proto_data, field_varint(2, 2));
        assert_eq!(commands[1].proto_data, field_varint(3, 3));
        assert_eq!(commands[2].proto_header, field_varint(4, 4));
    }

    #[test]
    fn parse_message_keeps_what_it_parsed_before_a_bad_tail() {
        let mut message = command_bytes(11, &[], &field_varint(1, 1));
        message.extend([0x45, 0x67, 0, 0, 0, 0, 0, 0, 0, 9, 0x89, 0xAB]);

        let commands = GameCommand::parse_message(&message);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].command_id, 11);

        assert!(GameCommand::parse_message(&[]).is_empty());
        assert!(GameCommand::parse_message(&[0u8; 64]).is_empty());
    }

    // -- key handling ----------------------------------------------------------

    #[test]
    fn magic_matches_agrees_with_a_full_decrypt() {
        let key = new_key_from_seed(0xdead_beef);
        for len in [12usize, 13, 100, 4095, 4096, 4097] {
            let plain = command_bytes(1, &[], &vec![0u8; len - 12]);
            let mut encrypted = plain.clone();
            decrypt_command(&key, &mut encrypted);

            assert!(magic_matches(&key, &encrypted), "len {len}");

            let mut wrong = encrypted.clone();
            wrong[0] ^= 0xFF;
            assert!(!magic_matches(&key, &wrong), "len {len}");
        }

        assert!(!magic_matches(&[], &[0u8; 20]), "empty key must not divide");
        assert!(!magic_matches(&key, &[0u8; 4]), "runt must not index");
    }

    #[test]
    fn short_kcp_messages_are_dropped_instead_of_panicking() {
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(new_key_from_seed(1)));

        for len in 0..GameCommand::HEADER_LEN + GameCommand::TAIL_LEN {
            assert!(
                sniffer.receive_commands(vec![0u8; len]).is_empty(),
                "len {len}"
            );
        }
        assert!(matches!(sniffer.key, Some(Key::Session(_))));
    }

    #[test]
    fn an_undecryptable_message_without_seeds_does_not_panic() {
        // The `sent_time.unwrap()` case: a dispatch key is installed, the
        // message does not decrypt with it, and no token response has been seen.
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Dispatch(new_key_from_seed(1)));

        assert!(sniffer.receive_commands(vec![0u8; 64]).is_empty());
        assert!(sniffer.session_seeds.is_none());
    }

    #[test]
    fn a_working_session_key_survives_an_undecryptable_message() {
        let key = new_key_from_seed(5);
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(key.clone()));

        for _ in 0..MAX_SESSION_FAILURES * 4 {
            assert!(sniffer.receive_commands(vec![0u8; 64]).is_empty());
        }

        match &sniffer.key {
            Some(Key::Session(live)) => assert_eq!(live, &key),
            _ => panic!("the session key must not be thrown away"),
        }
    }

    #[test]
    fn a_decodable_message_clears_the_failure_counter() {
        let key = new_key_from_seed(6);
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(key.clone()));

        assert!(sniffer.receive_commands(vec![0u8; 64]).is_empty());
        assert_eq!(sniffer.session_failures, 1);

        let mut message = command_bytes(99, &[], &field_varint(1, 1));
        decrypt_command(&key, &mut message);
        let commands = sniffer.receive_commands(message);

        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].command_id, 99);
        assert_eq!(sniffer.session_failures, 0);
    }

    #[test]
    fn every_command_in_one_kcp_message_is_decoded() {
        let key = new_key_from_seed(13);
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(key.clone()));

        let mut message = command_bytes(11, &[], &field_varint(1, 1));
        message.extend(command_bytes(22, &[], &field_varint(2, 2)));
        decrypt_command(&key, &mut message);

        let ids: Vec<u16> = sniffer
            .receive_commands(message)
            .iter()
            .map(|command| command.command_id)
            .collect();
        assert_eq!(ids, vec![11, 22]);
    }

    // -- session key recovery --------------------------------------------------

    /// Seeds whose session key `bruteforce` finds at depth 0 against `sent_ms`,
    /// with a message encrypted under it.
    fn recoverable_seeds(sent_ms: u64, command_id: u16) -> (u64, Vec<u8>) {
        const COMBINED_SEED: u64 = 0xDEAD_BEEF;

        let mut generator = Random::seeded(sent_ms as i32);
        let server_seed = generator.next_safe_uint64() ^ COMBINED_SEED;

        let mut message = command_bytes(command_id, &[], &field_varint(1, 1));
        decrypt_command(&new_key_from_seed(COMBINED_SEED), &mut message);

        (server_seed, message)
    }

    #[test]
    fn a_successful_recovery_does_not_spend_the_bruteforce_budget() {
        // The budget caps futile work. Charging successes to it meant a long
        // connection's fifth legitimate re-derivation was its last: nothing
        // clears the counter inside one login.
        let sent_ms = 1_700_000_000_000u64;
        let (server_seed, message) = recoverable_seeds(sent_ms, 42);

        let mut sniffer = GameSniffer::new();
        sniffer.session_seeds = Some(SessionSeeds {
            seeds: vec![server_seed],
            sent_ms,
        });

        for _ in 0..MAX_BRUTEFORCE_ATTEMPTS + 2 {
            assert!(sniffer.recover_session_key(&message));
            assert!(matches!(sniffer.key, Some(Key::Session(_))));
            assert_eq!(
                sniffer.bruteforce_attempts, 0,
                "a run that recovered a key was not futile work"
            );
            // Drop the anchor so the next round pays for the bruteforce again
            // rather than taking the retained-seed fast path.
            sniffer.last_time_seed = None;
        }
    }

    #[test]
    fn the_retained_anchor_is_tried_before_a_full_bruteforce() {
        let sent_ms = 1_700_000_000_000u64;
        let (server_seed, message) = recoverable_seeds(sent_ms, 43);

        let mut sniffer = GameSniffer::new();
        sniffer.session_seeds = Some(SessionSeeds {
            seeds: vec![server_seed],
            sent_ms,
        });
        sniffer.last_time_seed = Some(sent_ms);
        // Budget spent: only the anchor fast path can succeed from here.
        sniffer.bruteforce_attempts = MAX_BRUTEFORCE_ATTEMPTS;

        assert!(sniffer.recover_session_key(&message));
        assert_eq!(sniffer.last_time_seed, Some(sent_ms));
    }

    #[test]
    fn a_spent_budget_refuses_another_bruteforce() {
        let mut sniffer = GameSniffer::new();
        sniffer.session_seeds = Some(SessionSeeds {
            seeds: vec![1],
            sent_ms: 2,
        });
        sniffer.bruteforce_attempts = MAX_BRUTEFORCE_ATTEMPTS;

        assert!(!sniffer.recover_session_key(&[0u8; 64]));
        assert!(sniffer.key.is_none());
    }

    // -- unauthenticated state reset ------------------------------------------

    #[test]
    fn a_spoofable_handshake_does_not_wipe_a_live_session_key() {
        let key = new_key_from_seed(7);
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(key.clone()));

        for _ in 0..5 {
            sniffer.receive_packet(handshake_frame());
        }

        match &sniffer.key {
            Some(Key::Session(live)) => assert_eq!(live, &key),
            _ => panic!("one unauthenticated datagram must not end the capture"),
        }
        assert!(sniffer.pending_reset, "the reset should be pending");
        assert_eq!(
            sniffer.session_generation(),
            0,
            "a consumer latching on the generation must not see a forged reset"
        );
    }

    #[test]
    fn a_deferred_reset_fires_when_the_new_conversation_opens_in_an_unseen_direction() {
        // Capture started mid-session, or an earlier `KcpSniffer::try_new`
        // failed: this direction has no sniffer, so there is no conv id to
        // compare against. Waiting for the key to die instead would silently
        // eat the first two messages of the new connection -- and the
        // dispatch-key-encrypted `GetPlayerTokenRsp` is among them.
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(new_key_from_seed(11)));
        sniffer.last_time_seed = Some(1);

        sniffer.receive_packet(handshake_frame());
        assert!(sniffer.pending_reset);
        assert_eq!(sniffer.session_generation(), 0);

        sniffer.receive_packet(segment_frame(PacketDirection::Received, 7, &[0u8; 40]));

        assert!(sniffer.key.is_none(), "the dead session must be torn down");
        assert!(!sniffer.pending_reset);
        assert!(sniffer.last_time_seed.is_none());
        assert_eq!(sniffer.session_generation(), 1);
        assert!(
            sniffer.recv_kcp.as_ref().map(|kcp| kcp.conv_id) == Some(7),
            "the new conversation's sniffer must survive the reset it triggered"
        );
    }

    #[test]
    fn a_kcp_segment_alone_does_not_reset_a_live_session() {
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(new_key_from_seed(12)));

        sniffer.receive_packet(segment_frame(PacketDirection::Received, 7, &[0u8; 40]));

        assert!(matches!(sniffer.key, Some(Key::Session(_))));
        assert_eq!(sniffer.session_generation(), 0);
    }

    #[test]
    fn a_decodable_message_disarms_a_deferred_reset() {
        let key = new_key_from_seed(8);
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(key.clone()));
        sniffer.receive_packet(handshake_frame());
        assert!(sniffer.pending_reset);

        let mut message = command_bytes(1, &[], &field_varint(1, 1));
        decrypt_command(&key, &mut message);
        assert_eq!(sniffer.receive_commands(message).len(), 1);

        assert!(!sniffer.pending_reset);
    }

    #[test]
    fn a_deferred_reset_fires_once_the_session_key_is_also_dead() {
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(new_key_from_seed(9)));
        sniffer.last_time_seed = Some(1);
        sniffer.receive_packet(handshake_frame());

        for _ in 0..MAX_SESSION_FAILURES {
            sniffer.receive_commands(vec![0u8; 64]);
        }

        assert!(sniffer.key.is_none(), "a corroborated handshake must reset");
        assert!(!sniffer.pending_reset);
        assert!(sniffer.last_time_seed.is_none());
    }

    #[test]
    fn a_handshake_resets_when_no_session_key_is_live() {
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Dispatch(new_key_from_seed(10)));
        sniffer.last_time_seed = Some(1);
        sniffer.session_seeds = Some(SessionSeeds {
            seeds: vec![1],
            sent_ms: 2,
        });

        sniffer.receive_packet(handshake_frame());

        assert!(sniffer.key.is_none());
        assert!(sniffer.session_seeds.is_none());
        assert!(
            sniffer.last_time_seed.is_none(),
            "a stale anchor makes every reconnect burn a failing bruteforce"
        );
    }

    // -- property decoding -----------------------------------------------------

    #[test]
    fn property_values_are_read_from_the_declared_fields() {
        let ival = {
            let mut out = field_varint(1, 1001);
            out.extend(field_varint(2, 4242));
            out
        };
        // `fval = 1.0`. Read as a raw integer this is 1065353216, which used to
        // win every comparison it took part in.
        let fval = {
            let mut out = field_varint(1, 1002);
            out.extend(field_fixed32(3, 1.0f32.to_bits()));
            out
        };

        let packet = property_packet(&[
            (1001, ival),
            (1002, fval),
            (1003, prop_val(1003, 7)),
            (1004, prop_val(1004, 9_999_999_999)),
            (1005, prop_val(1005, 5)),
        ]);
        let properties = matches_player_property_packet(&command(packet)).expect("should match");

        assert_eq!(properties.get(&1001), Some(&4242));
        assert_eq!(properties.get(&1002), Some(&1));
        assert_eq!(properties.get(&1003), Some(&7));
        assert_eq!(
            properties.get(&1004),
            Some(&9_999_999_999),
            "Mora is capped above u32::MAX"
        );
    }

    #[test]
    fn a_property_worth_zero_is_recorded_rather_than_dropped() {
        // Spent resin is the everyday case: proto3 omits the zero entirely.
        let empty = field_varint(1, 1); // `type` only
        let packet = property_packet(&[
            (1, empty),
            (2, prop_val(2, 0)),
            (3, prop_val(3, 3)),
            (4, prop_val(4, 4)),
            (5, prop_val(5, 5)),
        ]);
        let properties = matches_player_property_packet(&command(packet)).expect("should match");

        assert_eq!(properties.get(&1), Some(&0));
        assert_eq!(properties.get(&2), Some(&0));
        assert_eq!(properties.len(), 5);
    }

    #[test]
    fn a_value_equal_to_its_own_property_id_survives() {
        let entries: Vec<(u32, Vec<u8>)> =
            (1..=5u32).map(|i| (i, prop_val(i, i64::from(i)))).collect();
        let properties =
            matches_player_property_packet(&command(property_packet(&entries))).expect("match");

        for i in 1..=5u32 {
            assert_eq!(properties.get(&i), Some(&u64::from(i)));
        }
    }

    #[test]
    fn a_drifted_prop_value_reads_fixed32_as_a_float() {
        // Every field number moved, so nothing the build knows is set and the
        // fallback walk has to do the reading.
        let drifted: Vec<(u32, Vec<u8>)> = (1..=5u32)
            .map(|i| (i, field_fixed32(9, 120.0f32.to_bits())))
            .collect();
        let properties =
            matches_player_property_packet(&command(property_packet(&drifted))).expect("match");

        assert_eq!(properties.get(&1), Some(&120));
    }

    #[test]
    fn a_property_map_is_not_mistaken_for_an_inventory() {
        let entries: Vec<(u32, Vec<u8>)> = (1..=40u32)
            .map(|i| (i, prop_val(i, i64::from(i) * 100)))
            .collect();
        let command = command(property_packet(&entries));

        assert!(matches_player_property_packet(&command).is_some());
        assert!(
            matches_item_packet(&command).is_none(),
            "prop map entries carry no guid and no detail arm"
        );
        assert!(matches_avatar_packet(&command).is_none());
    }

    #[test]
    fn a_prop_map_at_field_5_is_not_mistaken_for_an_inventory() {
        // The exact collision the audit called out: the item matcher runs first
        // in the caller's chain, so a prop map landing on field 5 would swallow
        // the properties entirely.
        let entries: Vec<Vec<u8>> = (1..=40u32)
            .map(|i| field_bytes(ITEM_LIST_TAG, &prop_entry(i, &prop_val(i, i64::from(i)))))
            .collect();
        let command = command(entries.concat());

        assert!(matches_item_packet(&command).is_none());
        assert!(matches_player_property_packet(&command).is_some());
    }

    // -- item and avatar matchers ---------------------------------------------

    #[test]
    fn an_inventory_is_recognised_and_claimed_only_once() {
        let command = command(item_packet(40));

        let items = matches_item_packet(&command).expect("should match");
        assert_eq!(items.len(), 40);
        assert!(matches_player_property_packet(&command).is_none());
        assert!(matches!(
            classify_command(&command),
            Some(CommandMatch::Items(_))
        ));
    }

    #[test]
    fn an_inventory_of_bare_ids_is_rejected() {
        // No guid, no detail arm: parses as items, is not an inventory.
        let bare: Vec<Vec<u8>> = (0..40u32)
            .map(|i| field_bytes(ITEM_LIST_TAG, &field_varint(1, u64::from(1000 + i))))
            .collect();
        assert!(matches_item_packet(&command(bare.concat())).is_none());
    }

    #[test]
    fn a_small_roster_still_exports() {
        // A new account owns a handful of characters. A count floor here would
        // lock those accounts out of every character and artifact export.
        for count in 1..=9u32 {
            let avatars =
                matches_avatar_packet(&command(avatar_packet(count))).expect("should match");
            assert_eq!(avatars.len() as u32, count);
        }
    }

    #[test]
    fn a_varint_pair_list_at_field_6_is_not_a_roster() {
        let pairs: Vec<Vec<u8>> = (0..40u32)
            .map(|i| {
                let mut entry = field_varint(1, u64::from(10_000_002 + i));
                entry.extend(field_varint(2, u64::from(i) + 1));
                field_bytes(AVATAR_LIST_TAG, &entry)
            })
            .collect();
        assert!(
            matches_avatar_packet(&command(pairs.concat())).is_none(),
            "an avatar carries a prop_map; a bare id/guid pair does not"
        );
    }

    #[test]
    fn out_of_range_avatar_ids_are_not_a_roster() {
        let monsters: Vec<Vec<u8>> = (0..20u32)
            .map(|i| {
                field_bytes(
                    AVATAR_LIST_TAG,
                    &avatar_entry(24_000_000 + i, u64::from(i) + 1),
                )
            })
            .collect();
        assert!(matches_avatar_packet(&command(monsters.concat())).is_none());
    }

    #[test]
    fn matchers_run_on_the_payload_and_not_on_the_packet_header() {
        // A header whose fields collide with the item list must not reach the
        // matcher, and must not stop the real payload from being recognised.
        let header = field_bytes(ITEM_LIST_TAG, &item_entry(1, 1));
        let bytes = command_bytes(1234, &header, &item_packet(40));
        let command = GameCommand::try_new(bytes).expect("valid");

        assert_eq!(command.proto_header, header);
        assert_eq!(matches_item_packet(&command).expect("match").len(), 40);
    }

    #[test]
    fn a_command_that_matches_nothing_is_classified_as_nothing() {
        assert!(classify_command(&command(field_varint(1, 1))).is_none());
    }
}
