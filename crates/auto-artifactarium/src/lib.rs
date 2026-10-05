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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use protobuf::Message;
use protobuf::UnknownValueRef::{Fixed32, Fixed64, LengthDelimited, Varint};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use tracing::{debug, info, info_span, instrument, trace, warn};

use crate::Key::Dispatch;
use crate::connection::parse_frame;
use crate::crypto::{bruteforce, decrypt_command, guess, lookup_initial_key};
use crate::r#gen::protos::{AvatarInfo, Item, PacketHead, PropValue, Unk, prop_value};
use crate::kcp::{KcpSniffer, SegmentHead, segment_head};
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
#[cfg(test)]
mod test_support;
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

/// Time seeds kept from earlier connections for [`GameSniffer::time_anchors`].
///
/// One per game process is all that is ever useful (every reconnect inside a
/// process draws from the same generator), so this only has to cover a few
/// game restarts while irminsul keeps running. Bounded so a long-lived capture
/// cannot grow it, and so the probe below stays a fixed cost.
const MAX_TIME_ANCHORS: usize = 4;

/// Client-seed draws tried against each time seed kept from an earlier
/// connection.
///
/// On an in-game reconnect the client does not reseed its `System.Random`: it
/// draws the next value from the generator it seeded at the first login (the
/// reason upstream konkers retains that seed across handshakes). Each
/// connection costs at least one draw, so this covers thousands of reconnects
/// at one draw each, or dozens even if something else drew a hundred values
/// in between. Upstream searched 5 deep.
///
/// Cost: one candidate is ~1.1 us (measured), so this is ~11 ms per retained
/// seed per server seed. The probe runs inside the bruteforce budget (at most
/// [`MAX_BRUTEFORCE_ATTEMPTS`] times per set of session seeds), so with
/// [`MAX_TIME_ANCHORS`] seeds a connection whose key is not there pays well
/// under a second in total -- against ~3.3 s for *each* full bruteforce run.
/// Four magic bytes are checked per candidate, so 40,000 candidates leave a
/// false-positive chance of about 1 in 100,000.
const RECONNECT_SEED_DEPTH: i32 = 10_000;

/// Conversations of ended connections remembered by
/// [`GameSniffer::retire_conversation`].
///
/// A straggler only matters for the few seconds after its connection ends, and
/// each reset retires at most one conversation (both directions share it), so
/// this covers several reconnects in quick succession while staying a fixed,
/// tiny cost to search.
const MAX_RETIRED_CONVS: usize = 8;

/// Datagrams of another conversation, counted from its first segment, that
/// switch a lane whose own conversation has decoded nothing.
///
/// Every one of them is kept and replayed into the new sniffer, so the count
/// only decides how sure the switch is, never what it costs in data. A login
/// sends far more than this within a second in each direction (the client
/// acknowledges every push), while a stray datagram or two cannot reach it.
/// Memory is bounded by this many datagrams per lane.
const REBIND_AFTER: usize = 32;

/// Messages the live session key has to decrypt after a handshake request
/// before the reset that request asked for is dropped as spoofed.
///
/// One used to be enough, and that broke real reconnects: after the client's
/// handshake the server can still push a few messages on the old conversation,
/// they decrypt under the old key, and once they had disarmed the reset the new
/// conversation was rejected as a foreign one for the rest of the session. The
/// new conversation's first segment follows the handshake within a round trip,
/// so the old connection gets nowhere near this many messages in first, while
/// a session that is really alive reaches it within a minute or so.
const PENDING_RESET_DISARM_MESSAGES: u32 = 64;

/// `PacketHead` field the server sets on a compressed message: the payload's
/// length once decompressed.
///
/// Not in the protos -- no generated type knows it -- so it is read from the
/// header's unknown fields. Seen on 2026-10-05 on the `GetPlayerTokenRsp` from
/// some gate servers only (25,563 bytes sent as 20,118), and on no other
/// message of that session. This build cannot decompress it, so all it can do
/// is say so.
const COMPRESSED_LEN_FIELD: u32 = 8;

/// Entries a property notify needs before it is believed.
///
/// Deliberately unchanged. Lowering it to catch single-property delta notifies
/// does not work -- the delta arrives under a different command id with a
/// different shape -- and would trade a known limitation for false positives.
const MIN_PROPERTIES: usize = 5;

/// The block of player property ids (the client's `PROP_*` enum).
///
/// Every player property is a five-digit id from 10001
/// (`PROP_LAST_CHANGE_AVATAR_TIME`) upwards: 10013 is the Adventure Rank, 10015
/// Primogems, 10016 Mora, and the newest ones a 7.1 login carries reach 10100.
/// Avatar properties (1001 EXP, 1002 ascension, 4001 level) sit outside it, and
/// so do the 20xxx ids of the identity map 7.1 also sends at login. Left
/// deliberately wide, like [`PLAYER_AVATAR_IDS`](unk_util::PLAYER_AVATAR_IDS),
/// so new properties cannot age it out; a property notify only has to have
/// *most* of its keys in here.
const PLAYER_PROPERTY_IDS: std::ops::RangeInclusive<u32> = 10_000..=10_999;

/// Ceiling used when ranking raw values recovered from an unrecognised
/// `PropValue` layout, so a float bit pattern can never outrank a real counter.
/// The largest real player property is Mora, capped at 9,999,999,999.
const MAX_PLAUSIBLE_PROPERTY: u64 = 1_000_000_000_000;

/// Distinct top-level fields a delete notify is allowed to carry.
///
/// `StoreItemDelNotify` is `{repeated uint64 guid_list, StoreType store_type}`.
/// Sweeping Grasscutter's generated protos for messages that carry exactly one
/// repeated-uint64 list and nothing but scalars beside it finds 23 of them at
/// three fields or fewer, so this bound is what the shape actually looks like
/// rather than a guess.
const MAX_ITEM_DEL_FIELDS: usize = 3;

/// Ceiling for the non-guid scalars in a delete notify.
///
/// The only one the message defines is `StoreType` (0, 1 or 2). The bound is
/// left far above that so an added retcode or count field does not reject a
/// real delete, while still ruling out a message whose "scalar" is a timestamp
/// or an id -- that is some other packet wearing a similar shape.
const MAX_ITEM_DEL_SCALAR: u64 = u16::MAX as u64;

/// Largest delete list believed. The inventory caps out in the low thousands,
/// so anything past this is a misparse rather than a mass decompose.
const MAX_ITEM_DEL_GUIDS: usize = 4096;

/// One-shot flags for the "this is what that command id is" discovery lines, so
/// a long capture logs each discovery once instead of once per packet.
static STORE_NOTIFY_LOGGED: AtomicBool = AtomicBool::new(false);
static ITEM_DEL_NOTIFY_LOGGED: AtomicBool = AtomicBool::new(false);
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

/// Which key a [`GameSniffer`] holds for the current connection, as reported
/// by [`GameSniffer::key_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// No key: nothing from the current connection has been decrypted.
    None,
    /// The baked-in dispatch key, which only covers the login exchange. Game
    /// data needs the session key, so a connection that stays here is not
    /// decoding anything useful.
    Dispatch,
    /// The session key recovered for this connection: game data decrypts.
    Session,
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

/// What the currently installed key can do with the message in hand.
enum KeyCheck {
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

/// One direction of the game connection.
#[derive(Default)]
struct Lane {
    kcp: Option<KcpSniffer>,
    /// The bound conversation has decoded into at least one command, so it is
    /// the real one in this direction and can never be switched away from.
    ///
    /// Decoded commands rather than delivered KCP messages: an empty push
    /// "delivers" a zero-length message, and a stray one is exactly what can
    /// put a lane on the wrong conversation.
    proven: bool,
    /// Datagrams of another conversation that arrived, from its first segment
    /// on, while this lane's own conversation had decoded nothing. Kept so
    /// the lane can switch to it without losing a message. See
    /// [`GameSniffer::consider_switching`].
    candidate: Option<Candidate>,
}

struct Candidate {
    conv: u32,
    datagrams: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct GameSniffer {
    sent: Lane,
    recv: Lane,
    /// The send time that produced the live session key. Named for what it holds
    /// -- it is a timestamp, not a seed the client chose.
    ///
    /// Scoped to the current connection: it is cleared by a reset and by a new
    /// token response, because [`Self::recover_session_key`] probes it *before*
    /// the bruteforce budget is checked. Time seeds that must outlive the
    /// connection live in [`Self::time_anchors`] instead.
    last_time_seed: Option<u64>,
    /// Every time seed that has recovered a session key, newest first, at most
    /// [`MAX_TIME_ANCHORS`] of them.
    ///
    /// Deliberately kept across resets and new token responses. The game
    /// seeds its client-seed generator once, at the first login of the
    /// process, and every in-game reconnect draws the next value from it --
    /// while the new token response is stamped with the reconnect's own time,
    /// possibly hours later. Searching around that new send time alone is what
    /// left every reconnect undecryptable.
    time_anchors: Vec<u64>,
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
    /// The dispatch key stopped decrypting this connection with no session
    /// seeds to recover its successor from: the token response never arrived
    /// in a form this build can read. Nothing of the connection can decrypt,
    /// so it counts as a given-up key recovery.
    seedless_login: bool,
    /// A compressed message was reported for this connection (once).
    compressed_reported: bool,
    /// A handshake request arrived while a session key was live. Nothing about
    /// that datagram is authenticated, so the reset it asks for waits for
    /// corroboration.
    pending_reset: bool,
    /// Messages the live session key has decrypted since `pending_reset` was
    /// set; see [`PENDING_RESET_DISARM_MESSAGES`].
    pending_reset_proof: u32,
    /// Protocol version the last "no key for this version" complaint was about,
    /// so the complaint is made once per version and not once per message.
    unknown_key_version: Option<u16>,
    /// Conversations of connections that have ended, oldest first, at most
    /// [`MAX_RETIRED_CONVS`]. A lane is never opened for one of them.
    retired_convs: Vec<u32>,
    /// The conversation last announced in the log, so each one is announced
    /// once rather than once per direction.
    announced_conv: Option<u32>,
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
    ///   and has since been corroborated -- by a KCP segment opening a new
    ///   conversation (at the start of its sequence space, and not one a
    ///   previous reset already ended), in either direction, or by the live key
    ///   going dead.
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

    /// Whether the session key of the current connection has been given up on.
    ///
    /// `true` once every search this library is willing to run for the
    /// current token response's seeds has failed, until a new token response
    /// (a new login) or a reset brings new seeds. Nothing from the connection
    /// decrypts in the meantime, so a caller can tell the user to log in again
    /// instead of showing a capture that looks healthy and stays empty.
    pub fn key_recovery_failed(&self) -> bool {
        (self.bruteforce_attempts >= MAX_BRUTEFORCE_ATTEMPTS
            || (self.seedless_login && self.session_seeds.is_none()))
            && !matches!(self.key, Some(Key::Session(_)))
    }

    /// Which key is installed for the current connection.
    ///
    /// Only [`KeyState::Session`] means game data is decrypting: the first
    /// login messages decrypt under the dispatch key alone, and a connection
    /// whose session key was never recovered stays on it.
    pub fn key_state(&self) -> KeyState {
        match self.key {
            None => KeyState::None,
            Some(Dispatch(_)) => KeyState::Dispatch,
            Some(Key::Session(_)) => KeyState::Session,
        }
    }

    /// The KCP conversation `direction` is bound to, if any. Diagnostics: a
    /// direction that stays unbound, or bound to a conversation the other
    /// direction is not on, explains a capture that receives packets and
    /// decodes nothing.
    pub fn bound_conversation(&self, direction: PacketDirection) -> Option<u32> {
        let lane = match direction {
            PacketDirection::Sent => &self.sent,
            PacketDirection::Received => &self.recv,
        };
        lane.kcp.as_ref().map(|kcp| kcp.conv_id)
    }

    #[instrument(skip_all, fields(len = bytes.len()))]
    pub fn receive_packet(&mut self, bytes: Vec<u8>) -> Option<GamePacket> {
        let (packet, server) = parse_frame(&PORTS, bytes)?;
        match packet {
            ConnectionPacket::HandshakeRequested => {
                // Any process able to put a 20-byte datagram on a game port
                // reaches this arm: nothing in `parse_connection_packet` is
                // authenticated, and the direction does not discriminate either
                // (a datagram sent *to* 22102 classifies as `Sent`, exactly like
                // a real client handshake). Wiping a live session key on that
                // alone hands anyone a one-packet kill switch, so while a
                // session key is live the reset waits for corroboration: a
                // segment opening a new KCP conversation, or the live key going
                // dead. A spoofed handshake then costs a log line or two, because
                // a session that keeps decrypting clears the flag again (see
                // `PENDING_RESET_DISARM_MESSAGES`).
                if matches!(self.key, Some(Key::Session(_))) {
                    if !self.pending_reset {
                        warn!(
                            "handshake requested while a session key is live; deferring the reset \
                             until a new conversation or a dead key corroborates it"
                        );
                        self.pending_reset_proof = 0;
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
                let commands = self.receive_kcp_segment(direction, &kcp_seg, server);
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
        // The ended connection's conversation may still have segments in
        // flight; none of them may open a lane for the next one.
        for direction in [PacketDirection::Sent, PacketDirection::Received] {
            let lane = std::mem::take(self.lane(direction));
            if let Some(kcp) = lane.kcp {
                self.retire_conversation(kcp.conv_id);
            }
        }
        self.key = None;
        self.session_seeds = None;
        // The live connection's anchor goes, because it is probed outside the
        // bruteforce budget. The time seeds themselves stay in `time_anchors`:
        // a reconnect's key is drawn from the same generator.
        self.last_time_seed = None;
        self.session_failures = 0;
        self.session_rederive_exhausted = false;
        self.bruteforce_attempts = 0;
        self.seedless_login = false;
        self.compressed_reported = false;
        self.pending_reset = false;
        self.pending_reset_proof = 0;
    }

    /// Remember that `conv` belonged to a connection that has ended, so a
    /// straggler of it can never be mistaken for the start of the next one.
    fn retire_conversation(&mut self, conv: u32) {
        if !self.retired_convs.contains(&conv) {
            self.retired_convs.push(conv);
        }
        if self.retired_convs.len() > MAX_RETIRED_CONVS {
            self.retired_convs.remove(0);
        }
    }

    fn lane(&mut self, direction: PacketDirection) -> &mut Lane {
        match direction {
            PacketDirection::Sent => &mut self.sent,
            PacketDirection::Received => &mut self.recv,
        }
    }

    fn is_bound_anywhere(&self, conv: u32) -> bool {
        self.bound_conversation(PacketDirection::Sent) == Some(conv)
            || self.bound_conversation(PacketDirection::Received) == Some(conv)
    }

    /// Whether `head` can be the first segment of a connection that replaces
    /// the current one: at the start of its sequence space, and a
    /// conversation that is neither the current one nor one that ended.
    fn could_start_connection(&self, head: &SegmentHead) -> bool {
        head.could_open_conversation()
            && !self.retired_convs.contains(&head.conv)
            && !self.is_bound_anywhere(head.conv)
    }

    /// Log a conversation the first time a lane binds to it. Both directions
    /// share one, so this is once per connection.
    fn announce_conversation(&mut self, conv: u32, server: Option<SocketAddr>) {
        if self.announced_conv == Some(conv) {
            return;
        }
        self.announced_conv = Some(conv);
        match server {
            Some(server) => info!(conv, %server, "new kcp conversation"),
            None => info!(conv, "new kcp conversation"),
        }
    }

    fn receive_kcp_segment(
        &mut self,
        direction: PacketDirection,
        kcp_seg: &[u8],
        server: Option<SocketAddr>,
    ) -> Option<Vec<GameCommand>> {
        let current_conv = self.bound_conversation(direction);

        // A datagram that is not even a game KCP header cannot bind, confirm
        // or feed anything.
        let Some(head) = segment_head(kcp_seg) else {
            return current_conv.map(|_| Vec::new());
        };

        // A new conversation is the corroboration a deferred reset was waiting
        // for: the game really did reconnect. "New" is checked, not assumed: a
        // straggler of an ended connection, or a segment from the middle of
        // some conversation, does not start one.
        if self.pending_reset
            && current_conv.is_some_and(|current| current != head.conv)
            && self.could_start_connection(&head)
        {
            self.reset_session("handshake request confirmed by a new kcp conversation");
        }

        if self.lane(direction).kcp.is_none() {
            // A conversation of a connection that already ended. The late
            // segment that bound one at 06:59 on 2026-10-04 left its lane
            // rejecting the live conversation until irminsul was closed.
            if self.retired_convs.contains(&head.conv) {
                debug!(
                    conv = head.conv,
                    ?direction,
                    "ignoring a segment of a conversation that has ended"
                );
                return Some(Vec::new());
            }
            // Capture began mid-conversation, or this is a straggler of one
            // that predates it: a sniffer bound here could never deliver.
            if !head.could_open_conversation() {
                debug!(
                    conv = head.conv,
                    ?direction,
                    "ignoring a segment from the middle of a conversation this lane never saw open"
                );
                return Some(Vec::new());
            }

            // No sniffer in this direction means no conv id to compare, so the
            // corroboration above cannot have fired: a genuine reconnect whose
            // first segment lands in a direction the previous connection never
            // used (capture started mid-session) would otherwise wait for the
            // key to die, silently eating the first two messages -- one of
            // which is the `GetPlayerTokenRsp` the whole session depends on.
            // The other direction's own conversation is not a new one, though.
            if self.pending_reset && !self.is_bound_anywhere(head.conv) {
                self.reset_session(
                    "handshake request confirmed by a new kcp conversation in a direction with \
                     no sniffer",
                );
            }
            self.announce_conversation(head.conv, server);
            *self.lane(direction) = Lane {
                kcp: Some(KcpSniffer::new(head.conv)),
                ..Lane::default()
            };
        }

        let lane = self.lane(direction);
        let kcp = lane.kcp.as_mut()?;
        if kcp.conv_id != head.conv {
            // Counted and logged (rate-limited) by the sniffer, then dropped.
            kcp.receive_segments(kcp_seg);
            return Some(self.consider_switching(direction, head, kcp_seg, server));
        }

        let messages = kcp.receive_segments(kcp_seg);
        let commands: Vec<GameCommand> = messages
            .into_iter()
            .flat_map(|data| self.receive_commands(data))
            .collect();
        self.note_lane_decoded(direction, &commands);
        Some(commands)
    }

    /// The bound conversation of `direction` produced `commands`. If any, it
    /// is the real one, so nothing may take its place.
    fn note_lane_decoded(&mut self, direction: PacketDirection, commands: &[GameCommand]) {
        if !commands.is_empty() {
            let lane = self.lane(direction);
            lane.proven = true;
            lane.candidate = None;
        }
    }

    /// A segment of another conversation reached a bound lane: switch the lane
    /// to that conversation if its own has never decoded anything and the
    /// other one keeps arriving from its start.
    ///
    /// This is the way out of a lane that was bound to the wrong conversation
    /// -- a straggler the retired list did not know about, a stray datagram --
    /// which otherwise rejects the live conversation for as long as the
    /// process runs. The other conversation's datagrams are kept from its
    /// first segment and replayed into the new sniffer, so switching loses
    /// nothing.
    ///
    /// A lane whose conversation has decoded even one command is the real
    /// session and is never switched: no burst of datagrams on another
    /// conversation, forged or not, can take it over. A reconnect replaces
    /// that lane through the deferred reset instead.
    fn consider_switching(
        &mut self,
        direction: PacketDirection,
        head: SegmentHead,
        datagram: &[u8],
        server: Option<SocketAddr>,
    ) -> Vec<GameCommand> {
        let retired = self.retired_convs.contains(&head.conv);
        let lane = self.lane(direction);
        let Some(bound) = lane.kcp.as_ref() else {
            return Vec::new();
        };
        if lane.proven || retired {
            return Vec::new();
        }
        let from = bound.conv_id;

        if let Some(candidate) = lane
            .candidate
            .as_mut()
            .filter(|candidate| candidate.conv == head.conv)
        {
            candidate.datagrams.push(datagram.to_vec());
        } else if head.could_open_conversation() {
            lane.candidate = Some(Candidate {
                conv: head.conv,
                datagrams: vec![datagram.to_vec()],
            });
        } else {
            return Vec::new();
        }

        if lane
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.datagrams.len() < REBIND_AFTER)
        {
            return Vec::new();
        }
        let Some(candidate) = lane.candidate.take() else {
            return Vec::new();
        };

        info!(
            ?direction,
            from,
            to = candidate.conv,
            datagrams = candidate.datagrams.len(),
            "this direction's conversation never decoded anything while another kept arriving \
             from its start; switching to it"
        );
        self.announce_conversation(candidate.conv, server);
        let lane = self.lane(direction);
        let mut kcp = KcpSniffer::new(candidate.conv);
        let messages: Vec<Vec<u8>> = candidate
            .datagrams
            .iter()
            .flat_map(|datagram| kcp.receive_segments(datagram))
            .collect();
        *lane = Lane {
            kcp: Some(kcp),
            ..Lane::default()
        };
        self.retire_conversation(from);

        let commands: Vec<GameCommand> = messages
            .into_iter()
            .flat_map(|data| self.receive_commands(data))
            .collect();
        self.note_lane_decoded(direction, &commands);
        commands
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
            None => KeyCheck::Absent,
            Some(Dispatch(key)) => {
                if magic_matches(key, data) {
                    KeyCheck::DispatchOk
                } else {
                    KeyCheck::DispatchStale
                }
            }
            Some(Key::Session(key)) => {
                if magic_matches(key, data) {
                    KeyCheck::SessionOk
                } else {
                    KeyCheck::SessionStale
                }
            }
        };

        match state {
            KeyCheck::Absent => self.install_dispatch_key(data),
            KeyCheck::DispatchOk => true,
            KeyCheck::SessionOk => {
                self.session_failures = 0;
                self.session_rederive_exhausted = false;
                // Once the session this key belongs to has *kept* decrypting,
                // whatever asked for a reset was not this game. Not on the
                // first message: a real reconnect's old connection still
                // delivers a few after the handshake.
                if self.pending_reset {
                    self.pending_reset_proof += 1;
                    if self.pending_reset_proof >= PENDING_RESET_DISARM_MESSAGES {
                        info!(
                            messages = self.pending_reset_proof,
                            "the session key kept decrypting after a handshake request; not \
                             resetting"
                        );
                        self.pending_reset = false;
                    }
                }
                true
            }
            KeyCheck::DispatchStale => {
                debug!("dispatch key no longer decrypts; looking for the session key");
                self.recover_session_key(data)
            }
            KeyCheck::SessionStale => self.handle_session_key_reject(data),
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
            // Said once: every later message of the connection lands here too,
            // and a log that just stops looks like a game that went quiet.
            if !self.seedless_login {
                warn!(
                    "the login moved past the dispatch key, but no token response with readable \
                     session seeds was seen; this connection cannot be decrypted -- return to the \
                     title screen and enter the world again"
                );
            } else {
                debug!("no session seeds retained yet; dropping the message");
            }
            self.seedless_login = true;
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

        // Time seeds from earlier connections, before the search around this
        // token response's send time. An in-game reconnect draws its client
        // seed from the generator the first login seeded, so the send time the
        // new response carries is the wrong anchor for it. Probing these first
        // costs a bounded few milliseconds (see `RECONNECT_SEED_DEPTH`), runs
        // inside the budget above, and leaves the bruteforce below unchanged
        // for the case it was built for: a fresh game process.
        let anchors = self.time_anchors.clone();
        for anchor in anchors {
            for &seed in &session.seeds {
                if let Some(key) = guess(anchor as i64, seed, RECONNECT_SEED_DEPTH, data) {
                    info!("recovered the session key from the time seed of an earlier connection");
                    self.install_session_key(key, anchor);
                    return true;
                }
            }
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
        // Said once, at the moment it happens: past this point every message
        // of the connection is dropped at debug level, and a log that just
        // stops is indistinguishable from a game that went quiet.
        if self.bruteforce_attempts == MAX_BRUTEFORCE_ATTEMPTS {
            warn!(
                attempts = self.bruteforce_attempts,
                "session key not recovered; this connection's packets are ignored until the next                  login or reconnect"
            );
        }
        false
    }

    fn install_session_key(&mut self, key: Vec<u8>, time_seed: u64) {
        self.last_time_seed = Some(time_seed);
        self.time_anchors.retain(|&anchor| anchor != time_seed);
        self.time_anchors.insert(0, time_seed);
        self.time_anchors.truncate(MAX_TIME_ANCHORS);
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
            self.report_compressed(command);
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
                // previous connection's live anchor and search budget go with it.
                // `time_anchors` stays: that is where a reconnect's key is found.
                self.last_time_seed = None;
                self.bruteforce_attempts = 0;
                self.seedless_login = false;
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

impl GameSniffer {
    /// Log, once per connection, a login message the server compressed.
    ///
    /// The token response is the one that matters: its seeds are what the
    /// session key is recovered from, and compressed they are unreadable.
    fn report_compressed(&mut self, command: &GameCommand) {
        if self.compressed_reported {
            return;
        }
        let Ok(header) = command.parse_header::<PacketHead>() else {
            return;
        };
        let Some(Varint(declared)) = header.unknown_fields().get(COMPRESSED_LEN_FIELD) else {
            return;
        };
        self.compressed_reported = true;
        warn!(
            command_id = command.command_id,
            sent = command.proto_data.len(),
            decompressed = declared,
            "a login message arrived compressed (packet header field 8), which this build cannot \
             read; if it is the token response, this login's session key cannot be recovered"
        );
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
    /// Guids the game says are gone. Candidates, not gospel -- see
    /// [`matches_item_del_packet`] for why the caller must intersect them with
    /// an inventory it actually holds.
    DeletedItems(Vec<u64>),
}

impl CommandMatch {
    /// Name of the packet kind, for logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Items(_) => "items",
            Self::Properties(_) => "properties",
            Self::Avatars(_) => "avatars",
            Self::Achievements(_) => "achievements",
            Self::DeletedItems(_) => "deleted items",
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
    // Last on purpose. Its shape -- one packed uint64 list beside a scalar or
    // two -- is the least specific of the five, so anything another matcher can
    // explain is not a delete notify.
    if let Some(guids) = matches_item_del_packet(game_command) {
        claims.push(CommandMatch::DeletedItems(guids));
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
/// Observed ids, kept as documentation only: the command was 8132 in 7.0 and
/// 22160 in 7.1, and its item list sat on field 5 in 7.0 and field 6 in 7.1.
/// Neither is matched on. The command is recognised by payload-intrinsic
/// evidence and the list is found by shape (see
/// [`matches_items_all_data_notify`]); the first match logs both numbers, so a
/// game patch that moves them shows up in the log rather than as a missing
/// inventory.
pub fn matches_item_packet(game_command: &GameCommand) -> Option<Vec<Item>> {
    let (field, items) = unk_util::discover_items(&game_command.proto_data)?;

    if first_time(&STORE_NOTIFY_LOGGED) {
        info!(
            command_id = game_command.command_id,
            field,
            count = items.len(),
            "discovered PlayerStoreNotify"
        );
    } else {
        debug!(
            command_id = game_command.command_id,
            field,
            count = items.len(),
            "item packet"
        );
    }
    Some(items)
}

/// Decode a packed repeated-varint field, or `None` if the bytes are not one.
///
/// Requires the buffer to be consumed exactly: a trailing partial varint means
/// this blob is a submessage or a string that happened to start with
/// varint-shaped bytes, not a packed list.
fn decode_packed_varints(bytes: &[u8]) -> Option<Vec<u64>> {
    let mut values = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *bytes.get(offset)?;
            offset += 1;
            // A u64 varint is ten bytes at most; past that the shift would panic
            // in a debug build and silently drop bits in a release one.
            if shift >= 64 {
                return None;
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        values.push(value);
    }

    Some(values)
}

/// `true` if every value could be an item guid from one account.
///
/// The game mints guids as `(uid << 32) + counter` (Grasscutter's
/// `Player::getNextGuid`), so a real guid never fits in 32 bits and every guid
/// belonging to one account shares its top half. That pair of facts is what
/// separates a guid list from any other packed varint field: ids, counts,
/// timestamps and flags all live below `u32::MAX`.
fn plausible_guid_list(values: &[u64]) -> bool {
    if values.is_empty() || values.len() > MAX_ITEM_DEL_GUIDS {
        return false;
    }

    let uid = values[0] >> 32;
    uid != 0 && values.iter().all(|guid| guid >> 32 == uid)
}

/// Recover the guids a `StoreItemDelNotify` says are gone, or `None` if this is
/// not one.
///
/// Observed command id: `StoreItemDelNotify` was 636 in 7.0, kept as
/// documentation only -- like every other matcher here this goes on shape,
/// because command ids are reshuffled every game version.
///
/// **The result is a list of candidates, and the caller must treat it as one.**
/// The shape -- one packed uint64 list beside a scalar or two -- is the least
/// specific this library matches on: sweeping Grasscutter's protos finds 23
/// messages wearing it, among them `AvatarDelNotify`, the avatar-team packets
/// and `ReliquaryDecomposeReq`. What makes acting on it safe is not this
/// function but the intersection the caller performs: remove only guids the
/// inventory actually holds. Every colliding message then resolves to one of
/// two harmless outcomes -- it carries avatar guids, which are drawn from the
/// same counter but are never an item's guid, so nothing intersects; or it
/// carries item guids that really are being destroyed (a decompose request, a
/// talent conversion), where acting early reaches the same state the delete
/// notify would a moment later.
pub fn matches_item_del_packet(game_command: &GameCommand) -> Option<Vec<u64>> {
    let msg = Unk::parse_from_bytes(&game_command.proto_data).ok()?;

    let mut blobs: Vec<(u32, &[u8])> = Vec::new();
    let mut varints: Vec<(u32, u64)> = Vec::new();

    for (number, value) in msg.unknown_fields().iter() {
        match value {
            LengthDelimited(bytes) => blobs.push((number, bytes)),
            Varint(scalar) => varints.push((number, scalar)),
            // A delete notify has no fixed-width fields. Something that does is
            // a different message.
            Fixed32(_) | Fixed64(_) => return None,
        }
    }

    let mut numbers: Vec<u32> = blobs
        .iter()
        .map(|(number, _)| *number)
        .chain(varints.iter().map(|(number, _)| *number))
        .collect();
    numbers.sort_unstable();
    numbers.dedup();
    if numbers.is_empty() || numbers.len() > MAX_ITEM_DEL_FIELDS {
        return None;
    }

    // The guid list is packed in every proto3 build of this message, so the
    // usual case is exactly one blob. More than one means a message carrying
    // submessages or strings, which a delete notify does not have.
    let (guid_field, guids) = match blobs.as_slice() {
        [(number, bytes)] => {
            let values = decode_packed_varints(bytes)?;
            if !plausible_guid_list(&values) {
                return None;
            }
            (*number, values)
        }
        // No blob at all: an unpacked encoding, where each guid is its own
        // varint under one field number. Accepted because `packed` is a wire
        // detail the server is free to change.
        [] => {
            let mut candidate = None;
            for &number in &numbers {
                let values: Vec<u64> = varints
                    .iter()
                    .filter(|(field, _)| *field == number)
                    .map(|(_, scalar)| *scalar)
                    .collect();
                if plausible_guid_list(&values) {
                    if candidate.is_some() {
                        // Two guid-shaped fields is not this message.
                        return None;
                    }
                    candidate = Some((number, values));
                }
            }
            candidate?
        }
        _ => return None,
    };

    // Whatever else the message carries has to be a small scalar -- `StoreType`
    // and at most a retcode-sized companion.
    for (number, scalar) in &varints {
        if *number != guid_field && *scalar > MAX_ITEM_DEL_SCALAR {
            trace!(
                command_id = game_command.command_id,
                field = *number,
                scalar = *scalar,
                "guid-shaped list, but a companion scalar is too large for a delete notify"
            );
            return None;
        }
    }

    if first_time(&ITEM_DEL_NOTIFY_LOGGED) {
        info!(
            command_id = game_command.command_id,
            count = guids.len(),
            "discovered StoreItemDelNotify"
        );
    } else {
        debug!(
            command_id = game_command.command_id,
            count = guids.len(),
            "item delete packet"
        );
    }
    Some(guids)
}

/// Recover the character roster from an `AvatarDataNotify`, or `None` if this is
/// not one.
///
/// Observed ids, kept as documentation only: the command was 6586 in 7.0 and
/// 27799 in 7.1, and its avatar list sat on field 6 in 7.0 and field 7 in 7.1.
/// Neither is matched on; the list is found by shape (see
/// [`matches_avatars_all_data_notify`]) and the first match logs both numbers.
///
/// The discriminator is that an `AvatarInfo` carries a playable id and a
/// `prop_map` holding its level; a plain `{varint, varint}` list does not.
/// There is deliberately **no** minimum roster size: a new account owns fewer
/// than ten characters and still has to export.
pub fn matches_avatar_packet(game_command: &GameCommand) -> Option<Vec<AvatarInfo>> {
    let (field, avatars) = unk_util::discover_avatars(&game_command.proto_data)?;

    if first_time(&AVATAR_NOTIFY_LOGGED) {
        info!(
            command_id = game_command.command_id,
            field,
            count = avatars.len(),
            "discovered AvatarDataNotify"
        );
    } else {
        debug!(
            command_id = game_command.command_id,
            field,
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
fn prop_value(prop: &PropValue) -> Option<u64> {
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
///
/// The `map<uint32, PropValue>` shape is not unique to this packet. A 7.1
/// login also sends a 14-entry map of ids 20046..=20392 whose every value is
/// its own key (command 24819 that day), and it used to be accepted -- and
/// logged as "discovered PlayerPropertyNotify" -- ahead of the real one. So a
/// map is only believed when most of its keys are player property ids (the
/// 10xxx block of the client's `PROP_*` enum) and it is not an identity map.
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

    // A list of ids wearing the map's shape: no counter in it is anything but
    // its own key. One such value is ordinary (a property can hold its own
    // id); a whole page of them is not a property map.
    if properties
        .iter()
        .all(|(key, value)| u64::from(*key) == *value)
    {
        trace!(
            command_id = game_command.command_id,
            count = properties.len(),
            "every value equals its own key; an id list, not player properties"
        );
        return None;
    }

    // Strictly more than half, so a few properties newer than the block (or a
    // stray foreign entry) cannot reject a real notify, while a map of some
    // other id space cannot pass for one.
    let player_ids = properties
        .keys()
        .filter(|key| PLAYER_PROPERTY_IDS.contains(key))
        .count();
    if player_ids * 2 <= properties.len() {
        trace!(
            command_id = game_command.command_id,
            player_ids,
            count = properties.len(),
            "most keys are not player property ids"
        );
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
    use tracing::Level;

    use super::*;
    use crate::crypto::new_key_from_seed;
    use crate::cs_rand::Random;
    use crate::test_support::{logged, warnings};

    const PROP_MAP_TAG: u32 = 4;
    /// Where 7.1 put `PlayerStoreNotify`'s item list and `AvatarDataNotify`'s
    /// avatar list. The matchers find them by shape; the fixtures use the real
    /// numbers unless a test says otherwise.
    const ITEM_LIST_TAG: u32 = 6;
    const AVATAR_LIST_TAG: u32 = 7;
    /// The uid half of the fixtures' guids.
    const TEST_UID: u64 = 800_123_456;

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

    /// `count` items on field `tag`, with guids minted the way the game does.
    fn item_packet_on(tag: u32, count: u32) -> Vec<u8> {
        (0..count)
            .flat_map(|i| field_bytes(tag, &item_entry(1000 + i, guid(TEST_UID, u64::from(i) + 1))))
            .collect()
    }

    fn item_packet(count: u32) -> Vec<u8> {
        item_packet_on(ITEM_LIST_TAG, count)
    }

    /// One `AvatarInfo` with an id, a guid and a one-entry `prop_map`.
    fn avatar_entry(avatar_id: u32, guid: u64) -> Vec<u8> {
        let mut out = field_varint(1, u64::from(avatar_id));
        out.extend(field_varint(2, guid));
        out.extend(field_bytes(3, &prop_entry(4001, &prop_val(4001, 90))));
        out
    }

    /// A roster of `count` characters on field `tag`.
    fn avatar_packet_on(tag: u32, count: u32) -> Vec<u8> {
        (0..count)
            .flat_map(|i| {
                field_bytes(
                    tag,
                    &avatar_entry(10_000_002 + i, guid(TEST_UID, u64::from(i) + 1)),
                )
            })
            .collect()
    }

    fn avatar_packet(count: u32) -> Vec<u8> {
        avatar_packet_on(AVATAR_LIST_TAG, count)
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
            // Drop the anchors so the next round pays for the bruteforce again
            // rather than taking either retained-seed path.
            sniffer.last_time_seed = None;
            sniffer.time_anchors.clear();
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

    // -- end-to-end connections ------------------------------------------------
    //
    // Everything below drives real frames through `receive_packet`: a handshake,
    // the token exchange under the dispatch key with a seed RSA-encrypted to the
    // embedded client key, then traffic under the session key. Reconnects are a
    // property of the whole state machine -- conversation binding, the deferred
    // reset, seed installation and key recovery all take part -- so they are
    // tested through it rather than by poking one method at a time.

    /// The dispatch key the harness's game speaks for the login exchange.
    fn dispatch_key() -> Vec<u8> {
        new_key_from_seed(0xD15_0A7C)
    }

    /// A sniffer that knows [`dispatch_key`], the way irminsul's `keys/gi.json`
    /// supplies the real ones.
    ///
    /// The version a key answers to is the first two bytes of the ciphertext XOR
    /// the magic, and the plaintext starts with the magic, so it is simply the
    /// key's own first two bytes.
    fn connected_sniffer() -> GameSniffer {
        let key = dispatch_key();
        let version = u16::from_be_bytes([key[0], key[1]]);
        GameSniffer::new().set_initial_keys(HashMap::from([(version, key)]))
    }

    /// PKCS#1 v1.5 padding wants random bytes, not secret ones; a fixed stream
    /// keeps the fixture deterministic.
    struct TestRng(u64);

    impl rsa::rand_core::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            // splitmix64
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.next_u64() as u8;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rsa::rand_core::CryptoRng for TestRng {}

    /// A `GetPlayerTokenRsp` payload carrying `seed` the way the server sends
    /// it: RSA-encrypted to the client's key, then base64'd into a string field.
    fn token_rsp_payload(sniffer: &GameSniffer, seed: u64) -> Vec<u8> {
        let public = sniffer.rsa_keys[0].to_public_key();
        let encrypted = public
            .encrypt(
                &mut TestRng(seed),
                rsa::Pkcs1v15Encrypt,
                &seed.to_be_bytes(),
            )
            .expect("an 8-byte seed fits the key");
        field_bytes(11, BASE64_STANDARD.encode(encrypted).as_bytes())
    }

    /// The `draw`-th client seed the game's `System.Random` produces from
    /// `time_seed` (0 is the first).
    fn client_draw(time_seed: u64, draw: usize) -> u64 {
        let mut generator = Random::seeded(time_seed as i32);
        let mut value = 0;
        for _ in 0..=draw {
            value = generator.next_safe_uint64();
        }
        value
    }

    /// One segment at an explicit position in its conversation.
    fn segment_frame_at(
        direction: PacketDirection,
        conv: u32,
        sn: u32,
        una: u32,
        content: &[u8],
    ) -> Vec<u8> {
        let mut segment = game_segment(conv, content);
        segment[16..20].copy_from_slice(&sn.to_le_bytes());
        segment[20..24].copy_from_slice(&una.to_le_bytes());
        match direction {
            PacketDirection::Received => udp_frame(22102, 50000, &segment),
            PacketDirection::Sent => udp_frame(50000, 22102, &segment),
        }
    }

    /// One game connection on the wire, numbering its own segments.
    struct Conn {
        conv: u32,
        sent_sn: u32,
        recv_sn: u32,
    }

    impl Conn {
        fn new(conv: u32) -> Self {
            Self {
                conv,
                sent_sn: 0,
                recv_sn: 0,
            }
        }

        /// The next push in `direction`, carrying `plain` encrypted under `key`.
        fn push(&mut self, direction: PacketDirection, key: &[u8], plain: &[u8]) -> Vec<u8> {
            let mut data = plain.to_vec();
            decrypt_command(key, &mut data);
            let (sn, una) = match direction {
                PacketDirection::Sent => {
                    self.sent_sn += 1;
                    (self.sent_sn - 1, self.recv_sn)
                }
                PacketDirection::Received => {
                    self.recv_sn += 1;
                    (self.recv_sn - 1, self.sent_sn)
                }
            };
            segment_frame_at(direction, self.conv, sn, una, &data)
        }

        /// A server message under `key`, with its own command id.
        fn server_message(&mut self, key: &[u8], command_id: u16) -> Vec<u8> {
            self.push(
                PacketDirection::Received,
                key,
                &command_bytes(command_id, &[], &field_varint(1, u64::from(command_id))),
            )
        }
    }

    /// Feed one frame and return the command ids it decoded to.
    fn command_ids(sniffer: &mut GameSniffer, frame: Vec<u8>) -> Vec<u16> {
        match sniffer.receive_packet(frame) {
            Some(GamePacket::Commands(commands)) => {
                commands.iter().map(|command| command.command_id).collect()
            }
            _ => Vec::new(),
        }
    }

    /// The login exchange over `conn`: a handshake, the client's token request
    /// and the server's token response under the dispatch key, then the first
    /// server message under the session key derived from `combined`.
    ///
    /// The token response carries `client_seed ^ combined` and is stamped
    /// `sent_ms`, which is all the sniffer gets to work from. Returns the
    /// command ids the session message decoded to: `[SESSION_MESSAGE]` when the
    /// key was recovered, nothing when it was not.
    fn log_in(
        sniffer: &mut GameSniffer,
        conn: &mut Conn,
        sent_ms: u64,
        client_seed: u64,
        combined: u64,
    ) -> Vec<u16> {
        sniffer.receive_packet(handshake_frame());
        token_exchange(sniffer, conn, sent_ms, client_seed ^ combined);
        command_ids(
            sniffer,
            conn.server_message(&new_key_from_seed(combined), SESSION_MESSAGE),
        )
    }

    /// The client's token request and the server's token response, both under
    /// the dispatch key; the response carries `seed` and is stamped `sent_ms`.
    fn token_exchange(sniffer: &mut GameSniffer, conn: &mut Conn, sent_ms: u64, seed: u64) {
        let dispatch = dispatch_key();
        let request = command_bytes(TOKEN_REQ, &[], &field_varint(1, 1));
        assert_eq!(
            command_ids(
                sniffer,
                conn.push(PacketDirection::Sent, &dispatch, &request)
            ),
            vec![TOKEN_REQ],
            "the token request decrypts under the dispatch key"
        );

        let response = command_bytes(
            TOKEN_RSP,
            &field_varint(6, sent_ms),
            &token_rsp_payload(sniffer, seed),
        );
        assert_eq!(
            command_ids(
                sniffer,
                conn.push(PacketDirection::Received, &dispatch, &response)
            ),
            vec![TOKEN_RSP],
            "the token response decrypts under the dispatch key"
        );
        assert_eq!(
            sniffer.session_seeds.as_ref().map(|s| s.sent_ms),
            Some(sent_ms),
            "the token response installs its seeds"
        );
    }

    /// Feed `frame` the way pktmon delivers it: eight identical copies.
    fn eight_times(sniffer: &mut GameSniffer, frame: Vec<u8>) -> Vec<u16> {
        let mut ids = Vec::new();
        for _ in 0..8 {
            ids.extend(command_ids(sniffer, frame.clone()));
        }
        ids
    }

    const TOKEN_REQ: u16 = 100;
    const TOKEN_RSP: u16 = 101;
    const SESSION_MESSAGE: u16 = 102;

    /// A realistic login time, in the epoch milliseconds `PacketHead` carries.
    const LOGIN_MS: u64 = 1_759_553_801_000;
    const HOUR_MS: u64 = 3_600_000;

    #[test]
    fn a_compressed_token_response_is_reported_as_a_lost_key_at_once() {
        // 2026-10-05 02:33 and 11:21: some gate servers send the
        // `GetPlayerTokenRsp` compressed -- header field 8 is its decompressed
        // length, the payload is not protobuf. It decrypts under the dispatch
        // key and parses as a command, yields no seeds, and every message after
        // it was dropped at debug level: no warning, no "key lost", nothing.
        let mut sniffer = connected_sniffer();
        let mut conn = Conn::new(131_847);
        let dispatch = dispatch_key();
        sniffer.receive_packet(handshake_frame());

        let request = command_bytes(TOKEN_REQ, &[], &field_varint(1, 1));
        assert_eq!(
            command_ids(
                &mut sniffer,
                conn.push(PacketDirection::Sent, &dispatch, &request)
            ),
            vec![TOKEN_REQ]
        );
        // Not protobuf: wire type 7 right after the first field.
        let compressed: Vec<u8> = [0x09, 0, 0xa8, 0x45, 0xf3, 0x09, 0x37, 0xf2, 0xdf, 0x7f]
            .into_iter()
            .chain((0..200u32).map(|i| (i * 37 + 11) as u8))
            .collect();
        let mut header = field_varint(3, 1);
        header.extend(field_varint(6, LOGIN_MS));
        header.extend(field_varint(COMPRESSED_LEN_FIELD, 25_563));
        let response = command_bytes(TOKEN_RSP, &header, &compressed);

        let logged = crate::test_support::warnings(|| {
            assert_eq!(
                command_ids(
                    &mut sniffer,
                    conn.push(PacketDirection::Received, &dispatch, &response)
                ),
                vec![TOKEN_RSP],
                "the response still decrypts under the dispatch key"
            );
            assert!(sniffer.session_seeds.is_none());
            assert!(!sniffer.key_recovery_failed(), "nothing is lost yet");

            let session = new_key_from_seed(0x1111_2222_3333_4444);
            for _ in 0..3 {
                assert!(
                    command_ids(&mut sniffer, conn.server_message(&session, SESSION_MESSAGE))
                        .is_empty()
                );
            }
        });

        assert!(sniffer.key_recovery_failed(), "the UI can say so at once");
        assert_eq!(sniffer.key_state(), KeyState::Dispatch);
        assert_eq!(
            logged.iter().filter(|l| l.contains("compressed")).count(),
            1,
            "{logged:#?}"
        );
        assert_eq!(
            logged
                .iter()
                .filter(|l| l.contains("no token response with readable session seeds"))
                .count(),
            1,
            "said once, not per message: {logged:#?}"
        );

        // A new login starts clean.
        sniffer.receive_packet(handshake_frame());
        assert!(!sniffer.key_recovery_failed());
    }

    #[test]
    fn a_first_login_recovers_the_session_key_from_the_send_time() {
        // The baseline every reconnect test builds on: the client seeds its
        // `System.Random` with the token response's send time and draws once.
        let mut sniffer = connected_sniffer();
        let mut conn = Conn::new(122_486);

        let decoded = log_in(
            &mut sniffer,
            &mut conn,
            LOGIN_MS,
            client_draw(LOGIN_MS, 0),
            0x1111_2222_3333_4444,
        );

        assert_eq!(decoded, vec![SESSION_MESSAGE]);
        assert!(matches!(sniffer.key, Some(Key::Session(_))));
        assert_eq!(sniffer.last_time_seed, Some(LOGIN_MS));
    }

    #[test]
    fn a_reconnect_recovers_its_key_from_the_first_logins_time_seed() {
        // What the log of 2026-10-04 shows, and what upstream konkers retains
        // the client seed for: on an in-game reconnect the client does not
        // reseed its `System.Random` -- it draws the *next* value from the one
        // seeded at the first login. The new token response is stamped hours
        // later, so a search around its send time finds nothing, however deep.
        let mut sniffer = connected_sniffer();
        let mut first = Conn::new(122_486);
        assert_eq!(
            log_in(
                &mut sniffer,
                &mut first,
                LOGIN_MS,
                client_draw(LOGIN_MS, 0),
                0x1111_2222_3333_4444,
            ),
            vec![SESSION_MESSAGE]
        );

        let mut second = Conn::new(122_628);
        let decoded = log_in(
            &mut sniffer,
            &mut second,
            LOGIN_MS + 3 * HOUR_MS,
            client_draw(LOGIN_MS, 1),
            0x5555_6666_7777_8888,
        );

        assert_eq!(decoded, vec![SESSION_MESSAGE], "the reconnect must decode");
        assert_eq!(
            sniffer.bruteforce_attempts, 0,
            "the retained time seed found it; no bruteforce run failed first"
        );
        assert_eq!(sniffer.session_generation(), 2);
        assert_eq!(sniffer.last_time_seed, Some(LOGIN_MS));
    }

    #[test]
    fn every_later_reconnect_draws_deeper_from_the_same_time_seed() {
        // Three reconnects in one game process, the later ones several draws
        // apart (anything else the client takes from that generator in between
        // pushes the next seed further down it).
        let mut sniffer = connected_sniffer();
        let mut conv = 122_486;
        for (hours, draw) in [(0u64, 0usize), (2, 1), (4, 5), (9, 40)] {
            let mut conn = Conn::new(conv);
            conv += 100;
            let combined = 0xC0FF_EE00_0000_0000 | draw as u64;
            let decoded = log_in(
                &mut sniffer,
                &mut conn,
                LOGIN_MS + hours * HOUR_MS,
                client_draw(LOGIN_MS, draw),
                combined,
            );
            assert_eq!(decoded, vec![SESSION_MESSAGE], "draw {draw}");
            assert_eq!(sniffer.bruteforce_attempts, 0, "draw {draw}");

            // And the connection keeps decoding afterwards.
            let key = new_key_from_seed(combined);
            assert_eq!(
                command_ids(&mut sniffer, conn.server_message(&key, 7)),
                vec![7]
            );
        }
    }

    #[test]
    fn a_new_game_process_is_still_found_by_the_bruteforce() {
        // Restarting the game reseeds the generator, so the retained time seed
        // is useless for the next login. Probing it must cost only its own
        // (bounded) search and then fall through to the search around the new
        // send time, exactly as before.
        let mut sniffer = connected_sniffer();
        let mut first = Conn::new(122_486);
        log_in(
            &mut sniffer,
            &mut first,
            LOGIN_MS,
            client_draw(LOGIN_MS, 0),
            0x1111_2222_3333_4444,
        );

        let restarted = LOGIN_MS + 5 * HOUR_MS;
        let mut second = Conn::new(130_000);
        let decoded = log_in(
            &mut sniffer,
            &mut second,
            restarted,
            client_draw(restarted, 0),
            0x9999_AAAA_BBBB_CCCC,
        );

        assert_eq!(decoded, vec![SESSION_MESSAGE]);
        assert_eq!(sniffer.last_time_seed, Some(restarted));
        assert_eq!(
            sniffer.time_anchors,
            vec![restarted, LOGIN_MS],
            "the newest time seed is probed first next time"
        );
    }

    #[test]
    fn retained_time_seeds_are_bounded_and_deduplicated() {
        let mut sniffer = GameSniffer::new();
        for seed in [1u64, 2, 1, 3, 4, 5, 6] {
            sniffer.install_session_key(new_key_from_seed(seed), seed);
        }

        assert_eq!(sniffer.time_anchors.len(), MAX_TIME_ANCHORS);
        assert_eq!(sniffer.time_anchors[0], 6, "newest first");
        let mut unique = sniffer.time_anchors.clone();
        unique.dedup();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), sniffer.time_anchors.len(), "no duplicates");
    }

    // -- state reported to the caller ---------------------------------------------

    #[test]
    fn the_key_state_follows_the_login() {
        let mut sniffer = connected_sniffer();
        assert_eq!(sniffer.key_state(), KeyState::None);

        let mut conn = Conn::new(122_486);
        sniffer.receive_packet(handshake_frame());
        let combined = 0x1111_2222_3333_4444;
        token_exchange(
            &mut sniffer,
            &mut conn,
            LOGIN_MS,
            client_draw(LOGIN_MS, 0) ^ combined,
        );
        assert_eq!(sniffer.key_state(), KeyState::Dispatch);

        command_ids(
            &mut sniffer,
            conn.server_message(&new_key_from_seed(combined), SESSION_MESSAGE),
        );
        assert_eq!(sniffer.key_state(), KeyState::Session);

        // A reconnect starts over.
        let mut next = Conn::new(122_628);
        sniffer.receive_packet(handshake_frame());
        token_exchange(&mut sniffer, &mut next, LOGIN_MS + HOUR_MS, 0x77);
        assert_eq!(sniffer.key_state(), KeyState::Dispatch);
    }

    #[test]
    fn each_new_conversation_is_logged_once_with_its_server() {
        let mut sniffer = connected_sniffer();
        let mut conn = Conn::new(122_486);
        let lines = crate::test_support::logged(tracing::Level::INFO, || {
            log_in(
                &mut sniffer,
                &mut conn,
                LOGIN_MS,
                client_draw(LOGIN_MS, 0),
                0x1111,
            );
            // More traffic in both directions is not news.
            let key = new_key_from_seed(0x1111);
            command_ids(&mut sniffer, conn.server_message(&key, 1));
        });

        let announced: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("new kcp conversation"))
            .collect();
        assert_eq!(announced.len(), 1, "{lines:#?}");
        assert!(announced[0].contains("122486"), "{announced:?}");
        assert!(announced[0].contains(":22102"), "{announced:?}");
    }

    // -- conversation binding ----------------------------------------------------

    /// A connection whose login stalled before any session key: the state the
    /// 06:55 reconnect of 2026-10-04 was left in when the next one came.
    fn stalled_login(sniffer: &mut GameSniffer, conv: u32) -> Conn {
        let mut conn = Conn::new(conv);
        sniffer.receive_packet(handshake_frame());
        token_exchange(sniffer, &mut conn, LOGIN_MS, 0x0BAD_5EED);
        assert!(matches!(sniffer.key, Some(Dispatch(_))));
        conn
    }

    /// The new connection's token exchange, as pktmon delivers it, with the
    /// command ids each side decoded to.
    fn new_connection_logs_in(sniffer: &mut GameSniffer, conn: &mut Conn) -> (Vec<u16>, Vec<u16>) {
        let dispatch = dispatch_key();
        let request = command_bytes(TOKEN_REQ, &[], &field_varint(1, 1));
        let sent = eight_times(
            sniffer,
            conn.push(PacketDirection::Sent, &dispatch, &request),
        );
        let response = command_bytes(TOKEN_RSP, &field_varint(6, LOGIN_MS), &[]);
        let received = eight_times(
            sniffer,
            conn.push(PacketDirection::Received, &dispatch, &response),
        );
        (sent, received)
    }

    #[test]
    fn a_late_segment_of_the_old_conversation_cannot_capture_a_lane() {
        // 06:59:37: with no session key live the handshake reset at once; a
        // late 32-byte segment of the old conversation 123542 then arrived
        // before the new one, bound the received direction, and the new
        // conversation 123582 was rejected 10,384 times until irminsul closed.
        let mut sniffer = connected_sniffer();
        let old = stalled_login(&mut sniffer, 123_542);
        let generation = sniffer.session_generation();

        for _ in 0..9 {
            sniffer.receive_packet(handshake_frame());
        }
        assert!(sniffer.session_generation() > generation);

        // The late segment: no content, far into the old conversation.
        eight_times(
            &mut sniffer,
            segment_frame_at(PacketDirection::Received, old.conv, 4096, 3000, &[]),
        );
        assert_eq!(sniffer.bound_conversation(PacketDirection::Received), None);

        let mut new = Conn::new(123_582);
        let (sent, received) = new_connection_logs_in(&mut sniffer, &mut new);
        assert_eq!(sent, vec![TOKEN_REQ]);
        assert_eq!(received, vec![TOKEN_RSP], "the server side must decode");
        assert_eq!(
            sniffer.bound_conversation(PacketDirection::Received),
            Some(123_582)
        );
    }

    #[test]
    fn a_young_old_conversation_is_still_kept_off_a_fresh_lane() {
        // The same race when the old conversation was only seconds old, so its
        // late segment still sits at the start of the sequence space: only the
        // record of which conversations a reset retired tells it apart.
        let mut sniffer = connected_sniffer();
        let old = stalled_login(&mut sniffer, 123_542);
        sniffer.receive_packet(handshake_frame());

        eight_times(
            &mut sniffer,
            segment_frame_at(PacketDirection::Received, old.conv, 2, 1, &[]),
        );
        assert_eq!(sniffer.bound_conversation(PacketDirection::Received), None);

        let mut new = Conn::new(123_582);
        let (sent, received) = new_connection_logs_in(&mut sniffer, &mut new);
        assert_eq!(sent, vec![TOKEN_REQ]);
        assert_eq!(received, vec![TOKEN_RSP]);
    }

    #[test]
    fn a_retired_conversation_does_not_confirm_a_deferred_reset() {
        // A handshake while a session key is live waits for a *new*
        // conversation. A straggler from the connection before last is not one.
        let mut sniffer = connected_sniffer();
        let mut first = Conn::new(122_486);
        log_in(
            &mut sniffer,
            &mut first,
            LOGIN_MS,
            client_draw(LOGIN_MS, 0),
            0x1111,
        );
        let mut second = Conn::new(122_628);
        log_in(
            &mut sniffer,
            &mut second,
            LOGIN_MS + HOUR_MS,
            client_draw(LOGIN_MS, 1),
            0x2222,
        );
        let generation = sniffer.session_generation();

        sniffer.receive_packet(handshake_frame());
        sniffer.receive_packet(segment_frame_at(
            PacketDirection::Received,
            first.conv,
            0,
            0,
            &[0u8; 40],
        ));

        assert_eq!(sniffer.session_generation(), generation);
        assert!(matches!(sniffer.key, Some(Key::Session(_))));
    }

    #[test]
    fn a_mid_stream_segment_does_not_confirm_a_deferred_reset() {
        // A new connection starts at the bottom of its sequence space. Anything
        // further in belongs to a conversation that was already running.
        let mut sniffer = connected_sniffer();
        let mut conn = Conn::new(122_486);
        log_in(
            &mut sniffer,
            &mut conn,
            LOGIN_MS,
            client_draw(LOGIN_MS, 0),
            0x1111,
        );
        let generation = sniffer.session_generation();

        sniffer.receive_packet(handshake_frame());
        sniffer.receive_packet(segment_frame_at(
            PacketDirection::Received,
            999_999,
            50_000,
            40_000,
            &[0u8; 40],
        ));

        assert_eq!(sniffer.session_generation(), generation);
        assert_eq!(
            sniffer.bound_conversation(PacketDirection::Received),
            Some(conn.conv)
        );
    }

    #[test]
    fn the_same_conversation_in_the_other_direction_is_not_a_new_one() {
        // Capture began mid-session, so only one direction was bound. That
        // conversation's first segment in the other direction is not a
        // reconnect, whatever a handshake datagram claimed.
        let mut sniffer = connected_sniffer();
        let key = new_key_from_seed(0x5E55);
        sniffer.key = Some(Key::Session(key.clone()));
        let mut conn = Conn::new(4242);
        assert_eq!(
            command_ids(&mut sniffer, conn.server_message(&key, 1)),
            vec![1]
        );

        sniffer.receive_packet(handshake_frame());
        let request = command_bytes(2, &[], &field_varint(1, 1));
        assert_eq!(
            command_ids(
                &mut sniffer,
                conn.push(PacketDirection::Sent, &key, &request)
            ),
            vec![2]
        );
        assert_eq!(sniffer.session_generation(), 0);
    }

    #[test]
    fn a_lane_stuck_on_a_silent_conversation_switches_to_the_live_one() {
        // Whatever else guards the binding, a lane can still end up on a
        // conversation that will never deliver (here: a stray segment before
        // anything was retired). The live conversation then keeps arriving
        // while the bound one stays silent; switching to it -- and replaying
        // what it sent meanwhile -- must lose nothing and duplicate nothing.
        let mut sniffer = connected_sniffer();
        sniffer.receive_packet(segment_frame_at(PacketDirection::Received, 555, 0, 0, &[]));
        assert_eq!(
            sniffer.bound_conversation(PacketDirection::Received),
            Some(555)
        );

        let dispatch = dispatch_key();
        let mut live = Conn::new(123_582);
        let request = command_bytes(TOKEN_REQ, &[], &field_varint(1, 1));
        assert_eq!(
            command_ids(
                &mut sniffer,
                live.push(PacketDirection::Sent, &dispatch, &request)
            ),
            vec![TOKEN_REQ]
        );

        let mut decoded = Vec::new();
        let messages: Vec<u16> = (1..=REBIND_AFTER as u16 + 8).collect();
        for &id in &messages {
            decoded.extend(command_ids(
                &mut sniffer,
                live.server_message(&dispatch, id),
            ));
        }

        assert_eq!(decoded, messages, "every message once, in order");
        assert_eq!(
            sniffer.bound_conversation(PacketDirection::Received),
            Some(123_582)
        );
        assert_eq!(sniffer.session_generation(), 0, "a lane switch is no reset");
    }

    #[test]
    fn a_delivering_lane_is_never_taken_over() {
        // The switch above is for a lane whose conversation has decoded
        // nothing. One that has is the real session, and no burst of datagrams
        // on another conversation -- forged or not -- may displace it.
        let mut sniffer = connected_sniffer();
        let mut conn = Conn::new(122_486);
        let combined = 0x1111_2222_3333_4444;
        log_in(
            &mut sniffer,
            &mut conn,
            LOGIN_MS,
            client_draw(LOGIN_MS, 0),
            combined,
        );
        let generation = sniffer.session_generation();

        let mut intruder = Conn::new(9_999);
        for id in 0..REBIND_AFTER as u16 * 4 {
            sniffer.receive_packet(intruder.server_message(&dispatch_key(), id));
        }

        assert_eq!(
            sniffer.bound_conversation(PacketDirection::Received),
            Some(conn.conv)
        );
        assert_eq!(sniffer.session_generation(), generation);
        let key = new_key_from_seed(combined);
        assert_eq!(
            command_ids(&mut sniffer, conn.server_message(&key, 77)),
            vec![77]
        );
    }

    #[test]
    fn a_switch_needs_the_other_conversation_from_its_start() {
        // Datagrams from the middle of a conversation cannot be replayed into
        // anything that delivers, so they never start the count.
        let mut sniffer = connected_sniffer();
        sniffer.receive_packet(segment_frame_at(PacketDirection::Received, 555, 0, 0, &[]));
        for sn in 0..REBIND_AFTER as u32 * 2 {
            sniffer.receive_packet(segment_frame_at(
                PacketDirection::Received,
                777,
                5_000 + sn,
                5_000,
                &[0u8; 40],
            ));
        }
        assert_eq!(
            sniffer.bound_conversation(PacketDirection::Received),
            Some(555)
        );
    }

    #[test]
    fn giving_up_on_a_connections_key_is_said_once_and_reported() {
        // After the budget is spent every further message of the connection is
        // dropped at debug level, which is how 1h44m of nothing decoding left
        // no trace in the log. Say it once, and let the caller show it.
        let mut sniffer = GameSniffer::new();
        sniffer.session_seeds = Some(SessionSeeds {
            seeds: vec![1],
            sent_ms: 2,
        });
        // A cheap stand-in for the failed runs before the last one.
        sniffer.bruteforce_attempts = MAX_BRUTEFORCE_ATTEMPTS - 1;
        sniffer.key = Some(Dispatch(new_key_from_seed(3)));
        assert!(!sniffer.key_recovery_failed());

        let logged = warnings(|| {
            for _ in 0..20 {
                assert!(!sniffer.recover_session_key(&[0u8; 64]));
            }
        });

        let gave_up = logged
            .iter()
            .filter(|line| line.contains("not recovered"))
            .count();
        assert_eq!(gave_up, 1, "{logged:#?}");
        assert!(sniffer.key_recovery_failed());

        // A new token response is a new chance.
        sniffer.bruteforce_attempts = 0;
        assert!(!sniffer.key_recovery_failed());
    }

    #[test]
    fn a_reset_clears_the_given_up_report() {
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Dispatch(new_key_from_seed(3)));
        sniffer.session_seeds = Some(SessionSeeds {
            seeds: vec![1],
            sent_ms: 2,
        });
        sniffer.bruteforce_attempts = MAX_BRUTEFORCE_ATTEMPTS;
        assert!(sniffer.key_recovery_failed());

        sniffer.receive_packet(handshake_frame());
        assert!(!sniffer.key_recovery_failed());
    }

    #[test]
    fn earlier_time_seeds_are_only_probed_inside_the_budget() {
        // Unlike the live anchor, these are probed for every undecryptable
        // message of a connection whose key is not found -- so they share the
        // bruteforce budget, which is what keeps a dead connection from paying
        // for them on every packet.
        let sent_ms = 1_700_000_000_000u64;
        let (server_seed, message) = recoverable_seeds(sent_ms, 44);

        let mut sniffer = GameSniffer::new();
        sniffer.session_seeds = Some(SessionSeeds {
            seeds: vec![server_seed],
            sent_ms: sent_ms + 3 * HOUR_MS,
        });
        sniffer.time_anchors = vec![sent_ms];
        sniffer.bruteforce_attempts = MAX_BRUTEFORCE_ATTEMPTS;
        assert!(!sniffer.recover_session_key(&message));

        sniffer.bruteforce_attempts = 0;
        assert!(sniffer.recover_session_key(&message));
        assert_eq!(sniffer.bruteforce_attempts, 0);
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
        sniffer.install_session_key(new_key_from_seed(11), 1);

        sniffer.receive_packet(handshake_frame());
        assert!(sniffer.pending_reset);
        assert_eq!(sniffer.session_generation(), 0);

        sniffer.receive_packet(segment_frame(PacketDirection::Received, 7, &[0u8; 40]));

        assert!(sniffer.key.is_none(), "the dead session must be torn down");
        assert!(!sniffer.pending_reset);
        // The live anchor is per connection (it is probed outside the budget);
        // the time seed itself is kept, because the reconnect's key is drawn
        // from the same generator.
        assert!(sniffer.last_time_seed.is_none());
        assert_eq!(sniffer.time_anchors, vec![1]);
        assert_eq!(sniffer.session_generation(), 1);
        assert!(
            sniffer.bound_conversation(PacketDirection::Received) == Some(7),
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
    fn sustained_decodable_traffic_disarms_a_deferred_reset() {
        // A spoofed handshake must not leave the session one stray segment away
        // from a reset forever, so a session that keeps decrypting clears it.
        // One message used to be enough, but a real reconnect still delivers a
        // few late messages of the old connection after its handshake -- and
        // once they had disarmed the reset, the new conversation was rejected
        // as foreign for good. It now takes a sustained run.
        let key = new_key_from_seed(8);
        let mut sniffer = GameSniffer::new();
        sniffer.key = Some(Key::Session(key.clone()));
        sniffer.receive_packet(handshake_frame());
        assert!(sniffer.pending_reset);

        for sent in 1..=PENDING_RESET_DISARM_MESSAGES {
            let mut message = command_bytes(1, &[], &field_varint(1, 1));
            decrypt_command(&key, &mut message);
            assert_eq!(sniffer.receive_commands(message).len(), 1);
            assert_eq!(
                sniffer.pending_reset,
                sent < PENDING_RESET_DISARM_MESSAGES,
                "after {sent} messages"
            );
        }
    }

    #[test]
    fn late_old_messages_after_a_handshake_do_not_strand_the_new_connection() {
        // In a reconnect the server can still push a message or two on the old
        // conversation after the client's handshake. They decrypt under the old
        // key, and they used to disarm the deferred reset -- after which the
        // new conversation was a foreign one on a proven lane, rejected for the
        // rest of the session.
        let mut sniffer = connected_sniffer();
        let mut old = Conn::new(122_486);
        let old_combined = 0x1111_2222_3333_4444;
        log_in(
            &mut sniffer,
            &mut old,
            LOGIN_MS,
            client_draw(LOGIN_MS, 0),
            old_combined,
        );
        let generation = sniffer.session_generation();

        sniffer.receive_packet(handshake_frame());
        let old_key = new_key_from_seed(old_combined);
        for id in [201, 202] {
            assert_eq!(
                command_ids(&mut sniffer, old.server_message(&old_key, id)),
                vec![id]
            );
        }

        let mut new = Conn::new(122_628);
        let new_combined = 0x5555_6666_7777_8888;
        token_exchange(
            &mut sniffer,
            &mut new,
            LOGIN_MS + HOUR_MS,
            client_draw(LOGIN_MS, 1) ^ new_combined,
        );
        assert_eq!(sniffer.session_generation(), generation + 1);
        assert_eq!(
            command_ids(
                &mut sniffer,
                new.server_message(&new_key_from_seed(new_combined), SESSION_MESSAGE)
            ),
            vec![SESSION_MESSAGE]
        );
    }

    #[test]
    fn a_disarmed_spoofed_handshake_leaves_a_live_session_alone() {
        let mut sniffer = connected_sniffer();
        let mut conn = Conn::new(122_486);
        let combined = 0x1111_2222_3333_4444;
        log_in(
            &mut sniffer,
            &mut conn,
            LOGIN_MS,
            client_draw(LOGIN_MS, 0),
            combined,
        );
        let generation = sniffer.session_generation();
        let key = new_key_from_seed(combined);

        sniffer.receive_packet(handshake_frame());
        for id in 0..PENDING_RESET_DISARM_MESSAGES as u16 {
            command_ids(&mut sniffer, conn.server_message(&key, id));
        }
        assert!(!sniffer.pending_reset);

        // A conversation opening afterwards is not this game reconnecting.
        sniffer.receive_packet(segment_frame_at(
            PacketDirection::Received,
            9_999,
            0,
            0,
            &[0u8; 40],
        ));
        assert_eq!(sniffer.session_generation(), generation);
        assert_eq!(
            command_ids(&mut sniffer, conn.server_message(&key, 500)),
            vec![500]
        );
    }

    #[test]
    fn a_deferred_reset_fires_once_the_session_key_is_also_dead() {
        let mut sniffer = GameSniffer::new();
        sniffer.install_session_key(new_key_from_seed(9), 1);
        sniffer.receive_packet(handshake_frame());

        for _ in 0..MAX_SESSION_FAILURES {
            sniffer.receive_commands(vec![0u8; 64]);
        }

        assert!(sniffer.key.is_none(), "a corroborated handshake must reset");
        assert!(!sniffer.pending_reset);
        assert!(sniffer.last_time_seed.is_none());
        assert_eq!(
            sniffer.time_anchors,
            vec![1],
            "the time seed outlives the connection it was found on"
        );
    }

    #[test]
    fn a_handshake_resets_when_no_session_key_is_live() {
        let mut sniffer = GameSniffer::new();
        sniffer.install_session_key(new_key_from_seed(10), 1);
        sniffer.key = Some(Dispatch(new_key_from_seed(10)));
        sniffer.session_seeds = Some(SessionSeeds {
            seeds: vec![1],
            sent_ms: 2,
        });

        sniffer.receive_packet(handshake_frame());

        assert!(sniffer.key.is_none());
        assert!(sniffer.session_seeds.is_none());
        // This used to assert that *every* anchor was dropped, on the grounds
        // that a stale one made each reconnect burn a failing bruteforce. That
        // was true while the anchor fed a full sweep; it now feeds a bounded
        // probe inside the budget, and dropping it is what made in-game
        // reconnects undecryptable. Only the live, per-connection anchor goes.
        assert!(sniffer.last_time_seed.is_none());
        assert_eq!(sniffer.time_anchors, vec![1]);
    }

    // -- property decoding -----------------------------------------------------

    /// The ids and (currency values aside) the values of the player property
    /// notify a real 7.1 login carried, command 3272 on 2026-10-04: 53 entries,
    /// every key in the 10xxx block.
    const LOGIN_PROPERTIES: [(u32, i64); 53] = [
        (10001, 44974),
        (10004, 1),
        (10005, 100),
        (10006, 1),
        (10007, 0),
        (10008, 0),
        (10009, 1),
        (10010, 24000),
        (10011, 22320),
        (10012, 0),
        (10013, 60),
        (10014, 0),
        (10015, 1600),
        (10016, 12_345_678),
        (10017, 1),
        (10019, 8),
        (10020, 160),
        (10022, 0),
        (10023, 0),
        (10025, 0),
        (10026, 0),
        (10027, 3),
        (10035, 0),
        (10036, 0),
        (10037, 0),
        (10038, 0),
        (10039, 9),
        (10040, 1_790_953_954),
        (10041, 8),
        (10042, 2400),
        (10043, 0),
        (10044, 0),
        (10048, 1),
        (10049, 12000),
        (10050, 12000),
        (10051, 1),
        (10052, 1),
        (10053, 9),
        (10054, 10000),
        (10055, 1880),
        (10058, 4220),
        (10060, 2),
        (10063, 0),
        (10064, 0),
        (10069, 1820),
        (10070, 0),
        (10073, 53),
        (10074, 1),
        (10075, 625),
        (10078, 0),
        (10079, 0),
        (10080, 40000),
        (10081, 38400),
    ];

    /// The keys of the identity map the same login sent first, command 24819:
    /// 14 entries, each value equal to its key.
    const LOGIN_ID_LIST: [u32; 14] = [
        20046, 20050, 20059, 20060, 20062, 20063, 20064, 20092, 20384, 20385, 20386, 20388, 20391,
        20392,
    ];

    /// A `PropValue` as the server encodes it: `type` always, `val` only when
    /// it is not zero (proto3 omits zeros).
    fn wire_prop(key: u32, value: i64) -> Vec<u8> {
        if value == 0 {
            field_varint(1, u64::from(key))
        } else {
            prop_val(key, value)
        }
    }

    #[test]
    fn the_login_property_snapshot_still_matches() {
        let entries: Vec<(u32, Vec<u8>)> = LOGIN_PROPERTIES
            .iter()
            .map(|&(key, value)| (key, wire_prop(key, value)))
            .collect();
        let command = command(property_packet(&entries));

        let properties = matches_player_property_packet(&command).expect("should match");
        assert_eq!(properties.len(), LOGIN_PROPERTIES.len());
        for (key, value) in LOGIN_PROPERTIES {
            assert_eq!(
                properties.get(&key),
                Some(&(value as u64)),
                "property {key}"
            );
        }
        // The five currencies irminsul exports, and the account values beside
        // them.
        assert_eq!(properties[&10015], 1600);
        assert_eq!(properties[&10016], 12_345_678);
        assert_eq!(properties[&10020], 160);
        assert_eq!(properties[&10025], 0);
        assert_eq!(properties[&10042], 2400);
        assert_eq!(properties[&10013], 60);
        assert!(matches!(
            classify_command(&command),
            Some(CommandMatch::Properties(_))
        ));
    }

    /// The false positive: an id list in the shape of a property map, sent at
    /// every 7.1 login. It used to be logged as the discovered property notify
    /// and folded into the player's properties.
    #[test]
    fn a_list_of_ids_in_the_shape_of_a_property_map_is_rejected() {
        // However the value is encoded, it reads back as its own key.
        let encodings: [fn(u32) -> Vec<u8>; 3] = [
            |key| prop_val(key, i64::from(key)),
            |key| {
                let mut out = field_varint(1, u64::from(key));
                out.extend(field_varint(2, u64::from(key)));
                out
            },
            // Drifted: no `type`, the id in a field this build does not know.
            |key| field_varint(9, u64::from(key)),
        ];
        for encode in encodings {
            let entries: Vec<(u32, Vec<u8>)> = LOGIN_ID_LIST
                .iter()
                .map(|&key| (key, encode(key)))
                .collect();
            let command = command(property_packet(&entries));

            assert!(matches_player_property_packet(&command).is_none());
            assert!(!matches!(
                classify_command(&command),
                Some(CommandMatch::Properties(_))
            ));
        }
    }

    #[test]
    fn an_identity_map_is_rejected_inside_the_player_block_too() {
        let entries: Vec<(u32, Vec<u8>)> = (10_001..=10_014u32)
            .map(|key| (key, prop_val(key, i64::from(key))))
            .collect();
        assert!(matches_player_property_packet(&command(property_packet(&entries))).is_none());
    }

    #[test]
    fn a_map_of_other_ids_is_not_player_properties() {
        // Real-looking counters, but keyed outside the player property block.
        let entries: Vec<(u32, Vec<u8>)> = LOGIN_ID_LIST
            .iter()
            .map(|&key| (key, prop_val(key, 1)))
            .collect();
        assert!(matches_player_property_packet(&command(property_packet(&entries))).is_none());

        // Avatar property ids are not player properties either.
        let avatar: Vec<(u32, Vec<u8>)> = [1001u32, 1002, 1003, 1004, 4001]
            .iter()
            .map(|&key| (key, prop_val(key, 90)))
            .collect();
        assert!(matches_player_property_packet(&command(property_packet(&avatar))).is_none());
    }

    #[test]
    fn a_few_foreign_ids_do_not_reject_a_property_notify() {
        // Strictly more than half is enough: properties newer than the block,
        // or a stray entry, must not cost the whole snapshot.
        let mut entries: Vec<(u32, Vec<u8>)> = [10013u32, 10015, 10016]
            .iter()
            .map(|&key| (key, prop_val(key, 7)))
            .collect();
        entries.extend([20046u32, 20050].iter().map(|&key| (key, prop_val(key, 7))));
        assert_eq!(
            matches_player_property_packet(&command(property_packet(&entries)))
                .expect("3 of 5 keys are player properties")
                .len(),
            5
        );

        entries.push((20059, prop_val(20059, 7)));
        assert!(
            matches_player_property_packet(&command(property_packet(&entries))).is_none(),
            "3 of 6 is not a majority"
        );
    }

    #[test]
    fn property_values_are_read_from_the_declared_fields() {
        let ival = {
            let mut out = field_varint(1, 10015);
            out.extend(field_varint(2, 4242));
            out
        };
        // `fval = 1.0`. Read as a raw integer this is 1065353216, which used to
        // win every comparison it took part in.
        let fval = {
            let mut out = field_varint(1, 10019);
            out.extend(field_fixed32(3, 1.0f32.to_bits()));
            out
        };

        let packet = property_packet(&[
            (10015, ival),
            (10019, fval),
            (10013, prop_val(10013, 7)),
            (10016, prop_val(10016, 9_999_999_999)),
            (10020, prop_val(10020, 5)),
        ]);
        let properties = matches_player_property_packet(&command(packet)).expect("should match");

        assert_eq!(properties.get(&10015), Some(&4242));
        assert_eq!(properties.get(&10019), Some(&1));
        assert_eq!(properties.get(&10013), Some(&7));
        assert_eq!(
            properties.get(&10016),
            Some(&9_999_999_999),
            "Mora is capped above u32::MAX"
        );
    }

    #[test]
    fn a_property_worth_zero_is_recorded_rather_than_dropped() {
        // Spent resin is the everyday case: proto3 omits the zero entirely.
        let empty = field_varint(1, 10020); // `type` only
        let packet = property_packet(&[
            (10020, empty),
            (10025, prop_val(10025, 0)),
            (10013, prop_val(10013, 60)),
            (10019, prop_val(10019, 8)),
            (10015, prop_val(10015, 234)),
        ]);
        let properties = matches_player_property_packet(&command(packet)).expect("should match");

        assert_eq!(properties.get(&10020), Some(&0));
        assert_eq!(properties.get(&10025), Some(&0));
        assert_eq!(properties.len(), 5);
    }

    #[test]
    fn a_value_equal_to_its_own_property_id_survives() {
        // One such value is an ordinary property (Realm Currency can hold
        // 10042); only a map made of nothing else is an id list.
        let packet = property_packet(&[
            (10013, prop_val(10013, 60)),
            (10019, prop_val(10019, 8)),
            (10020, prop_val(10020, 160)),
            (10015, prop_val(10015, 234)),
            (10042, prop_val(10042, 10042)),
        ]);
        let properties = matches_player_property_packet(&command(packet)).expect("match");

        assert_eq!(properties.get(&10042), Some(&10042));
        assert_eq!(properties.len(), 5);
    }

    #[test]
    fn a_drifted_prop_value_reads_fixed32_as_a_float() {
        // Every field number moved, so nothing the build knows is set and the
        // fallback walk has to do the reading.
        let drifted: Vec<(u32, Vec<u8>)> = (10_010..=10_014u32)
            .map(|i| (i, field_fixed32(9, 120.0f32.to_bits())))
            .collect();
        let properties =
            matches_player_property_packet(&command(property_packet(&drifted))).expect("match");

        assert_eq!(properties.get(&10_010), Some(&120));
    }

    #[test]
    fn a_property_map_is_not_mistaken_for_an_inventory() {
        let entries: Vec<(u32, Vec<u8>)> = (10_001..=10_040u32)
            .map(|i| (i, prop_val(i, i64::from(i % 100) * 100)))
            .collect();
        let command = command(property_packet(&entries));

        assert!(matches_player_property_packet(&command).is_some());
        assert!(
            matches_item_packet(&command).is_none(),
            "prop map entries carry no guid and no detail arm"
        );
        assert!(matches_avatar_packet(&command).is_none());
    }

    /// Field numbers the item and avatar lists have sat on (5 and 6 in 7.0, 6
    /// and 7 in 7.1), and one standing for wherever a later patch moves them.
    const LIST_TAGS: [u32; 4] = [5, 6, 7, 12];

    #[test]
    fn a_prop_map_is_not_mistaken_for_an_inventory_on_any_field() {
        // The collision the audit called out: the item matcher runs first in
        // the caller's chain, so a prop map taken for the item list would
        // swallow the properties entirely. With the list's field number no
        // longer fixed, it has to hold wherever the map sits.
        for tag in LIST_TAGS {
            let entries: Vec<Vec<u8>> = (10_001..=10_040u32)
                .map(|i| field_bytes(tag, &prop_entry(i, &prop_val(i, 1))))
                .collect();
            let command = command(entries.concat());

            assert!(matches_item_packet(&command).is_none(), "field {tag}");
            assert!(
                matches_player_property_packet(&command).is_some(),
                "field {tag}"
            );
        }
    }

    // -- item and avatar matchers ---------------------------------------------

    #[test]
    fn an_inventory_is_recognised_and_claimed_only_once() {
        let command = command(item_packet(40));

        let items = matches_item_packet(&command).expect("should match");
        assert_eq!(items.len(), 40);
        assert!(matches_player_property_packet(&command).is_none());
        assert!(matches_avatar_packet(&command).is_none());
        assert!(matches!(
            classify_command(&command),
            Some(CommandMatch::Items(_))
        ));
    }

    /// What a game patch used to break: the list moving to another field
    /// number (5 -> 6 for the inventory and 6 -> 7 for the roster in 7.1).
    #[test]
    fn the_lists_are_recognised_on_any_field_number() {
        for tag in LIST_TAGS {
            let store = command(item_packet_on(tag, 40));
            match classify_command(&store) {
                Some(CommandMatch::Items(items)) => assert_eq!(items.len(), 40, "field {tag}"),
                other => panic!("an inventory on field {tag} was classified as {other:?}"),
            }

            let roster = command(avatar_packet_on(tag, 3));
            match classify_command(&roster) {
                Some(CommandMatch::Avatars(avatars)) => {
                    assert_eq!(avatars.len(), 3, "field {tag}")
                }
                other => panic!("a roster on field {tag} was classified as {other:?}"),
            }
        }
    }

    /// A patch that moves a list has to show in the log, not only as data
    /// that went missing. The first match logs at INFO and every later one at
    /// DEBUG, and both carry the field number.
    #[test]
    fn the_field_a_list_was_found_on_is_logged() {
        let store = command(item_packet_on(12, 40));
        let roster = command(avatar_packet_on(5, 3));
        // The one-shot INFO line may already have gone to another test in this
        // process, so the second run of each is the one asserted on.
        let _ = matches_item_packet(&store);
        let _ = matches_avatar_packet(&roster);
        let lines = logged(Level::DEBUG, || {
            let _ = matches_item_packet(&store);
            let _ = matches_avatar_packet(&roster);
        });

        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("item packet") && line.contains(" field=12")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("avatar packet") && line.contains(" field=5")),
            "{lines:?}"
        );
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
    fn a_varint_pair_list_is_not_a_roster() {
        for tag in LIST_TAGS {
            let pairs: Vec<Vec<u8>> = (0..40u32)
                .map(|i| {
                    let mut entry = field_varint(1, u64::from(10_000_002 + i));
                    entry.extend(field_varint(2, guid(TEST_UID, u64::from(i) + 1)));
                    field_bytes(tag, &entry)
                })
                .collect();
            assert!(
                matches_avatar_packet(&command(pairs.concat())).is_none(),
                "an avatar carries a prop_map; a bare id/guid pair does not (field {tag})"
            );
        }
    }

    #[test]
    fn out_of_range_avatar_ids_are_not_a_roster() {
        let monsters: Vec<Vec<u8>> = (0..20u32)
            .map(|i| {
                field_bytes(
                    AVATAR_LIST_TAG,
                    &avatar_entry(24_000_000 + i, guid(TEST_UID, u64::from(i) + 1)),
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

    // -- item delete matcher ---------------------------------------------------

    /// Field numbers of the real `StoreItemDelNotify`, from Grasscutter. The
    /// matcher must not depend on them; using the real ones keeps the fixtures
    /// honest.
    const DEL_GUID_LIST_TAG: u32 = 4;
    const DEL_STORE_TYPE_TAG: u32 = 15;

    /// A guid as the game mints them: `(uid << 32) + counter`.
    fn guid(uid: u64, counter: u64) -> u64 {
        (uid << 32) | counter
    }

    fn packed(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|value| varint(*value)).collect()
    }

    /// A `StoreItemDelNotify`: a packed guid list plus `store_type`.
    fn delete_packet(guids: &[u64]) -> Vec<u8> {
        let mut out = field_bytes(DEL_GUID_LIST_TAG, &packed(guids));
        out.extend(field_varint(DEL_STORE_TYPE_TAG, 1));
        out
    }

    #[test]
    fn a_delete_notify_yields_its_guid_list() {
        let guids = [guid(800_123_456, 17), guid(800_123_456, 4096)];
        let command = command(delete_packet(&guids));

        assert_eq!(matches_item_del_packet(&command).expect("match"), guids);
        assert!(matches!(
            classify_command(&command),
            Some(CommandMatch::DeletedItems(_))
        ));
    }

    #[test]
    fn an_unpacked_guid_list_is_also_recognised() {
        // `packed` is a wire detail the server may change; each guid as its own
        // varint under one field number has to work too.
        let guids = [guid(800_123_456, 1), guid(800_123_456, 2)];
        let mut payload = Vec::new();
        for value in guids {
            payload.extend(field_varint(DEL_GUID_LIST_TAG, value));
        }
        payload.extend(field_varint(DEL_STORE_TYPE_TAG, 1));

        assert_eq!(
            matches_item_del_packet(&command(payload)).expect("match"),
            guids
        );
    }

    #[test]
    fn a_list_of_small_ids_is_not_a_guid_list() {
        // `AVATAR_ID_LIST` and friends wear the same shape but hold ids, which
        // never reach the uid half of a guid.
        let ids = [10_000_002u64, 10_000_003, 10_000_007];
        assert!(
            matches_item_del_packet(&command(field_bytes(DEL_GUID_LIST_TAG, &packed(&ids))))
                .is_none()
        );
    }

    #[test]
    fn guids_from_two_accounts_are_not_a_delete_notify() {
        let mixed = [guid(800_123_456, 1), guid(900_654_321, 2)];
        assert!(matches_item_del_packet(&command(delete_packet(&mixed))).is_none());
    }

    #[test]
    fn a_companion_scalar_too_large_for_a_store_type_is_rejected() {
        // A plausible guid list beside a timestamp is some other message.
        let mut payload = field_bytes(DEL_GUID_LIST_TAG, &packed(&[guid(800_123_456, 1)]));
        payload.extend(field_varint(2, 1_757_000_000_000));
        assert!(matches_item_del_packet(&command(payload)).is_none());
    }

    #[test]
    fn a_trailing_partial_varint_is_not_a_packed_list() {
        // A submessage or string that merely starts varint-shaped must not be
        // read as a guid list.
        let mut blob = packed(&[guid(800_123_456, 1)]);
        blob.push(0x80); // continuation bit set, no byte after it
        assert!(matches_item_del_packet(&command(field_bytes(DEL_GUID_LIST_TAG, &blob))).is_none());
    }

    #[test]
    fn a_message_carrying_submessages_is_not_a_delete_notify() {
        // An inventory has a blob per item; a delete notify has exactly one.
        let command = command(item_packet(40));
        assert!(matches_item_del_packet(&command).is_none());
        assert!(matches!(
            classify_command(&command),
            Some(CommandMatch::Items(_))
        ));
    }

    #[test]
    fn a_message_with_too_many_fields_is_not_a_delete_notify() {
        let mut payload = field_bytes(DEL_GUID_LIST_TAG, &packed(&[guid(800_123_456, 1)]));
        payload.extend(field_varint(1, 1));
        payload.extend(field_varint(2, 2));
        payload.extend(field_varint(3, 3));
        assert!(matches_item_del_packet(&command(payload)).is_none());
    }

    #[test]
    fn a_fixed_width_field_rules_out_a_delete_notify() {
        let mut payload = field_bytes(DEL_GUID_LIST_TAG, &packed(&[guid(800_123_456, 1)]));
        payload.extend(field_fixed32(2, 1));
        assert!(matches_item_del_packet(&command(payload)).is_none());
    }

    #[test]
    fn an_empty_guid_list_is_not_a_delete_notify() {
        assert!(matches_item_del_packet(&command(field_bytes(DEL_GUID_LIST_TAG, &[]))).is_none());
    }
}
