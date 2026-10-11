//! The Oodle Network 1 TCP decoder against known-answer vectors.
//!
//! Each `tests/data/oodle/*.ontv.gz` file is one stream encoded by the Oodle
//! SDK (2.9.16, zero dictionary of 65,536 bytes, hash bits 19) from synthetic
//! messages -- no captured game data. The decoder keeps state across a stream,
//! so every file is decoded in order by one decoder, and a single wrong model
//! update shows up as every later message failing.
//!
//! Format (little endian): `b"ONTV"`, version u32 (1), dictionary size u32,
//! hash bits u32, message count u32, then per message `raw_len u32`,
//! `comp_len u32`, the raw bytes and the bytes as sent. `comp_len == raw_len`
//! means the sender sent the message stored.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use auto_artifactarium::oodle::{DICT_SIZE, TcpDecoder};
use flate2::read::GzDecoder;

struct Message {
    raw: Vec<u8>,
    sent: Vec<u8>,
}

fn take<'a>(bytes: &mut &'a [u8], len: usize) -> &'a [u8] {
    let (head, tail) = bytes.split_at(len);
    *bytes = tail;
    head
}

fn take_u32(bytes: &mut &[u8]) -> u32 {
    u32::from_le_bytes(take(bytes, 4).try_into().unwrap())
}

fn read_vectors(path: &Path) -> Vec<Message> {
    let mut data = Vec::new();
    GzDecoder::new(File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    let mut bytes = data.as_slice();
    assert_eq!(take(&mut bytes, 4), b"ONTV");
    assert_eq!(take_u32(&mut bytes), 1, "format version");
    assert_eq!(take_u32(&mut bytes) as usize, DICT_SIZE, "dictionary size");
    assert_eq!(take_u32(&mut bytes), 19, "hash bits");
    let count = take_u32(&mut bytes);
    let messages = (0..count)
        .map(|_| {
            let raw_len = take_u32(&mut bytes) as usize;
            let sent_len = take_u32(&mut bytes) as usize;
            let raw = take(&mut bytes, raw_len).to_vec();
            let sent = take(&mut bytes, sent_len).to_vec();
            Message { raw, sent }
        })
        .collect();
    assert!(bytes.is_empty(), "trailing bytes in {}", path.display());
    messages
}

/// Decode one stream and check every message, returning (compressed, stored,
/// verbatim) counts.
fn check_stream(name: &str) -> (usize, usize, usize) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/oodle")
        .join(format!("{name}.ontv.gz"));
    let messages = read_vectors(&path);
    assert!(!messages.is_empty());

    let mut decoder = TcpDecoder::new();
    let mut kinds = (0, 0, 0);
    for (i, message) in messages.iter().enumerate() {
        let decoded = decoder
            .decode(&message.sent, message.raw.len())
            .unwrap_or_else(|e| panic!("{name} message {i}: {e}"));
        assert!(
            decoded == message.raw,
            "{name} message {i} ({} bytes sent as {}) decoded wrong",
            message.raw.len(),
            message.sent.len()
        );
        match message.raw.len() {
            0..=6 => kinds.2 += 1,
            len if len == message.sent.len() => kinds.1 += 1,
            _ => kinds.0 += 1,
        }
    }
    kinds
}

#[test]
fn tiny_messages() {
    let (_, _, verbatim) = check_stream("tiny_messages");
    assert!(verbatim > 0);
}

#[test]
fn small_messages() {
    check_stream("small_messages");
}

#[test]
fn big_messages() {
    check_stream("big_messages");
}

#[test]
fn long_zero_runs() {
    check_stream("long_zero_runs");
}

/// Stored messages between compressed ones: a stored message's state update
/// that is off by one model update shows up in the next compressed one.
#[test]
fn stored_mixed() {
    let (compressed, stored, _) = check_stream("stored_mixed");
    assert!(compressed > 0 && stored > 0);
}

#[test]
fn login_then_traffic() {
    check_stream("login_then_traffic");
}
