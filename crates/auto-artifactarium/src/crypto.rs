use std::collections::HashMap;

use rand_mt::Mt64;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::bytes_as_hex;
use crate::cs_rand::Random;

/// Length of a session XOR key in bytes: 512 big-endian 64-bit Mersenne Twister
/// draws.
const KEY_LEN: usize = 4096;

/// Smallest command the magic-byte checks can read. A real `GameCommand` is far
/// longer (12 bytes of fixed header), but two bytes is the hard floor below
/// which indexing `data[0]`/`data[len - 2]` would panic.
const MIN_COMMAND_LEN: usize = 2;

/// Number of candidate send times tried when recovering a session key, i.e. the
/// tolerated client/server clock skew is +/- `TIME_CANDIDATES / 2` ms.
const TIME_CANDIDATES: i64 = 3000;

/// Number of consecutive client seeds drawn from each candidate send time.
///
/// This was deliberately raised from 5 to 1000; because [`bruteforce`] searches
/// depth-major it only costs anything when the key is genuinely unrecoverable.
const SEED_DEPTH: i32 = 1000;

#[instrument(skip_all)]
pub fn decrypt_command(key: &[u8], encrypted: &mut [u8]) {
    if key.is_empty() {
        // `key[i % key.len()]` below would divide by zero. An empty key reaches
        // us when a caller supplies an empty initial key -- an empty base64
        // string decodes to an empty `Vec` without error -- so complain loudly
        // rather than taking down the whole capture task.
        error!("refusing to decrypt with an empty XOR key; leaving the command untouched");
        return;
    }

    trace!(data = bytes_as_hex(encrypted), "before decryption");

    for i in 0..encrypted.len() {
        encrypted[i] ^= key[i % key.len()];
    }

    trace!(data = bytes_as_hex(encrypted), "after decryption");
}

pub fn lookup_initial_key(initial_keys: &HashMap<u16, Vec<u8>>, bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < MIN_COMMAND_LEN {
        warn!(
            len = bytes.len(),
            "command too short to carry a key version"
        );
        return None;
    }

    let version = u16::from_be_bytes(bytes[..2].try_into().unwrap()) ^ 0x4567;

    // attempt to fetch from user provided initial keys, otherwise use our own baked-in ones
    let key = initial_keys.get(&version).cloned();
    match key {
        Some(key) => {
            info!(version, "found initial decryption key");
            Some(key)
        }
        None => {
            info!(version, "didn't find decryption key");
            None
        }
    }
}

/// The Mersenne Twister that produces a session key's bytes, positioned at the
/// key's first 64-bit word.
fn key_generator(seed: u64) -> Mt64 {
    let mut first = Mt64::new(seed);
    let mut generator = Mt64::new(first.next_u64());

    let _ = generator.next_u64(); // skip first number

    generator
}

pub fn new_key_from_seed(seed: u64) -> Vec<u8> {
    let mut generator = key_generator(seed);

    // Fill in place: the previous version reserved 512 bytes and then pushed
    // 4096, reallocating three times per candidate key.
    let mut key = vec![0u8; KEY_LEN];
    // `as_chunks_mut` over `chunks_exact_mut(8)`: the chunk size is a constant,
    // so this yields `&mut [u8; 8]` and `copy_from_slice` becomes a fixed-size
    // copy with no length check. Clippy's `chunks_exact_to_as_chunks` asks for
    // it by name on newer toolchains.
    let (words, remainder) = key.as_chunks_mut::<8>();
    debug_assert!(remainder.is_empty(), "KEY_LEN must be a multiple of 8");
    for word in words {
        *word = generator.next_u64().to_be_bytes();
    }
    key
}

/// The four key bytes a candidate seed has to reproduce for a command to look
/// like plaintext.
///
/// A decrypted `GameCommand` starts with `45 67` and ends with `89 AB`, so those
/// four key bytes are fully determined by the ciphertext. Checking them without
/// building the whole 4096-byte key is what makes the bruteforce reject path
/// cheap.
struct MagicProbe {
    /// Expected `key[0]` and `key[1]`.
    prefix: [u8; 2],
    /// `(key byte index, expected value)` for the two trailing magic bytes,
    /// sorted by index so the generator only has to be walked forwards once.
    /// The indices wrap modulo [`KEY_LEN`], so the pair can arrive out of order.
    suffix: [(usize, u8); 2],
}

impl MagicProbe {
    fn new(data: &[u8]) -> Option<Self> {
        if data.len() < MIN_COMMAND_LEN {
            return None;
        }

        let last = data.len() - 1;
        let mut suffix = [
            ((last - 1) % KEY_LEN, data[last - 1] ^ 0x89),
            (last % KEY_LEN, data[last] ^ 0xAB),
        ];
        suffix.sort_by_key(|&(index, _)| index);

        Some(Self {
            prefix: [data[0] ^ 0x45, data[1] ^ 0x67],
            suffix,
        })
    }

    /// Whether `new_key_from_seed(seed)` would reproduce all four magic bytes.
    ///
    /// Both prefix bytes live in the generator's first word, so all but roughly
    /// one candidate in 2^16 is rejected after a single draw and without
    /// allocating a key at all.
    fn matches(&self, seed: u64) -> bool {
        let mut generator = key_generator(seed);

        let mut word = generator.next_u64().to_be_bytes();
        if word[0] != self.prefix[0] || word[1] != self.prefix[1] {
            return false;
        }

        // Byte index of `word`'s first byte.
        let mut base = 0usize;
        for &(index, expected) in &self.suffix {
            while base + 8 <= index {
                word = generator.next_u64().to_be_bytes();
                base += 8;
            }
            if word[index - base] != expected {
                return false;
            }
        }

        true
    }
}

/// Search a single candidate send time for the session key.
///
/// This is the retained-anchor fast path of `GameSniffer::recover_session_key`,
/// so it runs on every message the installed key fails to decrypt: a wrong
/// answer here installs a wrong session key in production, not just in a test.
/// [`bruteforce`] covers the same space plus a +/-1499 ms sweep, but searches it
/// depth-major across all candidate times at once and so cannot call this.
pub fn guess(seed: i64, server_seed: u64, depth: i32, data: &[u8]) -> Option<Vec<u8>> {
    let probe = MagicProbe::new(data)?;

    let mut generator = Random::seeded(seed as i32);
    for i in 0..depth {
        let combined_seed = generator.next_safe_uint64() ^ server_seed;
        if probe.matches(combined_seed) {
            trace!(
                time_seed = seed,
                depth = i,
                combined_seed,
                "session key seed recovered"
            );
            info!(depth = i, "session key recovered");
            return Some(new_key_from_seed(combined_seed));
        }
    }

    None
}

/// The `i`-th candidate send time: 0, 0, +1, -1, +2, -2, ... ms around
/// `sent_time`.
///
/// `sent_time` comes off the wire, so the offset is applied with a wrapping add
/// instead of panicking in debug builds; the result is truncated to `i32` for
/// seeding regardless.
fn candidate_time(sent_time: u64, i: i64) -> i64 {
    let offset = if i % 2 == 0 { i / 2 } else { -(i - 1) / 2 };
    (sent_time as i64).wrapping_add(offset)
}

pub fn bruteforce(sent_time: u64, server_seed: u64, data: Vec<u8>) -> Option<(u64, Vec<u8>)> {
    debug!(
        sent_time,
        len = data.len(),
        "running session key bruteforce"
    );

    let Some(probe) = MagicProbe::new(&data) else {
        warn!(
            len = data.len(),
            "command too short to bruteforce a session key"
        );
        return None;
    };

    // One `Random` per candidate send time, so the search below can run
    // depth-major: every candidate time is tried at depth 0 before any is tried
    // at depth 1. The overwhelmingly common answer -- depth 0, a small clock
    // skew -- is then found within `TIME_CANDIDATES` probes instead of up to
    // `TIME_CANDIDATES * SEED_DEPTH` of them, so recovery cost stops scaling
    // with skew. A `Random` is 240 bytes, so holding 3000 of them is ~720 KiB.
    let mut generators: Vec<(i64, Random)> = (0..TIME_CANDIDATES)
        .map(|i| {
            let time = candidate_time(sent_time, i);
            (time, Random::seeded(time as i32))
        })
        .collect();

    for depth in 0..SEED_DEPTH {
        for (time, generator) in generators.iter_mut() {
            let combined_seed = generator.next_safe_uint64() ^ server_seed;
            if probe.matches(combined_seed) {
                trace!(
                    time_seed = *time,
                    depth, combined_seed, "session key seed recovered"
                );
                info!(
                    depth,
                    offset = *time - sent_time as i64,
                    "session key recovered"
                );
                return Some((*time as u64, new_key_from_seed(combined_seed)));
            }
        }
    }

    warn!(
        len = data.len(),
        "unable to find the session encryption key seed"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first six `NextDouble()` draws of .NET Framework 4.8's
    /// `System.Random`, as raw IEEE-754 bit patterns, captured on Windows
    /// PowerShell 5.1 with:
    ///
    /// ```powershell
    /// $r = New-Object System.Random(<seed>)
    /// 1..6 | % { '0x{0:x16}' -f [BitConverter]::DoubleToInt64Bits($r.NextDouble()) }
    /// ```
    ///
    /// [`Random`] is a hand port of that generator and key recovery is worthless
    /// if it drifts, so this is the crate's reference oracle. Seeds 0 and
    /// `i32::MAX` diverge only at the third draw, which is exactly the kind of
    /// seeding bug a refactor would introduce.
    const DOTNET_NEXT_DOUBLE_BITS: &[(i32, [u64; 6])] = &[
        (
            0,
            [
                0x3fe73d6286ae7ac5,
                0x3fea278783344f0f,
                0x3fe893a451b12749,
                0x3fe1dc74dbe3b8ea,
                0x3fca5f4b5d34be97,
                0x3fe1e2625d63c4c5,
            ],
        ),
        (
            1,
            [
                0x3fcfd45f463fa8bf,
                0x3fbc59b7a038b36f,
                0x3fdde380c33bc702,
                0x3fe8b0fb20b161f6,
                0x3fe50a65102a14ca,
                0x3fdbb2b5cbb7656c,
            ],
        ),
        (
            12345,
            [
                0x3fb11653be222ca7,
                0x3fb1f5f93c23ebf2,
                0x3fe8cae040b195c1,
                0x3fe05b40bd60b681,
                0x3fe9850aeb730a16,
                0x3fea794f3cb4f29e,
            ],
        ),
        // `(i32)1_756_400_000_000`, i.e. a realistic `PacketHead::sent_ms`
        // truncated the way `Random::seeded` truncates it.
        (
            -241624064,
            [
                0x3fd1bbfb0d2377f6,
                0x3fe4e2e5dce9c5cc,
                0x3fe6dc71396db8e2,
                0x3fec1aec10f835d8,
                0x3fdf1e05bc3e3c0b,
                0x3fc0aae4a92155c9,
            ],
        ),
        (
            i32::MAX,
            [
                0x3fe73d6286ae7ac5,
                0x3fea278783344f0f,
                0x3fe893a453312749,
                0x3fe1dc74dbe3b8ea,
                0x3fca5f4b5d34be97,
                0x3fe1e2625ce3c4c5,
            ],
        ),
        (
            i32::MIN,
            [
                0x3fe73d6286ae7ac5,
                0x3fea278783344f0f,
                0x3fe893a453312749,
                0x3fe1dc74dbe3b8ea,
                0x3fca5f4b5d34be97,
                0x3fe1e2625ce3c4c5,
            ],
        ),
        (
            161803398,
            [
                0x3fe86ca5aaf0d94b,
                0x3fc705a3c02e0b48,
                0x3fe93b4972327693,
                0x3f786e1a2030dc34,
                0x3fa8e5951831cb2a,
                0x3fc7a9e90e2f53d2,
            ],
        ),
    ];

    /// `(ulong)(new Random(seed).NextDouble() * (double)ulong.MaxValue)` from
    /// the same .NET Framework 4.8 runtime, i.e. the value key recovery
    /// actually consumes.
    const DOTNET_NEXT_SAFE_UINT64: &[(i32, [u64; 4])] = &[
        (
            0,
            [
                13396823736352909312,
                15076991733327230976,
                14167517994065479680,
                10296256650306605056,
            ],
        ),
        (
            12345,
            [
                1231263624214652672,
                1294214504634905088,
                14291894165341865984,
                9428855276824692736,
            ],
        ),
        (
            -241624064,
            [
                5111563812551514112,
                12040143699782295552,
                13178528441429331968,
                16201524320674955264,
            ],
        ),
    ];

    #[test]
    fn cs_random_is_bit_exact_with_dotnet_system_random() {
        for (seed, expected) in DOTNET_NEXT_DOUBLE_BITS {
            let mut random = Random::seeded(*seed);
            for (draw, want) in expected.iter().enumerate() {
                let got = random.next_double().to_bits();
                assert_eq!(
                    got, *want,
                    "seed {seed}, draw {draw}: {got:#018x} != {want:#018x}"
                );
            }
        }
    }

    #[test]
    fn next_safe_uint64_matches_dotnet() {
        for (seed, expected) in DOTNET_NEXT_SAFE_UINT64 {
            let mut random = Random::seeded(*seed);
            for (draw, want) in expected.iter().enumerate() {
                assert_eq!(random.next_safe_uint64(), *want, "seed {seed}, draw {draw}");
            }
        }
    }

    #[test]
    fn cs_random_folds_negative_seeds_onto_their_magnitude() {
        // .NET seeds from `Math.Abs(seed)`, with `i32::MIN` special-cased to
        // `i32::MAX` because its magnitude is not representable.
        for (a, b) in [(-1, 1), (i32::MIN, i32::MAX), (-12345, 12345)] {
            let mut left = Random::seeded(a);
            let mut right = Random::seeded(b);
            for draw in 0..8 {
                assert_eq!(
                    left.next_safe_uint64(),
                    right.next_safe_uint64(),
                    "seeds {a}/{b}, draw {draw}"
                );
            }
        }
    }

    #[test]
    fn key_from_seed_is_4096_big_endian_bytes() {
        for seed in [0u64, 1, 0xdead_beef_cafe_f00d, u64::MAX] {
            let key = new_key_from_seed(seed);
            assert_eq!(key.len(), KEY_LEN);

            // Straightforward reference construction the packed version must
            // stay byte-identical to.
            let mut first = Mt64::new(seed);
            let mut generator = Mt64::new(first.next_u64());
            let _ = generator.next_u64();
            let mut want = Vec::new();
            for _ in 0..KEY_LEN / 8 {
                want.extend_from_slice(&generator.next_u64().to_be_bytes());
            }

            assert_eq!(key, want, "seed {seed}");
        }
    }

    /// A ciphertext whose magic bytes decrypt correctly under `key`.
    fn craft_command(key: &[u8], len: usize) -> Vec<u8> {
        assert!(len >= 4, "prefix and suffix must not overlap");
        let mut data = vec![0u8; len];
        data[0] = key[0] ^ 0x45;
        data[1] = key[1] ^ 0x67;
        data[len - 2] = key[(len - 2) % KEY_LEN] ^ 0x89;
        data[len - 1] = key[(len - 1) % KEY_LEN] ^ 0xAB;
        data
    }

    /// The `server_seed` that makes `combined` the `draw`-th client seed drawn
    /// from time seed `time`.
    fn plant_seed(time: i64, draw: usize, combined: u64) -> u64 {
        let mut generator = Random::seeded(time as i32);
        let mut client_seed = 0;
        for _ in 0..=draw {
            client_seed = generator.next_safe_uint64();
        }
        client_seed ^ combined
    }

    #[test]
    fn magic_probe_agrees_with_the_full_key() {
        let combined = 0x5ca1_ab1e_0000_beef;
        let key = new_key_from_seed(combined);

        // 4097 and 8193 put the trailing magic bytes at key indices 4095 and 0,
        // i.e. the suffix pair wraps around the end of the key and arrives out
        // of order.
        for len in [4usize, 5, 7, 8, 9, 100, 4095, 4096, 4097, 4098, 8193] {
            let data = craft_command(&key, len);
            let probe = MagicProbe::new(&data).expect("long enough");
            assert!(probe.matches(combined), "len {len} should match");
            assert!(!probe.matches(combined ^ 1), "len {len} should not match");
        }
    }

    #[test]
    fn bruteforce_recovers_a_key_at_zero_skew_and_zero_depth() {
        let combined = 0x0123_4567_89ab_cdef;
        let key = new_key_from_seed(combined);
        let sent_time = 1_756_400_000_000u64;
        let server_seed = plant_seed(sent_time as i64, 0, combined);
        let data = craft_command(&key, 1400);

        let (time, found) = bruteforce(sent_time, server_seed, data).expect("key is recoverable");
        assert_eq!(time, sent_time);
        assert_eq!(found, key);
    }

    #[test]
    fn bruteforce_recovers_a_key_at_positive_skew_and_nonzero_depth() {
        // +7 ms of clock skew, and the 4th client seed drawn from that time.
        // Depth-major iteration must still reach it.
        let combined = 0xfeed_face_dead_beef;
        let key = new_key_from_seed(combined);
        let sent_time = 1_756_400_000_000u64;
        let server_seed = plant_seed(sent_time as i64 + 7, 3, combined);
        let data = craft_command(&key, 231);

        let (time, found) = bruteforce(sent_time, server_seed, data).expect("key is recoverable");
        assert_eq!(time, sent_time + 7);
        assert_eq!(found, key);
    }

    #[test]
    fn bruteforce_searches_the_full_negative_skew_range() {
        // -1499 ms is the very last offset the schedule emits; this pins both
        // the range and the alternating +/- order.
        let combined = 0x1122_3344_5566_7788;
        let key = new_key_from_seed(combined);
        let sent_time = 1_756_400_000_000u64;
        let server_seed = plant_seed(sent_time as i64 - 1499, 0, combined);
        let data = craft_command(&key, 64);

        let (time, found) = bruteforce(sent_time, server_seed, data).expect("key is recoverable");
        assert_eq!(time, sent_time - 1499);
        assert_eq!(found, key);
    }

    #[test]
    fn bruteforce_handles_a_command_longer_than_the_key() {
        let combined = 0x00ff_00ff_00ff_00ff;
        let key = new_key_from_seed(combined);
        let sent_time = 42u64;
        let server_seed = plant_seed(sent_time as i64, 0, combined);
        let data = craft_command(&key, 4097);

        let (_, found) = bruteforce(sent_time, server_seed, data).expect("key is recoverable");
        assert_eq!(found, key);
    }

    #[test]
    fn guess_respects_its_depth_bound() {
        let combined = 0xabad_1dea_0000_0001;
        let key = new_key_from_seed(combined);
        let time = 1234i64;
        let server_seed = plant_seed(time, 5, combined);
        let data = craft_command(&key, 100);

        // The planted seed is the 6th draw, so depth 6 reaches it and 5 does not.
        assert_eq!(guess(time, server_seed, 6, &data), Some(key));
        assert_eq!(guess(time, server_seed, 5, &data), None);
    }

    #[test]
    fn candidate_times_alternate_around_the_send_time() {
        let base = 1_000_000u64;
        let times: Vec<i64> = (0..8).map(|i| candidate_time(base, i)).collect();
        assert_eq!(
            times,
            vec![
                1_000_000, 1_000_000, 1_000_001, 999_999, 1_000_002, 999_998, 1_000_003, 999_997
            ]
        );

        // The schedule spans exactly +/- 1499 ms.
        let extremes: Vec<i64> = (0..TIME_CANDIDATES)
            .map(|i| candidate_time(base, i) - base as i64)
            .collect();
        assert_eq!(extremes.iter().copied().max(), Some(1499));
        assert_eq!(extremes.iter().copied().min(), Some(-1499));
    }

    #[test]
    fn candidate_time_does_not_overflow_on_an_extreme_send_time() {
        // `sent_ms` comes straight off the wire, so the offset must wrap rather
        // than panic in a debug build.
        for sent_time in [0u64, 1, u64::MAX, i64::MAX as u64, i64::MAX as u64 + 1] {
            for i in 0..TIME_CANDIDATES {
                let _ = candidate_time(sent_time, i);
            }
        }
    }

    #[test]
    fn short_commands_do_not_panic() {
        let keys = HashMap::new();
        for len in 0..MIN_COMMAND_LEN {
            let data = vec![0u8; len];
            assert!(lookup_initial_key(&keys, &data).is_none(), "len {len}");
            assert!(guess(0, 0, 4, &data).is_none(), "len {len}");
            assert!(bruteforce(0, 0, data).is_none(), "len {len}");
        }
    }

    #[test]
    fn decrypt_with_an_empty_key_is_a_no_op() {
        let mut data = vec![1u8, 2, 3, 4];
        decrypt_command(&[], &mut data);
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn decrypt_command_round_trips() {
        let key = new_key_from_seed(7);
        let plain = b"\x45\x67hello world\x89\xab".to_vec();
        let mut data = plain.clone();

        decrypt_command(&key, &mut data);
        assert_ne!(data, plain);
        decrypt_command(&key, &mut data);
        assert_eq!(data, plain);
    }

    #[test]
    fn lookup_initial_key_xors_the_version_field() {
        let mut keys = HashMap::new();
        keys.insert(0x1234u16, vec![9u8; 4]);

        let bytes = (0x1234u16 ^ 0x4567).to_be_bytes();
        assert_eq!(lookup_initial_key(&keys, &bytes), Some(vec![9u8; 4]));
        assert_eq!(lookup_initial_key(&keys, &[0, 0]), None);
    }
}
