//! Decoder for the server's compressed messages: Oodle Network 1, TCP mode.
//!
//! Some commands arrive with `PacketHead` field 8 set, which is the payload's
//! length once decompressed. The server compresses those payloads with Oodle
//! Network 1 in its TCP mode: an adaptive order-1 literal model plus matches
//! against a fixed dictionary, arithmetic coded. Every message of one direction
//! of one connection updates the same model state, so the messages have to be
//! decoded in order by one [`TcpDecoder`], and a single lost or misdecoded
//! message desynchronises everything after it.
//!
//! This is a clean-room implementation written from a functional
//! specification of SDK 2.9.16; it neither contains nor links Oodle code.
//!
//! ## The dictionary
//!
//! Oodle Network primes both ends with a shared dictionary ("window"). The game
//! uses an all-zero one, which collapses most of the dictionary machinery:
//!
//! * The hash table is filled from window positions `4 ..= N - 257`, keeping the
//!   *first* occurrence of each 3-byte context. Every context of a zero window
//!   is `0`, which hashes to slots 0 and 1, so slot 0 points at position 4, slot
//!   1 at position 5, and every other slot stays empty.
//! * A lookup only hits when its context equals the stored one, so only a
//!   position preceded by three zero bytes has a match candidate, and that
//!   candidate is always position 4 (slot 0 is checked first).
//!
//! So instead of a 2^19-entry table over 65,536 zero bytes, `lookup` and
//! `window_byte` model that window directly. What the window's *size* still
//! decides is where it ends: a match can run for at most `N - 4` bytes, and a
//! literal after a match is only coded when the match stopped short of the
//! window's end.

use std::fmt;

/// Size of the zero dictionary the server's streams are primed with.
///
/// The server's true size is unknown. The size only matters for runs of zero
/// bytes long enough to reach the window's end (see the module docs), and so
/// far 1 KiB through 16 MiB have decoded real traffic identically; 65,536 is
/// the size the test vectors were encoded with.
pub const DICT_SIZE: usize = 65_536;

/// Largest decompressed length [`TcpDecoder::decode`] accepts.
///
/// The length is read off the wire, so it bounds both the allocation and the
/// work one message can cost. Real messages are at most ~200 KB.
pub const MAX_RAW_LEN: usize = 16 << 20;

/// Messages this short are always sent verbatim and never touch the state.
const MIN_RAW: usize = 6;

/// Window position of the only hash entry a lookup can hit (see the module
/// docs). The fill starts at position 4.
const MATCH_POS: usize = 4;

// The fill inserts positions `4 <= i < N - 256`; with a smaller window not even
// position 4 makes it in, and nothing would ever match.
const _: () = assert!(DICT_SIZE > 260 && DICT_SIZE <= 1 << 24);

/// Multiplier of both context hashes.
const GOLDEN: u32 = 0x9E37_79B1;

/// Binary probabilities are out of `1 << PROB_BITS`.
const PROB_BITS: u32 = 11;
/// Adaptation speed of a binary probability.
const PROB_SHIFT: u32 = 4;
/// "Don't know" for a binary probability.
const PROB_INIT: u16 = 1 << (PROB_BITS - 1);
/// Initial "not this slot" probability of a symbol-rank slot.
const SLOT_INIT: u16 = 2040;
/// The arithmetic coder renormalises while its range is below this.
const MIN_RANGE: u32 = 1 << 24;

/// Match-flag contexts (12 bits).
const MATCH_CONTEXTS: usize = 1 << 12;
/// Match-length contexts (9 bits).
const LEN_CONTEXTS: usize = 1 << 9;
/// Literal-after-match contexts (12 bits).
const LIT_MATCH_CONTEXTS: usize = 1 << 12;

/// Why a message could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The declared length is over [`MAX_RAW_LEN`]. The state is untouched.
    TooLarge { raw_len: usize },
    /// More bytes were sent than the message decompresses to, which no sender
    /// does. The state is untouched.
    LongerThanRaw { comp_len: usize, raw_len: usize },
    /// The compressed bytes do not decode under the current state: corrupt
    /// input, or a state that no longer matches the sender's. The state is
    /// part-updated and the stream is lost.
    Corrupt(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { raw_len } => {
                write!(
                    f,
                    "declared length {raw_len} is over the {MAX_RAW_LEN}-byte cap"
                )
            }
            Self::LongerThanRaw { comp_len, raw_len } => write!(
                f,
                "{comp_len} bytes sent for a {raw_len}-byte message; compressed data is never \
                 longer"
            ),
            Self::Corrupt(why) => write!(f, "corrupt compressed data: {why}"),
        }
    }
}

impl std::error::Error for DecodeError {}

type Result<T> = std::result::Result<T, DecodeError>;

/// One stream's decoder: the model state both ends keep in step.
///
/// Created in the reset state, which is what a new connection starts from.
pub struct TcpDecoder {
    models: Box<Models>,
}

impl Default for TcpDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TcpDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpDecoder").finish_non_exhaustive()
    }
}

impl TcpDecoder {
    pub fn new() -> Self {
        Self {
            models: Box::new(Models::new()),
        }
    }

    /// Decode the next message of the stream: `comp` as sent, `raw_len` the
    /// length the header declares.
    ///
    /// Three shapes reach this, told apart by the lengths alone:
    ///
    /// * `raw_len <= 6`: sent verbatim, and the state is not touched.
    /// * `comp.len() == raw_len`: the sender's compressed output was no
    ///   shorter, so it sent the bytes as they are. Its models still went
    ///   through encoding them, so the decoder replays that encoding to stay in
    ///   step.
    /// * `comp.len() < raw_len`: compressed.
    ///
    /// Never panics and does work bounded by `raw_len` whatever the input.
    /// Reading past the end of `comp`, which a valid message does by up to
    /// three bytes, reads zeros.
    pub fn decode(&mut self, comp: &[u8], raw_len: usize) -> Result<Vec<u8>> {
        if raw_len > MAX_RAW_LEN {
            return Err(DecodeError::TooLarge { raw_len });
        }
        if raw_len <= MIN_RAW {
            // Never shorter in practice; a short one reads zeros like any
            // other read past the input.
            let mut raw = vec![0; raw_len];
            let have = comp.len().min(raw_len);
            raw[..have].copy_from_slice(&comp[..have]);
            return Ok(raw);
        }
        if comp.len() > raw_len {
            return Err(DecodeError::LongerThanRaw {
                comp_len: comp.len(),
                raw_len,
            });
        }
        if comp.len() == raw_len {
            self.models.replay(comp);
            return Ok(comp.to_vec());
        }
        self.models.decode(comp, raw_len)
    }
}

/// The 3-byte context in front of `p`: `buf[p-3] buf[p-2] buf[p-1] 00`.
fn context(buf: &[u8], p: usize) -> u32 {
    u32::from_be_bytes([buf[p - 3], buf[p - 2], buf[p - 1], 0])
}

/// Dictionary lookup: the window position whose context matches `context`.
///
/// For the zero window that is position 4 for context 0 and nothing otherwise
/// (see the module docs).
fn lookup(context: u32) -> Option<usize> {
    (context == 0).then_some(MATCH_POS)
}

/// A byte of the zero window.
fn window_byte(pos: usize) -> u8 {
    debug_assert!(pos < DICT_SIZE);
    0
}

/// Match-flag context of the previous byte and the predicted window byte.
fn match_context(prev: u8, predicted: u8) -> usize {
    let packed = (u32::from(prev) << 8) | u32::from(predicted);
    (packed.wrapping_mul(GOLDEN).swap_bytes() & 0xFFF) as usize
}

/// Match-length context: the low 9 bits of the match-flag context.
fn len_context(match_context: usize) -> usize {
    match_context & 0x1FF
}

/// Literal-after-match context of the previous byte and the excluded byte.
fn lit_match_context(prev: u8, excluded: u8) -> usize {
    let prev = u32::from(prev);
    ((((prev + (prev >> 3)) << 8) | u32::from(excluded)) & 0xFFF) as usize
}

/// Common prefix of `raw` and the window from `pos`, capped at the end of
/// either.
fn match_len(raw: &[u8], pos: usize) -> usize {
    let cap = raw.len().min(DICT_SIZE - pos);
    raw[..cap]
        .iter()
        .enumerate()
        .take_while(|&(i, &b)| b == window_byte(pos + i))
        .count()
}

// ----------------------------------------------------------------------------
// Arithmetic coding

/// Adapt a binary probability (of a 0) to the bit just coded.
fn adapt(p: &mut u16, bit: u32) {
    if bit == 0 {
        *p += ((1 << PROB_BITS) - *p) >> PROB_SHIFT;
    } else {
        *p -= *p >> PROB_SHIFT;
    }
}

/// The range decoder, reading `input` big-endian and zeros past its end.
struct ArithDecoder<'a> {
    input: &'a [u8],
    pos: usize,
    code: u32,
    range: u32,
}

impl<'a> ArithDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        let mut decoder = Self {
            input,
            pos: 0,
            code: 0,
            range: u32::MAX,
        };
        for _ in 0..4 {
            decoder.code = (decoder.code << 8) | u32::from(decoder.next_byte());
        }
        decoder
    }

    fn next_byte(&mut self) -> u8 {
        let byte = self.input.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        byte
    }

    fn renormalise(&mut self) -> Result<()> {
        // Only corrupt input can empty the range, and shifting an empty range
        // would never end.
        if self.range == 0 {
            return Err(DecodeError::Corrupt("arithmetic range ran out"));
        }
        while self.range < MIN_RANGE {
            self.code = (self.code << 8) | u32::from(self.next_byte());
            self.range <<= 8;
        }
        Ok(())
    }

    fn bit(&mut self, p: &mut u16) -> Result<u32> {
        let split = u32::from(*p) * (self.range >> PROB_BITS);
        let bit = if self.code >= split {
            self.code -= split;
            self.range -= split;
            1
        } else {
            self.range = split;
            0
        };
        adapt(p, bit);
        self.renormalise()?;
        Ok(bit)
    }

    /// First half of a frequency decode: the target within `0..total`.
    fn target(&mut self, total: u32) -> Result<u32> {
        self.range = self.range.checked_div(total).unwrap_or(0);
        if self.range == 0 {
            return Err(DecodeError::Corrupt("frequency total out of range"));
        }
        // The clamp is only reachable with corrupt input.
        Ok((self.code / self.range).min(total - 1))
    }

    /// Second half of a frequency decode: consume the symbol at `low`.
    fn consume(&mut self, low: u32, freq: u32) -> Result<()> {
        self.code = self.code.wrapping_sub(low.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(freq);
        self.renormalise()
    }

    fn raw_bits(&mut self, bits: u32) -> Result<u32> {
        self.range = self.range.checked_shr(bits).unwrap_or(0);
        if self.range == 0 {
            return Err(DecodeError::Corrupt("raw bit count out of range"));
        }
        let value = self.code / self.range;
        self.code -= value * self.range;
        self.renormalise()?;
        Ok(value)
    }

    /// Input bytes read so far, including any read past the end.
    fn consumed(&self) -> usize {
        self.pos
    }
}

/// The sender's range encoder, reduced to what decides model state: its range
/// and how many bytes it has written. Bytes, carries and the flush never feed
/// back into either, so they are left out.
struct RangeReplay {
    range: u32,
    written: usize,
}

impl RangeReplay {
    fn new() -> Self {
        Self {
            range: u32::MAX,
            written: 0,
        }
    }

    fn renormalise(&mut self) {
        // The range cannot empty here: raw-bit counts stay small for the
        // lengths a replay can code. Checked anyway so a mistake cannot hang.
        while self.range != 0 && self.range < MIN_RANGE {
            self.range <<= 8;
            self.written += 1;
        }
    }

    fn bit(&mut self, p: &mut u16, bit: u32) {
        let split = u32::from(*p) * (self.range >> PROB_BITS);
        if bit == 0 {
            self.range = split;
        } else {
            self.range -= split;
        }
        adapt(p, bit);
        self.renormalise();
    }

    fn frequency(&mut self, freq: u32, total: u32) {
        self.range = (self.range / total) * freq;
        self.renormalise();
    }

    fn raw_bits(&mut self, bits: u32) {
        self.range >>= bits;
        self.renormalise();
    }
}

// ----------------------------------------------------------------------------
// Models

/// Order-0 frequency table over bytes, shared by all contexts of one literal
/// model and consulted only on an escape.
struct Order0 {
    count: [u16; 256],
    sum: u32,
}

impl Order0 {
    const INCREMENT: u16 = 2;

    fn new() -> Self {
        Self {
            count: [1; 256],
            sum: 256,
        }
    }

    fn total(&self, excluded: &[u8]) -> u32 {
        self.sum
            - excluded
                .iter()
                .map(|&s| u32::from(self.count[usize::from(s)]))
                .sum::<u32>()
    }

    /// Decode a symbol outside `excluded` (distinct symbols). Does not adapt.
    fn decode(&self, ac: &mut ArithDecoder<'_>, excluded: &[u8]) -> Result<u8> {
        let target = ac.target(self.total(excluded))?;
        let mut low = 0;
        for symbol in 0..=255u8 {
            if excluded.contains(&symbol) {
                continue;
            }
            let freq = u32::from(self.count[usize::from(symbol)]);
            if target < low + freq {
                ac.consume(low, freq)?;
                return Ok(symbol);
            }
            low += freq;
        }
        // `target < total` and the counts outside `excluded` add up to total.
        Err(DecodeError::Corrupt("order-0 target past the table"))
    }

    fn encode(&self, enc: &mut RangeReplay, symbol: u8, excluded: &[u8]) {
        enc.frequency(
            u32::from(self.count[usize::from(symbol)]),
            self.total(excluded),
        );
    }

    fn increment(&mut self, symbol: u8) {
        let symbol = usize::from(symbol);
        if u32::from(self.count[symbol]) + u32::from(Self::INCREMENT) > u32::from(u16::MAX) {
            for count in &mut self.count {
                *count = (*count >> 1) + 1;
            }
            self.sum = self.count.iter().map(|&c| u32::from(c)).sum();
        }
        self.count[symbol] += Self::INCREMENT;
        self.sum += u32::from(Self::INCREMENT);
    }
}

/// Move `sym[k]` to the front, shifting the slots before it up one.
fn move_to_front<const N: usize>(sym: &mut [u8; N], k: usize) -> u8 {
    let symbol = sym[k];
    sym.copy_within(0..k, 1);
    sym[0] = symbol;
    symbol
}

/// The eight most recent symbols of one order-1 context, most recent first.
#[derive(Clone)]
struct Rank8 {
    sym: [u8; 8],
    /// `p[0..7]` per slot ("not this one"); `p[7]` is "one of the eight".
    /// Cells belong to slots, not symbols.
    p: [u16; 8],
}

impl Rank8 {
    const ANY: usize = 7;

    fn new() -> Self {
        let mut p = [SLOT_INIT; 8];
        // Softened once at init: (3 * 2040 + 1024) / 4.
        p[Self::ANY] = (3 * SLOT_INIT + PROB_INIT) / 4;
        Self {
            sym: [0, 1, 2, 3, 4, 5, 6, 7],
            p,
        }
    }

    /// `None` is an escape: the symbol is not in the list.
    fn decode(&mut self, ac: &mut ArithDecoder<'_>) -> Result<Option<u8>> {
        if ac.bit(&mut self.p[Self::ANY])? == 0 {
            return Ok(None);
        }
        for k in 0..7 {
            if ac.bit(&mut self.p[k])? == 1 {
                return Ok(Some(move_to_front(&mut self.sym, k)));
            }
        }
        Ok(Some(move_to_front(&mut self.sym, 7)))
    }

    /// `false` is an escape.
    fn encode(&mut self, enc: &mut RangeReplay, symbol: u8) -> bool {
        let Some(k) = self.sym.iter().position(|&s| s == symbol) else {
            enc.bit(&mut self.p[Self::ANY], 0);
            return false;
        };
        enc.bit(&mut self.p[Self::ANY], 1);
        for j in 0..k {
            enc.bit(&mut self.p[j], 0);
        }
        if k < 7 {
            enc.bit(&mut self.p[k], 1);
        }
        move_to_front(&mut self.sym, k);
        true
    }

    /// After an escape to `symbol`: in one before last, the last one out.
    fn insert(&mut self, symbol: u8) {
        self.sym[7] = self.sym[6];
        self.sym[6] = symbol;
    }
}

/// The four most recent symbols of one literal-after-match context, coded
/// with one byte known not to be next.
#[derive(Clone)]
struct Rank4 {
    sym: [u8; 4],
    any: u16,
    p: [u16; 3],
}

impl Rank4 {
    fn new() -> Self {
        Self {
            sym: [0x0A, 0x20, 0xFF, 0x00],
            any: PROB_INIT,
            p: [SLOT_INIT; 3],
        }
    }

    /// `None` is an escape. A slot holding `excluded` costs no bit.
    fn decode(&mut self, ac: &mut ArithDecoder<'_>, excluded: u8) -> Result<Option<u8>> {
        if ac.bit(&mut self.any)? == 0 {
            return Ok(None);
        }
        for k in 0..3 {
            if self.sym[k] != excluded && ac.bit(&mut self.p[k])? == 1 {
                return Ok(Some(move_to_front(&mut self.sym, k)));
            }
        }
        if self.sym[3] == excluded {
            return Err(DecodeError::Corrupt("literal decoded to its excluded byte"));
        }
        Ok(Some(move_to_front(&mut self.sym, 3)))
    }

    /// `false` is an escape. `symbol` is never `excluded`.
    fn encode(&mut self, enc: &mut RangeReplay, symbol: u8, excluded: u8) -> bool {
        let Some(k) = self.sym.iter().position(|&s| s == symbol) else {
            enc.bit(&mut self.any, 0);
            return false;
        };
        enc.bit(&mut self.any, 1);
        for j in 0..k {
            if self.sym[j] != excluded {
                enc.bit(&mut self.p[j], 0);
            }
        }
        if k < 3 {
            enc.bit(&mut self.p[k], 1);
        }
        move_to_front(&mut self.sym, k);
        true
    }

    fn insert(&mut self, symbol: u8) {
        self.sym[3] = self.sym[2];
        self.sym[2] = symbol;
    }

    /// What an escape excludes from the order-0 table: the four listed
    /// symbols and the excluded byte, each once.
    fn escape_exclusions(&self, excluded: u8) -> ([u8; 5], usize) {
        let list = [self.sym[0], self.sym[1], self.sym[2], self.sym[3], excluded];
        let len = if self.sym.contains(&excluded) { 4 } else { 5 };
        (list, len)
    }
}

/// Binary-tree, unary and raw-bit coder of a match length minus one.
struct LenCoder {
    unary: [[u16; LEN_CONTEXTS]; 3],
    /// A 4-bit binary tree per context; see [`LenCoder::tree_cell`].
    tree: [u16; 15 * LEN_CONTEXTS],
    first: [u16; LEN_CONTEXTS],
}

impl LenCoder {
    fn new() -> Self {
        Self {
            unary: [[PROB_INIT; LEN_CONTEXTS]; 3],
            tree: [PROB_INIT; 15 * LEN_CONTEXTS],
            first: [PROB_INIT; LEN_CONTEXTS],
        }
    }

    /// Tree nodes start at `ctx | 512` and double (plus the bit) per level;
    /// a node's cell is the node minus 512, which never collides between
    /// contexts and stays below `15 * 512`.
    fn tree_cell(node: usize) -> usize {
        node - LEN_CONTEXTS
    }

    fn decode(&mut self, ac: &mut ArithDecoder<'_>, ctx: usize) -> Result<u64> {
        for u in 0..3 {
            if ac.bit(&mut self.unary[u][ctx])? == 1 {
                return Ok(u as u64);
            }
        }
        let mut node = ctx | LEN_CONTEXTS;
        for _ in 0..4 {
            let bit = ac.bit(&mut self.tree[Self::tree_cell(node)])?;
            node = node * 2 + bit as usize;
        }
        let mut bits = (node - (ctx | LEN_CONTEXTS) * 16) as u32;
        match bits {
            0 => return Ok(3),
            1 => return Ok(4 + u64::from(ac.bit(&mut self.first[ctx])?)),
            15 => bits += ac.raw_bits(4)?,
            _ => {}
        }
        let first = u64::from(ac.bit(&mut self.first[ctx])?);
        let low = u64::from(ac.raw_bits(bits - 1)?);
        Ok(((2 + first) << (bits - 1)) + low + 2)
    }

    fn encode(&mut self, enc: &mut RangeReplay, ctx: usize, value: u64) {
        if value < 3 {
            for u in 0..value as usize {
                enc.bit(&mut self.unary[u][ctx], 0);
            }
            enc.bit(&mut self.unary[value as usize][ctx], 1);
            return;
        }
        for u in 0..3 {
            enc.bit(&mut self.unary[u][ctx], 0);
        }
        let w = value - 2;
        let bits = 63 - w.leading_zeros();
        let mut node = ctx | LEN_CONTEXTS;
        let tree_value = bits.min(15);
        for level in (0..4).rev() {
            let bit = (tree_value >> level) & 1;
            enc.bit(&mut self.tree[Self::tree_cell(node)], bit);
            node = node * 2 + bit as usize;
        }
        match bits {
            0 => {}
            1 => enc.bit(&mut self.first[ctx], (w & 1) as u32),
            _ => {
                if bits >= 15 {
                    enc.raw_bits(4);
                }
                enc.bit(&mut self.first[ctx], ((w >> (bits - 1)) & 1) as u32);
                enc.raw_bits(bits - 1);
            }
        }
    }
}

/// Everything one stream's two ends keep in step, in the reset state.
struct Models {
    /// Literal with no match candidate: order-1 ranks over one order-0 table.
    literal_ranks: Vec<Rank8>,
    literal_order0: Order0,
    /// Literal with a byte known not to be next.
    lit_match_ranks: Vec<Rank4>,
    lit_match_order0: Order0,
    match_flag: [u16; MATCH_CONTEXTS],
    len: LenCoder,
}

impl Models {
    fn new() -> Self {
        Self {
            literal_ranks: vec![Rank8::new(); 256],
            literal_order0: Order0::new(),
            lit_match_ranks: vec![Rank4::new(); LIT_MATCH_CONTEXTS],
            lit_match_order0: Order0::new(),
            match_flag: [PROB_INIT; MATCH_CONTEXTS],
            len: LenCoder::new(),
        }
    }

    fn decode_literal(&mut self, ac: &mut ArithDecoder<'_>, prev: u8) -> Result<u8> {
        let rank = &mut self.literal_ranks[usize::from(prev)];
        if let Some(symbol) = rank.decode(ac)? {
            return Ok(symbol);
        }
        let symbol = self.literal_order0.decode(ac, &rank.sym)?;
        self.literal_order0.increment(symbol);
        rank.insert(symbol);
        Ok(symbol)
    }

    fn encode_literal(&mut self, enc: &mut RangeReplay, prev: u8, symbol: u8) {
        let rank = &mut self.literal_ranks[usize::from(prev)];
        if rank.encode(enc, symbol) {
            return;
        }
        self.literal_order0.encode(enc, symbol, &rank.sym);
        self.literal_order0.increment(symbol);
        rank.insert(symbol);
    }

    fn decode_lit_match(
        &mut self,
        ac: &mut ArithDecoder<'_>,
        prev: u8,
        excluded: u8,
    ) -> Result<u8> {
        let rank = &mut self.lit_match_ranks[lit_match_context(prev, excluded)];
        if let Some(symbol) = rank.decode(ac, excluded)? {
            return Ok(symbol);
        }
        let (list, len) = rank.escape_exclusions(excluded);
        let symbol = self.lit_match_order0.decode(ac, &list[..len])?;
        self.lit_match_order0.increment(symbol);
        rank.insert(symbol);
        Ok(symbol)
    }

    fn encode_lit_match(&mut self, enc: &mut RangeReplay, prev: u8, excluded: u8, symbol: u8) {
        debug_assert_ne!(symbol, excluded);
        let rank = &mut self.lit_match_ranks[lit_match_context(prev, excluded)];
        if rank.encode(enc, symbol, excluded) {
            return;
        }
        let (list, len) = rank.escape_exclusions(excluded);
        self.lit_match_order0.encode(enc, symbol, &list[..len]);
        self.lit_match_order0.increment(symbol);
        rank.insert(symbol);
    }

    /// Decode a compressed message (`comp.len() < raw_len`, `raw_len > 6`).
    fn decode(&mut self, comp: &[u8], raw_len: usize) -> Result<Vec<u8>> {
        let mut ac = ArithDecoder::new(comp);
        let mut raw = vec![0u8; raw_len];

        raw[0] = self.decode_literal(&mut ac, 0)?;
        raw[1] = self.decode_literal(&mut ac, raw[0])?;
        raw[2] = self.decode_literal(&mut ac, raw[1])?;

        // The last byte is left to the tail below (unless a match or the
        // literal after one already covers it).
        let stop = raw_len - 1;
        let mut p = 3;
        while p < stop {
            let Some(pos) = lookup(context(&raw, p)) else {
                raw[p] = self.decode_literal(&mut ac, raw[p - 1])?;
                p += 1;
                continue;
            };
            let predicted = window_byte(pos);
            let flag_ctx = match_context(raw[p - 1], predicted);
            if ac.bit(&mut self.match_flag[flag_ctx])? == 0 {
                // Not a match, so not the predicted byte either.
                raw[p] = self.decode_lit_match(&mut ac, raw[p - 1], predicted)?;
                p += 1;
                continue;
            }

            // The sender never codes a match past the message or the window;
            // only corrupt input gets here with one.
            let len = self.len.decode(&mut ac, len_context(flag_ctx))? + 1;
            let Ok(len) = usize::try_from(len) else {
                return Err(DecodeError::Corrupt("match length overflow"));
            };
            if len > raw_len - p || len > DICT_SIZE - pos {
                return Err(DecodeError::Corrupt(
                    "match runs past the message or window",
                ));
            }
            for (i, byte) in raw[p..p + len].iter_mut().enumerate() {
                *byte = window_byte(pos + i);
            }
            p += len;

            // The byte after a match is not the window's next one, or the
            // match would have been longer -- unless the match ended at the
            // message or the window.
            if p < raw_len && pos + len < DICT_SIZE {
                let excluded = window_byte(pos + len);
                raw[p] = self.decode_lit_match(&mut ac, raw[p - 1], excluded)?;
                p += 1;
            }
        }
        while p < raw_len {
            raw[p] = self.decode_literal(&mut ac, raw[p - 1])?;
            p += 1;
        }

        // An extension of ours: the library never checks this. The decoder
        // reads 4 bytes plus one per renormalising shift; the sender wrote one
        // per shift plus a 1- or 2-byte flush, so a message decoded under the
        // sender's state reads exactly 3 or 2 bytes past its end. Anything
        // else means the state has drifted from the sender's, and every later
        // message would decode to garbage.
        let consumed = ac.consumed();
        if consumed != comp.len() + 2 && consumed != comp.len() + 3 {
            return Err(DecodeError::Corrupt(
                "compressed length disagrees with the decode",
            ));
        }
        Ok(raw)
    }

    /// Bring the models to where the sender's are after it encoded `raw` and
    /// then sent it stored (`raw.len() > 6`).
    ///
    /// The sender's encoder is deterministic -- greedy longest match, nothing
    /// optional -- so running it again over the same bytes makes the same model
    /// updates. One decision depends on its output length, which only needs
    /// the coder's range: see the `expanded` comment below.
    fn replay(&mut self, raw: &[u8]) {
        let raw_len = raw.len();
        let mut enc = RangeReplay::new();

        self.encode_literal(&mut enc, 0, raw[0]);
        self.encode_literal(&mut enc, raw[0], raw[1]);
        self.encode_literal(&mut enc, raw[1], raw[2]);

        let stop = raw_len - 1;
        let mut p = 3;
        // The sender's output reached the message's own length at the top of
        // some iteration: it restarted writing into its buffer (keeping one
        // byte), already knowing it would send the message stored, and so
        // skipped the tail literal. Checked only at the top of an iteration;
        // the tail then causes no model update at all.
        let mut expanded = false;
        while p < stop {
            if enc.written >= raw_len {
                expanded = true;
                enc.written = 1;
            }

            let symbol = raw[p];
            let Some(pos) = lookup(context(raw, p)) else {
                self.encode_literal(&mut enc, raw[p - 1], symbol);
                p += 1;
                continue;
            };
            let predicted = window_byte(pos);
            let flag_ctx = match_context(raw[p - 1], predicted);
            if symbol != predicted {
                enc.bit(&mut self.match_flag[flag_ctx], 0);
                self.encode_lit_match(&mut enc, raw[p - 1], predicted, symbol);
                p += 1;
                continue;
            }

            let len = match_len(&raw[p..], pos);
            enc.bit(&mut self.match_flag[flag_ctx], 1);
            self.len
                .encode(&mut enc, len_context(flag_ctx), (len - 1) as u64);
            p += len;
            if p < raw_len && pos + len < DICT_SIZE {
                let excluded = window_byte(pos + len);
                self.encode_lit_match(&mut enc, raw[p - 1], excluded, raw[p]);
                p += 1;
            }
        }
        if !expanded {
            while p < raw_len {
                self.encode_literal(&mut enc, raw[p - 1], raw[p]);
                p += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_match_the_spec_test_values() {
        for (prev, predicted, mc, mlc, lam) in [
            (0x00, 0x00, 0, 0, 0),
            (0x00, 0x01, 1950, 414, 1),
            (0x01, 0x00, 2359, 311, 256),
            (0x41, 0x42, 992, 480, 2370),
            (0xFF, 0xFF, 2523, 475, 3839),
        ] {
            assert_eq!(match_context(prev, predicted), mc);
            assert_eq!(len_context(mc), mlc);
            assert_eq!(lit_match_context(prev, predicted), lam);
        }
    }

    #[test]
    fn short_messages_are_verbatim_and_leave_the_state_alone() {
        let mut decoder = TcpDecoder::new();
        for len in 0..=MIN_RAW {
            let raw: Vec<u8> = (0..len as u8).map(|b| b ^ 0x5A).collect();
            assert_eq!(decoder.decode(&raw, len).unwrap(), raw);
        }
        // Lengths are not cross-checked for these: the declared one wins, and
        // a short input reads zeros.
        assert_eq!(decoder.decode(&[1, 2, 3, 4], 2).unwrap(), [1, 2]);
        assert_eq!(decoder.decode(&[1, 2], 4).unwrap(), [1, 2, 0, 0]);
        assert!(decoder.models.literal_ranks[0].sym == Rank8::new().sym);
        assert_eq!(decoder.models.literal_order0.sum, 256);
    }

    #[test]
    fn more_bytes_than_the_declared_length_fail_without_touching_the_state() {
        let mut decoder = TcpDecoder::new();
        assert_eq!(
            decoder.decode(&[0; 9], 8),
            Err(DecodeError::LongerThanRaw {
                comp_len: 9,
                raw_len: 8
            })
        );
        assert_eq!(decoder.models.literal_order0.sum, 256);
        assert_eq!(
            decoder.decode(&[], MAX_RAW_LEN + 1),
            Err(DecodeError::TooLarge {
                raw_len: MAX_RAW_LEN + 1
            })
        );
    }

    #[test]
    fn a_stored_message_comes_back_as_is_and_updates_the_state() {
        let raw = b"stored because it did not compress";
        let mut decoder = TcpDecoder::new();
        assert_eq!(decoder.decode(raw, raw.len()).unwrap(), raw);
        // Every byte went through a model: 's' through the context-0 ranks and
        // the order-0 table on an escape.
        assert_ne!(decoder.models.literal_order0.sum, 256);
        assert_eq!(decoder.models.literal_ranks[0].sym[6], b's');
    }

    #[test]
    fn a_long_zero_run_is_coded_as_matches_capped_at_the_window() {
        // The replay must split a run longer than the window into several
        // matches without a literal after a match that reached its end.
        let mut raw = vec![1, 2, 3];
        raw.extend(std::iter::repeat_n(0, 3 * DICT_SIZE));
        raw.push(9);
        let mut decoder = TcpDecoder::new();
        decoder.models.replay(&raw);
        assert_ne!(decoder.models.match_flag[0], PROB_INIT);
    }

    /// A deterministic byte source for the robustness test.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }

        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn garbage_never_panics() {
        let mut rng = Lcg(0x0DD1E);
        let mut decoder = TcpDecoder::new();
        for round in 0..4000 {
            if round % 64 == 0 {
                decoder = TcpDecoder::new();
            }
            let comp_len = (rng.next() % 200) as usize;
            let mut comp = rng.bytes(comp_len);
            // Some all-zero and all-0xFF inputs, which drive the coder to its
            // extremes (long zero runs, huge match lengths).
            match round % 7 {
                0 => comp.fill(0),
                1 => comp.fill(0xFF),
                _ => {}
            }
            let raw_len = match round % 5 {
                0 => comp_len,
                1 => (rng.next() % 8) as usize,
                2 => comp_len + 1 + (rng.next() % 100_000) as usize,
                _ => comp_len + 1 + (rng.next() % 2_000) as usize,
            };
            if let Ok(raw) = decoder.decode(&comp, raw_len) {
                assert_eq!(raw.len(), raw_len);
            }
        }
    }
}
