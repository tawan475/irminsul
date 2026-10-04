//! Reading packet recordings back, for `--replay-export`.
//!
//! Two formats: pcapng, which is what debug builds record every captured frame
//! to (`pcapng.rs`) and what Wireshark writes, and classic pcap, which is what
//! `irminsul -b pcap <template>` records.
//!
//! A reader of its own rather than libpcap's, because replaying has to work in
//! the build that made the recording: the default Windows build has no pcap
//! support at all (it needs the Npcap SDK to build and Npcap's DLLs to start),
//! and nothing here needs more from libpcap than the frames themselves.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

/// `LINKTYPE_ETHERNET`, the only link layer the sniffer parses.
pub const LINKTYPE_ETHERNET: u16 = 1;

/// A block or record larger than this is taken for corruption rather than
/// allocated. Real frames are at most 64 KiB.
const MAX_BLOCK_LEN: usize = 16 * 1024 * 1024;

const PCAPNG_SECTION_HEADER: u32 = 0x0A0D_0D0A;
const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const PCAPNG_INTERFACE_DESCRIPTION: u32 = 1;
const PCAPNG_OBSOLETE_PACKET: u32 = 2;
const PCAPNG_SIMPLE_PACKET: u32 = 3;
const PCAPNG_ENHANCED_PACKET: u32 = 6;

const OPT_END_OF_OPT: u16 = 0;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_IF_TSOFFSET: u16 = 14;

/// One frame read from a recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedFrame {
    /// When it was captured, in nanoseconds since the Unix epoch. `None` for
    /// a pcapng simple packet block, which carries no time.
    pub timestamp_ns: Option<u64>,
    /// The link type of the interface it was captured on.
    pub link_type: u16,
    pub data: Vec<u8>,
}

/// A recording being read, frame by frame.
pub struct Recording<R> {
    reader: R,
    format: Format,
    /// The file ended part-way through a block, as one still being written
    /// (or cut short by a crash) does.
    truncated: bool,
}

enum Format {
    Pcap {
        big_endian: bool,
        /// Sub-second timestamps are nanoseconds rather than microseconds.
        nanos: bool,
        link_type: u16,
    },
    Pcapng {
        big_endian: bool,
        /// The current section's interfaces, by id.
        interfaces: Vec<Interface>,
    },
}

#[derive(Debug, Clone, Copy)]
struct Interface {
    link_type: u16,
    snap_len: u32,
    resolution: Resolution,
    /// `if_tsoffset`: seconds added to every timestamp.
    offset_secs: i64,
}

/// How long one timestamp unit is (`if_tsresol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolution {
    /// 10^-n seconds.
    Decimal(u8),
    /// 2^-n seconds.
    Binary(u8),
}

impl Resolution {
    /// pcapng's default: microseconds.
    const DEFAULT: Self = Self::Decimal(6);

    fn from_option(value: u8) -> Self {
        if value & 0x80 == 0 {
            Self::Decimal(value)
        } else {
            Self::Binary(value & 0x7F)
        }
    }

    fn to_nanos(self, units: u64) -> u64 {
        let nanos: u128 = match self {
            Self::Decimal(exp) if exp <= 9 => u128::from(units) * 10u128.pow(u32::from(9 - exp)),
            // Finer than a nanosecond; the exponent is at most 127 here.
            Self::Decimal(exp) => {
                u128::from(units) / 10u128.checked_pow(u32::from(exp - 9)).unwrap_or(u128::MAX)
            }
            Self::Binary(exp) => (u128::from(units) * 1_000_000_000u128)
                .checked_shr(u32::from(exp))
                .unwrap_or(0),
        };
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }
}

impl Interface {
    fn timestamp_ns(&self, units: u64) -> u64 {
        let nanos = self.resolution.to_nanos(units);
        let offset = self.offset_secs.saturating_mul(1_000_000_000);
        if offset >= 0 {
            nanos.saturating_add(offset as u64)
        } else {
            nanos.saturating_sub(offset.unsigned_abs())
        }
    }
}

impl Recording<BufReader<File>> {
    /// Open a recording. Shared for reading only, so a file a running
    /// Irminsul is still writing can be replayed without disturbing it.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        Self::new(BufReader::new(file))
            .with_context(|| format!("cannot read {} as a recording", path.display()))
    }
}

impl<R: Read> Recording<R> {
    /// Start reading a recording, telling the format from its first bytes.
    pub fn new(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        if read_full(&mut reader, &mut magic)? < magic.len() {
            bail!("the file is too short to be a pcap or pcapng recording");
        }

        let format = match u32::from_le_bytes(magic) {
            PCAPNG_SECTION_HEADER => {
                let mut recording = Self {
                    reader,
                    format: Format::Pcapng {
                        big_endian: false,
                        interfaces: Vec::new(),
                    },
                    truncated: false,
                };
                // The first block's type has been read already.
                if !recording.read_section_header()? {
                    bail!("the file ends inside its first pcapng section header");
                }
                return Ok(recording);
            }
            0xA1B2_C3D4 => (false, false),
            0xA1B2_3C4D => (false, true),
            0xD4C3_B2A1 => (true, false),
            0x4D3C_B2A1 => (true, true),
            other => bail!("not a pcap or pcapng file (it starts with {other:#010x})"),
        };
        let (big_endian, nanos) = format;

        // The rest of the classic pcap global header: version (2 + 2), the
        // GMT offset and accuracy (4 + 4), the snapshot length (4) and the
        // link type (4).
        let mut header = [0u8; 20];
        if read_full(&mut reader, &mut header)? < header.len() {
            bail!("the file ends inside its pcap header");
        }
        // The upper bits of the last field carry FCS details, not the type.
        let link_type = read_u32(&header[16..20], big_endian) as u16;

        Ok(Self {
            reader,
            format: Format::Pcap {
                big_endian,
                nanos,
                link_type,
            },
            truncated: false,
        })
    }

    /// Whether the file ended part-way through a block or record.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// The next frame, or `None` at the end of the file.
    ///
    /// An incomplete block at the very end is not an error -- a recording that
    /// is still being written ends in one -- but sets [`truncated`](Self::truncated).
    pub fn next_frame(&mut self) -> Result<Option<RecordedFrame>> {
        match self.format {
            Format::Pcap {
                big_endian,
                nanos,
                link_type,
            } => self.next_pcap_record(big_endian, nanos, link_type),
            Format::Pcapng { .. } => self.next_pcapng_frame(),
        }
    }

    fn next_pcap_record(
        &mut self,
        big_endian: bool,
        nanos: bool,
        link_type: u16,
    ) -> Result<Option<RecordedFrame>> {
        let mut header = [0u8; 16];
        let got = read_full(&mut self.reader, &mut header)?;
        if got == 0 {
            return Ok(None);
        }
        if got < header.len() {
            self.truncated = true;
            return Ok(None);
        }

        let seconds = u64::from(read_u32(&header[0..4], big_endian));
        let fraction = u64::from(read_u32(&header[4..8], big_endian));
        let captured = read_u32(&header[8..12], big_endian) as usize;
        if captured > MAX_BLOCK_LEN {
            bail!("a pcap record claims {captured} bytes; the file is corrupt");
        }

        let mut data = vec![0u8; captured];
        if read_full(&mut self.reader, &mut data)? < captured {
            self.truncated = true;
            return Ok(None);
        }

        let fraction_ns = if nanos { fraction } else { fraction * 1_000 };
        Ok(Some(RecordedFrame {
            timestamp_ns: Some(
                seconds
                    .saturating_mul(1_000_000_000)
                    .saturating_add(fraction_ns),
            ),
            link_type,
            data,
        }))
    }

    fn next_pcapng_frame(&mut self) -> Result<Option<RecordedFrame>> {
        loop {
            let mut block_type = [0u8; 4];
            let got = read_full(&mut self.reader, &mut block_type)?;
            if got == 0 {
                return Ok(None);
            }
            if got < block_type.len() {
                self.truncated = true;
                return Ok(None);
            }

            // Palindromic, so it reads the same whatever the byte order.
            if u32::from_le_bytes(block_type) == PCAPNG_SECTION_HEADER {
                if !self.read_section_header()? {
                    return Ok(None);
                }
                continue;
            }

            let big_endian = match &self.format {
                Format::Pcapng { big_endian, .. } => *big_endian,
                Format::Pcap { .. } => unreachable!("only called for pcapng"),
            };
            let block_type = read_u32(&block_type, big_endian);
            let Some(body) = self.read_block_body(big_endian, 8)? else {
                return Ok(None);
            };

            if let Some(frame) = self.block_frame(block_type, &body, big_endian)? {
                return Ok(Some(frame));
            }
        }
    }

    /// Read a section header block whose type has just been read, switching
    /// to its byte order and forgetting the previous section's interfaces.
    /// `false` when the file ends inside it.
    fn read_section_header(&mut self) -> Result<bool> {
        // Block length, then the byte-order magic that says how to read it.
        let mut head = [0u8; 8];
        if read_full(&mut self.reader, &mut head)? < head.len() {
            self.truncated = true;
            return Ok(false);
        }
        let big_endian = match u32::from_le_bytes(head[4..8].try_into().unwrap()) {
            PCAPNG_BYTE_ORDER_MAGIC => false,
            magic if magic.swap_bytes() == PCAPNG_BYTE_ORDER_MAGIC => true,
            magic => bail!("bad pcapng byte-order magic {magic:#010x}"),
        };
        self.format = Format::Pcapng {
            big_endian,
            interfaces: Vec::new(),
        };

        let block_len = read_u32(&head[0..4], big_endian) as usize;
        let Some(_body) = self.read_rest_of_block(block_len, big_endian, 12)? else {
            return Ok(false);
        };
        Ok(true)
    }

    /// Read the rest of a block whose type has been read: its length, its
    /// body and the trailing copy of the length. `None` when the file ends
    /// inside it.
    fn read_block_body(&mut self, big_endian: bool, header_len: usize) -> Result<Option<Vec<u8>>> {
        let mut len = [0u8; 4];
        if read_full(&mut self.reader, &mut len)? < len.len() {
            self.truncated = true;
            return Ok(None);
        }
        let block_len = read_u32(&len, big_endian) as usize;
        self.read_rest_of_block(block_len, big_endian, header_len)
    }

    /// The body of a `block_len`-byte block of which `already_read` bytes
    /// have been consumed, after checking its trailing length.
    fn read_rest_of_block(
        &mut self,
        block_len: usize,
        big_endian: bool,
        already_read: usize,
    ) -> Result<Option<Vec<u8>>> {
        if block_len < already_read + 4 || !block_len.is_multiple_of(4) || block_len > MAX_BLOCK_LEN
        {
            bail!("a pcapng block claims {block_len} bytes; the file is corrupt");
        }

        let mut rest = vec![0u8; block_len - already_read];
        if read_full(&mut self.reader, &mut rest)? < rest.len() {
            self.truncated = true;
            return Ok(None);
        }

        let trailer_at = rest.len() - 4;
        let trailer = read_u32(&rest[trailer_at..], big_endian) as usize;
        if trailer != block_len {
            bail!(
                "a pcapng block's lengths disagree ({block_len} and {trailer}); the file is corrupt"
            );
        }
        rest.truncate(trailer_at);
        Ok(Some(rest))
    }

    /// The frame a block carries, if it is a packet block; interface
    /// descriptions are recorded on the way.
    fn block_frame(
        &mut self,
        block_type: u32,
        body: &[u8],
        big_endian: bool,
    ) -> Result<Option<RecordedFrame>> {
        let Format::Pcapng { interfaces, .. } = &mut self.format else {
            unreachable!("only called for pcapng");
        };
        let short =
            || anyhow!("a pcapng block of type {block_type} is too short; the file is corrupt");

        match block_type {
            PCAPNG_INTERFACE_DESCRIPTION => {
                if body.len() < 8 {
                    return Err(short());
                }
                interfaces.push(parse_interface(body, big_endian));
                Ok(None)
            }
            PCAPNG_ENHANCED_PACKET | PCAPNG_OBSOLETE_PACKET => {
                if body.len() < 20 {
                    return Err(short());
                }
                let interface_id = if block_type == PCAPNG_ENHANCED_PACKET {
                    read_u32(&body[0..4], big_endian) as usize
                } else {
                    usize::from(read_u16(&body[0..2], big_endian))
                };
                let units = (u64::from(read_u32(&body[4..8], big_endian)) << 32)
                    | u64::from(read_u32(&body[8..12], big_endian));
                let captured = read_u32(&body[12..16], big_endian) as usize;
                let data = body.get(20..20 + captured).ok_or_else(short)?;
                let interface = interfaces.get(interface_id).ok_or_else(|| {
                    anyhow!("a packet names interface {interface_id}, which was never described")
                })?;
                Ok(Some(RecordedFrame {
                    timestamp_ns: Some(interface.timestamp_ns(units)),
                    link_type: interface.link_type,
                    data: data.to_vec(),
                }))
            }
            PCAPNG_SIMPLE_PACKET => {
                if body.len() < 4 {
                    return Err(short());
                }
                let interface = interfaces.first().ok_or_else(|| {
                    anyhow!("a simple packet block comes before any interface description")
                })?;
                let original = read_u32(&body[0..4], big_endian) as usize;
                let mut captured = original.min(body.len() - 4);
                if interface.snap_len != 0 {
                    captured = captured.min(interface.snap_len as usize);
                }
                Ok(Some(RecordedFrame {
                    timestamp_ns: None,
                    link_type: interface.link_type,
                    data: body[4..4 + captured].to_vec(),
                }))
            }
            // Name resolution, statistics, custom blocks...: nothing to replay.
            _ => Ok(None),
        }
    }
}

/// An interface description block's body.
fn parse_interface(body: &[u8], big_endian: bool) -> Interface {
    let mut interface = Interface {
        link_type: read_u16(&body[0..2], big_endian),
        snap_len: read_u32(&body[4..8], big_endian),
        resolution: Resolution::DEFAULT,
        offset_secs: 0,
    };

    // Options: code (2), length (2), the value padded to 4 bytes. A
    // malformed list just ends the scan; the defaults stand.
    let mut options = &body[8..];
    while options.len() >= 4 {
        let code = read_u16(&options[0..2], big_endian);
        let len = usize::from(read_u16(&options[2..4], big_endian));
        if code == OPT_END_OF_OPT {
            break;
        }
        let Some(value) = options.get(4..4 + len) else {
            break;
        };
        match (code, len) {
            (OPT_IF_TSRESOL, 1) => interface.resolution = Resolution::from_option(value[0]),
            (OPT_IF_TSOFFSET, 8) => {
                interface.offset_secs = read_u64(value, big_endian) as i64;
            }
            _ => {}
        }
        let padded = (len + 3) & !3;
        options = options.get(4 + padded..).unwrap_or_default();
    }
    interface
}

/// Fill `buf` as far as the reader allows, returning how much was read: less
/// than `buf.len()` only at the end of the file.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn read_u16(bytes: &[u8], big_endian: bool) -> u16 {
    let bytes: [u8; 2] = bytes[..2].try_into().unwrap();
    if big_endian {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    }
}

fn read_u32(bytes: &[u8], big_endian: bool) -> u32 {
    let bytes: [u8; 4] = bytes[..4].try_into().unwrap();
    if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}

fn read_u64(bytes: &[u8], big_endian: bool) -> u64 {
    let bytes: [u8; 8] = bytes[..8].try_into().unwrap();
    if big_endian {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One pcapng block in the given byte order, padded to 4 bytes.
    pub(crate) fn block(block_type: u32, body: &[u8], big_endian: bool) -> Vec<u8> {
        let u32_bytes = |v: u32| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let padded = (body.len() + 3) & !3;
        let total = (12 + padded) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&u32_bytes(block_type));
        out.extend_from_slice(&u32_bytes(total));
        out.extend_from_slice(body);
        out.resize(8 + padded, 0);
        out.extend_from_slice(&u32_bytes(total));
        out
    }

    pub(crate) fn section_header(big_endian: bool) -> Vec<u8> {
        let mut body = Vec::new();
        if big_endian {
            body.extend_from_slice(&PCAPNG_BYTE_ORDER_MAGIC.to_be_bytes());
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
        } else {
            body.extend_from_slice(&PCAPNG_BYTE_ORDER_MAGIC.to_le_bytes());
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
        }
        body.extend_from_slice(&[0xFF; 8]); // section length: unknown
        block(PCAPNG_SECTION_HEADER, &body, big_endian)
    }

    /// An interface description; `options` is a list of `(code, value)`.
    pub(crate) fn interface(link_type: u16, options: &[(u16, &[u8])], big_endian: bool) -> Vec<u8> {
        let u16_bytes = |v: u16| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut body = Vec::new();
        body.extend_from_slice(&u16_bytes(link_type));
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&if big_endian {
            65535u32.to_be_bytes()
        } else {
            65535u32.to_le_bytes()
        });
        for (code, value) in options {
            body.extend_from_slice(&u16_bytes(*code));
            body.extend_from_slice(&u16_bytes(value.len() as u16));
            body.extend_from_slice(value);
            body.resize((body.len() + 3) & !3, 0);
        }
        body.extend_from_slice(&[0, 0, 0, 0]);
        block(PCAPNG_INTERFACE_DESCRIPTION, &body, big_endian)
    }

    pub(crate) fn enhanced_packet(
        interface_id: u32,
        units: u64,
        data: &[u8],
        big_endian: bool,
    ) -> Vec<u8> {
        let u32_bytes = |v: u32| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut body = Vec::new();
        body.extend_from_slice(&u32_bytes(interface_id));
        body.extend_from_slice(&u32_bytes((units >> 32) as u32));
        body.extend_from_slice(&u32_bytes(units as u32));
        body.extend_from_slice(&u32_bytes(data.len() as u32));
        body.extend_from_slice(&u32_bytes(data.len() as u32));
        body.extend_from_slice(data);
        block(PCAPNG_ENHANCED_PACKET, &body, big_endian)
    }

    fn read_all(bytes: &[u8]) -> (Vec<RecordedFrame>, bool) {
        let mut recording = Recording::new(bytes).unwrap();
        let mut frames = Vec::new();
        while let Some(frame) = recording.next_frame().unwrap() {
            frames.push(frame);
        }
        (frames, recording.truncated())
    }

    #[test]
    fn reads_back_what_the_debug_build_records() {
        // The exact writer debug builds use for `irminsul-data/log/latest.pcapng`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("latest.pcapng");
        let mut writer = crate::pcapng::PcapngWriter::new(path.clone()).unwrap();
        writer
            .write_packet(1_759_553_801_123_456_789, &[1, 2, 3])
            .unwrap();
        writer
            .write_packet(1_759_553_802_000_000_000, &[4; 61])
            .unwrap();
        drop(writer);

        let mut recording = Recording::open(&path).unwrap();
        let first = recording.next_frame().unwrap().unwrap();
        assert_eq!(first.timestamp_ns, Some(1_759_553_801_123_456_789));
        assert_eq!(first.link_type, LINKTYPE_ETHERNET);
        assert_eq!(first.data, vec![1, 2, 3]);
        let second = recording.next_frame().unwrap().unwrap();
        assert_eq!(second.data, vec![4; 61]);
        assert_eq!(recording.next_frame().unwrap(), None);
        assert!(!recording.truncated());
    }

    #[test]
    fn a_recording_still_being_written_ends_at_its_last_whole_block() {
        let mut bytes = section_header(false);
        bytes.extend(interface(1, &[(OPT_IF_TSRESOL, &[9])], false));
        bytes.extend(enhanced_packet(0, 5, &[7; 10], false));
        let whole = bytes.len();
        bytes.extend(enhanced_packet(0, 6, &[8; 10], false));
        bytes.truncate(whole + 13);

        let (frames, truncated) = read_all(&bytes);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, vec![7; 10]);
        assert!(truncated);
    }

    #[test]
    fn several_interfaces_keep_their_own_link_type_and_clock() {
        let mut bytes = section_header(false);
        // Microseconds by default.
        bytes.extend(interface(1, &[], false));
        // Raw IP, in 2^-10 s units, offset by 100 s.
        bytes.extend(interface(
            101,
            &[
                (OPT_IF_TSRESOL, &[0x80 | 10]),
                (OPT_IF_TSOFFSET, &100u64.to_le_bytes()),
            ],
            false,
        ));
        bytes.extend(enhanced_packet(1, 1024, &[0xAA], false));
        bytes.extend(enhanced_packet(0, 1_500_000, &[0xBB], false));

        let (frames, _) = read_all(&bytes);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].link_type, 101);
        assert_eq!(frames[0].timestamp_ns, Some(101_000_000_000));
        assert_eq!(frames[1].link_type, 1);
        assert_eq!(frames[1].timestamp_ns, Some(1_500_000_000));
    }

    #[test]
    fn a_big_endian_section_is_read_in_its_own_byte_order() {
        let mut bytes = section_header(true);
        bytes.extend(interface(1, &[(OPT_IF_TSRESOL, &[3])], true));
        bytes.extend(enhanced_packet(0, 42, &[1, 2, 3, 4, 5], true));
        // A second, little-endian section resets the interfaces.
        bytes.extend(section_header(false));
        bytes.extend(interface(1, &[], false));
        bytes.extend(enhanced_packet(0, 1, &[9], false));

        let (frames, _) = read_all(&bytes);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].timestamp_ns, Some(42_000_000));
        assert_eq!(frames[0].data, vec![1, 2, 3, 4, 5]);
        assert_eq!(frames[1].timestamp_ns, Some(1_000));
    }

    #[test]
    fn simple_packets_and_unknown_blocks_are_handled() {
        let mut bytes = section_header(false);
        bytes.extend(interface(1, &[], false));
        // A name resolution block: skipped.
        bytes.extend(block(4, &[0, 0, 0, 0], false));
        let mut simple = 3u32.to_le_bytes().to_vec();
        simple.extend_from_slice(&[5, 6, 7]);
        bytes.extend(block(PCAPNG_SIMPLE_PACKET, &simple, false));

        let (frames, truncated) = read_all(&bytes);
        assert!(!truncated);
        assert_eq!(
            frames,
            vec![RecordedFrame {
                timestamp_ns: None,
                link_type: 1,
                data: vec![5, 6, 7],
            }]
        );
    }

    #[test]
    fn a_packet_on_an_undescribed_interface_is_an_error() {
        let mut bytes = section_header(false);
        bytes.extend(enhanced_packet(0, 1, &[1], false));
        let mut recording = Recording::new(&bytes[..]).unwrap();
        assert!(recording.next_frame().is_err());
    }

    #[test]
    fn mismatched_block_lengths_are_corruption() {
        let mut bytes = section_header(false);
        let mut idb = interface(1, &[], false);
        let last = idb.len() - 4;
        idb[last] ^= 0x04;
        bytes.extend(idb);
        let mut recording = Recording::new(&bytes[..]).unwrap();
        assert!(recording.next_frame().is_err());
    }

    /// A classic pcap file: global header, then `(seconds, fraction, data)`.
    fn pcap_file(magic: u32, big_endian: bool, records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let u32_bytes = |v: u32| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let u16_bytes = |v: u16| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut out = Vec::new();
        out.extend_from_slice(&u32_bytes(magic));
        out.extend_from_slice(&u16_bytes(2));
        out.extend_from_slice(&u16_bytes(4));
        out.extend_from_slice(&u32_bytes(0));
        out.extend_from_slice(&u32_bytes(0));
        out.extend_from_slice(&u32_bytes(65535));
        out.extend_from_slice(&u32_bytes(1));
        for (seconds, fraction, data) in records {
            out.extend_from_slice(&u32_bytes(*seconds));
            out.extend_from_slice(&u32_bytes(*fraction));
            out.extend_from_slice(&u32_bytes(data.len() as u32));
            out.extend_from_slice(&u32_bytes(data.len() as u32));
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn classic_pcap_in_either_byte_order_and_resolution() {
        let (frames, _) = read_all(&pcap_file(0xA1B2_C3D4, false, &[(10, 5, &[1, 2])]));
        assert_eq!(frames[0].timestamp_ns, Some(10_000_005_000));
        assert_eq!(frames[0].link_type, 1);
        assert_eq!(frames[0].data, vec![1, 2]);

        let (frames, _) = read_all(&pcap_file(0xA1B2_3C4D, true, &[(10, 5, &[3])]));
        assert_eq!(frames[0].timestamp_ns, Some(10_000_000_005));
        assert_eq!(frames[0].data, vec![3]);
    }

    #[test]
    fn a_truncated_pcap_record_ends_the_recording() {
        let mut bytes = pcap_file(0xA1B2_C3D4, false, &[(1, 0, &[1; 8]), (2, 0, &[2; 8])]);
        bytes.truncate(bytes.len() - 3);
        let (frames, truncated) = read_all(&bytes);
        assert_eq!(frames.len(), 1);
        assert!(truncated);
    }

    #[test]
    fn other_files_are_refused_by_name() {
        let error = Recording::new(&b"{\"format\":\"GOOD\"}"[..])
            .err()
            .expect("JSON is not a recording")
            .to_string();
        assert!(error.contains("not a pcap or pcapng file"), "{error}");
        assert!(Recording::new(&b"ab"[..]).is_err());
    }
}
