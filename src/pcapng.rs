#[cfg(debug_assertions)]
use std::fs::File;
#[cfg(debug_assertions)]
use std::io::Write;
#[cfg(debug_assertions)]
use std::path::PathBuf;

/// pcapng option code for `if_tsresol` (interface timestamp resolution).
#[cfg(debug_assertions)]
const OPT_IF_TSRESOL: u16 = 9;

/// `if_tsresol` value for nanosecond timestamps.
///
/// The high bit selects the base (0 = power of ten, 1 = power of two); the
/// remaining bits are the negative exponent. `9` therefore means 10^-9 s.
/// Without this option the pcapng default is 10^-6 s, so a reader would divide
/// our nanosecond timestamps by a million and place every frame in 1970.
#[cfg(debug_assertions)]
const IF_TSRESOL_NANOSECONDS: u8 = 9;

#[cfg(debug_assertions)]
pub struct PcapngWriter {
    file: File,
    packet_count: u32,
}

#[cfg(debug_assertions)]
impl PcapngWriter {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = PcapngWriter {
            file,
            packet_count: 0,
        };
        writer.write_shb()?;
        writer.write_idb()?;
        Ok(writer)
    }

    fn write_shb(&mut self) -> std::io::Result<()> {
        let mut block = Vec::new();
        block.extend_from_slice(&0x0a0d0d0a_u32.to_le_bytes());

        let total_len: u32 = 32;
        block.extend_from_slice(&total_len.to_le_bytes());

        block.extend_from_slice(&0x1a2b3c4d_u32.to_le_bytes());
        block.extend_from_slice(&1_u16.to_le_bytes());
        block.extend_from_slice(&0_u16.to_le_bytes());
        block.extend_from_slice(&0xffffffffffffffff_u64.to_le_bytes());

        block.extend_from_slice(&0_u32.to_le_bytes());

        block.extend_from_slice(&total_len.to_le_bytes());

        self.file.write_all(&block)
    }

    fn write_idb(&mut self) -> std::io::Result<()> {
        self.file.write_all(&Self::idb_block())
    }

    /// Build the Interface Description Block.
    ///
    /// Layout: block type, block length, linktype + reserved, snaplen, the
    /// `if_tsresol` option, `opt_endofopt`, and the trailing block length.
    fn idb_block() -> Vec<u8> {
        let mut block = Vec::new();
        block.extend_from_slice(&0x00000001_u32.to_le_bytes());

        // 4 (type) + 4 (len) + 4 (linktype/reserved) + 4 (snaplen)
        //   + 8 (if_tsresol option, 1 byte of value padded to 4)
        //   + 4 (opt_endofopt) + 4 (trailing len)
        let total_len: u32 = 32;
        block.extend_from_slice(&total_len.to_le_bytes());

        block.extend_from_slice(&1_u16.to_le_bytes());
        block.extend_from_slice(&0_u16.to_le_bytes());
        block.extend_from_slice(&65536_u32.to_le_bytes());

        // if_tsresol: our packet timestamps are nanoseconds since the epoch.
        block.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
        block.extend_from_slice(&1_u16.to_le_bytes());
        block.push(IF_TSRESOL_NANOSECONDS);
        block.extend_from_slice(&[0u8; 3]);

        // opt_endofopt (code 0, length 0).
        block.extend_from_slice(&0_u32.to_le_bytes());

        block.extend_from_slice(&total_len.to_le_bytes());

        block
    }

    pub fn write_packet(&mut self, timestamp_ns: u64, data: &[u8]) -> std::io::Result<()> {
        let mut block = Vec::new();

        block.extend_from_slice(&0x00000006_u32.to_le_bytes());

        let interface_id: u32 = 0;
        let ts_high: u32 = (timestamp_ns >> 32) as u32;
        let ts_low: u32 = (timestamp_ns & 0xffffffff) as u32;
        let captured_len: u32 = data.len() as u32;
        let orig_len: u32 = data.len() as u32;

        let padded_len = (data.len() + 3) & !3usize;
        let options_end: u32 = 0;

        let total_len: u32 = 4 + 4 + 4 + 4 + 4 + 4 + 4 + padded_len as u32 + 4 + 4;

        block.extend_from_slice(&total_len.to_le_bytes());
        block.extend_from_slice(&interface_id.to_le_bytes());
        block.extend_from_slice(&ts_high.to_le_bytes());
        block.extend_from_slice(&ts_low.to_le_bytes());
        block.extend_from_slice(&captured_len.to_le_bytes());
        block.extend_from_slice(&orig_len.to_le_bytes());

        block.extend_from_slice(data);
        if padded_len > data.len() {
            block.extend(vec![0u8; padded_len - data.len()]);
        }

        block.extend_from_slice(&options_end.to_le_bytes());

        block.extend_from_slice(&total_len.to_le_bytes());

        self.file.write_all(&block)?;
        self.packet_count += 1;
        Ok(())
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    #[test]
    fn idb_declares_nanosecond_timestamps() {
        let block = PcapngWriter::idb_block();

        // The declared length must match both length fields and the real size.
        assert_eq!(block.len(), 32);
        let declared = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let trailing = u32::from_le_bytes(block[28..32].try_into().unwrap());
        assert_eq!(declared, 32);
        assert_eq!(trailing, 32);
        assert_eq!(declared as usize, block.len());

        // Block type and linktype (LINKTYPE_ETHERNET) are unchanged.
        assert_eq!(u32::from_le_bytes(block[0..4].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(block[8..10].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(block[12..16].try_into().unwrap()), 65536);

        // if_tsresol = 9 (10^-9 s) in a 1-byte value padded to 4 bytes.
        assert_eq!(u16::from_le_bytes(block[16..18].try_into().unwrap()), 9);
        assert_eq!(u16::from_le_bytes(block[18..20].try_into().unwrap()), 1);
        assert_eq!(block[20], 9);
        assert_eq!(&block[21..24], &[0, 0, 0]);

        // opt_endofopt terminates the option list.
        assert_eq!(u32::from_le_bytes(block[24..28].try_into().unwrap()), 0);
    }

    #[test]
    fn idb_block_length_is_a_multiple_of_four() {
        // pcapng requires every block to be 32-bit aligned.
        assert_eq!(PcapngWriter::idb_block().len() % 4, 0);
    }
}
