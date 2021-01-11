use crate::writer::Encodable;
use crate::{enums::BlockType, utils::pad_to_32};
use byteorder::{ByteOrder, WriteBytesExt};
use std::io::Write;
use std::{convert::TryInto, io};

/*
    Based on the draft standard:

           PCAP Next Generation (pcapng) Capture File Format
                     draft-tuexen-opsawg-pcapng-02

    https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02#section-4.2
*/

/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Block Type                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Block Total Length                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                          Block Body                           /
       /              variable length, padded to 32 bits               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Block Total Length                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Figure 1: Basic block structure.
*/

trait Block {
    const TYPE: BlockType;

    fn length(&self) -> u32;

    fn padding(&self) -> Vec<u8> {
        let n = pad_to_32(self.length().try_into().unwrap());
        vec![0u8; n]
    }
}

/// A raw pcapng block.
#[derive(Debug)]
pub struct RawBlock<'a> {
    block_type: u32,
    total_length1: u32,
    total_length2: u32,
    body: &'a [u8],
}

impl<'a> RawBlock<'a> {
    pub fn new(block_type: u32, total_length1: u32, total_length2: u32, body: &'a [u8]) -> Self {
        Self {
            block_type,
            total_length1,
            total_length2,
            body,
        }
    }
}

impl<'a, W: Write> Encodable<W> for RawBlock<'a> {
    /// For raw blocks, the total length fields are not automatically
    /// calculated.
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        w.write_u32::<B>(self.block_type)?;
        w.write_u32::<B>(self.total_length1)?;
        w.write_all(self.body)?;
        w.write_u32::<B>(self.total_length2)?;
        Ok(())
    }
}

mod epb;
mod idb;
mod isb;
pub mod options;
mod shb;
mod spb;

pub use crate::blocks::epb::EnhancedPacketBlock;
pub use crate::blocks::idb::InterfaceDescriptionBlock;
pub use crate::blocks::isb::InterfaceStatisticsBlock;
pub use crate::blocks::shb::SectionHeaderBlock;
pub use crate::blocks::spb::SimplePacketBlock;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::options::*;
    use crate::blocks::EnhancedPacketBlock;
    use byteorder::{BigEndian, LittleEndian};

    #[test]
    fn new_raw_be() {
        let opts = Options::new();
        let epb = EnhancedPacketBlock::new(1, 1, 2, 10, 20, &[9; 10], &opts);
        let mut epb_buf = vec![];
        epb.encode::<BigEndian>(&mut epb_buf).unwrap();
        let raw = RawBlock::new(
            6,
            44,
            44,
            &[
                0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 10, 0, 0, 0, 20, 9, 9, 9, 9, 9, 9, 9,
                9, 9, 9, 0, 0,
            ],
        );
        let mut raw_buf = vec![];
        raw.encode::<BigEndian>(&mut raw_buf).unwrap();
        assert_eq!(epb_buf, raw_buf);
    }

    #[test]
    fn new_raw_le() {
        let opts = Options::new();
        let epb = EnhancedPacketBlock::new(1, 1, 2, 10, 20, &[9; 10], &opts);
        let mut epb_buf = vec![];
        epb.encode::<LittleEndian>(&mut epb_buf).unwrap();
        let raw = RawBlock::new(
            6,
            44,
            44,
            &[
                1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9,
                9, 9, 9, 0, 0,
            ],
        );
        let mut raw_buf = vec![];
        raw.encode::<LittleEndian>(&mut raw_buf).unwrap();
        assert_eq!(epb_buf, raw_buf);
    }
}
