use crate::enums::BlockType;
use crate::writer::Encodable;
use byteorder::{ByteOrder, WriteBytesExt};
use std::convert::TryInto;
use std::io;
use std::io::Write;

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
        let mut n = (self.length() % 4).try_into().unwrap();
        if n > 0 {
            n = 4 - n;
        }
        vec![0u8; n]
    }
}

#[derive(Debug)]
pub struct RawBlock<'a> {
    block_type: u32,
    total_length: u32,
    body: &'a [u8],
}

impl<'a, W: Write> Encodable<W> for RawBlock<'a> {
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        let total_length = self.body.len() as u32;
        w.write_u32::<B>(self.block_type)?;
        w.write_u32::<B>(total_length)?;
        w.write_all(self.body)?;
        w.write_u32::<B>(total_length)?;
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
