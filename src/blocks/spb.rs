use crate::blocks::Block;
use crate::constants::*;
use crate::enums::*;
use crate::writer::Encodable;
use byteorder::{ByteOrder, WriteBytesExt};
use std::io;
use std::io::Write;

/*

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +---------------------------------------------------------------+
     0 |                    Block Type = 0x00000003                    |
       +---------------------------------------------------------------+
     4 |                      Block Total Length                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     8 |                    Original Packet Length                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    12 /                                                               /
       /                          Packet Data                          /
       /              variable length, padded to 32 bits               /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Block Total Length                       |
       +---------------------------------------------------------------+

                    Figure 12: Simple Packet Block Format
*/

/// Represents a [Simple Header Block](https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02#section-4.4).
#[derive(Debug)]
pub struct SimplePacketBlock<'a> {
    orig_packet_len: u32,
    packet_data: &'a [u8],
}

impl<'a> SimplePacketBlock<'a> {
    pub fn new(orig_len: u32, packet_data: &'a [u8]) -> SimplePacketBlock {
        SimplePacketBlock {
            orig_packet_len: orig_len,
            packet_data,
        }
    }

    fn data_padding(&self) -> Vec<u8> {
        let n = self.packet_data.len() % 4;
        vec![0u8; n]
    }
}

impl<'a> Block for SimplePacketBlock<'a> {
    const TYPE: BlockType = BlockType::SimplePacket;

    fn length(&self) -> u32 {
        BLOCK_COMMON_LEN + 4 + self.packet_data.len() as u32 + self.data_padding().len() as u32
    }
}

impl<W: Write> Encodable<W> for SimplePacketBlock<'_> {
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        let total_length = self.length();
        w.write_u32::<B>(Self::TYPE.value())?;
        w.write_u32::<B>(total_length)?;
        w.write_u32::<B>(self.orig_packet_len)?;
        w.write_all(self.packet_data)?;
        w.write_all(&self.data_padding())?;
        w.write_u32::<B>(total_length)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, LittleEndian};
    use nom::IResult;
    use pcapng;

    #[test]
    fn new_spb() {
        let spb = SimplePacketBlock::new(10, &[9; 10]);
        let mut buf = vec![];
        spb.encode::<BigEndian>(&mut buf).unwrap();
        // original length
        assert_eq!(&buf[8..12], &[0, 0, 0, 0xa]);
        // packet data
        assert_eq!(&buf[12..22], &[9; 10]);
        // padding
        assert_eq!(&buf[22..24], &[0, 0]);
        let mut buf = vec![];
        spb.encode::<LittleEndian>(&mut buf).unwrap();
        // original length
        assert_eq!(&buf[8..12], &[0xa, 0, 0, 0]);
        // packet data
        assert_eq!(&buf[12..22], &[9; 10]);
        // padding
        assert_eq!(&buf[22..24], &[0, 0]);
    }

    #[test]
    fn round_trip() {
        let spb = SimplePacketBlock::new(10, &[9; 10]);
        let mut buf = vec![];
        spb.encode::<LittleEndian>(&mut buf).unwrap();
        if let IResult::Done(_, blocks) = pcapng::block::parse_blocks(&buf[..]) {
            for raw in blocks {
                if let IResult::Done(_, block) = raw.parse() {
                    if let pcapng::block::Block::UnknownBlock(r) = block {
                        // pcapng-rs doesn't have a parser for Simple
                        // Packet Block. We just check the type.
                        assert_eq!(r.ty, BlockType::SimplePacket.value());
                    } else {
                        panic!()
                    }
                } else {
                    panic!();
                }
            }
        } else {
            panic!();
        }
    }
}
