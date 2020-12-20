use crate::blocks::options::Options;
use crate::blocks::Block;
use crate::constants::*;
use crate::enums::*;
use crate::utils::TimestampResolution;
use crate::writer::Encodable;
use byteorder::{ByteOrder, WriteBytesExt};
use std::io;
use std::io::Write;

/*
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +---------------------------------------------------------------+
     0 |                    Block Type = 0x00000006                    |
       +---------------------------------------------------------------+
     4 |                      Block Total Length                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     8 |                         Interface ID                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    12 |                        Timestamp (High)                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    16 |                        Timestamp (Low)                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    20 |                    Captured Packet Length                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    24 |                    Original Packet Length                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    28 /                                                               /
       /                          Packet Data                          /
       /              variable length, padded to 32 bits               /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                                                               /
       /                      Options (variable)                       /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Block Total Length                       |
       +---------------------------------------------------------------+

                   Figure 11: Enhanced Packet Block Format
*/

/// Represents an [Enhanced Packet Block](https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02#section-4.3).
#[derive(Debug)]
pub struct EnhancedPacketBlock<'a> {
    interface_id: u32,
    ts_high: u32,
    ts_low: u32,
    cap_packet_len: u32,
    orig_packet_len: u32,
    packet_data: &'a [u8],
    options: &'a Options<'a>,
}

impl<'a> EnhancedPacketBlock<'a> {
    /// Create a new `EnhancedPacketBlock`.
    pub fn new(
        interface_id: u32,
        ts_high: u32,
        ts_low: u32,
        cap_len: u32,
        orig_len: u32,
        packet_data: &'a [u8],
        options: &'a Options,
    ) -> EnhancedPacketBlock<'a> {
        EnhancedPacketBlock {
            interface_id,
            ts_high,
            ts_low,
            cap_packet_len: cap_len,
            orig_packet_len: orig_len,
            packet_data,
            options,
        }
    }

    /// Create a new `EnhancedPacketBlock`. Uses a
    /// `TimestampResolution` and number of nanoseconds to populate
    /// the timestamp fields.
    pub fn from_timestamp(
        interface_id: u32,
        ts_res: &TimestampResolution,
        nanoseconds: u128,
        cap_len: u32,
        orig_len: u32,
        packet_data: &'a [u8],
        options: &'a Options,
    ) -> EnhancedPacketBlock<'a> {
        let (ts_high, ts_low) = ts_res.ts_from_nanoseconds(nanoseconds);
        Self::new(
            interface_id,
            ts_high,
            ts_low,
            cap_len,
            orig_len,
            packet_data,
            options,
        )
    }

    fn data_padding(&self) -> Vec<u8> {
        let n = self.packet_data.len() % 4;
        vec![0u8; n]
    }
}

impl Block for EnhancedPacketBlock<'_> {
    const TYPE: BlockType = BlockType::EnhancedPacket;

    fn length(&self) -> u32 {
        BLOCK_COMMON_LEN
            + 4
            + 4
            + 4
            + 4
            + 4
            + self.packet_data.len() as u32
            + self.data_padding().len() as u32
            + self.options.length()
    }
}

impl<W: Write> Encodable<W> for EnhancedPacketBlock<'_> {
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        let total_length = self.length();
        w.write_u32::<B>(Self::TYPE.value())?;
        w.write_u32::<B>(total_length)?;
        w.write_u32::<B>(self.interface_id)?;
        w.write_u32::<B>(self.ts_high)?;
        w.write_u32::<B>(self.ts_low)?;
        w.write_u32::<B>(self.cap_packet_len)?;
        w.write_u32::<B>(self.orig_packet_len)?;
        w.write_all(self.packet_data)?;
        w.write_all(&self.data_padding())?;
        self.options.encode::<B>(w)?;
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
    fn new_epb() {
        let opts = Options::new();
        let epb = EnhancedPacketBlock::new(1, 1, 2, 10, 10, &[9; 10], &opts);
        let mut buf = vec![];
        epb.encode::<BigEndian>(&mut buf).unwrap();
        // interface ID
        assert_eq!(&buf[8..12], &[0, 0, 0, 1]);
        // packet data
        assert_eq!(&buf[28..38], &[9; 10]);
        // padding
        assert_eq!(&buf[38..40], &[0, 0]);
        let mut buf = vec![];
        epb.encode::<LittleEndian>(&mut buf).unwrap();
        // interface ID
        assert_eq!(&buf[8..12], &[1, 0, 0, 0]);
        // packet data
        assert_eq!(&buf[28..38], &[9; 10]);
        // padding
        assert_eq!(&buf[38..40], &[0, 0]);
    }

    #[test]
    fn round_trip() {
        let opts = Options::new();
        let epb = EnhancedPacketBlock::new(1, 1, 2, 10, 20, &[9; 10], &opts);
        let mut buf = vec![];
        epb.encode::<LittleEndian>(&mut buf).unwrap();
        if let IResult::Done(_, blocks) = pcapng::block::parse_blocks(&buf[..]) {
            for raw in blocks {
                if let IResult::Done(_, block) = raw.parse() {
                    if let pcapng::block::Block::EnhancedPacket(parsed_epb) = block {
                        assert_eq!(parsed_epb.captured_len, 10);
                        assert_eq!(parsed_epb.packet_len, 20);
                        assert_eq!(parsed_epb.timestamp_hi, 1);
                        assert_eq!(parsed_epb.timestamp_lo, 2);
                        assert_eq!(parsed_epb.data, &[9; 10]);
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
