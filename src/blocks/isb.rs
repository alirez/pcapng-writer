use crate::blocks::options::Options;
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
     0 |                   Block Type = 0x00000005                     |
       +---------------------------------------------------------------+
     4 |                      Block Total Length                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     8 |                         Interface ID                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    12 |                        Timestamp (High)                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    16 |                        Timestamp (Low)                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    20 /                                                               /
       /                      Options (variable)                       /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Block Total Length                       |
       +---------------------------------------------------------------+

                Figure 14: Interface Statistics Block Format
*/

/// Represents an [Interface Statistics Block](https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02#section-4.6).
#[derive(Debug)]
pub struct InterfaceStatisticsBlock<'a> {
    interface_id: u32,
    ts_high: u32,
    ts_low: u32,
    options: &'a Options<'a>,
}

impl<'a> InterfaceStatisticsBlock<'a> {
    pub fn new(
        interface_id: u32,
        ts_high: u32,
        ts_low: u32,
        options: &'a Options,
    ) -> InterfaceStatisticsBlock<'a> {
        InterfaceStatisticsBlock {
            interface_id,
            ts_high,
            ts_low,
            options,
        }
    }
}

impl Block for InterfaceStatisticsBlock<'_> {
    const TYPE: BlockType = BlockType::InterfaceStatistics;

    fn length(&self) -> u32 {
        BLOCK_COMMON_LEN + 4 + 4 + 4 + self.options.length()
    }
}

impl<W: Write> Encodable<W> for InterfaceStatisticsBlock<'_> {
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        let total_length = self.length();
        w.write_u32::<B>(Self::TYPE.value())?;
        w.write_u32::<B>(total_length)?;
        w.write_u32::<B>(self.interface_id)?;
        w.write_u32::<B>(self.ts_high)?;
        w.write_u32::<B>(self.ts_low)?;
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
    fn new_isb() {
        let opts = Options::new();
        let isb = InterfaceStatisticsBlock::new(1, 100, 200, &opts);
        let mut buf = vec![];
        isb.encode::<BigEndian>(&mut buf).unwrap();
        // interface ID
        assert_eq!(&buf[8..12], &[0, 0, 0, 1]);
        let mut buf = vec![];
        isb.encode::<LittleEndian>(&mut buf).unwrap();
        // interface ID
        assert_eq!(&buf[8..12], &[1, 0, 0, 0]);
    }

    #[test]
    fn round_trip() {
        let opts = Options::new();
        let isb = InterfaceStatisticsBlock::new(1, 100, 200, &opts);
        let mut buf = vec![];
        isb.encode::<LittleEndian>(&mut buf).unwrap();
        if let IResult::Done(_, blocks) = pcapng::block::parse_blocks(&buf[..]) {
            for raw in blocks {
                if let IResult::Done(_, block) = raw.parse() {
                    if let pcapng::block::Block::InterfaceStatistics(parsed_isb) = block {
                        assert_eq!(parsed_isb.interface_id, 1);
                        assert_eq!(parsed_isb.timestamp_high, 100);
                        assert_eq!(parsed_isb.timestamp_low, 200);
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
