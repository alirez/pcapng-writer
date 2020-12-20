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
     0 |                    Block Type = 0x00000001                    |
       +---------------------------------------------------------------+
     4 |                      Block Total Length                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     8 |           LinkType            |           Reserved            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    12 |                            SnapLen                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    16 /                                                               /
       /                      Options (variable)                       /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Block Total Length                       |
       +---------------------------------------------------------------+

             Figure 12: Interface Description Block Format
*/

/// Represents an [Interface Description Block](https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02#section-4.2).
#[derive(Debug)]
pub struct InterfaceDescriptionBlock<'a> {
    link_type: u16,
    snap_len: u32,
    options: &'a Options<'a>,
}

impl<'a> InterfaceDescriptionBlock<'a> {
    pub fn new(
        link_type: LinkType,
        snap_len: u32,
        options: &'a Options,
    ) -> InterfaceDescriptionBlock<'a> {
        InterfaceDescriptionBlock {
            link_type: link_type.value(),
            snap_len,
            options,
        }
    }
}

impl Block for InterfaceDescriptionBlock<'_> {
    const TYPE: BlockType = BlockType::InterfaceDescription;

    fn length(&self) -> u32 {
        BLOCK_COMMON_LEN + 2 + 2 + 4 + self.options.length()
    }
}

impl<W: Write> Encodable<W> for InterfaceDescriptionBlock<'_> {
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        let total_length = self.length();
        w.write_u32::<B>(Self::TYPE.value())?;
        w.write_u32::<B>(total_length)?;
        w.write_u16::<B>(self.link_type)?;
        w.write_u16::<B>(0)?;
        w.write_u32::<B>(self.snap_len)?;
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
    fn new_idb() {
        let opts = Options::new();
        let idb = InterfaceDescriptionBlock::new(LinkType::Ethernet, 1500, &opts);
        let mut buf = vec![];
        idb.encode::<BigEndian>(&mut buf).unwrap();
        // snaplen
        assert_eq!(&buf[12..16], &[0, 0, 0x05, 0xdc]);
        let mut buf = vec![];
        idb.encode::<LittleEndian>(&mut buf).unwrap();
        // snaplen
        assert_eq!(&buf[12..16], &[0xdc, 0x05, 0, 0]);
    }

    #[test]
    fn round_trip() {
        let opts = Options::new();
        let idb = InterfaceDescriptionBlock::new(LinkType::Ethernet, 1500, &opts);
        let mut buf = vec![];
        idb.encode::<LittleEndian>(&mut buf).unwrap();
        if let IResult::Done(_, blocks) = pcapng::block::parse_blocks(&buf[..]) {
            for raw in blocks {
                if let IResult::Done(_, block) = raw.parse() {
                    if let pcapng::block::Block::InterfaceDescription(parsed_idb) = block {
                        assert_eq!(parsed_idb.link_type, 1);
                        assert_eq!(parsed_idb.snap_len, 1500);
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
