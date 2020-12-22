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
     0 |                   Block Type = 0x0A0D0D0A                     |
       +---------------------------------------------------------------+
     4 |                      Block Total Length                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     8 |                      Byte-Order Magic                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    12 |          Major Version        |         Minor Version         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    16 |                                                               |
       |                          Section Length                       |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    24 /                                                               /
       /                      Options (variable)                       /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Block Total Length                       |
       +---------------------------------------------------------------+

                 Figure 10: Section Header Block Format
*/

/// Represents a [Section Header Block](https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02#section-4.1).
#[derive(Debug)]
pub struct SectionHeaderBlock<'a> {
    byte_order_magic: u32,
    major_version: u16,
    minor_version: u16,
    section_length: u64,
    options: &'a Options<'a>,
}

impl<'a> SectionHeaderBlock<'a> {
    /// Create a new Section Header Block
    pub fn new(
        byte_order_magic: u32,
        major_version: u16,
        minor_version: u16,
        section_length: SectionHeaderSectionLength,
        options: &'a Options,
    ) -> Self {
        Self {
            byte_order_magic,
            major_version,
            minor_version,
            section_length: section_length.value(),
            options,
        }
    }

    /// Create a new Section Header Block with version set to 1.0 and
    /// Section Length "unspecified"
    pub fn new_with_defaults(options: &'a Options) -> Self {
        Self::new(
            BYTE_ORDER_MAGIC,
            1,
            0,
            SectionHeaderSectionLength::Unspecified,
            options,
        )
    }
}

impl Block for SectionHeaderBlock<'_> {
    const TYPE: BlockType = BlockType::SectionHeader;

    fn length(&self) -> u32 {
        BLOCK_COMMON_LEN + 4 + 2 + 2 + 8 + self.options.length()
    }
}

impl<W: Write> Encodable<W> for SectionHeaderBlock<'_> {
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        let total_length = self.length();
        w.write_u32::<B>(Self::TYPE.value())?;
        w.write_u32::<B>(total_length)?;
        w.write_u32::<B>(self.byte_order_magic)?;
        w.write_u16::<B>(self.major_version)?;
        w.write_u16::<B>(self.minor_version)?;
        w.write_u64::<B>(self.section_length)?;
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
    fn new_shb() {
        let opts = Options::new();
        let shb = SectionHeaderBlock::new_with_defaults(&opts);
        let mut buf = vec![];
        shb.encode::<BigEndian>(&mut buf).unwrap();
        assert_eq!(&buf[..4], &[0xa, 0xd, 0xd, 0xa]);
        assert_eq!(&buf[8..12], &[0x1a, 0x2b, 0x3c, 0x4d]);
        let mut buf = vec![];
        shb.encode::<LittleEndian>(&mut buf).unwrap();
        assert_eq!(&buf[..4], &[0xa, 0xd, 0xd, 0xa]);
        assert_eq!(&buf[8..12], &[0x4d, 0x3c, 0x2b, 0x1a]);
    }

    #[test]
    fn round_trip() {
        let opts = Options::new();
        let shb = SectionHeaderBlock::new_with_defaults(&opts);
        let mut buf = vec![];
        shb.encode::<LittleEndian>(&mut buf).unwrap();
        if let IResult::Done(_, blocks) = pcapng::block::parse_blocks(&buf[..]) {
            for raw in blocks {
                if let IResult::Done(_, block) = raw.parse() {
                    if let pcapng::block::Block::SectionHeader(parsed_shb) = block {
                        assert_eq!(parsed_shb.major_version, 1);
                        assert_eq!(parsed_shb.minor_version, 0);
                        assert_eq!(
                            parsed_shb.section_length,
                            pcapng::blocks::section_header::SectionLength::Unspecified
                        );
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
