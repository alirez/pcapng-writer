use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::io;
use std::io::Write;

/// Represents the endiannes of data in a pcapng file
#[derive(Debug, PartialEq)]
pub enum Endianness {
    Big,
    Little,
}

/// A trait for encoding (serializing) data
pub trait Encodable<W: Write> {
    /// Serializes the object and appends it to the `std::io::Write`
    /// provided
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()>;
}

/// The `PcapNgWriter` manages serialization of data with the
/// speicified endiannes.
#[derive(Debug)]
pub struct PcapNgWriter<W: Write> {
    endianness: Endianness,
    writer: W,
}

impl<W: Write> PcapNgWriter<W> {
    /// Creates a new pcapng writer.
    pub fn new(endianness: Endianness, writer: W) -> Self {
        Self { endianness, writer }
    }

    /// Creates a new little-endian pcapng writer.
    pub fn new_le(writer: W) -> Self {
        Self::new(Endianness::Little, writer)
    }

    /// Creates a new big-endian pcapng writer.
    pub fn new_be(writer: W) -> Self {
        Self::new(Endianness::Big, writer)
    }

    /// Serializes and writes a block to the underlying "write".
    pub fn write<T: Encodable<W>>(&mut self, block: &T) -> io::Result<()> {
        match self.endianness {
            Endianness::Little => block.encode::<LittleEndian>(self.get_writer_mut()),
            Endianness::Big => block.encode::<BigEndian>(self.get_writer_mut()),
        }
    }

    /// Returns an immutable reference to the underlying writer.
    pub fn get_writer(&self) -> &W {
        &self.writer
    }

    /// Returns mutable reference to the underlying writer.
    pub fn get_writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::options::Options;
    use crate::blocks::EnhancedPacketBlock;
    use crate::blocks::InterfaceDescriptionBlock;
    use crate::blocks::SectionHeaderBlock;
    use crate::enums;
    use crate::writer::PcapNgWriter;
    use nom::IResult;
    use pcapng;
    use std::collections::HashMap;
    use std::fs::File;
    use std::path::Path;

    #[test]
    fn new_le() {
        let mut buf = vec![];
        let writer = PcapNgWriter::new_le(&mut buf);
        assert_eq!(writer.endianness, Endianness::Little);
    }

    #[test]
    fn new_be() {
        let mut buf = vec![];
        let writer = PcapNgWriter::new_be(&mut buf);
        assert_eq!(writer.endianness, Endianness::Big);
    }

    #[test]
    fn round_trip_le() {
        let opts = Options::new();
        let mut buf = vec![];
        let mut writer = PcapNgWriter::new(Endianness::Little, &mut buf);
        let mut counts: HashMap<enums::BlockType, u32> = HashMap::new();
        let shb = SectionHeaderBlock::new_with_defaults(&opts);
        let p = b"\x00\x11\x22\x33\x44\x01\x00\x11\x22\x33\x44\x02\x08\x00\x45\x00\
                  \x00\x42\x88\x1f\x40\x00\x40\x11\x2f\x30\xc0\xa8\x01\x0a\xc0\xa8\
                  \x01\x01\x8c\xdf\x00\x35\x00\x2e\x83\x9b\xbd\x67\x01\x00\x00\x01\
                  \x00\x00\x00\x00\x00\x00\x04\x6e\x65\x77\x73\x0b\x79\x63\x6f\x6d\
                  \x62\x69\x6e\x61\x74\x6f\x72\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

        let idb0 = InterfaceDescriptionBlock::new(enums::LinkType::Ethernet, 1500, &opts);
        let idb1 = InterfaceDescriptionBlock::new(enums::LinkType::Ethernet, 1500, &opts);
        let ehp = EnhancedPacketBlock::new(1, 0, 0, p.len() as u32, p.len() as u32, &p[..], &opts);
        writer.write(&shb).unwrap();
        writer.write(&idb0).unwrap();
        writer.write(&idb1).unwrap();
        for _i in 0..100 {
            writer.write(&ehp).unwrap();
        }

        if let IResult::Done(_, blocks) = pcapng::block::parse_blocks(&buf[..]) {
            for raw in blocks {
                if let IResult::Done(_, block) = raw.parse() {
                    match block {
                        pcapng::block::Block::SectionHeader(parsed_shb) => {
                            *counts.entry(enums::BlockType::SectionHeader).or_insert(0) += 1;
                            assert_eq!(
                                parsed_shb.section_length,
                                pcapng::blocks::section_header::SectionLength::Unspecified
                            );
                        }
                        pcapng::block::Block::InterfaceDescription(_) => {
                            *counts
                                .entry(enums::BlockType::InterfaceDescription)
                                .or_insert(0) += 1;
                        }
                        pcapng::block::Block::EnhancedPacket(parsed_epb) => {
                            *counts.entry(enums::BlockType::EnhancedPacket).or_insert(0) += 1;
                            assert_eq!(parsed_epb.interface_id, 1);
                        }
                        _ => {
                            panic!();
                        }
                    }
                } else {
                    panic!()
                }
            }
        } else {
            panic!()
        }
        assert_eq!(counts[&enums::BlockType::SectionHeader], 1);
        assert_eq!(counts[&enums::BlockType::InterfaceDescription], 2);
        assert_eq!(counts[&enums::BlockType::EnhancedPacket], 100);
    }

    #[test]
    fn new_pcapng_file() {
        let opts = Options::new();
        use crate::blocks::options::{OptionComment, OptionEndOfOpt, OptionEpbFlags};
        use crate::enums::{PacketDirection, ReceptionType};
        let shb = SectionHeaderBlock::new_with_defaults(&opts);
        let p = b"\x00\x11\x22\x33\x44\x01\x00\x11\x22\x33\x44\x02\x08\x00\x45\x00\
                  \x00\x42\x88\x1f\x40\x00\x40\x11\x2f\x30\xc0\xa8\x01\x0a\xc0\xa8\
                  \x01\x01\x8c\xdf\x00\x35\x00\x2e\x83\x9b\xbd\x67\x01\x00\x00\x01\
                  \x00\x00\x00\x00\x00\x00\x04\x6e\x65\x77\x73\x0b\x79\x63\x6f\x6d\
                  \x62\x69\x6e\x61\x74\x6f\x72\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

        let comment_opt = OptionComment::new_option("Test Comment");
        let eoo = OptionEndOfOpt::new_option();
        let flags_opt = OptionEpbFlags::new_option(
            PacketDirection::Inbound,
            ReceptionType::Promiscuous,
            None,
            0,
        );
        let mut epb_options = Options::new();
        epb_options.add_option(&comment_opt);
        epb_options.add_option(&flags_opt);
        epb_options.add_option(&eoo);
        let epb = EnhancedPacketBlock::new(
            0,
            0,
            0,
            p.len() as u32,
            p.len() as u32,
            &p[..],
            &epb_options,
        );
        let idb = InterfaceDescriptionBlock::new(enums::LinkType::Ethernet, 1500, &opts);
        let path = Path::new("/tmp/z.pcap");
        let mut file = File::create(&path).unwrap();
        let mut writer = PcapNgWriter::new(Endianness::Big, &mut file);
        writer.write(&shb).unwrap();
        writer.write(&idb).unwrap();
        for _i in 0..100 {
            writer.write(&epb).unwrap();
        }
    }
}
