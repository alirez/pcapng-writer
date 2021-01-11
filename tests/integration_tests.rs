use pcapng_writer::blocks::options::{
    OptionComment, OptionEndOfOpt, OptionEpbFlags, OptionIfTsResol, Options,
};
use pcapng_writer::blocks::{EnhancedPacketBlock, InterfaceDescriptionBlock, SectionHeaderBlock};
use pcapng_writer::enums::{LinkType, PacketDirection, ReceptionType};
use pcapng_writer::utils::DEFAULT_TSRES;
use pcapng_writer::writer::*;
use std::fs::{metadata, remove_file, File};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn get_test_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");
    return d;
}

#[test]
fn pcapng_file_from_bytes() {
    const FILENAME: &str = "test1.pcapng";
    let eoo = OptionEndOfOpt::new_option();
    let mut opts = Options::new();
    let tsresol = &OptionIfTsResol::new_option(DEFAULT_TSRES);
    opts.add_option(tsresol);
    opts.add_option(&eoo);
    let shb = SectionHeaderBlock::new_with_defaults(&opts);
    let p = b"\x00\x11\x22\x33\x44\x01\x00\x11\x22\x33\x44\x02\x08\x00\x45\x00\
              \x00\x42\x88\x1f\x40\x00\x40\x11\x2f\x30\xc0\xa8\x01\x0a\xc0\xa8\
              \x01\x01\x8c\xdf\x00\x35\x00\x2e\x83\x9b\xbd\x67\x01\x00\x00\x01\
              \x00\x00\x00\x00\x00\x00\x04\x6e\x65\x77\x73\x0b\x79\x63\x6f\x6d\
              \x62\x69\x6e\x61\x74\x6f\x72\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

    let comment_opt = OptionComment::new_option("Test Comment");
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

    let idb = InterfaceDescriptionBlock::new(LinkType::Ethernet, 1500, &opts);
    let mut path = get_test_dir();
    path.push(FILENAME);
    let mut file = File::create(&path).unwrap();
    let mut writer = PcapNgWriter::new(Endianness::Big, &mut file);
    writer.write(&shb).unwrap();
    writer.write(&idb).unwrap();
    for _i in 0..100 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let epb = EnhancedPacketBlock::new_with_timestamp(
            0,
            DEFAULT_TSRES,
            nanos,
            p.len() as u32,
            p.len() as u32,
            &p[..],
            &epb_options,
        );
        writer.write(&epb).unwrap();
    }
    assert!(path.exists());
    assert_eq!(metadata(&path).unwrap().len(), 14072);
    remove_file(&path).unwrap();
}
