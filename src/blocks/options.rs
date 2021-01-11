use crate::utils::TimestampResolution;
use crate::writer::Encodable;
use crate::{
    enums::{PacketDirection, ReceptionType},
    utils::pad_to_32,
};
use byteorder::{ByteOrder, WriteBytesExt};
use std::convert::TryInto;
use std::io;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |      Option Code              |         Option Length         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                       Option Value                            /
       /              variable length, padded to 32 bits               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       /                                                               /
       /                 . . . other options . . .                     /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Option Code == opt_endofopt  |  Option Length == 0          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                         Figure 7: Options Format
*/

#[derive(Debug)]
pub enum BlockOption {
    OptEndOfOpt(OptionEndOfOpt),
    OptComment(OptionComment),
    OptCustom(u16),
    ShbHardware,
    ShbOs,
    ShbUserAppl,
    IfName(OptionIfName),
    IfDescription(OptionIfDescription),
    IfIpv4Addr(OptionIfIpv4Addr),
    IfIpv6Addr(OptionIfIpv6Addr),
    IfMacAddr(OptionIfMacAddr),
    IfEuiAddr,
    IfSpeed,
    IfTsResol(OptionIfTsResol),
    IfTZone,
    IfFilter,
    IfOs,
    IfFcsLen,
    IfTsOffset,
    IfHardware,
    EpbFlags(OptionEpbFlags),
    EpbHash,
    EpbDropCount,
    Raw(RawOption),
}

impl BlockOption {
    pub fn code(&self) -> u16 {
        match self {
            Self::OptEndOfOpt(_) => 0,
            Self::OptComment(_) => 1,
            Self::OptCustom(x) => *x,
            Self::ShbHardware => 2,
            Self::ShbOs => 3,
            Self::ShbUserAppl => 4,
            Self::IfName(_) => 2,
            Self::IfDescription(_) => 3,
            Self::IfIpv4Addr(_) => 4,
            Self::IfIpv6Addr(_) => 5,
            Self::IfMacAddr(_) => 6,
            Self::IfEuiAddr => 7,
            Self::IfSpeed => 8,
            Self::IfTsResol(_) => 9,
            Self::IfTZone => 10,
            Self::IfFilter => 11,
            Self::IfOs => 12,
            Self::IfFcsLen => 13,
            Self::IfTsOffset => 14,
            Self::IfHardware => 15,
            Self::EpbFlags(_) => 2,
            Self::EpbHash => 3,
            Self::EpbDropCount => 4,
            Self::Raw(_) => unimplemented!(),
        }
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        match self {
            Self::OptEndOfOpt(o) => o.bytes::<B>(),
            Self::OptComment(o) => o.bytes::<B>(),
            Self::IfName(o) => o.bytes::<B>(),
            Self::IfDescription(o) => o.bytes::<B>(),
            Self::IfIpv4Addr(o) => o.bytes::<B>(),
            Self::IfIpv6Addr(o) => o.bytes::<B>(),
            Self::IfMacAddr(o) => o.bytes::<B>(),
            Self::IfTsResol(o) => o.bytes::<B>(),
            Self::EpbFlags(o) => o.bytes::<B>(),
            Self::Raw(r) => r.bytes::<B>(),
            _ => unimplemented!(),
        }
    }

    fn length(&self) -> u16 {
        match self {
            Self::OptEndOfOpt(o) => o.length(),
            Self::OptComment(o) => o.length(),
            Self::IfName(o) => o.length(),
            Self::IfDescription(o) => o.length(),
            Self::IfIpv4Addr(o) => o.length(),
            Self::IfIpv6Addr(o) => o.length(),
            Self::IfMacAddr(o) => o.length(),
            Self::IfTsResol(o) => o.length(),
            Self::EpbFlags(o) => o.length(),
            Self::Raw(r) => r.length,
            _ => unimplemented!(),
        }
    }

    fn padding(&self) -> Vec<u8> {
        let n = pad_to_32(self.length().into());
        vec![0u8; n]
    }
}

impl<W: Write> Encodable<W> for BlockOption {
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        if let Self::Raw(_) = self {
            w.write_all(&self.bytes::<B>())?;
            w.write_all(&self.padding())?;
            Ok(())
        } else {
            w.write_u16::<B>(self.code())?;
            w.write_u16::<B>(self.length())?;
            w.write_all(&self.bytes::<B>())?;
            w.write_all(&self.padding())?;
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
pub struct Options<'a>(Vec<&'a BlockOption>);

impl<'a, W: Write> Encodable<W> for Options<'a> {
    fn encode<B: ByteOrder>(&self, w: &mut W) -> io::Result<()> {
        for opt in &self.0 {
            opt.encode::<B>(w)?;
        }
        Ok(())
    }
}

impl<'a> Options<'a> {
    pub fn new() -> Options<'a> {
        Default::default()
    }

    pub fn add_option(&mut self, opt: &'a BlockOption) {
        self.0.push(opt);
    }

    pub fn length(&self) -> u32 {
        self.0
            .iter()
            .map(|opt| opt.length() as u32 + opt.padding().len() as u32 + 4)
            .sum()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[derive(Debug)]
pub struct RawOption {
    code: u16,
    length: u16,
    value: Vec<u8>,
}

impl RawOption {
    pub fn new(code: u16, length: u16, value: Vec<u8>) -> RawOption {
        RawOption {
            code,
            length,
            value,
        }
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![];
        buf.write_u16::<B>(self.code).unwrap();
        buf.write_u16::<B>(self.length).unwrap();
        buf.write_all(&self.value).unwrap();
        buf
    }
}

/*
   opt_endofopt:  The opt_endofopt option delimits the end of the
      optional fields.  This option MUST NOT be repeated within a given
      list of options.
*/

#[derive(Debug, Default)]
pub struct OptionEndOfOpt;

impl OptionEndOfOpt {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_option() -> BlockOption {
        BlockOption::OptEndOfOpt(Self::new())
    }

    fn length(&self) -> u16 {
        0
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        vec![]
    }
}

/*
   opt_comment:  The opt_comment option is a UTF-8 string containing
      human-readable comment text that is associated to the current
      block.  Line separators SHOULD be a carriage-return + linefeed
      ('\r\n') or just linefeed ('\n'); either form may appear and be
      considered a line separator.  The string is not zero-terminated.
*/

#[derive(Debug)]
pub struct OptionComment {
    comment: String,
}

impl OptionComment {
    pub fn new(comment: &str) -> Self {
        Self {
            comment: comment.to_string(),
        }
    }

    pub fn new_option(comment: &str) -> BlockOption {
        BlockOption::OptComment(Self::new(comment))
    }

    fn length(&self) -> u16 {
        self.comment.len().try_into().unwrap()
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        self.comment.as_bytes().to_vec()
    }
}

/*
  if_name:  The if_name option is a UTF-8 string containing the name of
     the device used to capture data.  The string is not zero-
     terminated.

         Examples: "eth0",
         "\Device\NPF\_{AD1CE675-96D0-47C5-ADD0-2504B9126B68}".
*/

#[derive(Debug)]
pub struct OptionIfName {
    if_name: String,
}

impl OptionIfName {
    pub fn new(name: &str) -> Self {
        Self {
            if_name: name.to_string(),
        }
    }

    pub fn new_option(name: &str) -> BlockOption {
        BlockOption::IfName(Self::new(name))
    }

    fn length(&self) -> u16 {
        self.if_name.len().try_into().unwrap()
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        self.if_name.as_bytes().to_vec()
    }
}

/*
   if_description:  The if_description option is a UTF-8 string
      containing the description of the device used to capture data.
      The string is not zero-terminated.

          Examples: "Wi-Fi", "Local Area Connection", "Wireless Network
          Connection", "First Ethernet Interface".
*/

#[derive(Debug)]
pub struct OptionIfDescription {
    if_description: String,
}

impl OptionIfDescription {
    pub fn new(description: &str) -> Self {
        Self {
            if_description: description.to_string(),
        }
    }

    pub fn new_option(description: &str) -> BlockOption {
        BlockOption::IfDescription(Self::new(description))
    }

    fn length(&self) -> u16 {
        self.if_description.len().try_into().unwrap()
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        self.if_description.as_bytes().to_vec()
    }
}

/*
  if_IPv4addr:  The if_IPv4addr option is an IPv4 network address and
     corresponding netmask for the interface.  The first four octets
     are the IP address, and the next four octets are the netmask.
     This option can be repeated multiple times within the same
     Interface Description Block when multiple IPv4 addresses are
     assigned to the interface.  Note that the IP address and netmask
     are both treated as four octets, one for each octet of the address
     or mask; they are not 32-bit numbers, and thus the endianness of
     the SHB does not affect this field's value.

         Examples: '192 168 1 1 255 255 255 0'.
*/

#[derive(Debug)]
pub struct OptionIfIpv4Addr {
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
}

impl OptionIfIpv4Addr {
    pub fn new(ip: &str, netmask: &str) -> Self {
        Self {
            ip: ip.parse().unwrap(),
            netmask: netmask.parse().unwrap(),
        }
    }

    pub fn new_option(ip: &str, netmask: &str) -> BlockOption {
        BlockOption::IfIpv4Addr(Self::new(ip, netmask))
    }

    fn length(&self) -> u16 {
        4 + 4
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        let mut buf = self.ip.octets().to_vec();
        buf.extend(&self.netmask.octets());
        buf
    }
}

/*
   if_IPv6addr:  The if_IPv6addr option is an IPv6 network address and
      corresponding prefix length for the interface.  The first 16
      octets are the IP address and the next octet is the prefix length.
      This option can be repeated multiple times within the same
      Interface Description Block when multiple IPv6 addresses are
      assigned to the interface.

          Example: 2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64 is
          written (in hex) as '20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03
          70 73 44 40'.
*/

#[derive(Debug)]
pub struct OptionIfIpv6Addr {
    ip: Ipv6Addr,
    prefix_len: u8,
}

impl OptionIfIpv6Addr {
    pub fn new(ip: &str, prefix_len: u8) -> Self {
        Self {
            ip: ip.parse().unwrap(),
            prefix_len,
        }
    }

    pub fn new_option(ip: &str, prefix_len: u8) -> BlockOption {
        BlockOption::IfIpv6Addr(Self::new(ip, prefix_len))
    }

    fn length(&self) -> u16 {
        16 + 1
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        let mut buf = self.ip.octets().to_vec();
        buf.push(self.prefix_len);
        buf
    }
}

/*
   if_MACaddr:  The if_MACaddr option is the Interface Hardware MAC
      address (48 bits), if available.

          Example: '00 01 02 03 04 05'.
*/

#[derive(Debug)]
pub struct OptionIfMacAddr {
    mac_addr: [u8; 6],
}

impl OptionIfMacAddr {
    pub fn new(mac_addr: &str) -> Self {
        let split = mac_addr
            .split('.')
            .map(|x| x.parse().unwrap())
            .collect::<Vec<u8>>();
        Self {
            mac_addr: split.try_into().unwrap(),
        }
    }

    pub fn new_option(mac_addr: &str) -> BlockOption {
        BlockOption::IfMacAddr(Self::new(mac_addr))
    }

    fn length(&self) -> u16 {
        6
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        self.mac_addr.to_vec()
    }
}

/*
   if_tsresol:  The if_tsresol option identifies the resolution of
      timestamps.  If the Most Significant Bit is equal to zero, the
      remaining bits indicates the resolution of the timestamp as a
      negative power of 10 (e.g. 6 means microsecond resolution,
      timestamps are the number of microseconds since 1970-01-01
      00:00:00 UTC).  If the Most Significant Bit is equal to one, the
      remaining bits indicates the resolution as as negative power of 2
      (e.g. 10 means 1/1024 of second).  If this option is not present,
      a resolution of 10^-6 is assumed (i.e. timestamps have the same
      resolution of the standard 'libpcap' timestamps).

          Example: '6'.
*/

#[derive(Debug)]
pub struct OptionIfTsResol {
    tsresol: u8,
}

impl OptionIfTsResol {
    pub fn new(tsresol: u8) -> Self {
        Self { tsresol }
    }

    pub fn new_option(tsresol: &TimestampResolution) -> BlockOption {
        BlockOption::IfTsResol(Self::new(tsresol.to_tsresol()))
    }

    fn length(&self) -> u16 {
        1
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        [self.tsresol].to_vec()
    }
}

/*
   epb_flags:  The epb_flags option is a 32-bit flags word containing
      link- layer information.  A complete specification of the allowed
      flags can be found in Section 4.3.1.

          Example: '0'.
*/

#[derive(Debug)]
pub struct OptionEpbFlags {
    flags: u32,
}

impl OptionEpbFlags {
    pub fn new(
        dir: PacketDirection,
        reception: ReceptionType,
        fcs_length: Option<u8>,
        error_flags: u16,
    ) -> Self {
        let dir_bits = dir.value() & 0b11;
        let rec_bits = reception.value() & 0b111;
        let fcs_bits = fcs_length.map_or(0, |x| x & 0b1111);
        let flags: u32 = dir_bits as u32
            | ((rec_bits as u32) << 2)
            | ((fcs_bits as u32) << 5)
            | ((error_flags as u32) << 16);
        Self { flags }
    }

    pub fn new_option(
        dir: PacketDirection,
        reception: ReceptionType,
        fcs_length: Option<u8>,
        error_flags: u16,
    ) -> BlockOption {
        BlockOption::EpbFlags(Self::new(dir, reception, fcs_length, error_flags))
    }

    pub fn from_u32(flags: u32) -> Self {
        Self { flags }
    }

    fn length(&self) -> u16 {
        4
    }

    fn bytes<B: ByteOrder>(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![];
        buf.write_u32::<B>(self.flags).unwrap();
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, LittleEndian};

    #[test]
    fn option_encode() {
        let data = vec![9u8; 10];
        let raw = BlockOption::Raw(RawOption::new(2, data.len() as u16, data));
        let mut buf = vec![];
        raw.encode::<LittleEndian>(&mut buf).unwrap();
        assert_eq!(buf.len(), 16);
        // padding
        assert_eq!(&buf[14..], &[0, 0]);
    }

    #[test]
    fn padding() {
        for i in 9..=12 {
            let data = vec![9u8; i];
            let raw = BlockOption::Raw(RawOption::new(2, data.len() as u16, data));
            let mut buf = vec![];
            raw.encode::<LittleEndian>(&mut buf).unwrap();
            assert_eq!(buf.len(), 16);
            assert_eq!(raw.padding().len(), 12 - i);
        }
    }

    #[test]
    fn opt_comment() {
        let opt = BlockOption::OptComment(OptionComment::new("Hello World!!"));
        let mut buf = vec![];
        opt.encode::<BigEndian>(&mut buf).unwrap();
        assert_eq!(
            buf,
            [0, 1, 0, 13, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33, 33, 0, 0, 0]
        );
        let opt = BlockOption::OptComment(OptionComment::new("Hello World!!"));
        let mut buf = vec![];
        opt.encode::<LittleEndian>(&mut buf).unwrap();
        assert_eq!(
            buf,
            [1, 0, 13, 0, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33, 33, 0, 0, 0]
        );
    }
}
