//! A pcapng encoder.
//!
//! This crate contains a pcapng encoder. It can be use to write the
//! pcapng format to a file or anything that implmenets
//! `std::io::Write`.
//!
//! Implementation is based on the draft standard version 02
//! ([draft-tuexen-opsawg-pcapng-02](https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02)).
//!
//! # Use
//!
//! The `blocks` module contains types for the supported pcapng block
//! types. pcapng "option" types are located in `blocks::options`.
//!
//! `writer::PcapNgWriter` can be used to write blocks and options to
//! a file.
//!
//! # Timestamps
//!
//! pcapng define two types of timestamp
//! resolution. `utils::TimestampResolution` is an enum that
//! represents these two types. This enum has mothods to generate data
//! to be used in the if_tsresol option, as well as the timestamp
//! field of the Enhanced Packet Block.
//!
//! # Examples
//!
//! Note that in the following example we are writing just a single
//! block (an Enhanced Packet Block). This does not produce a valid
//! pcapng file, as there is no Section Header Block, etc. This is
//! only to demonstarate how to create a block with options, and write
//! it to a file.
//!
//! ```
//! use pcapng_writer::blocks::EnhancedPacketBlock;
//! use pcapng_writer::writer::PcapNgWriter;
//! use pcapng_writer::utils::DEFAULT_TSRES;
//! use pcapng_writer::blocks::options::{OptionComment, OptionEndOfOpt, Options};
//! use std::time::{SystemTime, UNIX_EPOCH};
//! // create options
//! let comment_opt = OptionComment::new_option("Test Comment");
//! let eoo = OptionEndOfOpt::new_option();
//!
//! // create an "Options" instance (option container)
//! let mut epb_options = Options::new();
//! epb_options.add_option(&comment_opt);
//! epb_options.add_option(&eoo);
//!
//! // get system time in nanoseconds
//! let nanos = SystemTime::now()
//!     .duration_since(UNIX_EPOCH)
//!     .unwrap()
//!     .as_nanos();
//!
//! // the actual packet content
//! let payload = b"\x00\x11\x22\x33\x44\x01\x00\x11\x22\x33\x44\x02\x08\x00";
//! let epb = EnhancedPacketBlock::from_timestamp(
//!     0,
//!     DEFAULT_TSRES,
//!     nanos,
//!     payload.len() as u32,
//!     payload.len() as u32,
//!     &payload[..],
//!     &epb_options,
//! );
//!
//! // using a byte vector here instead of a file
//! let mut buf: Vec<u8> = vec![];
//! let mut writer = PcapNgWriter::new_le(&mut buf);
//! writer.write(&epb).unwrap();
//! ```

pub mod blocks;
pub mod constants;
pub mod enums;
pub mod utils;
pub mod writer;
