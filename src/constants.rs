/// Number of bytes in Block Type and the two Block Total Length
/// fields.
pub(crate) const BLOCK_COMMON_LEN: u32 = 12;

/// Byte-Order Magic (see section 4.1 of the draft)
pub const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// The value indicating that the length of the section is not
/// specified in Section Header Block
pub(crate) const SHB_UNSPECIFIED_LENGTH: u64 = 0xFFFF_FFFF_FFFF_FFFF;
