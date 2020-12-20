/// Number of bytes in Block Type and the two Block Total Length
/// fields.
pub(crate) const BLOCK_COMMON_LEN: u32 = 12;

pub const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// The value indicating length is not specified in Section Header
/// Block
pub const SHB_UNSPECIFIED_LENGTH: u64 = 0xFFFFFFFFFFFFFFFF;
