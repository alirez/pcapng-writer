pub const MICRO_SECOND_TSRES: &TimestampResolution = &TimestampResolution::PowerOfTen(6);
pub const NANO_SECOND_TSRES: &TimestampResolution = &TimestampResolution::PowerOfTen(9);
pub const DEFAULT_TSRES: &TimestampResolution = MICRO_SECOND_TSRES;

/// Represents a timestamp resolution as specified by the pcapng
/// standard section 4.2.
pub enum TimestampResolution {
    PowerOfTen(u8),
    PowerOfTwo(u8),
}

impl TimestampResolution {
    /// Returns a value that can be used in the `if_tsresol` option of
    /// the Interface Description Block.
    pub fn to_tsresol(&self) -> u8 {
        match *self {
            Self::PowerOfTwo(power) => 1u8 << 7 | power,
            Self::PowerOfTen(power) => power & !(1u8 << 7),
        }
    }

    /// Returns a tuple of integers that can be used in "Timestamp
    /// (High)" and "Timestamp (Low)" of the Enhanced Packet Block
    /// respectively.
    pub fn ts_from_nanoseconds(&self, nanos: u128) -> (u32, u32) {
        let high: u32;
        let low: u32;
        match *self {
            Self::PowerOfTen(power) => {
                let t: u128 = nanos / ((10u128).pow(9 - power as u32));
                high = (t >> 32) as u32;
                low = (t & 0xffff_ffff) as u32;
            }
            Self::PowerOfTwo(power) => {
                let t: u128 = (nanos / 1_000_000_000) * (2u128).pow(power as u32);
                high = (t >> 32) as u32;
                low = (t & 0xffff_ffff) as u32;
            }
        }
        (high, low)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn tsresol_power_of_ten() {
        let ts = TimestampResolution::PowerOfTen(6);
        assert_eq!(ts.to_tsresol(), 0b00000110);
    }

    #[test]
    fn tsresol_power_of_two() {
        let ts = TimestampResolution::PowerOfTwo(6);
        assert_eq!(ts.to_tsresol(), 0b10000110);
    }

    #[test]
    fn from_nanos_power_of_ten() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let ts_micro = TimestampResolution::PowerOfTen(6);
        let (high, low) = ts_micro.ts_from_nanoseconds(nanos);
        assert_eq!(((high as u64) << 32) | (low as u64), (nanos / 1000) as u64);
        let ts_nano = TimestampResolution::PowerOfTen(9);
        let (high, low) = ts_nano.ts_from_nanoseconds(nanos);
        assert_eq!(((high as u64) << 32) | (low as u64), nanos as u64);
    }

    #[test]
    fn from_nanos_power_of_two() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let ts_2_6 = TimestampResolution::PowerOfTwo(6);
        let (high, low) = ts_2_6.ts_from_nanoseconds(nanos);
        assert_eq!(
            (((high as u64) << 32) | (low as u64)) / (2u64).pow(6),
            (nanos / 1_000_000_000) as u64
        );
        let ts_2_14 = TimestampResolution::PowerOfTwo(14);
        let (high, low) = ts_2_14.ts_from_nanoseconds(nanos);
        assert_eq!(
            (((high as u64) << 32) | (low as u64)) / (2u64).pow(14),
            (nanos / 1_000_000_000) as u64
        );
    }
}
