//! Internal little-endian reading and signature helpers.
//!
//! These are the bounds-checked primitives shared by the container and record
//! parsers. Each reader takes an explicit offset and returns `None` instead of
//! panicking when the requested bytes fall outside `data`, so callers can treat
//! a short or malformed input as a recoverable miss.

/// Returns whether the input begins with the DOS `MZ` executable signature.
///
/// # Arguments
///
/// * `data` - Bytes to inspect, typically the start of a candidate input file.
///
/// # Returns
///
/// `true` if `data` starts with the two-byte `MZ` magic; `false` otherwise,
/// including when `data` is shorter than two bytes.
#[must_use]
pub fn has_mz_header(data: &[u8]) -> bool {
    data.starts_with(b"MZ")
}

/// Reads a little-endian `u16` at `offset`.
///
/// # Arguments
///
/// * `data` - Buffer to read from.
/// * `offset` - Byte offset of the first of the two little-endian bytes.
///
/// # Returns
///
/// The decoded `u16`, or `None` if `offset + 2` overflows `usize` or extends
/// past the end of `data`.
#[must_use]
pub fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = data.get(offset..end)?;
    let array: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

/// Reads a little-endian `u32` at `offset`.
///
/// # Arguments
///
/// * `data` - Buffer to read from.
/// * `offset` - Byte offset of the first of the four little-endian bytes.
///
/// # Returns
///
/// The decoded `u32`, or `None` if `offset + 4` overflows `usize` or extends
/// past the end of `data`.
#[must_use]
pub fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = data.get(offset..end)?;
    let array: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}
