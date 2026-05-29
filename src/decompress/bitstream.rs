//! MSB-first bit reader.
//!
//! Provides [`BitStream`], a forward-only reader that consumes a byte slice one bit at a time with
//! the most significant bit first. The decompressors use it to pull variable-width fields and
//! Huffman codes out of packed payloads.

use crate::Error;

/// MSB-first bit stream over a byte slice.
#[derive(Debug)]
pub struct BitStream<'a> {
    data: &'a [u8],
    bit_offset: usize,
}

impl<'a> BitStream<'a> {
    /// Creates a new bit stream positioned at the first bit of `data`.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice to read bits from, MSB-first.
    ///
    /// # Returns
    ///
    /// A [`BitStream`] borrowing `data` with its bit cursor at offset 0.
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bit_offset: 0,
        }
    }

    /// Reads `count` bits as an unsigned integer, MSB-first.
    ///
    /// Consumes `count` bits in order, shifting each into the low end of the accumulator so the
    /// first bit read becomes the most significant bit of the result.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of bits to read; values above 32 overflow the accumulated `u32`.
    ///
    /// # Returns
    ///
    /// The assembled unsigned value. Reading zero bits yields 0.
    ///
    /// # Errors
    ///
    /// Propagates the error from [`BitStream::read_bit`]: [`Error::truncated`] if the stream runs
    /// out of bytes, or [`Error::compression_error`] on cursor arithmetic failure.
    pub fn read_bits(&mut self, count: usize) -> Result<u32, Error> {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit()?);
        }
        Ok(value)
    }

    /// Reads and consumes a single bit, advancing the cursor by one.
    ///
    /// Locates the current bit within its byte and extracts it MSB-first (bit offset 0 is the top
    /// bit of byte 0), then increments the bit cursor.
    ///
    /// # Returns
    ///
    /// The bit value, either 0 or 1.
    ///
    /// # Errors
    ///
    /// Returns [`Error::truncated`] if the cursor has run past the end of the backing slice, or
    /// [`Error::compression_error`] if the in-byte shift or cursor increment would overflow.
    fn read_bit(&mut self) -> Result<u8, Error> {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let byte = *self.data.get(byte_index).ok_or_else(Error::truncated)?;
        let shift = 7usize
            .checked_sub(bit_index)
            .ok_or_else(Error::compression_error)?;
        self.bit_offset = self
            .bit_offset
            .checked_add(1)
            .ok_or_else(Error::compression_error)?;
        Ok((byte >> shift) & 1)
    }
}
