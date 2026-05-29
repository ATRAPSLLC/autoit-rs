//! Bounded byte reader for AU3 records.

use crate::{Error, util};

/// Checked byte reader over a borrowed input buffer.
#[derive(Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over `data` with the cursor positioned at `offset`.
    ///
    /// # Arguments
    ///
    /// * `data` - Borrowed input buffer the reader reads from.
    /// * `offset` - Absolute starting offset for the cursor.
    ///
    /// # Returns
    ///
    /// A [`Reader`] whose cursor begins at `offset`.
    pub const fn new(data: &'a [u8], offset: usize) -> Self {
        Self {
            data,
            cursor: offset,
        }
    }

    /// Returns the current absolute file offset of the cursor.
    ///
    /// # Returns
    ///
    /// The cursor position, in bytes, from the start of the input buffer.
    pub const fn position(&self) -> usize {
        self.cursor
    }

    /// Returns the number of unread bytes remaining after the cursor.
    ///
    /// Saturates at zero when the cursor has advanced past the end of the input.
    ///
    /// # Returns
    ///
    /// The count of bytes between the cursor and the end of the input buffer.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.cursor)
    }

    /// Returns a checked byte slice of the underlying input, without moving the cursor.
    ///
    /// # Arguments
    ///
    /// * `start` - Absolute start offset of the range.
    /// * `end` - Absolute exclusive end offset of the range.
    ///
    /// # Returns
    ///
    /// `Some` with the requested slice, or `None` when the range is out of bounds
    /// or otherwise invalid.
    pub fn range(&self, start: usize, end: usize) -> Option<&'a [u8]> {
        self.data.get(start..end)
    }

    /// Reads a single byte and advances the cursor by one.
    ///
    /// # Returns
    ///
    /// The byte at the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::truncated`] when no byte remains at the cursor.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let bytes = self.read_bytes(1)?;
        bytes.first().copied().ok_or_else(Error::truncated)
    }

    /// Reads a little-endian `u32` and advances the cursor by four bytes.
    ///
    /// # Returns
    ///
    /// The decoded little-endian `u32` at the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::truncated`] when fewer than four bytes remain at the cursor
    /// or the advanced cursor would overflow.
    pub fn read_u32_le(&mut self) -> Result<u32, Error> {
        let offset = self.cursor;
        let value = util::read_u32_le(self.data, offset).ok_or_else(Error::truncated)?;
        self.cursor = self.cursor.checked_add(4).ok_or_else(Error::truncated)?;
        Ok(value)
    }

    /// Reads a little-endian `u64` and advances the cursor by eight bytes.
    ///
    /// Composed from two little-endian `u32` reads, low half first.
    ///
    /// # Returns
    ///
    /// The decoded little-endian `u64` at the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::truncated`] when fewer than eight bytes remain at the cursor.
    pub fn read_u64_le(&mut self) -> Result<u64, Error> {
        let low = u64::from(self.read_u32_le()?);
        let high = u64::from(self.read_u32_le()?);
        Ok(low | (high << 32))
    }

    /// Reads `len` bytes and advances the cursor past them.
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to read.
    ///
    /// # Returns
    ///
    /// A slice of `len` bytes starting at the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::truncated`] when fewer than `len` bytes remain at the cursor
    /// or the advanced cursor would overflow.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.cursor.checked_add(len).ok_or_else(Error::truncated)?;
        let bytes = self
            .data
            .get(self.cursor..end)
            .ok_or_else(Error::truncated)?;
        self.cursor = end;
        Ok(bytes)
    }
}
