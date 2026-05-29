//! AutoIt compressed payload decompression.
//!
//! Dispatches on the 8-byte wrapper header (4-byte magic plus a big-endian
//! decompressed-size field) to the matching codec: the `EA04`/`EA05`/`EA06` LZ
//! scheme handled here, or the `JB00`/`JB01` adaptive-Huffman + LZSS scheme in
//! the `jb` submodule.

mod bitstream;
mod jb;

use crate::{Encoding, Error};
use bitstream::BitStream;

const HEADER_LEN: usize = 8;
const MAGIC_EA04: &[u8; 4] = b"EA04";
const MAGIC_EA05: &[u8; 4] = b"EA05";
const MAGIC_EA06: &[u8; 4] = b"EA06";
const MAGIC_JB00: &[u8; 4] = b"JB00";
const MAGIC_JB01: &[u8; 4] = b"JB01";

/// Decompression limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum decompressed output size in bytes.
    pub max_output_size: usize,
}

impl Default for Limits {
    /// Returns limits with a 64 MiB maximum decompressed output size.
    ///
    /// # Returns
    ///
    /// A [`Limits`] whose `max_output_size` is 64 MiB.
    fn default() -> Self {
        Self {
            max_output_size: 64 * 1024 * 1024,
        }
    }
}

/// Decompresses an AutoIt compressed blob.
///
/// Parses the 8-byte header (4-byte magic and a big-endian decompressed size)
/// and dispatches to the LZ codec for `EA04`/`EA05`/`EA06` or the JB codec for
/// `JB00`/`JB01`.
///
/// # Arguments
///
/// * `data` - The full compressed blob including the 8-byte wrapper header.
/// * `limits` - Caps applied during decompression, notably the maximum output size.
///
/// # Returns
///
/// The fully decompressed bytes on success.
///
/// # Errors
///
/// Returns [`Error::truncated`] if the header or its size field is missing or
/// the payload slice is absent. Returns [`Error::limit_exceeded`] if the
/// advertised size does not fit in a `usize` or exceeds `limits.max_output_size`.
/// Returns [`Error::compression_error`] for an unrecognized magic. Errors from
/// the selected codec are propagated.
pub fn decompress(data: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    let header = data.get(0..HEADER_LEN).ok_or_else(Error::truncated)?;
    let magic = header.get(0..4).ok_or_else(Error::truncated)?;
    let size_bytes: [u8; 4] = header
        .get(4..8)
        .ok_or_else(Error::truncated)?
        .try_into()
        .map_err(|_err| Error::truncated())?;
    let output_size =
        usize::try_from(u32::from_be_bytes(size_bytes)).map_err(|_err| Error::limit_exceeded())?;
    if output_size > limits.max_output_size {
        return Err(Error::limit_exceeded());
    }
    let payload = data.get(HEADER_LEN..).ok_or_else(Error::truncated)?;

    if magic == MAGIC_EA04 {
        decompress_lz(payload, output_size, Encoding::Ea04)
    } else if magic == MAGIC_EA05 {
        decompress_lz(payload, output_size, Encoding::Ea05)
    } else if magic == MAGIC_EA06 {
        decompress_lz(payload, output_size, Encoding::Ea06)
    } else if magic == MAGIC_JB00 || magic == MAGIC_JB01 {
        jb::decompress_jb01(payload, output_size)
    } else {
        Err(Error::compression_error())
    }
}

/// Decompresses an `EA04`/`EA05`/`EA06` LZ payload into `output_size` bytes.
///
/// Each token starts with a single control bit: when it equals the encoding's
/// literal symbol the next 8 bits are an output byte, otherwise a 15-bit
/// back-reference offset followed by a staged match length (see
/// [`read_match_len`]) selects bytes to copy from earlier output. The literal
/// control bit is `0` for `EA04`/`EA05` and `1` for `EA06`.
///
/// # Arguments
///
/// * `data` - The compressed payload after the 8-byte wrapper header.
/// * `output_size` - The exact decompressed length to produce.
/// * `encoding` - Which EA variant the payload uses, selecting the literal control bit.
///
/// # Returns
///
/// The decompressed bytes of length `output_size`.
///
/// # Errors
///
/// Returns [`Error::unsupported_encoding`] if `encoding` is [`Encoding::Jb01`].
/// Returns [`Error::compression_error`] if a decoded byte, offset, or match
/// length cannot be represented or a match is invalid. Propagates
/// [`Error::truncated`] from the bit stream when input is exhausted.
fn decompress_lz(data: &[u8], output_size: usize, encoding: Encoding) -> Result<Vec<u8>, Error> {
    let literal_symbol = match encoding {
        Encoding::Ea04 | Encoding::Ea05 => 0,
        Encoding::Ea06 => 1,
        Encoding::Jb01 => return Err(Error::unsupported_encoding()),
    };
    let mut bits = BitStream::new(data);
    let mut output = Vec::with_capacity(output_size);
    while output.len() < output_size {
        let control = bits.read_bits(1)?;
        if control == literal_symbol {
            let byte =
                u8::try_from(bits.read_bits(8)?).map_err(|_err| Error::compression_error())?;
            output.push(byte);
        } else {
            let offset =
                usize::try_from(bits.read_bits(15)?).map_err(|_err| Error::compression_error())?;
            let match_len = read_match_len(&mut bits)?;
            copy_match(&mut output, offset, match_len, output_size)?;
        }
    }
    Ok(output)
}

/// Reads a staged, variable-width match length from the bit stream.
///
/// The length is encoded in successive stages, each with a base value and a
/// fixed-width field: if the field's value is below the stage's "more" sentinel
/// the length is `base + value`; if it equals the sentinel decoding advances to
/// the next stage. The final (base 299) stage repeats, accumulating the
/// 8-bit sentinel each iteration until a sub-sentinel field terminates it.
///
/// # Arguments
///
/// * `bits` - The bit stream positioned at the start of the length code.
///
/// # Returns
///
/// The decoded match length.
///
/// # Errors
///
/// Returns [`Error::compression_error`] if an accumulated length overflows or a
/// field cannot be converted. Propagates [`Error::truncated`] when the bit
/// stream is exhausted.
fn read_match_len(bits: &mut BitStream<'_>) -> Result<usize, Error> {
    let stages = [
        (3usize, 2usize, 0b11u32),
        (6, 3, 0b111),
        (13, 5, 0b1_1111),
        (44, 8, 0xff),
        (299, 8, 0xff),
    ];
    for (base, width, more) in stages {
        let add = bits.read_bits(width)?;
        if add != more {
            return usize::try_from(add)
                .ok()
                .and_then(|value| base.checked_add(value))
                .ok_or_else(Error::compression_error);
        }
        if base == 299 {
            let mut length = base;
            loop {
                length = length
                    .checked_add(usize::try_from(more).map_err(|_err| Error::compression_error())?)
                    .ok_or_else(Error::compression_error)?;
                let extra = bits.read_bits(width)?;
                if extra != more {
                    return length
                        .checked_add(
                            usize::try_from(extra).map_err(|_err| Error::compression_error())?,
                        )
                        .ok_or_else(Error::compression_error);
                }
            }
        }
    }
    Err(Error::compression_error())
}

/// Copies a back-reference match onto the end of the output buffer.
///
/// Bytes are copied one at a time from `offset` positions behind the current
/// end, so overlapping matches (offset smaller than the length) repeat the
/// preceding window as they extend.
///
/// # Arguments
///
/// * `output` - The decompressed buffer being appended to.
/// * `offset` - Distance behind the current end to copy from; must be in `1..=output.len()`.
/// * `match_len` - Number of bytes to copy.
/// * `output_size` - The final output length, used to reject overruns.
///
/// # Returns
///
/// The unit value on success, with `match_len` bytes appended to `output`.
///
/// # Errors
///
/// Returns [`Error::compression_error`] if `offset` is zero or larger than the
/// current output, if appending would overflow or exceed `output_size`, or if a
/// source index cannot be reached.
fn copy_match(
    output: &mut Vec<u8>,
    offset: usize,
    match_len: usize,
    output_size: usize,
) -> Result<(), Error> {
    if offset == 0 || offset > output.len() {
        return Err(Error::compression_error());
    }
    let end = output
        .len()
        .checked_add(match_len)
        .ok_or_else(Error::compression_error)?;
    if end > output_size {
        return Err(Error::compression_error());
    }
    for _ in 0..match_len {
        let source = output
            .len()
            .checked_sub(offset)
            .ok_or_else(Error::compression_error)?;
        let byte = *output.get(source).ok_or_else(Error::compression_error)?;
        output.push(byte);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompresses_ea06_literal_only() -> Result<(), String> {
        let mut blob = Vec::from(*MAGIC_EA06);
        blob.extend_from_slice(&3u32.to_be_bytes());
        blob.extend_from_slice(
            pack_bits(&[
                1, 0, 1, 0, 0, 0, 0, 0, 1, // A
                1, 0, 1, 0, 0, 0, 0, 1, 0, // B
                1, 0, 1, 0, 0, 0, 0, 1, 1, // C
            ])?
            .as_slice(),
        );

        let decompressed =
            decompress(blob.as_slice(), Limits::default()).map_err(|err| err.to_string())?;
        check_eq(decompressed, b"ABC".to_vec(), "decompressed")
    }

    #[test]
    fn decompresses_ea05_literal_only() -> Result<(), String> {
        let mut blob = Vec::from(*MAGIC_EA05);
        blob.extend_from_slice(&2u32.to_be_bytes());
        blob.extend_from_slice(
            pack_bits(&[
                0, 0, 1, 0, 0, 1, 0, 0, 0, // H
                0, 0, 1, 0, 0, 1, 0, 0, 1, // I
            ])?
            .as_slice(),
        );

        let decompressed =
            decompress(blob.as_slice(), Limits::default()).map_err(|err| err.to_string())?;
        check_eq(decompressed, b"HI".to_vec(), "decompressed")
    }

    #[test]
    fn decompresses_overlapping_match() -> Result<(), String> {
        let mut blob = Vec::from(*MAGIC_EA06);
        blob.extend_from_slice(&5u32.to_be_bytes());
        blob.extend_from_slice(
            pack_bits(&[
                1, 0, 1, 0, 0, 0, 0, 0, 1, // A
                1, 0, 1, 0, 0, 0, 0, 1, 0, // B
                0, // match
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, // offset 2
                0, 0, // length 3
            ])?
            .as_slice(),
        );

        let decompressed =
            decompress(blob.as_slice(), Limits::default()).map_err(|err| err.to_string())?;
        check_eq(decompressed, b"ABABA".to_vec(), "decompressed")
    }

    #[test]
    fn rejects_invalid_match_offset() -> Result<(), String> {
        let mut blob = Vec::from(*MAGIC_EA06);
        blob.extend_from_slice(&3u32.to_be_bytes());
        blob.extend_from_slice(
            pack_bits(&[
                0, // match
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // offset 0
                0, 0, // length 3
            ])?
            .as_slice(),
        );

        let Err(err) = decompress(blob.as_slice(), Limits::default()) else {
            return Err("unexpected decompression success".to_string());
        };
        check_eq(
            err.recognition_failure(),
            Some(crate::RecognitionFailure::CompressionError),
            "error",
        )
    }

    #[test]
    fn rejects_truncated_bitstream() -> Result<(), String> {
        let mut blob = Vec::from(*MAGIC_EA06);
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.push(0b1000_0000);

        let Err(err) = decompress(blob.as_slice(), Limits::default()) else {
            return Err("unexpected decompression success".to_string());
        };
        check_eq(
            err.recognition_failure(),
            Some(crate::RecognitionFailure::Truncated),
            "error",
        )
    }

    #[test]
    fn rejects_advertised_size_above_limit() -> Result<(), String> {
        let mut blob = Vec::from(*MAGIC_EA06);
        blob.extend_from_slice(&2u32.to_be_bytes());

        let Err(err) = decompress(blob.as_slice(), Limits { max_output_size: 1 }) else {
            return Err("unexpected decompression success".to_string());
        };
        check_eq(
            err.recognition_failure(),
            Some(crate::RecognitionFailure::LimitExceeded),
            "error",
        )
    }

    fn pack_bits(bits: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        while cursor < bits.len() {
            let mut byte = 0u8;
            for bit_index in 0..8usize {
                let source_index = cursor
                    .checked_add(bit_index)
                    .ok_or_else(|| "bit offset overflow".to_string())?;
                let bit = bits
                    .get(source_index)
                    .copied()
                    .map_or(0, core::convert::identity);
                byte = (byte << 1) | bit;
            }
            out.push(byte);
            cursor = cursor
                .checked_add(8)
                .ok_or_else(|| "bit offset overflow".to_string())?;
        }
        Ok(out)
    }

    fn check_eq<T>(actual: T, expected: T, context: &str) -> Result<(), String>
    where
        T: core::fmt::Debug + PartialEq,
    {
        if actual == expected {
            Ok(())
        } else {
            Err(format!("{context}: got {actual:?}, expected {expected:?}"))
        }
    }
}
