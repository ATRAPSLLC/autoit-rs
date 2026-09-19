//! Raw string extraction over recovered payload bytes.

use crate::Record;

/// String extraction limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Minimum string length in Unicode scalar values.
    pub min_chars: usize,
    /// Maximum number of string findings to retain.
    pub max_findings: usize,
}

impl Default for Limits {
    /// Returns the default extraction limits.
    ///
    /// # Returns
    ///
    /// A [`Limits`] requiring at least 4 characters per string and retaining up to
    /// 4096 findings.
    fn default() -> Self {
        Self {
            min_chars: 4,
            max_findings: 4096,
        }
    }
}

/// A raw string found in recovered bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringFinding {
    record_index: usize,
    offset: usize,
    encoding: StringEncoding,
    value: String,
}

impl StringFinding {
    /// Returns the source record index.
    ///
    /// # Returns
    ///
    /// The index of the [`Record`] this string was extracted from.
    #[must_use]
    pub const fn record_index(&self) -> usize {
        self.record_index
    }

    /// Returns byte offset inside the record payload.
    ///
    /// # Returns
    ///
    /// The byte offset within the record payload where the string begins.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns string encoding used for extraction.
    ///
    /// # Returns
    ///
    /// The [`StringEncoding`] under which this string was extracted.
    #[must_use]
    pub const fn encoding(&self) -> StringEncoding {
        self.encoding
    }

    /// Returns extracted string value.
    ///
    /// # Returns
    ///
    /// The extracted string value.
    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
}

/// String encoding used for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// Printable ASCII byte string.
    Ascii,
    /// UTF-16 little-endian string with printable ASCII-range code units.
    Utf16Le,
}

/// Extracts raw strings from every recovered record payload.
///
/// Scans each record payload for both printable ASCII and UTF-16LE strings,
/// stopping early once `limits.max_findings` results are collected.
///
/// # Arguments
///
/// * `records` - Parsed AU3 records whose payloads are scanned.
/// * `limits` - Minimum string length and maximum finding count.
///
/// # Returns
///
/// A vector of [`StringFinding`] values, capped at `limits.max_findings`.
#[must_use]
pub fn extract_from_records(records: &[Record], limits: Limits) -> Vec<StringFinding> {
    let mut findings = Vec::new();
    for record in records {
        extract_ascii(record.index(), record.payload_data(), limits, &mut findings);
        if findings.len() >= limits.max_findings {
            return findings;
        }
        extract_utf16le(record.index(), record.payload_data(), limits, &mut findings);
        if findings.len() >= limits.max_findings {
            return findings;
        }
    }
    findings
}

/// Scans payload bytes for printable ASCII runs and appends findings.
///
/// Walks the bytes tracking the start of each printable run and flushes a finding
/// when a non-printable byte ends the run or the data is exhausted.
///
/// # Arguments
///
/// * `record_index` - Index of the source record, stored on each finding.
/// * `data` - Payload bytes to scan.
/// * `limits` - Minimum string length and maximum finding count.
/// * `findings` - Output vector that findings are appended to.
fn extract_ascii(
    record_index: usize,
    data: &[u8],
    limits: Limits,
    findings: &mut Vec<StringFinding>,
) {
    let mut start = None;
    for (index, byte) in data.iter().enumerate() {
        if is_ascii_string_byte(*byte) {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(offset) = start {
            push_ascii(record_index, data, offset, index, limits, findings);
            start = None;
        }
        if findings.len() >= limits.max_findings {
            return;
        }
    }
    if let Some(offset) = start {
        push_ascii(record_index, data, offset, data.len(), limits, findings);
    }
}

/// Pushes one ASCII finding for the byte range `start..end` when it qualifies.
///
/// The candidate is dropped when shorter than `limits.min_chars`, when the
/// finding cap is already reached, when the length arithmetic underflows, or when
/// the range is out of bounds.
///
/// # Arguments
///
/// * `record_index` - Index of the source record, stored on the finding.
/// * `data` - Payload bytes containing the candidate run.
/// * `start` - Inclusive start offset of the run.
/// * `end` - Exclusive end offset of the run.
/// * `limits` - Minimum string length and maximum finding count.
/// * `findings` - Output vector that the finding is appended to.
fn push_ascii(
    record_index: usize,
    data: &[u8],
    start: usize,
    end: usize,
    limits: Limits,
    findings: &mut Vec<StringFinding>,
) {
    let Some(len) = end.checked_sub(start) else {
        return;
    };
    if len < limits.min_chars || findings.len() >= limits.max_findings {
        return;
    }
    let Some(bytes) = data.get(start..end) else {
        return;
    };
    let value = String::from_utf8_lossy(bytes).into_owned();
    findings.push(StringFinding {
        record_index,
        offset: start,
        encoding: StringEncoding::Ascii,
        value,
    });
}

/// Scans payload bytes for printable UTF-16LE runs and appends findings.
///
/// Scans at both even and odd byte alignments so strings are found regardless of
/// their position, flushing a finding when a non-printable code unit ends a run
/// or the data is exhausted.
///
/// # Arguments
///
/// * `record_index` - Index of the source record, stored on each finding.
/// * `data` - Payload bytes to scan.
/// * `limits` - Minimum string length and maximum finding count.
/// * `findings` - Output vector that findings are appended to.
fn extract_utf16le(
    record_index: usize,
    data: &[u8],
    limits: Limits,
    findings: &mut Vec<StringFinding>,
) {
    for alignment in 0..2usize {
        let mut start = None;
        let mut cursor = alignment;
        while cursor.checked_add(1).is_some_and(|end| end < data.len()) {
            let Some(unit) = read_u16_at(data, cursor) else {
                return;
            };
            if is_utf16_string_unit(unit) {
                if start.is_none() {
                    start = Some(cursor);
                }
            } else if let Some(offset) = start {
                push_utf16(record_index, data, offset, cursor, limits, findings);
                start = None;
            }
            if findings.len() >= limits.max_findings {
                return;
            }
            let Some(next) = cursor.checked_add(2) else {
                return;
            };
            cursor = next;
        }
        if let Some(offset) = start {
            push_utf16(record_index, data, offset, cursor, limits, findings);
        }
    }
}

/// Pushes one UTF-16LE finding for the byte range `start..end` when it qualifies.
///
/// The candidate is dropped when its code-unit count is below `limits.min_chars`,
/// when the finding cap is already reached, when the length arithmetic
/// underflows, when the range is out of bounds, or when the bytes cannot be read
/// back as 16-bit units.
///
/// # Arguments
///
/// * `record_index` - Index of the source record, stored on the finding.
/// * `data` - Payload bytes containing the candidate run.
/// * `start` - Inclusive start byte offset of the run.
/// * `end` - Exclusive end byte offset of the run.
/// * `limits` - Minimum string length and maximum finding count.
/// * `findings` - Output vector that the finding is appended to.
fn push_utf16(
    record_index: usize,
    data: &[u8],
    start: usize,
    end: usize,
    limits: Limits,
    findings: &mut Vec<StringFinding>,
) {
    let Some(byte_len) = end.checked_sub(start) else {
        return;
    };
    let char_len = byte_len / 2;
    if char_len < limits.min_chars || findings.len() >= limits.max_findings {
        return;
    }
    let Some(bytes) = data.get(start..end) else {
        return;
    };
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    findings.push(StringFinding {
        record_index,
        offset: start,
        encoding: StringEncoding::Utf16Le,
        value: String::from_utf16_lossy(units.as_slice()),
    });
}

/// Reports whether a byte is treated as part of a printable ASCII string.
///
/// # Arguments
///
/// * `byte` - The byte to test.
///
/// # Returns
///
/// `true` for printable ASCII (`0x20..=0x7e`) or tab, `false` otherwise.
fn is_ascii_string_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t')
}

/// Reports whether a UTF-16 code unit is treated as part of a printable string.
///
/// # Arguments
///
/// * `unit` - The 16-bit code unit to test.
///
/// # Returns
///
/// `true` for printable ASCII-range units (`0x20..=0x7e`) or tab, `false`
/// otherwise.
fn is_utf16_string_unit(unit: u16) -> bool {
    matches!(unit, 0x20..=0x7e | 0x09)
}

/// Reads a little-endian `u16` from `data` at the given byte offset.
///
/// # Arguments
///
/// * `data` - The byte slice to read from.
/// * `offset` - Byte offset of the first byte of the 16-bit value.
///
/// # Returns
///
/// `Some` with the decoded `u16`, or `None` when the offset arithmetic overflows
/// or the two bytes lie outside `data`.
fn read_u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes: [u8; 2] = data.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::au3::{DecodedString, DecompressionStatus, RecordTestParts};

    #[test]
    fn extracts_ascii_and_utf16_strings() -> Result<(), String> {
        let mut payload = Vec::from(b"\0abcd\x01\x01".as_slice());
        for unit in "WXYZ".encode_utf16() {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
        payload.push(0);
        let record = test_record(payload)?;

        let findings = extract_from_records(
            &[record],
            Limits {
                min_chars: 4,
                max_findings: 8,
            },
        );

        check_eq(findings.len(), 2, "finding count")?;
        check_eq(
            findings.first().map(StringFinding::value),
            Some("abcd"),
            "ascii",
        )?;
        check_eq(
            findings.get(1).map(StringFinding::encoding),
            Some(StringEncoding::Utf16Le),
            "utf16 encoding",
        )?;
        check_eq(
            findings.get(1).map(StringFinding::value),
            Some("WXYZ"),
            "utf16",
        )
    }

    fn test_record(payload: Vec<u8>) -> Result<Record, String> {
        let payload_len = u32::try_from(payload.len()).map_err(|err| err.to_string())?;
        Ok(Record::from_parts_for_test(RecordTestParts {
            index: 3,
            offset: 0,
            subtype: DecodedString::from_text_for_test("artifact"),
            name: DecodedString::from_text_for_test("artifact.bin"),
            compressed: false,
            compressed_size: payload_len,
            uncompressed_size: payload_len,
            checksum: 0,
            checksum_valid: false,
            creation_time: 0,
            last_write_time: 0,
            encrypted_data: payload.clone(),
            decrypted_data: payload,
            decompressed_data: None,
            decompression_status: DecompressionStatus::NotCompressed,
            profile: crate::RecordProfile {
                encoding: crate::Encoding::Ea06,
                encryption: crate::EncryptionProfile::Ea06Lame,
                compression: crate::CompressionProfile::None,
            },
        }))
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
