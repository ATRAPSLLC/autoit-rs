//! Script recovery from AU3 records.

use crate::{Record, token};

const TOKENIZED_SCRIPT_SUBTYPE: &str = ">>>AUTOIT SCRIPT<<<";
const UNICODE_SCRIPT_SUBTYPE: &str = ">AUTOIT UNICODE SCRIPT<";
const PLAIN_SCRIPT_SUBTYPE: &str = ">AUTOIT SCRIPT<";
// AutoHotkey-classic (JB01) script subtypes; both store plain script text.
const AHK_SCRIPT_SUBTYPE: &str = ">AUTOHOTKEY SCRIPT<";
const AHK_WITH_ICON_SUBTYPE: &str = ">AHK WITH ICON<";

/// Recovered AutoIt script view.
#[derive(Debug, Clone, PartialEq)]
pub struct Script {
    record_index: usize,
    name: String,
    kind: ScriptKind,
    bytes: Vec<u8>,
    text: Option<ScriptText>,
    decode_error: Option<ScriptDecodeError>,
    token_stream: Option<token::TokenStream>,
    creation_time: u64,
    last_write_time: u64,
}

impl Script {
    /// Returns the source record index.
    ///
    /// # Returns
    ///
    /// The index of the [`Record`] this script was recovered from.
    #[must_use]
    pub const fn record_index(&self) -> usize {
        self.record_index
    }

    /// Returns the stored script name/path.
    ///
    /// # Returns
    ///
    /// The decoded name/path string of the source record.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the recovered script kind.
    ///
    /// # Returns
    ///
    /// The [`ScriptKind`] classifying how the script was recovered.
    #[must_use]
    pub const fn kind(&self) -> ScriptKind {
        self.kind
    }

    /// Returns raw recovered script bytes.
    ///
    /// # Returns
    ///
    /// The best available payload bytes for the source record, before any text
    /// decode.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Returns decoded script text when available.
    ///
    /// # Returns
    ///
    /// `Some` with the [`ScriptText`] when text was recovered, or `None` when
    /// decoding failed or was not attempted.
    #[must_use]
    pub const fn text(&self) -> Option<&ScriptText> {
        self.text.as_ref()
    }

    /// Returns text decode error details when text recovery failed.
    ///
    /// # Returns
    ///
    /// `Some` with the [`ScriptDecodeError`] when decoding failed, or `None`
    /// otherwise.
    #[must_use]
    pub const fn decode_error(&self) -> Option<ScriptDecodeError> {
        self.decode_error
    }

    /// Returns parsed token stream for tokenized scripts when available.
    ///
    /// # Returns
    ///
    /// `Some` with the [`token::TokenStream`] for a tokenized EA06 script, or
    /// `None` for other kinds or when token parsing failed.
    #[must_use]
    pub const fn token_stream(&self) -> Option<&token::TokenStream> {
        self.token_stream.as_ref()
    }

    /// Returns decoded source text when available.
    ///
    /// # Returns
    ///
    /// `Some` with the decoded text string when [`Self::text`] is present, or
    /// `None` otherwise.
    #[must_use]
    pub fn source_text(&self) -> Option<&str> {
        self.text.as_ref().map(ScriptText::text)
    }

    /// Returns the source record creation timestamp as raw Windows FILETIME.
    ///
    /// # Returns
    ///
    /// The raw 64-bit Windows FILETIME creation timestamp from the source record.
    #[must_use]
    pub const fn creation_time(&self) -> u64 {
        self.creation_time
    }

    /// Returns the source record last-write timestamp as raw Windows FILETIME.
    ///
    /// # Returns
    ///
    /// The raw 64-bit Windows FILETIME last-write timestamp from the source
    /// record.
    #[must_use]
    pub const fn last_write_time(&self) -> u64 {
        self.last_write_time
    }
}

/// Recovered script kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    /// Tokenized EA06 AutoIt script, detokenized to source-like text and a
    /// structured [`token::TokenStream`].
    Tokenized,
    /// UTF-16 script text.
    UnicodeText,
    /// Plain byte script text.
    PlainText,
}

/// Script text recovery error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptDecodeError {
    /// UTF-16LE bytes had an odd byte count.
    OddUtf16ByteLength,
    /// Token stream parsing failed.
    Token(token::TokenError),
}

/// Decoded script text plus decode mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptText {
    encoding: ScriptTextEncoding,
    text: String,
}

impl ScriptText {
    /// Returns the text encoding used for recovery.
    ///
    /// # Returns
    ///
    /// The [`ScriptTextEncoding`] describing how this text was decoded.
    #[must_use]
    pub const fn encoding(&self) -> ScriptTextEncoding {
        self.encoding
    }

    /// Returns decoded text.
    ///
    /// # Returns
    ///
    /// The recovered text string.
    #[must_use]
    pub fn text(&self) -> &str {
        self.text.as_str()
    }
}

/// Script text encoding used during recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptTextEncoding {
    /// UTF-8-compatible lossy decode.
    Utf8Lossy,
    /// UTF-16 little-endian lossy decode.
    Utf16LeLossy,
    /// Source-like rendering of tokenized AutoIt script bytes.
    TokenRender,
}

/// Recovers script records from parsed AU3 records.
///
/// # Arguments
///
/// * `records` - Parsed AU3 records to scan for script subtypes.
///
/// # Returns
///
/// A vector of [`Script`] views, one per record whose subtype is a recognized
/// script subtype; empty when none match.
#[must_use]
pub fn recover_scripts(records: &[Record]) -> Vec<Script> {
    records.iter().filter_map(recover_script).collect()
}

/// Recovers a single script from a record when its subtype is a script subtype.
///
/// Classifies the record by subtype, then decodes its payload accordingly:
/// tokenized EA06 scripts are detokenized into a token stream and source-like
/// text, UTF-16 scripts are lossily decoded, and plain scripts are lossily
/// decoded as UTF-8. Decode failures are preserved on the returned [`Script`]
/// rather than discarding the record.
///
/// # Arguments
///
/// * `record` - The AU3 record to classify and decode.
///
/// # Returns
///
/// `Some` with the recovered [`Script`] when the record subtype is a recognized
/// script subtype, or `None` otherwise.
fn recover_script(record: &Record) -> Option<Script> {
    let kind = match record.subtype() {
        TOKENIZED_SCRIPT_SUBTYPE => ScriptKind::Tokenized,
        UNICODE_SCRIPT_SUBTYPE => ScriptKind::UnicodeText,
        PLAIN_SCRIPT_SUBTYPE | AHK_SCRIPT_SUBTYPE | AHK_WITH_ICON_SUBTYPE => ScriptKind::PlainText,
        _ => return None,
    };
    let bytes = record.payload_data().to_vec();
    let mut token_stream = None;
    let (text, decode_error) = match kind {
        ScriptKind::Tokenized => match token::parse(bytes.as_slice()) {
            Ok(stream) => (
                {
                    let rendered = stream.render_source();
                    token_stream = Some(stream);
                    Some(ScriptText {
                        encoding: ScriptTextEncoding::TokenRender,
                        text: rendered,
                    })
                },
                None,
            ),
            Err(err) => (None, Some(ScriptDecodeError::Token(err))),
        },
        ScriptKind::UnicodeText => match decode_utf16_lossy(bytes.as_slice()) {
            Ok(text) => (
                Some(ScriptText {
                    encoding: ScriptTextEncoding::Utf16LeLossy,
                    text,
                }),
                None,
            ),
            Err(err) => (None, Some(err)),
        },
        ScriptKind::PlainText => (
            Some(ScriptText {
                encoding: ScriptTextEncoding::Utf8Lossy,
                text: String::from_utf8_lossy(bytes.as_slice()).into_owned(),
            }),
            None,
        ),
    };
    Some(Script {
        record_index: record.index(),
        name: record.name().to_string(),
        kind,
        bytes,
        text,
        decode_error,
        token_stream,
        creation_time: record.creation_time(),
        last_write_time: record.last_write_time(),
    })
}

/// Decodes little-endian UTF-16 bytes into a string with lossy replacement.
///
/// # Arguments
///
/// * `data` - The UTF-16LE byte sequence to decode.
///
/// # Returns
///
/// The decoded string, with unpaired surrogates replaced by U+FFFD.
///
/// # Errors
///
/// Returns [`ScriptDecodeError::OddUtf16ByteLength`] when `data` does not contain
/// a whole number of 16-bit code units.
fn decode_utf16_lossy(data: &[u8]) -> Result<String, ScriptDecodeError> {
    let chunks = data.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(ScriptDecodeError::OddUtf16ByteLength);
    }
    let code_units: Result<Vec<u16>, ScriptDecodeError> = chunks
        .map(|chunk| {
            let bytes: [u8; 2] = chunk
                .try_into()
                .map_err(|_err| ScriptDecodeError::OddUtf16ByteLength)?;
            Ok(u16::from_le_bytes(bytes))
        })
        .collect();
    Ok(String::from_utf16_lossy(code_units?.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::au3::{DecodedString, DecompressionStatus, RecordTestParts};

    #[test]
    fn recovers_plain_script_text() -> Result<(), String> {
        let record = test_record(">AUTOIT SCRIPT<", "main.au3", b"MsgBox(0, \"x\", \"y\")")?;
        let scripts = recover_scripts(&[record]);
        let script = scripts
            .first()
            .ok_or_else(|| "missing script".to_string())?;

        check_eq(script.record_index(), 7, "record index")?;
        check_eq(script.name(), "main.au3", "name")?;
        check_eq(script.kind(), ScriptKind::PlainText, "kind")?;
        check_eq(script.creation_time(), 13, "creation time")?;
        check_eq(script.last_write_time(), 17, "last-write time")?;
        check_eq(
            script.source_text(),
            Some("MsgBox(0, \"x\", \"y\")"),
            "text",
        )
    }

    #[test]
    fn recovers_utf16_script_text() -> Result<(), String> {
        let mut payload = Vec::new();
        for unit in "MsgBox(0, \"x\", \"y\")".encode_utf16() {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
        let record = test_record(">AUTOIT UNICODE SCRIPT<", "unicode.au3", payload.as_slice())?;
        let scripts = recover_scripts(&[record]);
        let script = scripts
            .first()
            .ok_or_else(|| "missing script".to_string())?;

        check_eq(script.kind(), ScriptKind::UnicodeText, "kind")?;
        check_eq(script.decode_error(), None, "decode error")?;
        check_eq(
            script.source_text(),
            Some("MsgBox(0, \"x\", \"y\")"),
            "text",
        )
    }

    #[test]
    fn preserves_tokenized_script_bytes_without_text() -> Result<(), String> {
        let tokenized = tokenized_assignment()?;
        let record = test_record(">>>AUTOIT SCRIPT<<<", "tokenized.au3", tokenized.as_slice())?;
        let scripts = recover_scripts(&[record]);
        let script = scripts
            .first()
            .ok_or_else(|| "missing script".to_string())?;

        check_eq(script.kind(), ScriptKind::Tokenized, "kind")?;
        check_eq(script.bytes(), tokenized.as_slice(), "bytes")?;
        check_eq(script.source_text(), Some("$x = 1\r\n"), "text")?;
        check_eq(script.token_stream().is_some(), true, "token stream")
    }

    #[test]
    fn renders_tokenized_msgbox_script() -> Result<(), String> {
        let tokenized = tokenized_msgbox()?;
        let record = test_record(">>>AUTOIT SCRIPT<<<", "msgbox.au3", tokenized.as_slice())?;
        let scripts = recover_scripts(&[record]);
        let script = scripts
            .first()
            .ok_or_else(|| "missing script".to_string())?;

        check_eq(script.kind(), ScriptKind::Tokenized, "kind")?;
        check_eq(
            script.source_text(),
            Some("MsgBox(0, \"title\", \"text\")\r\n"),
            "text",
        )
    }

    #[test]
    fn preserves_bad_utf16_script_bytes_with_decode_error() -> Result<(), String> {
        let record = test_record(">AUTOIT UNICODE SCRIPT<", "bad.au3", b"\xff")?;
        let scripts = recover_scripts(&[record]);
        let script = scripts
            .first()
            .ok_or_else(|| "missing script".to_string())?;

        check_eq(script.bytes(), b"\xff".as_slice(), "bytes")?;
        check_eq(script.source_text(), None, "text")?;
        check_eq(
            script.decode_error(),
            Some(ScriptDecodeError::OddUtf16ByteLength),
            "decode error",
        )
    }

    fn test_record(subtype: &str, name: &str, payload: &[u8]) -> Result<Record, String> {
        let payload_len = u32::try_from(payload.len()).map_err(|err| err.to_string())?;
        Ok(Record::from_parts_for_test(RecordTestParts {
            index: 7,
            offset: 11,
            subtype: DecodedString::from_text_for_test(subtype),
            name: DecodedString::from_text_for_test(name),
            compressed: false,
            compressed_size: payload_len,
            uncompressed_size: payload_len,
            checksum: 0,
            checksum_valid: false,
            creation_time: 13,
            last_write_time: 17,
            encrypted_data: payload.to_vec(),
            decrypted_data: payload.to_vec(),
            decompressed_data: None,
            decompression_status: DecompressionStatus::NotCompressed,
            profile: crate::RecordProfile {
                encoding: crate::Encoding::Ea06,
                encryption: crate::EncryptionProfile::Ea06Lame,
                compression: crate::CompressionProfile::None,
            },
        }))
    }

    fn tokenized_assignment() -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(0x33);
        append_xored_string(&mut data, "x")?;
        data.push(0x41);
        data.push(0x05);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(0x7f);
        Ok(data)
    }

    fn tokenized_msgbox() -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(0x01);
        data.extend_from_slice(&248i32.to_le_bytes());
        data.push(0x47);
        data.push(0x05);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(0x40);
        data.push(0x36);
        append_xored_string(&mut data, "title")?;
        data.push(0x40);
        data.push(0x36);
        append_xored_string(&mut data, "text")?;
        data.push(0x48);
        data.push(0x7f);
        Ok(data)
    }

    fn append_xored_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
        let units: Vec<u16> = value.encode_utf16().collect();
        let key = u32::try_from(units.len()).map_err(|err| err.to_string())?;
        out.extend_from_slice(&key.to_le_bytes());
        let key16 = u16::try_from(key).map_err(|err| err.to_string())?;
        for unit in units {
            out.extend_from_slice(&(unit ^ key16).to_le_bytes());
        }
        Ok(())
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
