//! AU3 compiled payload record parsing.

mod reader;

use crate::{Encoding, Error, RecognitionFailure, crypto, decompress};
use reader::Reader;

const FILE_MARKER_LEN: usize = 4;

/// Parser limits for AU3 record extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of records to parse.
    pub max_records: usize,
    /// Maximum encrypted blob size accepted for a single record.
    pub max_encrypted_blob_size: usize,
    /// Maximum decoded metadata string length in bytes.
    pub max_metadata_string_bytes: usize,
    /// Maximum decompressed blob size accepted for a single record.
    pub max_decompressed_blob_size: usize,
}

impl Default for Limits {
    /// Returns conservative default parser limits.
    ///
    /// Allows up to 256 records, 64 MiB per encrypted blob, 1 MiB per decoded
    /// metadata string, and 64 MiB per decompressed blob.
    ///
    /// # Returns
    ///
    /// A [`Limits`] populated with the default caps.
    fn default() -> Self {
        Self {
            max_records: 256,
            max_encrypted_blob_size: 64 * 1024 * 1024,
            max_metadata_string_bytes: 1024 * 1024,
            max_decompressed_blob_size: 64 * 1024 * 1024,
        }
    }
}

/// Decompression status for a record payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompressionStatus {
    /// The record was not marked compressed.
    NotCompressed,
    /// The record was marked compressed and decompressed successfully.
    Decompressed,
    /// The record was marked compressed but decompression failed.
    Failed {
        /// Structured reason for the decompression failure.
        reason: RecognitionFailure,
    },
}

/// Diagnostic produced when AU3 record parsing stops after partial recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordParseDiagnostic {
    /// Zero-based record index that failed to parse.
    pub record_index: usize,
    /// File offset where the failing record began, or where a configured limit
    /// stopped parsing.
    pub offset: usize,
    /// Structured reason parsing stopped.
    pub reason: RecognitionFailure,
}

/// Result of tolerant AU3 record parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordParseReport {
    records: Vec<Record>,
    diagnostic: Option<RecordParseDiagnostic>,
}

impl RecordParseReport {
    /// Returns the parsed records recovered before parsing stopped.
    ///
    /// # Returns
    ///
    /// A borrowed slice of the recovered [`Record`]s, in parse order.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        self.records.as_slice()
    }

    /// Consumes the report and returns the recovered records by value.
    ///
    /// # Returns
    ///
    /// The owned [`Record`] vector recovered before parsing stopped.
    #[must_use]
    pub fn into_records(self) -> Vec<Record> {
        self.records
    }

    /// Returns the diagnostic describing why parsing stopped, when present.
    ///
    /// # Returns
    ///
    /// `Some` with a [`RecordParseDiagnostic`] when parsing stopped on a failure or
    /// limit, or `None` when the stream ended cleanly at a non-`FILE` marker.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<RecordParseDiagnostic> {
        self.diagnostic
    }
}

/// Cryptographic stream used for record decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionProfile {
    /// EA05 Mersenne Twister-derived stream.
    Ea05Mt,
    /// EA06 LAME-derived stream.
    Ea06Lame,
}

/// Compression wrapper/profile observed for record data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionProfile {
    /// Record was not marked compressed.
    None,
    /// EA04 AutoIt LZ wrapper (same LZ scheme as EA05).
    Ea04,
    /// EA05 AutoIt LZ wrapper.
    Ea05,
    /// EA06 AutoIt LZ wrapper.
    Ea06,
    /// JB00 adaptive-Huffman wrapper (AutoHotkey-classic / AutoIt v2-era).
    Jb00,
    /// JB01 adaptive-Huffman wrapper (AutoHotkey-classic / AutoIt v2-era).
    Jb01,
    /// Record was marked compressed but wrapper magic was unrecognized or data
    /// was too short.
    Unknown,
}

/// Extraction profile facts for a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordProfile {
    /// AU3 encoding profile used for record metadata and payload decryption.
    pub encoding: Encoding,
    /// Cryptographic stream used for decryption.
    pub encryption: EncryptionProfile,
    /// Compression wrapper/profile observed for payload data.
    pub compression: CompressionProfile,
}

/// One AU3 resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    index: usize,
    offset: usize,
    subtype: DecodedString,
    name: DecodedString,
    compressed: bool,
    compressed_size: u32,
    uncompressed_size: u32,
    checksum: u32,
    checksum_valid: bool,
    creation_time: u64,
    last_write_time: u64,
    encrypted_data: Vec<u8>,
    decrypted_data: Vec<u8>,
    decompressed_data: Option<Vec<u8>>,
    decompression_status: DecompressionStatus,
    profile: RecordProfile,
}

impl Record {
    /// Returns the zero-based record index.
    ///
    /// # Returns
    ///
    /// The position of this record within the parsed stream.
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Returns the file offset where this record starts.
    ///
    /// # Returns
    ///
    /// The absolute byte offset of the record's `FILE` marker in the input.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the decoded subtype text.
    ///
    /// # Returns
    ///
    /// The record subtype as decoded text (e.g. the `>>>AUTOIT SCRIPT<<<` tag).
    #[must_use]
    pub fn subtype(&self) -> &str {
        self.subtype.text()
    }

    /// Returns the raw decrypted subtype bytes.
    ///
    /// # Returns
    ///
    /// The decrypted subtype bytes prior to text decoding.
    #[must_use]
    pub fn subtype_bytes(&self) -> &[u8] {
        self.subtype.bytes()
    }

    /// Returns the decoded stored name/path text.
    ///
    /// # Returns
    ///
    /// The record's stored name or path as decoded text.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.text()
    }

    /// Returns the raw decrypted name/path bytes.
    ///
    /// # Returns
    ///
    /// The decrypted name/path bytes prior to text decoding.
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        self.name.bytes()
    }

    /// Returns whether the record payload is marked compressed.
    ///
    /// # Returns
    ///
    /// `true` when the record's compression flag is set, `false` otherwise.
    #[must_use]
    pub const fn compressed(&self) -> bool {
        self.compressed
    }

    /// Returns the stored encrypted/compressed data size.
    ///
    /// # Returns
    ///
    /// The byte length of the on-disk encrypted (and possibly compressed) blob.
    #[must_use]
    pub const fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    /// Returns the advertised uncompressed data size.
    ///
    /// # Returns
    ///
    /// The uncompressed byte length declared in the record header.
    #[must_use]
    pub const fn uncompressed_size(&self) -> u32 {
        self.uncompressed_size
    }

    /// Returns the stored checksum value.
    ///
    /// For EA04/JB01 records, which carry no checksum field, this is `0`.
    ///
    /// # Returns
    ///
    /// The stored adler32 checksum (EA05/EA06), or `0` when absent (EA04/JB01).
    #[must_use]
    pub const fn checksum(&self) -> u32 {
        self.checksum
    }

    /// Returns whether the stored checksum matches the decrypted record data.
    ///
    /// EA04/JB01 records carry no checksum, so they are treated as validated and
    /// this returns `true`.
    ///
    /// # Returns
    ///
    /// `true` when the adler32 of the decrypted data matches the stored checksum,
    /// or when no checksum is present (EA04/JB01); `false` on mismatch.
    #[must_use]
    pub const fn checksum_valid(&self) -> bool {
        self.checksum_valid
    }

    /// Returns the creation timestamp as a raw Windows FILETIME.
    ///
    /// # Returns
    ///
    /// The record's creation time as a 64-bit Windows FILETIME value.
    #[must_use]
    pub const fn creation_time(&self) -> u64 {
        self.creation_time
    }

    /// Returns the last-write timestamp as a raw Windows FILETIME.
    ///
    /// # Returns
    ///
    /// The record's last-write time as a 64-bit Windows FILETIME value.
    #[must_use]
    pub const fn last_write_time(&self) -> u64 {
        self.last_write_time
    }

    /// Returns the encrypted record data bytes as stored on disk.
    ///
    /// # Returns
    ///
    /// The raw encrypted (and possibly compressed) payload bytes.
    #[must_use]
    pub fn encrypted_data(&self) -> &[u8] {
        self.encrypted_data.as_slice()
    }

    /// Returns the decrypted record data bytes.
    ///
    /// These are still in their compressed (wrapped) form when the record is marked
    /// compressed.
    ///
    /// # Returns
    ///
    /// The decrypted payload bytes, prior to any decompression.
    #[must_use]
    pub fn decrypted_data(&self) -> &[u8] {
        self.decrypted_data.as_slice()
    }

    /// Returns the decompressed record data bytes when decompression succeeded.
    ///
    /// # Returns
    ///
    /// `Some` with the decompressed bytes when the record was compressed and
    /// decompression succeeded, or `None` when the record was not compressed or
    /// decompression failed.
    #[must_use]
    pub fn decompressed_data(&self) -> Option<&[u8]> {
        self.decompressed_data.as_deref()
    }

    /// Returns the best available payload bytes.
    ///
    /// This is decompressed data when present, otherwise decrypted record data.
    ///
    /// # Returns
    ///
    /// The decompressed bytes when available, otherwise the decrypted bytes.
    #[must_use]
    pub fn payload_data(&self) -> &[u8] {
        match self.decompressed_data.as_deref() {
            Some(data) => data,
            None => self.decrypted_data.as_slice(),
        }
    }

    /// Returns the decompression status for this record.
    ///
    /// # Returns
    ///
    /// A [`DecompressionStatus`] describing whether the record was compressed and,
    /// if so, whether decompression succeeded.
    #[must_use]
    pub const fn decompression_status(&self) -> DecompressionStatus {
        self.decompression_status
    }

    /// Returns the extraction profile facts for this record.
    ///
    /// # Returns
    ///
    /// A [`RecordProfile`] describing the encoding, encryption stream, and
    /// compression wrapper observed for the record.
    #[must_use]
    pub const fn profile(&self) -> RecordProfile {
        self.profile
    }

    /// Builds a [`Record`] directly from explicit parts, for tests.
    ///
    /// Bypasses parsing so tests can construct records with arbitrary field values.
    ///
    /// # Arguments
    ///
    /// * `parts` - The [`RecordTestParts`] supplying every field of the record.
    ///
    /// # Returns
    ///
    /// A [`Record`] whose fields are taken verbatim from `parts`.
    #[cfg(test)]
    pub fn from_parts_for_test(parts: RecordTestParts) -> Self {
        Self {
            index: parts.index,
            offset: parts.offset,
            subtype: parts.subtype,
            name: parts.name,
            compressed: parts.compressed,
            compressed_size: parts.compressed_size,
            uncompressed_size: parts.uncompressed_size,
            checksum: parts.checksum,
            checksum_valid: parts.checksum_valid,
            creation_time: parts.creation_time,
            last_write_time: parts.last_write_time,
            encrypted_data: parts.encrypted_data,
            decrypted_data: parts.decrypted_data,
            decompressed_data: parts.decompressed_data,
            decompression_status: parts.decompression_status,
            profile: parts.profile,
        }
    }
}

/// Field values used to construct a [`Record`] directly in tests.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct RecordTestParts {
    /// Zero-based record index.
    pub index: usize,
    /// File offset where the record begins.
    pub offset: usize,
    /// Decoded subtype string.
    pub subtype: DecodedString,
    /// Decoded name/path string.
    pub name: DecodedString,
    /// Whether the payload is marked compressed.
    pub compressed: bool,
    /// Stored encrypted/compressed data size.
    pub compressed_size: u32,
    /// Advertised uncompressed data size.
    pub uncompressed_size: u32,
    /// Stored checksum value.
    pub checksum: u32,
    /// Whether the checksum was validated.
    pub checksum_valid: bool,
    /// Creation timestamp as raw Windows FILETIME.
    pub creation_time: u64,
    /// Last-write timestamp as raw Windows FILETIME.
    pub last_write_time: u64,
    /// Encrypted record data bytes.
    pub encrypted_data: Vec<u8>,
    /// Decrypted record data bytes.
    pub decrypted_data: Vec<u8>,
    /// Decompressed record data bytes, when present.
    pub decompressed_data: Option<Vec<u8>>,
    /// Decompression status for the record.
    pub decompression_status: DecompressionStatus,
    /// Extraction profile facts for the record.
    pub profile: RecordProfile,
}

/// Decoded string plus its raw decrypted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedString {
    raw: Vec<u8>,
    text: String,
}

impl DecodedString {
    /// Pairs raw decrypted bytes with their decoded text.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw decrypted string bytes.
    /// * `text` - The decoded text form of `raw`.
    ///
    /// # Returns
    ///
    /// A [`DecodedString`] holding both representations.
    fn new(raw: Vec<u8>, text: String) -> Self {
        Self { raw, text }
    }

    /// Builds a [`DecodedString`] from text, for tests.
    ///
    /// The raw bytes are taken as the UTF-8 encoding of `text`.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to wrap; its UTF-8 bytes become the raw bytes.
    ///
    /// # Returns
    ///
    /// A [`DecodedString`] whose text and raw bytes both derive from `text`.
    #[cfg(test)]
    pub fn from_text_for_test(text: &str) -> Self {
        Self {
            raw: text.as_bytes().to_vec(),
            text: text.to_string(),
        }
    }

    /// Returns the decoded text.
    ///
    /// # Returns
    ///
    /// The decoded text representation of the string.
    #[must_use]
    pub fn text(&self) -> &str {
        self.text.as_str()
    }

    /// Returns the raw decrypted string bytes.
    ///
    /// # Returns
    ///
    /// The decrypted bytes prior to text decoding.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.raw.as_slice()
    }
}

/// Per-encoding constants and behavior for decrypting and decoding records.
#[derive(Debug, Clone, Copy)]
struct Profile {
    /// AU3 encoding this profile applies to.
    encoding: Encoding,
    /// Decryption key for the `FILE` record marker.
    file_key: u32,
    /// XOR mask applied to the encoded subtype character length.
    subtype_len_xor: u32,
    /// Base decryption key for the subtype string (combined with its length).
    subtype_key_base: u32,
    /// XOR mask applied to the encoded name character length.
    name_len_xor: u32,
    /// Base decryption key for the name string (combined with its length).
    name_key_base: u32,
    /// XOR mask applied to the encoded compressed/uncompressed size fields.
    size_xor: u32,
    /// XOR mask applied to the encoded checksum field (unused when absent).
    checksum_xor: u32,
    /// Base value for deriving the payload data-decryption key.
    data_key_base: u32,
    /// Whether each record carries a 4-byte checksum field between the size
    /// fields and the timestamps. EA04 omits it; EA05/EA06 include it.
    has_checksum: bool,
}

impl Profile {
    /// Builds the decryption/decoding profile for an AU3 encoding.
    ///
    /// EA04 and JB01 share EA05's Mersenne Twister field keys but carry no
    /// per-record checksum field, so their `checksum_xor` is unused. EA06 uses its
    /// own LAME-derived key set.
    ///
    /// # Arguments
    ///
    /// * `encoding` - The AU3 encoding to build a profile for.
    ///
    /// # Returns
    ///
    /// A [`Profile`] holding the constants and flags for `encoding`.
    ///
    /// # Errors
    ///
    /// Currently infallible for all supported [`Encoding`] variants; the `Result`
    /// is retained for forward compatibility.
    fn for_encoding(encoding: Encoding) -> Result<Self, Error> {
        match encoding {
            // EA04 shares EA05's MT field keys but has no per-record checksum
            // field; `checksum_xor` is therefore unused.
            Encoding::Ea04 => Ok(Self {
                encoding,
                file_key: 0x16fa,
                subtype_len_xor: 0x29bc,
                subtype_key_base: 0xa25e,
                name_len_xor: 0x29ac,
                name_key_base: 0xf25e,
                size_xor: 0x45aa,
                checksum_xor: 0,
                data_key_base: 0x22af,
                has_checksum: false,
            }),
            Encoding::Ea05 => Ok(Self {
                encoding,
                file_key: 0x16fa,
                subtype_len_xor: 0x29bc,
                subtype_key_base: 0xa25e,
                name_len_xor: 0x29ac,
                name_key_base: 0xf25e,
                size_xor: 0x45aa,
                checksum_xor: 0xc3d2,
                data_key_base: 0x22af,
                has_checksum: true,
            }),
            Encoding::Ea06 => Ok(Self {
                encoding,
                file_key: 0x18ee,
                subtype_len_xor: 0xadbc,
                subtype_key_base: 0xb33f,
                name_len_xor: 0xf820,
                name_key_base: 0xf479,
                size_xor: 0x87bc,
                checksum_xor: 0xa685,
                data_key_base: 0x2477,
                has_checksum: true,
            }),
            // JB01 (AutoHotkey-classic / AutoIt v2-era) shares EA05's MT field
            // keys and EA04's checksum-less record layout.
            Encoding::Jb01 => Ok(Self {
                encoding,
                file_key: 0x16fa,
                subtype_len_xor: 0x29bc,
                subtype_key_base: 0xa25e,
                name_len_xor: 0x29ac,
                name_key_base: 0xf25e,
                size_xor: 0x45aa,
                checksum_xor: 0,
                data_key_base: 0x22af,
                has_checksum: false,
            }),
        }
    }

    /// Decrypts a byte slice using this profile's cipher and a key.
    ///
    /// EA04/EA05/JB01 use the Mersenne Twister stream cipher; EA06 uses the LAME
    /// stream cipher.
    ///
    /// # Arguments
    ///
    /// * `data` - The encrypted bytes to decrypt.
    /// * `key` - The seed key for the stream cipher.
    ///
    /// # Returns
    ///
    /// The decrypted bytes on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::crypto_mismatch`] when the underlying cipher rejects the
    /// input (e.g. the keystream cannot be derived for the given input).
    fn decrypt(self, data: &[u8], key: u32) -> Result<Vec<u8>, Error> {
        match self.encoding {
            Encoding::Ea04 | Encoding::Ea05 | Encoding::Jb01 => {
                crypto::mt::decrypt(data, key).ok_or_else(Error::crypto_mismatch)
            }
            Encoding::Ea06 => crypto::lame::decrypt(data, key).ok_or_else(Error::crypto_mismatch),
        }
    }

    /// Returns the byte width of one metadata-string character for this encoding.
    ///
    /// EA04/EA05/JB01 store single-byte characters; EA06 stores UTF-16 code units.
    ///
    /// # Returns
    ///
    /// `1` for single-byte encodings, `2` for the UTF-16 EA06 encoding.
    fn character_width(self) -> usize {
        match self.encoding {
            Encoding::Ea04 | Encoding::Ea05 | Encoding::Jb01 => 1,
            Encoding::Ea06 => 2,
        }
    }

    /// Returns the cryptographic stream identifier for this encoding.
    ///
    /// # Returns
    ///
    /// [`EncryptionProfile::Ea05Mt`] for EA04/EA05/JB01, or
    /// [`EncryptionProfile::Ea06Lame`] for EA06.
    fn encryption_profile(self) -> EncryptionProfile {
        match self.encoding {
            Encoding::Ea04 | Encoding::Ea05 | Encoding::Jb01 => EncryptionProfile::Ea05Mt,
            Encoding::Ea06 => EncryptionProfile::Ea06Lame,
        }
    }

    /// Derives the payload data-decryption key for this encoding.
    ///
    /// For EA04/EA05/JB01 the key is the data-key base plus the salt/checksum
    /// (wrapping); EA06 ignores the salt and uses the data-key base directly.
    ///
    /// # Arguments
    ///
    /// * `checksum` - The per-stream salt value (the EA05 data-key salt) folded
    ///   into the key for MT-based encodings; ignored for EA06.
    ///
    /// # Returns
    ///
    /// The seed key used to decrypt the record payload.
    fn data_key(self, checksum: u32) -> u32 {
        match self.encoding {
            Encoding::Ea04 | Encoding::Ea05 | Encoding::Jb01 => {
                checksum.wrapping_add(self.data_key_base)
            }
            Encoding::Ea06 => self.data_key_base,
        }
    }
}

/// Parses AU3 records from `offset`, strictly failing on any partial-parse stop.
///
/// Parsing stops normally when the next record marker does not decrypt to
/// `FILE`. If no `FILE` marker is present at `offset`, this returns an empty
/// vector. Unlike [`parse_records_partial`], any diagnostic recorded mid-stream
/// is converted into an error and the recovered records are discarded.
///
/// # Arguments
///
/// * `data` - The full input buffer to parse from.
/// * `offset` - Absolute offset of the first record.
/// * `encoding` - The AU3 [`Encoding`] to interpret records with.
/// * `limits` - Parser [`Limits`] bounding record count and blob sizes.
///
/// # Returns
///
/// The fully parsed [`Record`] vector, empty when no `FILE` marker is present.
///
/// # Errors
///
/// Propagates the encoding-profiling error for an unsupported encoding, and
/// converts any partial-parse diagnostic into the matching [`Error`] - including
/// [`Error::truncated`], [`Error::crypto_mismatch`], [`Error::compression_error`],
/// or [`Error::limit_exceeded`] when the configured limits are reached.
pub fn parse_records(
    data: &[u8],
    offset: usize,
    encoding: Encoding,
    limits: Limits,
) -> Result<Vec<Record>, Error> {
    let report = parse_records_partial(data, offset, encoding, limits)?;
    if let Some(diagnostic) = report.diagnostic() {
        return Err(error_from_failure(diagnostic.reason));
    }
    Ok(report.into_records())
}

/// Parses AU3 records from `offset`, tolerantly preserving records recovered
/// before a later parse failure.
///
/// Parsing stops normally when the next record marker does not decrypt to
/// `FILE`. If no `FILE` marker is present at `offset`, this returns an empty
/// report without a diagnostic. A failure while parsing a record, or reaching
/// the `max_records` limit, is reported as a [`RecordParseDiagnostic`] on the
/// returned report rather than as an `Err`, keeping the earlier records.
///
/// The EA05 data-key salt is computed once from the 16 bytes preceding the
/// record stream and reused for every record; EA04/JB01 use a salt of `0` and
/// EA06 ignores the salt entirely.
///
/// # Arguments
///
/// * `data` - The full input buffer to parse from.
/// * `offset` - Absolute offset of the first record.
/// * `encoding` - The AU3 [`Encoding`] to interpret records with.
/// * `limits` - Parser [`Limits`] bounding record count and blob sizes.
///
/// # Returns
///
/// A [`RecordParseReport`] holding the recovered records and, when parsing
/// stopped on a failure or limit, a [`RecordParseDiagnostic`].
///
/// # Errors
///
/// Returns an error when the encoding cannot be profiled. Per-record parse
/// failures are not returned as `Err`; they are captured in the report's
/// diagnostic instead.
pub fn parse_records_partial(
    data: &[u8],
    offset: usize,
    encoding: Encoding,
    limits: Limits,
) -> Result<RecordParseReport, Error> {
    let profile = Profile::for_encoding(encoding)?;
    let mut reader = Reader::new(data, offset);
    let mut records = Vec::new();

    // The EA05 data-decryption key salt is the byte sum of the 16 bytes that
    // precede the record stream. It is fixed for the whole stream, so compute
    // it once from the first record offset and reuse it for every record.
    // (EA06 ignores the salt entirely; see `Profile::data_key`.)
    //
    // EA04 derives its salt from the signed byte sum of the compiled-in
    // passphrase hash, which is empty (sum 0) for password-free scripts; only
    // those are supported here, so the salt is 0.
    let data_key_salt = match encoding {
        Encoding::Ea04 | Encoding::Jb01 => 0,
        _ => ea05_data_key_salt(&reader, offset),
    };

    while records.len() < limits.max_records {
        let index = records.len();
        let record_offset = reader.position();
        let parse_result = parse_one(&mut reader, profile, index, limits, data_key_salt);
        let Some(record) = (match parse_result {
            Ok(record) => record,
            Err(err) => {
                return Ok(RecordParseReport {
                    records,
                    diagnostic: Some(RecordParseDiagnostic {
                        record_index: index,
                        offset: record_offset,
                        reason: failure_from_error(&err),
                    }),
                });
            }
        }) else {
            return Ok(RecordParseReport {
                records,
                diagnostic: None,
            });
        };
        records.push(record);
    }

    Ok(RecordParseReport {
        records,
        diagnostic: Some(RecordParseDiagnostic {
            record_index: limits.max_records,
            offset: reader.position(),
            reason: RecognitionFailure::LimitExceeded,
        }),
    })
}

/// Maps an [`Error`] to the [`RecognitionFailure`] recorded in a diagnostic.
///
/// Errors without an associated recognition failure are reported as
/// [`RecognitionFailure::MalformedContainer`].
///
/// # Arguments
///
/// * `err` - The error to classify.
///
/// # Returns
///
/// The structured [`RecognitionFailure`] for `err`.
fn failure_from_error(err: &Error) -> RecognitionFailure {
    match err.recognition_failure() {
        Some(reason) => reason,
        None => RecognitionFailure::MalformedContainer,
    }
}

/// Maps a [`RecognitionFailure`] back to its corresponding [`Error`].
///
/// Inverse of [`failure_from_error`], used by [`parse_records`] to turn a
/// diagnostic into a strict error.
///
/// # Arguments
///
/// * `failure` - The structured failure to convert.
///
/// # Returns
///
/// The [`Error`] constructed for `failure` (e.g. [`Error::truncated`],
/// [`Error::limit_exceeded`], or [`Error::crypto_mismatch`]).
fn error_from_failure(failure: RecognitionFailure) -> Error {
    match failure {
        RecognitionFailure::NotRecognized => Error::not_recognized(),
        RecognitionFailure::UnsupportedEncoding => Error::unsupported_encoding(),
        RecognitionFailure::MalformedContainer => Error::malformed_container(),
        RecognitionFailure::Truncated => Error::truncated(),
        RecognitionFailure::LimitExceeded => Error::limit_exceeded(),
        RecognitionFailure::CryptoMismatch => Error::crypto_mismatch(),
        RecognitionFailure::CompressionError => Error::compression_error(),
        RecognitionFailure::TokenError => Error::token_error(),
    }
}

/// Parses a single AU3 record at the reader's current position.
///
/// Reads and decrypts the `FILE` marker, the subtype and name strings, the
/// size/checksum/timestamp header, and the encrypted payload. EA05/EA06 verify
/// an Adler-32 checksum against the decrypted data; EA04/JB01 have no checksum
/// field and are treated as integrity-validated. The payload is decompressed
/// when the record's compressed flag is set.
///
/// # Arguments
///
/// * `reader` - The [`Reader`] positioned at the start of the record.
/// * `profile` - The encoding [`Profile`] supplying keys and layout flags.
/// * `index` - The zero-based index to assign to the parsed record.
/// * `limits` - Parser [`Limits`] bounding string and blob sizes.
/// * `data_key_salt` - The per-stream salt folded into the payload data key.
///
/// # Returns
///
/// `Some` with the parsed [`Record`] when a `FILE` marker is present, or `None`
/// when the reader is exhausted or the next marker does not decrypt to `FILE`
/// (signalling a clean end of stream).
///
/// # Errors
///
/// Returns [`Error::truncated`] when the input ends mid-record,
/// [`Error::crypto_mismatch`] when decryption fails, [`Error::limit_exceeded`]
/// when a size exceeds the configured limits or overflows `usize`, and the
/// errors propagated from [`read_string`] and [`Profile::decrypt`].
fn parse_one(
    reader: &mut Reader<'_>,
    profile: Profile,
    index: usize,
    limits: Limits,
    data_key_salt: u32,
) -> Result<Option<Record>, Error> {
    if reader.remaining() == 0 {
        return Ok(None);
    }
    let offset = reader.position();
    let marker = reader.read_bytes(FILE_MARKER_LEN)?;
    let decrypted_marker = profile.decrypt(marker, profile.file_key)?;
    if decrypted_marker != b"FILE" {
        return Ok(None);
    }

    let subtype_len = reader.read_u32_le()? ^ profile.subtype_len_xor;
    let subtype = read_string(
        reader,
        profile,
        subtype_len,
        profile.subtype_key_base,
        limits.max_metadata_string_bytes,
    )?;

    let name_len = reader.read_u32_le()? ^ profile.name_len_xor;
    let name = read_string(
        reader,
        profile,
        name_len,
        profile.name_key_base,
        limits.max_metadata_string_bytes,
    )?;

    let compressed = reader.read_u8()? != 0;
    let compressed_size = reader.read_u32_le()? ^ profile.size_xor;
    let uncompressed_size = reader.read_u32_le()? ^ profile.size_xor;
    // EA04 records have no checksum field; EA05/EA06 store an Adler-32 here.
    let checksum = if profile.has_checksum {
        reader.read_u32_le()? ^ profile.checksum_xor
    } else {
        0
    };
    let creation_time = reader.read_u64_le()?;
    let last_write_time = reader.read_u64_le()?;

    let encrypted_len = usize::try_from(compressed_size).map_err(|_err| Error::limit_exceeded())?;
    if encrypted_len > limits.max_encrypted_blob_size {
        return Err(Error::limit_exceeded());
    }
    let encrypted_data = reader.read_bytes(encrypted_len)?.to_vec();
    let decrypted_data =
        profile.decrypt(encrypted_data.as_slice(), profile.data_key(data_key_salt))?;
    // Without a stored checksum (EA04) there is nothing to fail against, so the
    // record is treated as integrity-validated.
    let checksum_valid = !profile.has_checksum
        || adler32(decrypted_data.as_slice()).is_some_and(|actual| actual == checksum);
    let (decompressed_data, decompression_status) = maybe_decompress(
        decrypted_data.as_slice(),
        compressed,
        limits.max_decompressed_blob_size,
    );
    let record_profile = RecordProfile {
        encoding: profile.encoding,
        encryption: profile.encryption_profile(),
        compression: compression_profile(decrypted_data.as_slice(), compressed),
    };

    Ok(Some(Record {
        index,
        offset,
        subtype,
        name,
        compressed,
        compressed_size,
        uncompressed_size,
        checksum,
        checksum_valid,
        creation_time,
        last_write_time,
        encrypted_data,
        decrypted_data,
        decompressed_data,
        decompression_status,
        profile: record_profile,
    }))
}

/// Decompresses record data when it is marked compressed.
///
/// When `compressed` is false this is a no-op. Otherwise the data is passed to
/// the decompressor; a failure is mapped to its [`RecognitionFailure`] (defaulting
/// to [`RecognitionFailure::CompressionError`] when none is associated) and
/// surfaced via [`DecompressionStatus::Failed`] rather than returned as an error.
///
/// # Arguments
///
/// * `data` - The decrypted (possibly compressed) payload bytes.
/// * `compressed` - Whether the record was marked compressed.
/// * `max_output_size` - Maximum allowed decompressed size.
///
/// # Returns
///
/// A tuple of the optional decompressed bytes and the resulting
/// [`DecompressionStatus`].
fn maybe_decompress(
    data: &[u8],
    compressed: bool,
    max_output_size: usize,
) -> (Option<Vec<u8>>, DecompressionStatus) {
    if !compressed {
        return (None, DecompressionStatus::NotCompressed);
    }
    match decompress::decompress(data, decompress::Limits { max_output_size }) {
        Ok(bytes) => (Some(bytes), DecompressionStatus::Decompressed),
        Err(err) => {
            let reason = match err.recognition_failure() {
                Some(reason) => reason,
                None => RecognitionFailure::CompressionError,
            };
            (None, DecompressionStatus::Failed { reason })
        }
    }
}

/// Computes the EA05 payload data-key salt from bytes preceding the record stream.
///
/// The salt is the unsigned byte sum of the 16 bytes immediately before the first
/// record, but only when an `EA05` marker sits in the four bytes just before those
/// 16. It is fixed for the whole stream, so it is computed once and reused.
///
/// # Arguments
///
/// * `reader` - The [`Reader`] over the input, used for bounds-checked range reads.
/// * `record_offset` - Absolute offset of the first record.
///
/// # Returns
///
/// The byte-sum salt, or `0` when the preceding `EA05` marker or salt bytes are
/// absent or out of bounds.
fn ea05_data_key_salt(reader: &Reader<'_>, record_offset: usize) -> u32 {
    let Some(marker_start) = record_offset.checked_sub(20) else {
        return 0;
    };
    let Some(marker_end) = marker_start.checked_add(4) else {
        return 0;
    };
    if reader.range(marker_start, marker_end) != Some(b"EA05") {
        return 0;
    }
    let Some(salt_start) = record_offset.checked_sub(16) else {
        return 0;
    };
    reader
        .range(salt_start, record_offset)
        .map_or(0, |bytes| bytes.iter().map(|byte| u32::from(*byte)).sum())
}

/// Identifies the compression wrapper from the decrypted payload's leading magic.
///
/// Inspects the first four bytes for a known wrapper magic (`EA04`, `EA05`,
/// `EA06`, `JB00`, `JB01`). An unrecognized or too-short magic on a record marked
/// compressed yields [`CompressionProfile::Unknown`].
///
/// # Arguments
///
/// * `data` - The decrypted payload bytes.
/// * `compressed` - Whether the record was marked compressed.
///
/// # Returns
///
/// The matching [`CompressionProfile`]; [`CompressionProfile::None`] when the
/// record is not compressed.
fn compression_profile(data: &[u8], compressed: bool) -> CompressionProfile {
    if !compressed {
        return CompressionProfile::None;
    }
    match data.get(0..4) {
        Some(magic) if magic == b"EA04" => CompressionProfile::Ea04,
        Some(magic) if magic == b"EA05" => CompressionProfile::Ea05,
        Some(magic) if magic == b"EA06" => CompressionProfile::Ea06,
        Some(magic) if magic == b"JB00" => CompressionProfile::Jb00,
        Some(magic) if magic == b"JB01" => CompressionProfile::Jb01,
        _ => CompressionProfile::Unknown,
    }
}

/// Reads, decrypts, and decodes a length-prefixed metadata string.
///
/// The byte length is `char_len` times the encoding's character width. The
/// decryption key is `key_base` plus `char_len` (wrapping). EA04/EA05/JB01 decode
/// the bytes as lossy UTF-8; EA06 decodes them as lossy UTF-16.
///
/// # Arguments
///
/// * `reader` - The [`Reader`] positioned at the encrypted string bytes.
/// * `profile` - The encoding [`Profile`] supplying the cipher and character width.
/// * `char_len` - The character count (already XOR-decoded) of the string.
/// * `key_base` - The base decryption key, combined with `char_len`.
/// * `max_bytes` - Maximum allowed decoded byte length.
///
/// # Returns
///
/// A [`DecodedString`] holding the raw decrypted bytes and decoded text.
///
/// # Errors
///
/// Returns [`Error::limit_exceeded`] when the byte length overflows `usize` or
/// exceeds `max_bytes`, [`Error::truncated`] when the input ends early, the error
/// from [`Profile::decrypt`] on a crypto failure, and the [`decode_utf16_lossy`]
/// error for malformed EA06 UTF-16 lengths.
fn read_string(
    reader: &mut Reader<'_>,
    profile: Profile,
    char_len: u32,
    key_base: u32,
    max_bytes: usize,
) -> Result<DecodedString, Error> {
    let chars = usize::try_from(char_len).map_err(|_err| Error::limit_exceeded())?;
    let byte_len = chars
        .checked_mul(profile.character_width())
        .ok_or_else(Error::limit_exceeded)?;
    if byte_len > max_bytes {
        return Err(Error::limit_exceeded());
    }
    let encrypted = reader.read_bytes(byte_len)?;
    let key = key_base.wrapping_add(char_len);
    let raw = profile.decrypt(encrypted, key)?;
    let text = match profile.encoding {
        Encoding::Ea04 | Encoding::Ea05 | Encoding::Jb01 => {
            String::from_utf8_lossy(raw.as_slice()).into_owned()
        }
        Encoding::Ea06 => decode_utf16_lossy(raw.as_slice())?,
    };
    Ok(DecodedString::new(raw, text))
}

/// Decodes little-endian UTF-16 bytes into a string, replacing invalid units.
///
/// # Arguments
///
/// * `data` - The UTF-16LE bytes to decode; its length must be even.
///
/// # Returns
///
/// The decoded string, with unpaired surrogates replaced by U+FFFD.
///
/// # Errors
///
/// Returns [`Error::truncated`] when `data` has an odd number of bytes (a
/// dangling half code unit).
fn decode_utf16_lossy(data: &[u8]) -> Result<String, Error> {
    let (chunks, remainder) = data.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(Error::truncated());
    }
    let code_units: Vec<u16> = chunks
        .iter()
        .map(|&bytes| u16::from_le_bytes(bytes))
        .collect();
    Ok(String::from_utf16_lossy(code_units.as_slice()))
}

/// Computes the Adler-32 checksum of a byte slice.
///
/// Used to validate EA05/EA06 record payloads against their stored checksum. The
/// two running sums are reduced modulo 65521 and combined as `(b << 16) | a`.
///
/// # Arguments
///
/// * `data` - The bytes to checksum.
///
/// # Returns
///
/// `Some` with the Adler-32 value, or `None` if an internal accumulator addition
/// would overflow.
fn adler32(data: &[u8]) -> Option<u32> {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = a.checked_add(u32::from(*byte))? % MOD_ADLER;
        b = b.checked_add(a)? % MOD_ADLER;
    }
    Some((b << 16) | a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ea06_record() -> Result<(), String> {
        let mut data = Vec::new();
        append_ea06_record(
            &mut data,
            ">>>AUTOIT SCRIPT<<<",
            "main.au3",
            false,
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            b"payload",
        )?;

        let records = parse_records(data.as_slice(), 0, Encoding::Ea06, Limits::default())
            .map_err(|err| err.to_string())?;
        let record = records
            .first()
            .ok_or_else(|| "missing first record".to_string())?;

        check_eq(records.len(), 1, "record count")?;
        check_eq(record.index(), 0, "record index")?;
        check_eq(record.offset(), 0, "record offset")?;
        check_eq(record.subtype(), ">>>AUTOIT SCRIPT<<<", "subtype")?;
        check_eq(record.name(), "main.au3", "name")?;
        check_eq(record.compressed(), false, "compressed")?;
        check_eq(record.compressed_size(), 7, "compressed size")?;
        check_eq(record.uncompressed_size(), 7, "uncompressed size")?;
        check_eq(record.checksum_valid(), true, "checksum")?;
        check_eq(record.creation_time(), 0x0102_0304_0506_0708, "created")?;
        check_eq(record.last_write_time(), 0x1112_1314_1516_1718, "modified")?;
        check_eq(
            record.profile(),
            RecordProfile {
                encoding: Encoding::Ea06,
                encryption: EncryptionProfile::Ea06Lame,
                compression: CompressionProfile::None,
            },
            "profile",
        )?;
        check_eq(record.decrypted_data(), b"payload".as_slice(), "data")
    }

    #[test]
    fn parses_ea05_record() -> Result<(), String> {
        let mut data = Vec::new();
        append_ea05_record(
            &mut data,
            ">AUTOIT SCRIPT<",
            "legacy.au3",
            false,
            0,
            0,
            b"legacy",
        )?;

        let records = parse_records(data.as_slice(), 0, Encoding::Ea05, Limits::default())
            .map_err(|err| err.to_string())?;
        let record = records
            .first()
            .ok_or_else(|| "missing first record".to_string())?;

        check_eq(records.len(), 1, "record count")?;
        check_eq(record.subtype(), ">AUTOIT SCRIPT<", "subtype")?;
        check_eq(record.name(), "legacy.au3", "name")?;
        check_eq(record.compressed(), false, "compressed")?;
        check_eq(record.checksum_valid(), true, "checksum")?;
        check_eq(
            record.profile(),
            RecordProfile {
                encoding: Encoding::Ea05,
                encryption: EncryptionProfile::Ea05Mt,
                compression: CompressionProfile::None,
            },
            "profile",
        )?;
        check_eq(record.decrypted_data(), b"legacy".as_slice(), "data")
    }

    #[test]
    fn stores_decompressed_payload_for_compressed_record() -> Result<(), String> {
        let compressed = ea06_literal_blob(b"ABC")?;
        let mut data = Vec::new();
        append_ea06_record(
            &mut data,
            ">AUTOIT SCRIPT<",
            "compressed.au3",
            true,
            0,
            0,
            compressed.as_slice(),
        )?;

        let records = parse_records(data.as_slice(), 0, Encoding::Ea06, Limits::default())
            .map_err(|err| err.to_string())?;
        let record = records
            .first()
            .ok_or_else(|| "missing first record".to_string())?;

        check_eq(
            record.decompression_status(),
            DecompressionStatus::Decompressed,
            "decompression status",
        )?;
        check_eq(
            record.decompressed_data(),
            Some(b"ABC".as_slice()),
            "decompressed data",
        )?;
        check_eq(
            record.profile().compression,
            CompressionProfile::Ea06,
            "compression profile",
        )?;
        check_eq(record.payload_data(), b"ABC".as_slice(), "payload data")
    }

    #[test]
    fn partial_parser_preserves_records_before_truncated_record() -> Result<(), String> {
        let mut data = Vec::new();
        append_ea06_record(&mut data, ">AUTOIT SCRIPT<", "ok.au3", false, 0, 0, b"ok")?;
        let truncated_offset = data.len();
        append_encrypted(&mut data, b"FILE", Encoding::Ea06, 0x18ee)?;

        let report = parse_records_partial(data.as_slice(), 0, Encoding::Ea06, Limits::default())
            .map_err(|err| err.to_string())?;

        check_eq(report.records().len(), 1, "record count")?;
        check_eq(
            report.diagnostic(),
            Some(RecordParseDiagnostic {
                record_index: 1,
                offset: truncated_offset,
                reason: RecognitionFailure::Truncated,
            }),
            "diagnostic",
        )?;

        let Err(err) = parse_records(data.as_slice(), 0, Encoding::Ea06, Limits::default()) else {
            return Err("strict parser unexpectedly succeeded".to_string());
        };
        check_eq(
            err.recognition_failure(),
            Some(RecognitionFailure::Truncated),
            "strict error",
        )
    }

    fn append_ea06_record(
        out: &mut Vec<u8>,
        subtype: &str,
        name: &str,
        compressed: bool,
        creation_time: u64,
        last_write_time: u64,
        data: &[u8],
    ) -> Result<(), String> {
        append_encrypted(out, b"FILE", Encoding::Ea06, 0x18ee)?;
        append_xored_u32(out, utf16_len(subtype)?, 0xadbc);
        append_encrypted_utf16(out, subtype, 0xb33f)?;
        append_xored_u32(out, utf16_len(name)?, 0xf820);
        append_encrypted_utf16(out, name, 0xf479)?;
        out.push(if compressed { 1 } else { 0 });
        let data_len = u32::try_from(data.len()).map_err(|err| err.to_string())?;
        append_xored_u32(out, data_len, 0x87bc);
        append_xored_u32(out, data_len, 0x87bc);
        append_xored_u32(
            out,
            adler32(data).ok_or_else(|| "adler failed".to_string())?,
            0xa685,
        );
        append_u64(out, creation_time);
        append_u64(out, last_write_time);
        append_encrypted(out, data, Encoding::Ea06, 0x2477)
    }

    fn ea06_literal_blob(data: &[u8]) -> Result<Vec<u8>, String> {
        let mut blob = Vec::from(*b"EA06");
        let len = u32::try_from(data.len()).map_err(|err| err.to_string())?;
        blob.extend_from_slice(&len.to_be_bytes());
        let mut bits = Vec::new();
        for byte in data {
            bits.push(1);
            for shift in (0..8u8).rev() {
                bits.push((byte >> shift) & 1);
            }
        }
        blob.extend_from_slice(pack_bits(bits.as_slice())?.as_slice());
        Ok(blob)
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
                let bit = bits.get(source_index).copied().unwrap_or(0);
                byte = (byte << 1) | bit;
            }
            out.push(byte);
            cursor = cursor
                .checked_add(8)
                .ok_or_else(|| "bit offset overflow".to_string())?;
        }
        Ok(out)
    }

    fn append_ea05_record(
        out: &mut Vec<u8>,
        subtype: &str,
        name: &str,
        compressed: bool,
        creation_time: u64,
        last_write_time: u64,
        data: &[u8],
    ) -> Result<(), String> {
        append_encrypted(out, b"FILE", Encoding::Ea05, 0x16fa)?;
        append_xored_u32(out, byte_len(subtype)?, 0x29bc);
        append_encrypted(
            out,
            subtype.as_bytes(),
            Encoding::Ea05,
            0xa25e_u32.wrapping_add(byte_len(subtype)?),
        )?;
        append_xored_u32(out, byte_len(name)?, 0x29ac);
        append_encrypted(
            out,
            name.as_bytes(),
            Encoding::Ea05,
            0xf25e_u32.wrapping_add(byte_len(name)?),
        )?;
        out.push(if compressed { 1 } else { 0 });
        let data_len = u32::try_from(data.len()).map_err(|err| err.to_string())?;
        append_xored_u32(out, data_len, 0x45aa);
        append_xored_u32(out, data_len, 0x45aa);
        append_xored_u32(
            out,
            adler32(data).ok_or_else(|| "adler failed".to_string())?,
            0xc3d2,
        );
        append_u64(out, creation_time);
        append_u64(out, last_write_time);
        append_encrypted(out, data, Encoding::Ea05, 0x22af)
    }

    fn append_encrypted_utf16(out: &mut Vec<u8>, value: &str, key_base: u32) -> Result<(), String> {
        let char_len = utf16_len(value)?;
        let key = key_base.wrapping_add(char_len);
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        append_encrypted(out, bytes.as_slice(), Encoding::Ea06, key)
    }

    fn append_encrypted(
        out: &mut Vec<u8>,
        plain: &[u8],
        encoding: Encoding,
        key: u32,
    ) -> Result<(), String> {
        let encrypted = match encoding {
            Encoding::Ea04 | Encoding::Ea05 | Encoding::Jb01 => {
                crate::crypto::mt::decrypt(plain, key)
            }
            Encoding::Ea06 => crate::crypto::lame::decrypt(plain, key),
        }
        .ok_or_else(|| "encryption failed".to_string())?;
        out.extend_from_slice(encrypted.as_slice());
        Ok(())
    }

    fn append_xored_u32(out: &mut Vec<u8>, value: u32, mask: u32) {
        append_u32(out, value ^ mask);
    }

    fn append_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn append_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn utf16_len(value: &str) -> Result<u32, String> {
        u32::try_from(value.encode_utf16().count()).map_err(|err| err.to_string())
    }

    fn byte_len(value: &str) -> Result<u32, String> {
        u32::try_from(value.len()).map_err(|err| err.to_string())
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
