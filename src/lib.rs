//! Extract and inspect compiled AutoIt payloads.
//!
//! This crate is intended to recover information from AutoIt2Exe and `.a3x`
//! inputs: container details, compiled resource records, scripts, token streams,
//! timestamps, checksums, and embedded file payloads.
//!
//! It does not execute AutoIt code, emulate expressions, or classify script
//! behavior. Decoded source text and token streams are exposed as recovered
//! information for downstream consumers.
//!
//! # Extraction Model
//!
//! `AutoItBinary::try_parse` performs container discovery first, then parses the
//! AU3 record stream when an encoding and stream offset are available. The
//! high-level object keeps every recovered view additive:
//!
//! - [`ContainerInfo`] summarizes PE, `.a3x`, raw stream, offset, and resource
//!   facts.
//! - [`ObservationLog`] records concrete recognition observations.
//! - [`Record`] exposes raw record metadata plus encrypted, decrypted, and best
//!   available payload bytes.
//! - [`Script`] exposes script bytes, decoded source text when available, and
//!   token streams for tokenized EA06 scripts.
//! - [`Artifact`] preserves non-script record payloads.
//! - [`StringFinding`] reports raw strings found in recovered payload bytes.
//!
//! Record parsing is tolerant at the high level: records recovered before a
//! later malformed record remain available, while [`AutoItBinary::record_diagnostics`]
//! reports the failing record index, offset, and reason. Lower-level
//! [`au3::parse_records`] remains strict for callers that need all-or-nothing
//! parsing.
//!
//! # Common Failure Modes
//!
//! - Packed or protected PE stubs may hide the AutoIt resource until an external
//!   unpacking step has been performed.
//! - Legacy encodings outside the implemented EA05/EA06 record profiles are
//!   reported as unsupported rather than guessed.
//! - Tokenized source rendering is source-like reconstruction, not guaranteed to
//!   be byte-for-byte identical to the original script text.
//! - Decompression failures preserve decrypted bytes and attach structured
//!   decompression status to the source record.
//!
//! # Quick Start
//!
//! ```no_run
//! use autoit::{AutoItBinary, RecognitionFailure};
//!
//! let data = std::fs::read("sample.exe")?;
//! match AutoItBinary::try_parse(&data) {
//!     Ok(binary) => {
//!         println!("{:?}", binary.input_kind());
//!         println!("{:?}", binary.encoding());
//!     }
//!     Err(err) if err.recognition_failure() == Some(RecognitionFailure::NotRecognized) => {
//!         println!("not an AutoIt payload");
//!     }
//!     Err(err) => return Err(Box::<dyn std::error::Error>::from(err)),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod error;
pub mod format;

pub mod au3;
pub mod decompress;
pub mod script;
pub mod strings;
pub mod token;

mod container;
mod crypto;
mod util;

pub use au3::{
    CompressionProfile, DecompressionStatus, EncryptionProfile, Record, RecordParseDiagnostic,
    RecordParseReport, RecordProfile,
};
pub use error::{Error, RecognitionFailure};
pub use format::{
    ContainerInfo, KnownSubtype, Observation, ObservationLog, PackedMarkerInfo,
    PeScriptResourceInfo, VersionMarkerInfo,
};
pub use script::{Script, ScriptDecodeError, ScriptKind, ScriptText, ScriptTextEncoding};
pub use strings::{StringEncoding, StringFinding};
pub use token::{Token, TokenError, TokenStream};

/// High-level view of an AutoIt payload.
///
/// Produced by [`AutoItBinary::try_parse`], this type owns every recovered view:
/// the recognized container facts and analysis observations, the parsed AU3 records,
/// any recovered scripts and non-script artifacts, and raw strings found in the
/// payload bytes. Each view is exposed through an accessor and kept additive, so
/// partial recovery from a malformed sample still yields everything decoded
/// before the failure.
#[derive(Debug, Clone)]
pub struct AutoItBinary {
    input_kind: InputKind,
    encoding: Option<Encoding>,
    container: ContainerInfo,
    observations: ObservationLog,
    records: Vec<Record>,
    record_diagnostics: Vec<RecordParseDiagnostic>,
    scripts: Vec<Script>,
    artifacts: Vec<Artifact>,
    strings: Vec<StringFinding>,
}

impl AutoItBinary {
    /// Attempts to parse an AutoIt payload from bytes.
    ///
    /// Recognizes the container (PE, `.a3x`, or a carved record stream) and its
    /// encoding, then parses the AU3 record stream when one is located:
    /// decrypting and decompressing record payloads, recovering scripts
    /// (including EA06 detokenization), preserving non-script artifacts, and
    /// extracting raw strings. Record parsing is tolerant — records recovered
    /// before a later malformed record remain available via [`Self::records`],
    /// with the failure reported in [`Self::record_diagnostics`].
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the input is not recognized as AutoIt, or when a
    /// recognized container is too malformed to begin record parsing. Use
    /// [`Error::recognition_failure`] to distinguish the cause.
    pub fn try_parse(data: &[u8]) -> Result<Self, Error> {
        let raw = container::raw::scan(data);
        let pe_resource = container::pe::find_script_resource(data);
        let loose_version = loose_autoit_version_marker(data);
        let packed_marker = packed_marker(data);
        // EA04 (AutoIt v3.1.x) and JB01 (AutoHotkey-classic / AutoIt v2) carry
        // neither an `AU3!` signature nor a PE script resource, so fall back to
        // scanning for their appended streams.
        let (ea04_stream_offset, jb01_stream_offset) = if raw.is_none() && pe_resource.is_none() {
            (
                container::raw::scan_ea04_stream(data),
                container::raw::scan_jb01_stream(data),
            )
        } else {
            (None, None)
        };
        if raw.is_none()
            && pe_resource.is_none()
            && ea04_stream_offset.is_none()
            && jb01_stream_offset.is_none()
            && !(util::has_mz_header(data) && packed_marker.is_some() && loose_version.is_some())
        {
            return Err(Error::not_recognized());
        };

        let input_kind = if util::has_mz_header(data) {
            InputKind::Pe
        } else if raw.is_some_and(|candidate| candidate.signature_offset() == 0) {
            InputKind::A3x
        } else {
            InputKind::RawStream
        };

        let mut observations = ObservationLog::new();
        if input_kind == InputKind::Pe {
            observations.push(Observation::OuterPeHeaderFound);
        }
        if let Some(marker) = packed_marker {
            observations.push(Observation::PackedMarkerFound {
                name: marker.name,
                offset: marker.offset,
            });
        }
        if let Some(resource) = pe_resource {
            observations.push(Observation::PeScriptResourceFound {
                type_id: resource.resource_type_id(),
                type_name: resource.resource_type_name(),
                name: resource.resource_name(),
                language_id: resource.language_id(),
                rva: resource.rva(),
                offset: resource.file_offset(),
                size: resource.size(),
            });
            if let Some(offset) = resource.stream_offset() {
                observations.push(Observation::PayloadStreamStartFound { offset });
                if first_file_record_matches(data, offset, Encoding::Ea06) {
                    observations.push(Observation::FirstFileRecordDecrypted {
                        encoding: Encoding::Ea06,
                        offset,
                    });
                }
            }
        }
        if let Some(raw) = raw {
            observations.push(Observation::AutoItSignatureFound {
                offset: raw.signature_offset(),
            });
            observations.push(Observation::VersionMarkerFound {
                encoding: raw.encoding(),
                offset: raw.version_offset(),
            });
            observations.push(Observation::PayloadStreamStartFound {
                offset: raw.payload_offset(),
            });
            if first_file_record_matches(data, raw.payload_offset(), raw.encoding()) {
                observations.push(Observation::FirstFileRecordDecrypted {
                    encoding: raw.encoding(),
                    offset: raw.payload_offset(),
                });
            }
        } else if let Some(offset) = jb01_stream_offset {
            // Checked before EA04: JB01's GUID + marker byte is a specific
            // signature, whereas the EA04 scan also matches a JB01 stream (same
            // encrypted `FILE` marker and shared subtype validation).
            observations.push(Observation::PayloadStreamStartFound { offset });
            observations.push(Observation::FirstFileRecordDecrypted {
                encoding: Encoding::Jb01,
                offset,
            });
        } else if let Some(offset) = ea04_stream_offset {
            observations.push(Observation::PayloadStreamStartFound { offset });
            observations.push(Observation::FirstFileRecordDecrypted {
                encoding: Encoding::Ea04,
                offset,
            });
        } else if let Some(version) = loose_version {
            observations.push(Observation::VersionMarkerFound {
                encoding: version.encoding,
                offset: version.offset,
            });
        }

        let encoding = raw
            .map(container::raw::RawScan::encoding)
            .or_else(|| first_file_encoding(observations.entries()))
            .or_else(|| loose_version.map(|version| version.encoding));

        let (records, record_diagnostics) = encoding
            .and_then(|record_encoding| {
                first_stream_offset(observations.entries()).map(|offset| (record_encoding, offset))
            })
            .map_or_else(
                || Ok::<(Vec<Record>, Vec<RecordParseDiagnostic>), Error>((Vec::new(), Vec::new())),
                |(record_encoding, offset)| {
                    let record_report = au3::parse_records_partial(
                        data,
                        offset,
                        record_encoding,
                        au3::Limits::default(),
                    )?;
                    let diagnostics = match record_report.diagnostic() {
                        Some(diagnostic) => vec![diagnostic],
                        None => Vec::new(),
                    };
                    Ok((record_report.into_records(), diagnostics))
                },
            )?;
        if let Some(record) = records.first()
            && let Some(subtype) = known_subtype(record.subtype())
        {
            observations.push(Observation::KnownSubtypeDecrypted {
                encoding: record.profile().encoding,
                offset: record.offset(),
                subtype,
            });
        }

        let scripts = script::recover_scripts(records.as_slice());
        let artifacts = recover_artifacts(records.as_slice(), scripts.as_slice());
        let strings = strings::extract_from_records(records.as_slice(), strings::Limits::default());

        Ok(Self {
            input_kind,
            encoding,
            container: ContainerInfo::from_observations(input_kind, encoding, observations.entries()),
            scripts,
            artifacts,
            strings,
            observations,
            records,
            record_diagnostics,
        })
    }

    /// Returns the recognized input container kind.
    ///
    /// # Returns
    ///
    /// The [`InputKind`] determined during analysis ([`InputKind::Pe`],
    /// [`InputKind::A3x`], or [`InputKind::RawStream`]).
    #[must_use]
    pub const fn input_kind(&self) -> InputKind {
        self.input_kind
    }

    /// Returns the recognized AutoIt payload encoding, if known.
    ///
    /// # Returns
    ///
    /// `Some` with the recognized [`Encoding`], or `None` when no encoding could be
    /// determined from the container.
    #[must_use]
    pub const fn encoding(&self) -> Option<Encoding> {
        self.encoding
    }

    /// Returns summarized container-level facts.
    ///
    /// # Returns
    ///
    /// A reference to the [`ContainerInfo`] built from the recorded observations.
    #[must_use]
    pub const fn container(&self) -> &ContainerInfo {
        &self.container
    }

    /// Returns the analysis observations.
    ///
    /// # Returns
    ///
    /// A reference to the [`ObservationLog`] holding the concrete observations
    /// recorded during analysis.
    #[must_use]
    pub const fn observations(&self) -> &ObservationLog {
        &self.observations
    }

    /// Returns parsed AU3 records.
    ///
    /// Records recovered before any later malformed record remain present here;
    /// the failure is reported separately via [`Self::record_diagnostics`].
    ///
    /// # Returns
    ///
    /// A slice of the parsed [`Record`] values, empty when no record stream was
    /// located.
    #[must_use]
    pub fn records(&self) -> &[Record] {
        self.records.as_slice()
    }

    /// Returns diagnostics from tolerant AU3 record parsing.
    ///
    /// # Returns
    ///
    /// A slice of [`RecordParseDiagnostic`] entries describing records that failed
    /// to parse; empty when every record parsed cleanly.
    #[must_use]
    pub fn record_diagnostics(&self) -> &[RecordParseDiagnostic] {
        self.record_diagnostics.as_slice()
    }

    /// Returns recovered script records.
    ///
    /// # Returns
    ///
    /// A slice of recovered [`Script`] views; empty when no script records were
    /// found.
    #[must_use]
    pub fn scripts(&self) -> &[Script] {
        self.scripts.as_slice()
    }

    /// Returns recovered non-script artifact records.
    ///
    /// # Returns
    ///
    /// A slice of [`Artifact`] views for every record that was not recovered as a
    /// [`Script`]; empty when there are none.
    #[must_use]
    pub fn artifacts(&self) -> &[Artifact] {
        self.artifacts.as_slice()
    }

    /// Returns raw strings found in recovered record payload bytes.
    ///
    /// # Returns
    ///
    /// A slice of [`StringFinding`] values extracted from record payloads; empty
    /// when none were found.
    #[must_use]
    pub fn strings(&self) -> &[StringFinding] {
        self.strings.as_slice()
    }
}

/// Recovered non-script artifact view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    record_index: usize,
    subtype: String,
    name: String,
    bytes: Vec<u8>,
    creation_time: u64,
    last_write_time: u64,
    checksum_valid: bool,
    decompression_status: DecompressionStatus,
}

impl Artifact {
    /// Returns the source record index.
    ///
    /// # Returns
    ///
    /// The index of the [`Record`] this artifact was recovered from.
    #[must_use]
    pub const fn record_index(&self) -> usize {
        self.record_index
    }

    /// Returns the record subtype.
    ///
    /// # Returns
    ///
    /// The decoded subtype string of the source record.
    #[must_use]
    pub fn subtype(&self) -> &str {
        self.subtype.as_str()
    }

    /// Returns the stored record name/path.
    ///
    /// # Returns
    ///
    /// The decoded name/path string of the source record.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns recovered artifact bytes.
    ///
    /// # Returns
    ///
    /// The best available payload bytes for the source record.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Returns creation timestamp as raw Windows FILETIME.
    ///
    /// # Returns
    ///
    /// The raw 64-bit Windows FILETIME creation timestamp from the source record.
    #[must_use]
    pub const fn creation_time(&self) -> u64 {
        self.creation_time
    }

    /// Returns last-write timestamp as raw Windows FILETIME.
    ///
    /// # Returns
    ///
    /// The raw 64-bit Windows FILETIME last-write timestamp from the source
    /// record.
    #[must_use]
    pub const fn last_write_time(&self) -> u64 {
        self.last_write_time
    }

    /// Returns checksum validation status from the source record.
    ///
    /// # Returns
    ///
    /// `true` if the source record's stored checksum validated, `false` otherwise.
    #[must_use]
    pub const fn checksum_valid(&self) -> bool {
        self.checksum_valid
    }

    /// Returns decompression status from the source record.
    ///
    /// # Returns
    ///
    /// The [`DecompressionStatus`] recorded for the source record.
    #[must_use]
    pub const fn decompression_status(&self) -> DecompressionStatus {
        self.decompression_status
    }
}

/// Builds artifact views for every record not already recovered as a script.
///
/// # Arguments
///
/// * `records` - Parsed AU3 records to convert into artifacts.
/// * `scripts` - Scripts already recovered; their source records are excluded.
///
/// # Returns
///
/// A vector of [`Artifact`] values, one per record whose index does not match
/// any recovered [`Script`].
fn recover_artifacts(records: &[Record], scripts: &[Script]) -> Vec<Artifact> {
    records
        .iter()
        .filter(|record| {
            !scripts
                .iter()
                .any(|script| script.record_index() == record.index())
        })
        .map(|record| Artifact {
            record_index: record.index(),
            subtype: record.subtype().to_string(),
            name: record.name().to_string(),
            bytes: record.payload_data().to_vec(),
            creation_time: record.creation_time(),
            last_write_time: record.last_write_time(),
            checksum_valid: record.checksum_valid(),
            decompression_status: record.decompression_status(),
        })
        .collect()
}

/// Checks whether the first record marker at `offset` decrypts to `FILE`.
///
/// Reads the four bytes at `offset` and decrypts them with the field key for the
/// given encoding, confirming a genuine AU3 record stream begins there.
///
/// # Arguments
///
/// * `data` - The full input bytes.
/// * `offset` - File offset where the encrypted record-type marker is expected.
/// * `encoding` - Encoding whose decryption profile and key to apply.
///
/// # Returns
///
/// `true` if the four bytes at `offset` decrypt to `FILE`, `false` when the slice
/// is out of bounds, the offset arithmetic overflows, or decryption does not yield
/// `FILE`.
fn first_file_record_matches(data: &[u8], offset: usize, encoding: Encoding) -> bool {
    let Some(end) = offset.checked_add(4) else {
        return false;
    };
    let Some(marker) = data.get(offset..end) else {
        return false;
    };
    let decrypted = match encoding {
        Encoding::Ea04 | Encoding::Ea05 | Encoding::Jb01 => crypto::mt::decrypt(marker, 0x16fa),
        Encoding::Ea06 => crypto::lame::decrypt(marker, 0x18ee),
    };
    decrypted.is_some_and(|bytes| bytes == b"FILE")
}

/// Returns the offset where the AU3 record stream is expected to begin.
///
/// # Arguments
///
/// * `observations` - Observations collected in [`ObservationLog`], scanned in
///   recording order.
///
/// # Returns
///
/// The offset from the first [`Observation::PayloadStreamStartFound`] observation,
/// or `None` when no payload stream start was recorded.
fn first_stream_offset(observations: &[Observation]) -> Option<usize> {
    observations.iter().find_map(|observation| match observation {
        Observation::PayloadStreamStartFound { offset } => Some(*offset),
        _ => None,
    })
}

/// Returns the encoding proven by the first decrypted `FILE` record marker.
///
/// # Arguments
///
/// * `observations` - Observations collected in [`ObservationLog`], scanned in
///   recording order.
///
/// # Returns
///
/// The encoding from the first [`Observation::FirstFileRecordDecrypted`]
/// observation, or `None` if no `FILE` marker was decrypted during analysis.
fn first_file_encoding(observations: &[Observation]) -> Option<Encoding> {
    observations.iter().find_map(|observation| match observation {
        Observation::FirstFileRecordDecrypted { encoding, .. } => Some(*encoding),
        _ => None,
    })
}

/// Maps a record subtype string to its known script category.
///
/// # Arguments
///
/// * `subtype` - Decoded record subtype string to classify.
///
/// # Returns
///
/// `Some` with the matching [`KnownSubtype`] for a recognized AutoIt script
/// subtype, or `None` for any other subtype.
fn known_subtype(subtype: &str) -> Option<KnownSubtype> {
    match subtype {
        ">>>AUTOIT SCRIPT<<<" => Some(KnownSubtype::TokenizedScript),
        ">AUTOIT UNICODE SCRIPT<" => Some(KnownSubtype::UnicodeScript),
        ">AUTOIT SCRIPT<" => Some(KnownSubtype::PlainScript),
        _ => None,
    }
}

/// A version marker located by a loose textual scan rather than a full container.
#[derive(Debug, Clone, Copy)]
struct LooseVersionMarker {
    /// Encoding represented by the located marker.
    encoding: Encoding,
    /// File offset where the marker begins.
    offset: usize,
}

/// A packer marker located in the outer input.
#[derive(Debug, Clone, Copy)]
struct PackedMarker {
    /// Marker name.
    name: &'static str,
    /// File offset where the marker begins.
    offset: usize,
}

/// Scans for a loose AutoIt version marker when no full container was recognized.
///
/// Requires at least one of the `AU3!`, `AutoIt`, or `SCRIPT` text anchors to be
/// present before reporting a marker, then returns the first encoding marker
/// found.
///
/// # Arguments
///
/// * `data` - The full input bytes to scan.
///
/// # Returns
///
/// `Some` with the first [`LooseVersionMarker`] (`EA06`, `EA05`, then `JB01`
/// order) when an anchor and a marker are both present, or `None` otherwise.
fn loose_autoit_version_marker(data: &[u8]) -> Option<LooseVersionMarker> {
    if find_bytes(data, b"AU3!").is_none()
        && find_bytes(data, b"AutoIt").is_none()
        && find_bytes(data, b"SCRIPT").is_none()
    {
        return None;
    }

    [
        (Encoding::Ea06, b"EA06".as_slice()),
        (Encoding::Ea05, b"EA05".as_slice()),
        (Encoding::Jb01, b"JB01".as_slice()),
    ]
    .into_iter()
    .find_map(|(encoding, marker)| {
        find_bytes(data, marker).map(|offset| LooseVersionMarker { encoding, offset })
    })
}

/// Scans for a known packer marker in the outer input.
///
/// # Arguments
///
/// * `data` - The full input bytes to scan.
///
/// # Returns
///
/// `Some` with a [`PackedMarker`] when a `UPX` marker is found, or `None`
/// otherwise.
fn packed_marker(data: &[u8]) -> Option<PackedMarker> {
    find_bytes(data, b"UPX").map(|offset| PackedMarker {
        name: "UPX",
        offset,
    })
}

/// Finds the first occurrence of a byte sequence within the input.
///
/// # Arguments
///
/// * `data` - The bytes to search.
/// * `needle` - The byte sequence to locate.
///
/// # Returns
///
/// The offset of the first match, or `None` when `needle` is empty, longer than
/// `data`, or absent.
fn find_bytes(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > data.len() {
        return None;
    }
    data.windows(needle.len())
        .position(|candidate| candidate == needle)
}

/// Recognized outer input kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// A Windows PE executable containing AutoIt payload data.
    Pe,
    /// A compiled `.a3x` AutoIt payload.
    A3x,
    /// A carved AutoIt record stream without a full original container.
    RawStream,
}

/// Recognized AutoIt payload encoding family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// AutoIt v3.1.x EA04 payload format. Predates EA05: MT-encrypted with the
    /// same field keys, but the record header carries no per-record checksum
    /// field and the compression wrapper magic is `EA04`.
    Ea04,
    /// AutoIt v3 EA05 payload format.
    Ea05,
    /// AutoIt v3 EA06 payload format.
    Ea06,
    /// AutoIt v2 / related JB01 payload format.
    Jb01,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: [u8; 20] = [
        0xa3, 0x48, 0x4b, 0xbe, 0x98, 0x6c, 0x4a, 0xa9, 0x99, 0x4c, 0x53, 0x0a, 0x86, 0xd6, 0x48,
        0x7d, 0x41, 0x55, 0x33, 0x21,
    ];

    #[test]
    fn scans_raw_ea06_signature() -> Result<(), String> {
        let mut data = Vec::from(PREFIX);
        data.extend_from_slice(b"EA06");

        let binary = AutoItBinary::try_parse(&data).map_err(|err| err.to_string())?;

        check_eq(binary.input_kind(), InputKind::A3x, "input kind")?;
        check_eq(binary.encoding(), Some(Encoding::Ea06), "encoding")?;
        check_eq(
            binary.container().autoit_signature_offset(),
            Some(0),
            "signature offset",
        )?;
        check_eq(
            binary.container().version_marker(),
            Some(VersionMarkerInfo {
                encoding: Encoding::Ea06,
                offset: 20,
            }),
            "version marker",
        )?;
        check_eq(
            binary.container().payload_stream_offsets(),
            [24usize].as_slice(),
            "payload offsets",
        )?;
        check_eq(binary.observations().entries().len(), 3, "observation count")
    }

    #[test]
    fn validates_raw_ea06_first_file_record() -> Result<(), String> {
        let mut data = Vec::from(PREFIX);
        data.extend_from_slice(b"EA06");
        append_ea06_record(&mut data, ">>>AUTOIT SCRIPT<<<", "main.au3", b"payload")?;

        let binary = AutoItBinary::try_parse(&data).map_err(|err| err.to_string())?;

        check_eq(binary.encoding(), Some(Encoding::Ea06), "encoding")?;
        check_eq(binary.records().len(), 1, "record count")?;
        let found = binary.observations().entries().iter().any(|observation| {
            matches!(
                observation,
                Observation::FirstFileRecordDecrypted {
                    encoding: Encoding::Ea06,
                    offset: 24
                }
            )
        });
        if found {
            let subtype_found = binary.observations().entries().iter().any(|observation| {
                matches!(
                    observation,
                    Observation::KnownSubtypeDecrypted {
                        encoding: Encoding::Ea06,
                        offset: 24,
                        subtype: KnownSubtype::TokenizedScript
                    }
                )
            });
            if subtype_found {
                Ok(())
            } else {
                Err("missing known subtype observation".to_string())
            }
        } else {
            Err("missing first FILE record observation".to_string())
        }
    }

    #[test]
    fn preserves_records_when_later_record_is_truncated() -> Result<(), String> {
        let mut data = Vec::from(PREFIX);
        data.extend_from_slice(b"EA06");
        append_ea06_record(&mut data, ">AUTOIT SCRIPT<", "main.au3", b"payload")?;
        let truncated_offset = data.len();
        append_encrypted(&mut data, b"FILE", 0x18ee)?;

        let binary = AutoItBinary::try_parse(&data).map_err(|err| err.to_string())?;

        check_eq(binary.records().len(), 1, "record count")?;
        check_eq(binary.scripts().len(), 1, "script count")?;
        check_eq(
            binary.record_diagnostics(),
            [RecordParseDiagnostic {
                record_index: 1,
                offset: truncated_offset,
                reason: RecognitionFailure::Truncated,
            }]
            .as_slice(),
            "diagnostics",
        )
    }

    #[test]
    fn scans_pe_wrapped_signature() -> Result<(), String> {
        let mut data = Vec::from(b"MZ");
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&PREFIX);
        data.extend_from_slice(b"EA05");

        let binary = AutoItBinary::try_parse(&data).map_err(|err| err.to_string())?;

        check_eq(binary.input_kind(), InputKind::Pe, "input kind")?;
        check_eq(binary.encoding(), Some(Encoding::Ea05), "encoding")?;
        check_eq(binary.observations().entries().len(), 4, "observation count")
    }

    #[test]
    fn rejects_unknown_input() -> Result<(), String> {
        let Err(err) = AutoItBinary::try_parse(b"not autoit") else {
            return Err("unexpected parse success".to_string());
        };

        check_eq(
            err.recognition_failure(),
            Some(RecognitionFailure::NotRecognized),
            "recognition failure",
        )
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

    fn append_ea06_record(
        out: &mut Vec<u8>,
        subtype: &str,
        name: &str,
        data: &[u8],
    ) -> Result<(), String> {
        append_encrypted(out, b"FILE", 0x18ee)?;
        append_xored_u32(out, utf16_len(subtype)?, 0xadbc);
        append_encrypted_utf16(out, subtype, 0xb33f)?;
        append_xored_u32(out, utf16_len(name)?, 0xf820);
        append_encrypted_utf16(out, name, 0xf479)?;
        out.push(0);
        let data_len = u32::try_from(data.len()).map_err(|err| err.to_string())?;
        append_xored_u32(out, data_len, 0x87bc);
        append_xored_u32(out, data_len, 0x87bc);
        append_xored_u32(out, 0, 0xa685);
        append_u64(out, 0);
        append_u64(out, 0);
        append_encrypted(out, data, 0x2477)
    }

    fn append_encrypted_utf16(out: &mut Vec<u8>, value: &str, key_base: u32) -> Result<(), String> {
        let char_len = utf16_len(value)?;
        let key = key_base.wrapping_add(char_len);
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        append_encrypted(out, bytes.as_slice(), key)
    }

    fn append_encrypted(out: &mut Vec<u8>, plain: &[u8], key: u32) -> Result<(), String> {
        let encrypted = crypto::lame::decrypt(plain, key)
            .ok_or_else(|| "EA06 encryption failed".to_string())?;
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
}
