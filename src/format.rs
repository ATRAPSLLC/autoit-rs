//! Format metadata and analysis observations.

use crate::{Encoding, InputKind};

/// Summary of recognized container-level facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    input_kind: InputKind,
    encoding: Option<Encoding>,
    autoit_signature_offset: Option<usize>,
    version_marker: Option<VersionMarkerInfo>,
    payload_stream_offsets: Vec<usize>,
    pe_script_resource: Option<PeScriptResourceInfo>,
    packed_markers: Vec<PackedMarkerInfo>,
}

impl ContainerInfo {
    /// Builds container facts from recorded observations.
    ///
    /// Folds the recorded observations into a single summary, capturing the
    /// signature offset, version marker, payload stream offsets, PE script
    /// resource, and packed markers. Observations without container facts
    /// ([`Observation::OuterPeHeaderFound`],
    /// [`Observation::FirstFileRecordDecrypted`], and
    /// [`Observation::KnownSubtypeDecrypted`]) are ignored.
    ///
    /// # Arguments
    ///
    /// * `input_kind` - The recognized outer [`InputKind`].
    /// * `encoding` - The recognized [`Encoding`], if any.
    /// * `observations` - Observations to fold into the summary.
    ///
    /// # Returns
    ///
    /// A populated [`ContainerInfo`].
    #[must_use]
    pub fn from_observations(
        input_kind: InputKind,
        encoding: Option<Encoding>,
        observations: &[Observation],
    ) -> Self {
        let mut info = Self {
            input_kind,
            encoding,
            autoit_signature_offset: None,
            version_marker: None,
            payload_stream_offsets: Vec::new(),
            pe_script_resource: None,
            packed_markers: Vec::new(),
        };
        for observation in observations {
            match *observation {
                Observation::AutoItSignatureFound { offset } => {
                    info.autoit_signature_offset = Some(offset);
                }
                Observation::VersionMarkerFound { encoding, offset } => {
                    info.version_marker = Some(VersionMarkerInfo { encoding, offset });
                }
                Observation::PayloadStreamStartFound { offset } => {
                    info.payload_stream_offsets.push(offset);
                }
                Observation::PeScriptResourceFound {
                    type_id,
                    type_name,
                    name,
                    language_id,
                    rva,
                    offset,
                    size,
                } => {
                    info.pe_script_resource = Some(PeScriptResourceInfo {
                        type_id,
                        type_name,
                        name,
                        language_id,
                        rva,
                        offset,
                        size,
                    });
                }
                Observation::PackedMarkerFound { name, offset } => {
                    info.packed_markers.push(PackedMarkerInfo { name, offset });
                }
                Observation::OuterPeHeaderFound
                | Observation::FirstFileRecordDecrypted { .. }
                | Observation::KnownSubtypeDecrypted { .. } => {}
            }
        }
        info
    }

    /// Returns recognized input kind.
    ///
    /// # Returns
    ///
    /// The [`InputKind`] recorded for this container.
    #[must_use]
    pub const fn input_kind(&self) -> InputKind {
        self.input_kind
    }

    /// Returns recognized encoding.
    ///
    /// # Returns
    ///
    /// `Some` with the recognized [`Encoding`], or `None` when none was determined.
    #[must_use]
    pub const fn encoding(&self) -> Option<Encoding> {
        self.encoding
    }

    /// Returns AutoIt signature offset when present.
    ///
    /// # Returns
    ///
    /// `Some` with the file offset of the `AU3!` signature, or `None` when no
    /// signature was located.
    #[must_use]
    pub const fn autoit_signature_offset(&self) -> Option<usize> {
        self.autoit_signature_offset
    }

    /// Returns version marker facts when present.
    ///
    /// # Returns
    ///
    /// `Some` with the [`VersionMarkerInfo`], or `None` when no version marker was
    /// found.
    #[must_use]
    pub const fn version_marker(&self) -> Option<VersionMarkerInfo> {
        self.version_marker
    }

    /// Returns payload stream start offsets.
    ///
    /// # Returns
    ///
    /// A slice of file offsets where record streams are expected to begin, in
    /// recording order.
    #[must_use]
    pub fn payload_stream_offsets(&self) -> &[usize] {
        self.payload_stream_offsets.as_slice()
    }

    /// Returns PE script resource facts when present.
    ///
    /// # Returns
    ///
    /// `Some` with the [`PeScriptResourceInfo`], or `None` when no PE script
    /// resource was found.
    #[must_use]
    pub const fn pe_script_resource(&self) -> Option<PeScriptResourceInfo> {
        self.pe_script_resource
    }

    /// Returns packed-container markers found in the outer input.
    ///
    /// # Returns
    ///
    /// A slice of [`PackedMarkerInfo`] entries, in recording order.
    #[must_use]
    pub fn packed_markers(&self) -> &[PackedMarkerInfo] {
        self.packed_markers.as_slice()
    }
}

/// Version marker facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMarkerInfo {
    /// Encoding represented by the marker.
    pub encoding: Encoding,
    /// File offset of the marker.
    pub offset: usize,
}

/// PE `RT_RCDATA/SCRIPT` resource facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeScriptResourceInfo {
    /// PE resource type id.
    pub type_id: u16,
    /// PE resource type name, when recognized.
    pub type_name: Option<&'static str>,
    /// PE resource name.
    pub name: &'static str,
    /// PE resource language id, when present.
    pub language_id: Option<u16>,
    /// Resource data RVA.
    pub rva: u32,
    /// Resource data file offset.
    pub offset: usize,
    /// Resource data size.
    pub size: u32,
}

/// Packed-container marker facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedMarkerInfo {
    /// Marker name.
    pub name: &'static str,
    /// File offset where the marker begins.
    pub offset: usize,
}

/// Log of analysis observations.
///
/// Records concrete observations made while analyzing an AutoIt payload. It
/// intentionally contains facts rather than behavior labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservationLog {
    entries: Vec<Observation>,
}

impl ObservationLog {
    /// Creates an empty log.
    ///
    /// # Returns
    ///
    /// An [`ObservationLog`] holding no observations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds an observation.
    ///
    /// # Arguments
    ///
    /// * `observation` - The [`Observation`] to append, preserving recording order.
    pub fn push(&mut self, observation: Observation) {
        self.entries.push(observation);
    }

    /// Returns the recorded observations.
    ///
    /// # Returns
    ///
    /// A slice of the recorded [`Observation`] values in recording order.
    #[must_use]
    pub fn entries(&self) -> &[Observation] {
        self.entries.as_slice()
    }
}

/// A concrete observation made while analyzing an AutoIt payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// The outer input begins with an `MZ` PE header.
    OuterPeHeaderFound,
    /// The AutoIt `AU3!` signature prefix was found at the given file offset.
    AutoItSignatureFound {
        /// File offset where the AutoIt signature prefix begins.
        offset: usize,
    },
    /// A supported AutoIt version marker was found at the given file offset.
    VersionMarkerFound {
        /// Encoding represented by the version marker.
        encoding: Encoding,
        /// File offset where the version marker begins.
        offset: usize,
    },
    /// The offset where the AU3 record stream is expected to begin.
    PayloadStreamStartFound {
        /// File offset where record parsing should begin.
        offset: usize,
    },
    /// A PE `RT_RCDATA` resource named `SCRIPT` was found.
    PeScriptResourceFound {
        /// PE resource type id.
        type_id: u16,
        /// PE resource type name, when recognized.
        type_name: Option<&'static str>,
        /// PE resource name.
        name: &'static str,
        /// PE resource language id, when present.
        language_id: Option<u16>,
        /// Resource data RVA.
        rva: u32,
        /// Resource data file offset.
        offset: usize,
        /// Resource data size in bytes.
        size: u32,
    },
    /// A known packer marker was found in the outer container.
    PackedMarkerFound {
        /// Marker name.
        name: &'static str,
        /// File offset where the marker begins.
        offset: usize,
    },
    /// The first AU3 record type decrypted to `FILE`.
    FirstFileRecordDecrypted {
        /// Encoding profile used for decryption.
        encoding: Encoding,
        /// File offset of the encrypted `FILE` marker.
        offset: usize,
    },
    /// The first AU3 record subtype decrypted to a known script subtype.
    KnownSubtypeDecrypted {
        /// Encoding profile used for decryption.
        encoding: Encoding,
        /// File offset where the source record begins.
        offset: usize,
        /// Known subtype that was recovered.
        subtype: KnownSubtype,
    },
}

/// Known AU3 record subtype categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownSubtype {
    /// Tokenized script subtype `>>>AUTOIT SCRIPT<<<`.
    TokenizedScript,
    /// UTF-16 text script subtype `>AUTOIT UNICODE SCRIPT<`.
    UnicodeScript,
    /// Plain text script subtype `>AUTOIT SCRIPT<`.
    PlainScript,
}
