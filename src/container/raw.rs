//! Raw AutoIt signature discovery.
//!
//! Scans arbitrary byte slices for the 16-byte AutoIt GUID, the `AU3!` tag, and
//! the version marker that follows it ([`Encoding::Ea05`]/[`Encoding::Ea06`]),
//! then resolves the offset of the appended AU3 record stream. EA04 and JB01
//! streams carry no `AU3!` tag and are located by dedicated marker scans
//! ([`scan_ea04_stream`], [`scan_jb01_stream`]).

use crate::Encoding;

/// 16-byte AutoIt GUID followed by the ASCII `AU3!` tag.
const AUTOIT_SIGNATURE: &[u8] = &[
    0xa3, 0x48, 0x4b, 0xbe, 0x98, 0x6c, 0x4a, 0xa9, 0x99, 0x4c, 0x53, 0x0a, 0x86, 0xd6, 0x48, 0x7d,
    0x41, 0x55, 0x33, 0x21,
];
/// Alternate AutoIt GUID variant (two bytes transposed) seen in some builds.
const AUTOIT_SIGNATURE_ALT_GUID: &[u8] = &[
    0xa3, 0x48, 0x4b, 0xbe, 0x98, 0x6c, 0xa9, 0x4a, 0x99, 0x4c, 0x53, 0x0a, 0x86, 0xd6, 0x48, 0x7d,
    0x41, 0x55, 0x33, 0x21,
];

/// Result of raw AutoIt marker discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawScan {
    /// Encoding inferred from the version marker.
    encoding: Encoding,
    /// File offset of the 16-byte AutoIt GUID.
    signature_offset: usize,
    /// File offset of the 4-byte version marker (e.g. `EA06`).
    version_offset: usize,
    /// File offset where the AU3 record stream begins.
    payload_offset: usize,
}

impl RawScan {
    /// Returns the recognized [`Encoding`].
    ///
    /// # Returns
    ///
    /// The encoding inferred from the version marker.
    #[must_use]
    pub const fn encoding(self) -> Encoding {
        self.encoding
    }

    /// Returns the AutoIt GUID file offset.
    ///
    /// # Returns
    ///
    /// The byte offset of the 16-byte AutoIt GUID within the scanned slice.
    #[must_use]
    pub const fn signature_offset(self) -> usize {
        self.signature_offset
    }

    /// Returns the version marker file offset.
    ///
    /// # Returns
    ///
    /// The byte offset of the 4-byte version marker (e.g. `EA06`).
    #[must_use]
    pub const fn version_offset(self) -> usize {
        self.version_offset
    }

    /// Returns the payload stream file offset.
    ///
    /// # Returns
    ///
    /// The byte offset where the AU3 record stream begins.
    #[must_use]
    pub const fn payload_offset(self) -> usize {
        self.payload_offset
    }
}

/// Finds a supported AutoIt signature and version marker.
///
/// Locates the AutoIt GUID, reads the 4-byte version marker that follows it,
/// maps it to an [`Encoding`] ([`Encoding::Ea05`], [`Encoding::Ea06`], or
/// [`Encoding::Jb01`]), and resolves the AU3 record stream offset.
///
/// # Arguments
///
/// * `data` - bytes to scan for the signature.
///
/// # Returns
///
/// `Some` with a [`RawScan`] when a supported signature and a recognized
/// version marker are found; `None` when no signature is present or the version
/// marker is unrecognized.
#[must_use]
pub fn scan(data: &[u8]) -> Option<RawScan> {
    let signature_offset = find_signature(data)?;
    let version_offset = signature_offset.checked_add(AUTOIT_SIGNATURE.len())?;
    let version = data.get(version_offset..)?;
    let encoding = if version.starts_with(b"EA05") {
        Encoding::Ea05
    } else if version.starts_with(b"EA06") {
        Encoding::Ea06
    } else if version.starts_with(b"JB01") {
        Encoding::Jb01
    } else {
        return None;
    };
    let payload_offset = payload_offset_after_version(data, version_offset, encoding)?;

    Some(RawScan {
        encoding,
        signature_offset,
        version_offset,
        payload_offset,
    })
}

/// Returns the best candidate AU3 record stream offset after a version marker.
///
/// For [`Encoding::Ea05`]/[`Encoding::Ea06`] the stream may be preceded by a
/// 16-byte salt, so the offset is probed with [`salted_payload_offset`]. EA04
/// has no `AU3!` version marker and is never resolved through this path (it is
/// located by [`scan_ea04_stream`]); for EA04 and [`Encoding::Jb01`] the
/// stream starts directly after the marker.
///
/// # Arguments
///
/// * `data` - bytes containing the stream.
/// * `version_offset` - offset of the 4-byte version marker.
/// * `encoding` - encoding selecting the offset probing strategy.
///
/// # Returns
///
/// `Some` with the resolved stream offset, or `None` on offset overflow.
pub fn payload_offset_after_version(
    data: &[u8],
    version_offset: usize,
    encoding: Encoding,
) -> Option<usize> {
    let direct_offset = version_offset.checked_add(4)?;
    match encoding {
        Encoding::Ea05 | Encoding::Ea06 => salted_payload_offset(data, direct_offset, encoding),
        // EA04 has no `AU3!` version marker, so it is never resolved through this
        // signature path; EA04 streams are located by `scan_ea04_stream`.
        Encoding::Ea04 | Encoding::Jb01 => Some(direct_offset),
    }
}

/// Probes whether an EA05/EA06 stream begins directly or after a 16-byte salt.
///
/// Checks the first record marker at `direct_offset`; if it does not decrypt to
/// `FILE`, retries 16 bytes later to account for a salt block. Falls back to the
/// direct offset when neither candidate matches.
///
/// # Arguments
///
/// * `data` - bytes containing the stream.
/// * `direct_offset` - candidate offset immediately after the version marker.
/// * `encoding` - encoding selecting the record decryption scheme.
///
/// # Returns
///
/// `Some` with the chosen stream offset, or `None` on offset overflow.
fn salted_payload_offset(data: &[u8], direct_offset: usize, encoding: Encoding) -> Option<usize> {
    if first_file_record_matches(data, direct_offset, encoding) {
        return Some(direct_offset);
    }
    let hashed_offset = direct_offset.checked_add(16)?;
    if first_file_record_matches(data, hashed_offset, encoding) {
        Some(hashed_offset)
    } else {
        Some(direct_offset)
    }
}

/// Reports whether the 4-byte marker at `offset` decrypts to `FILE`.
///
/// Decrypts the marker with the record key for the given `encoding` (the MT
/// cipher for EA04/EA05/JB01, the LAME cipher for [`Encoding::Ea06`]) and
/// compares the plaintext against the literal `FILE` record marker.
///
/// # Arguments
///
/// * `data` - bytes containing the candidate marker.
/// * `offset` - offset of the 4-byte encrypted marker.
/// * `encoding` - encoding selecting the decryption scheme.
///
/// # Returns
///
/// `true` if the marker decrypts to `FILE`; `false` if the bytes are out of
/// range, decryption fails, or the plaintext differs.
pub fn first_file_record_matches(data: &[u8], offset: usize, encoding: Encoding) -> bool {
    let Some(end) = offset.checked_add(4) else {
        return false;
    };
    let Some(marker) = data.get(offset..end) else {
        return false;
    };
    let decrypted = match encoding {
        Encoding::Ea04 | Encoding::Ea05 | Encoding::Jb01 => {
            crate::crypto::mt::decrypt(marker, 0x16fa)
        }
        Encoding::Ea06 => crate::crypto::lame::decrypt(marker, 0x18ee),
    };
    decrypted.is_some_and(|bytes| bytes == b"FILE")
}

/// Finds the offset of the first AutoIt GUID in `data`.
///
/// Searches for either the canonical [`AUTOIT_SIGNATURE`] GUID or the
/// [`AUTOIT_SIGNATURE_ALT_GUID`] variant.
///
/// # Arguments
///
/// * `data` - bytes to scan.
///
/// # Returns
///
/// `Some` with the offset of the matching GUID, or `None` if neither is found.
fn find_signature(data: &[u8]) -> Option<usize> {
    data.windows(AUTOIT_SIGNATURE.len()).position(|candidate| {
        candidate == AUTOIT_SIGNATURE || candidate == AUTOIT_SIGNATURE_ALT_GUID
    })
}

/// `FILE` encrypted with the EA04/EA05 MT record key (`0x16fa`). EA04 streams
/// carry no `AU3!` signature, so the encrypted record marker is the only stable
/// anchor for locating an appended EA04 stream.
const ENCRYPTED_FILE_MARKER: &[u8; 4] = &[0xff, 0x6d, 0xb0, 0xce];

/// Finds the start of an appended EA04 record stream, if present.
///
/// EA04 (AutoIt v3.1.x) embeds the stream in the PE overlay without the `AU3!`
/// signature used by EA05/EA06. Scans for the encrypted `FILE` marker
/// and accepts the first candidate whose first record decrypts to a known
/// AutoIt subtype string, which rejects incidental byte matches.
///
/// # Arguments
///
/// * `data` - bytes to scan for an appended EA04 stream.
///
/// # Returns
///
/// `Some` with the stream start offset, or `None` if no plausible candidate is
/// found.
#[must_use]
pub fn scan_ea04_stream(data: &[u8]) -> Option<usize> {
    let mut from = 0usize;
    while let Some(slice) = data.get(from..) {
        let rel = slice
            .windows(ENCRYPTED_FILE_MARKER.len())
            .position(|candidate| candidate == ENCRYPTED_FILE_MARKER)?;
        let offset = from.checked_add(rel)?;
        if ea04_first_record_is_plausible(data, offset) {
            return Some(offset);
        }
        from = offset.checked_add(1)?;
    }
    None
}

/// Confirms an EA04 candidate by decrypting the first record's subtype with the
/// EA05-shared field keys and requiring a known AutoIt subtype string.
///
/// Reads the obfuscated subtype length, bounds it to 1..=64, then decrypts the
/// subtype bytes with the length-derived key and checks it against the known
/// subtype set via [`is_known_subtype`].
///
/// # Arguments
///
/// * `data` - bytes containing the candidate record.
/// * `offset` - offset of the record's `FILE` marker.
///
/// # Returns
///
/// `true` if the subtype decrypts to a known AutoIt subtype; `false` on any
/// out-of-range read, implausible length, or unrecognized subtype.
fn ea04_first_record_is_plausible(data: &[u8], offset: usize) -> bool {
    let Some(subtype_len_offset) = offset.checked_add(4) else {
        return false;
    };
    let Some(len_end) = subtype_len_offset.checked_add(4) else {
        return false;
    };
    let Some(len_bytes) = data.get(subtype_len_offset..len_end) else {
        return false;
    };
    let Ok(len_array) = <[u8; 4]>::try_from(len_bytes) else {
        return false;
    };
    let subtype_len = u32::from_le_bytes(len_array) ^ 0x29bc;
    if !(1..=64).contains(&subtype_len) {
        return false;
    }
    let Ok(len) = usize::try_from(subtype_len) else {
        return false;
    };
    let subtype_start = len_end;
    let Some(subtype_end) = subtype_start.checked_add(len) else {
        return false;
    };
    let Some(encrypted) = data.get(subtype_start..subtype_end) else {
        return false;
    };
    let key = 0xa25e_u32.wrapping_add(subtype_len);
    crate::crypto::mt::decrypt(encrypted, key).is_some_and(|subtype| is_known_subtype(&subtype))
}

/// Reports whether `subtype` is one of the recognized AutoIt/AutoHotkey
/// record subtype strings.
///
/// # Arguments
///
/// * `subtype` - decrypted subtype bytes to test.
///
/// # Returns
///
/// `true` if the bytes match a known subtype marker; `false` otherwise.
fn is_known_subtype(subtype: &[u8]) -> bool {
    matches!(
        subtype,
        b">AUTOIT SCRIPT<"
            | b">AUTOIT UNICODE SCRIPT<"
            | b">>>AUTOIT SCRIPT<<<"
            | b">>>AUTOIT NO CMDEXECUTE<<<"
            | b">AUTOHOTKEY SCRIPT<"
            | b">AHK WITH ICON<"
    )
}

/// Finds the start of a JB01 record stream (AutoHotkey-classic / AutoIt v2).
///
/// JB01 uses the same 16-byte GUID that prefixes the EA05/EA06 signature, but it
/// is *not* followed by the `AU3!` tag - instead a marker byte `3`, then a
/// length-prefixed passphrase block, then the record stream. Matching the marker
/// byte distinguishes JB01 from an EA05/EA06 signature sharing the GUID.
///
/// Each GUID match is validated by [`jb01_stream_after_guid`] and then by
/// [`ea04_first_record_is_plausible`] to reject incidental GUID hits.
///
/// # Arguments
///
/// * `data` - bytes to scan for a JB01 stream.
///
/// # Returns
///
/// `Some` with the first-record offset, or `None` if no plausible JB01 header
/// is found.
#[must_use]
pub fn scan_jb01_stream(data: &[u8]) -> Option<usize> {
    let guid = AUTOIT_SIGNATURE.get(0..16)?;
    let mut from = 0usize;
    while let Some(slice) = data.get(from..) {
        let rel = slice.windows(16).position(|candidate| candidate == guid)?;
        let guid_offset = from.checked_add(rel)?;
        if let Some(stream_offset) = jb01_stream_after_guid(data, guid_offset)
            && ea04_first_record_is_plausible(data, stream_offset)
        {
            return Some(stream_offset);
        }
        from = guid_offset.checked_add(1)?;
    }
    None
}

/// Returns the first-record offset after a JB01 GUID, or `None` if the bytes do
/// not match the JB01 marker + passphrase header.
///
/// Requires the marker byte `3` immediately after the 16-byte GUID, then reads
/// the obfuscated (XOR `0xfac1`) length-prefixed passphrase block. The
/// passphrase length is bounded to 1024 bytes so a spurious GUID match cannot
/// point an arbitrary distance away.
///
/// # Arguments
///
/// * `data` - bytes containing the candidate header.
/// * `guid_offset` - offset of the 16-byte JB01 GUID.
///
/// # Returns
///
/// `Some` with the offset of the first record (after the passphrase block), or
/// `None` if the marker byte is absent, a read is out of range, or the
/// passphrase length is implausible.
fn jb01_stream_after_guid(data: &[u8], guid_offset: usize) -> Option<usize> {
    let marker_offset = guid_offset.checked_add(16)?;
    if *data.get(marker_offset)? != 3 {
        return None;
    }
    let len_offset = marker_offset.checked_add(1)?;
    let len_bytes = data.get(len_offset..len_offset.checked_add(4)?)?;
    let passphrase_len = u32::from_le_bytes(<[u8; 4]>::try_from(len_bytes).ok()?) ^ 0xfac1;
    let passphrase_len = usize::try_from(passphrase_len).ok()?;
    // Bound the passphrase length so a bogus GUID match cannot point far away.
    if passphrase_len > 1024 {
        return None;
    }
    len_offset.checked_add(4)?.checked_add(passphrase_len)
}
