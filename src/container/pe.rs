//! Minimal PE resource discovery for AutoIt payloads.
//!
//! Parses just enough of a PE file to locate the embedded AutoIt script: the
//! DOS/PE headers, the optional header's resource data directory, and the
//! section table used to translate RVAs to file offsets. It then walks the
//! resource directory tree (`RT_RCDATA` -> `SCRIPT` -> language) to the data
//! entry and probes the resource payload for an AU3 stream offset.

use crate::{
    Encoding,
    container::raw,
    util::{read_u16_le, read_u32_le},
};

const IMAGE_DOS_E_LFANEW_OFFSET: usize = 0x3c;
const PE_SIGNATURE: &[u8] = b"PE\0\0";
const FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const OPTIONAL_MAGIC_PE32: u16 = 0x10b;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x20b;
const PE32_DATA_DIRECTORY_OFFSET: usize = 96;
const PE32_PLUS_DATA_DIRECTORY_OFFSET: usize = 112;
const RESOURCE_DIRECTORY_INDEX: usize = 2;
const DATA_DIRECTORY_SIZE: usize = 8;
const RESOURCE_DIRECTORY_HEADER_SIZE: usize = 16;
const RESOURCE_ENTRY_SIZE: usize = 8;
const RESOURCE_DATA_ENTRY_SIZE: usize = 16;
const RESOURCE_DIRECTORY_FLAG: u32 = 0x8000_0000;
const RESOURCE_NAME_STRING_FLAG: u32 = 0x8000_0000;
const RESOURCE_MASK: u32 = 0x7fff_ffff;
const RT_RCDATA: u16 = 10;
const AUTOIT_RESOURCE_LEADING_BYTES: usize = 0x18;

/// Located AutoIt PE script resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptResource {
    /// PE resource type id (`RT_RCDATA`).
    resource_type_id: u16,
    /// Human-readable resource type name, when known.
    resource_type_name: Option<&'static str>,
    /// PE resource name (`SCRIPT`).
    resource_name: &'static str,
    /// Resource language id, when present.
    language_id: Option<u16>,
    /// Resource RVA from the resource data entry.
    rva: u32,
    /// File offset of the resource payload.
    file_offset: usize,
    /// Resource payload size in bytes.
    size: u32,
    /// File offset where the AU3 stream begins, when resolved.
    stream_offset: Option<usize>,
}

impl ScriptResource {
    /// Returns the PE resource type id.
    ///
    /// # Returns
    ///
    /// The resource type id (`RT_RCDATA`).
    #[must_use]
    pub const fn resource_type_id(self) -> u16 {
        self.resource_type_id
    }

    /// Returns the PE resource type name, when known.
    ///
    /// # Returns
    ///
    /// `Some` with the human-readable type name, or `None` if it is unknown.
    #[must_use]
    pub const fn resource_type_name(self) -> Option<&'static str> {
        self.resource_type_name
    }

    /// Returns the PE resource name.
    ///
    /// # Returns
    ///
    /// The resource name (`SCRIPT`).
    #[must_use]
    pub const fn resource_name(self) -> &'static str {
        self.resource_name
    }

    /// Returns the PE resource language id, when present.
    ///
    /// # Returns
    ///
    /// `Some` with the language id, or `None` if the entry had none.
    #[must_use]
    pub const fn language_id(self) -> Option<u16> {
        self.language_id
    }

    /// Returns the resource RVA.
    ///
    /// # Returns
    ///
    /// The relative virtual address from the resource data entry.
    #[must_use]
    pub const fn rva(self) -> u32 {
        self.rva
    }

    /// Returns the resource file offset.
    ///
    /// # Returns
    ///
    /// The file offset of the resource payload.
    #[must_use]
    pub const fn file_offset(self) -> usize {
        self.file_offset
    }

    /// Returns the resource size.
    ///
    /// # Returns
    ///
    /// The resource payload size in bytes.
    #[must_use]
    pub const fn size(self) -> u32 {
        self.size
    }

    /// Returns the expected AU3 stream start file offset.
    ///
    /// # Returns
    ///
    /// `Some` with the file offset where the AU3 stream begins, or `None` if it
    /// could not be resolved.
    #[must_use]
    pub const fn stream_offset(self) -> Option<usize> {
        self.stream_offset
    }
}

/// A single PE section header's address and size fields.
#[derive(Debug, Clone, Copy)]
struct Section {
    /// Section RVA (virtual address).
    virtual_address: u32,
    /// Section virtual size.
    virtual_size: u32,
    /// Section raw file offset (pointer to raw data).
    raw_offset: u32,
    /// Section raw data size on disk.
    raw_size: u32,
}

/// Minimal parsed view of a PE file's resource directory location.
#[derive(Debug)]
struct PeView {
    /// RVA of the resource data directory.
    resource_rva: u32,
    /// Size of the resource data directory.
    resource_size: u32,
    /// Section table used to translate RVAs to file offsets.
    sections: Vec<Section>,
}

/// Resolved location of a resource data entry's payload.
#[derive(Debug, Clone, Copy)]
struct ResourceData {
    /// Resource payload RVA.
    rva: u32,
    /// File offset of the resource payload.
    file_offset: usize,
    /// Resource payload size in bytes.
    size: u32,
    /// File offset where the AU3 stream begins, when resolved.
    stream_offset: Option<usize>,
}

/// Finds `RT_RCDATA/SCRIPT` in a PE file.
///
/// Parses the PE headers via [`parse_pe`], locates the resource directory, and
/// walks the resource tree by type (`RT_RCDATA`), then name (`SCRIPT`), then
/// language to the data entry, returning the resolved [`ScriptResource`].
///
/// # Arguments
///
/// * `data` - the full PE file bytes.
///
/// # Returns
///
/// `Some` with the located [`ScriptResource`], or `None` if the file is not a
/// PE, has no resource directory, or lacks an `RT_RCDATA/SCRIPT` resource.
#[must_use]
pub fn find_script_resource(data: &[u8]) -> Option<ScriptResource> {
    let pe = parse_pe(data)?;
    let resource_base_offset = rva_to_file_offset(pe.resource_rva, pe.sections.as_slice())?;
    let resource_size = usize::try_from(pe.resource_size).ok()?;
    let resource_end = resource_base_offset.checked_add(resource_size)?;
    data.get(resource_base_offset..resource_end)?;

    let root = ResourceDirectory::parse(data, resource_base_offset)?;
    let rcdata_entry = root.find_id(data, resource_base_offset, RT_RCDATA)?;
    let rcdata_dir_offset = directory_offset(resource_base_offset, rcdata_entry)?;
    let rcdata_dir = ResourceDirectory::parse(data, rcdata_dir_offset)?;
    let script_entry = rcdata_dir.find_name(data, resource_base_offset, "SCRIPT")?;
    let script_dir_offset = directory_offset(resource_base_offset, script_entry)?;
    let script_dir = ResourceDirectory::parse(data, script_dir_offset)?;
    let (language_id, data_entry) = script_dir.first_data_entry(data)?;
    let data_entry_offset = entry_data_offset(resource_base_offset, data_entry)?;

    parse_resource_data_entry(data, data_entry_offset, pe.sections.as_slice()).map(|location| {
        ScriptResource {
            resource_type_id: RT_RCDATA,
            resource_type_name: Some("RT_RCDATA"),
            resource_name: "SCRIPT",
            language_id,
            rva: location.rva,
            file_offset: location.file_offset,
            size: location.size,
            stream_offset: location.stream_offset,
        }
    })
}

/// Parses the PE headers needed to locate the resource directory.
///
/// Verifies the `MZ`/`PE\0\0` signatures, reads the section count and optional
/// header size from the file header, selects the data-directory offset for
/// PE32 or PE32+, and extracts the resource directory's RVA and size. The
/// section table that follows the optional header is parsed for RVA mapping.
///
/// # Arguments
///
/// * `data` - the full PE file bytes.
///
/// # Returns
///
/// `Some` with a [`PeView`], or `None` if any signature, header field, or the
/// resource directory entry is missing, malformed, or empty.
fn parse_pe(data: &[u8]) -> Option<PeView> {
    if !data.starts_with(b"MZ") {
        return None;
    }

    let pe_offset = usize::try_from(read_u32_le(data, IMAGE_DOS_E_LFANEW_OFFSET)?).ok()?;
    let pe_sig_end = pe_offset.checked_add(PE_SIGNATURE.len())?;
    if data.get(pe_offset..pe_sig_end)? != PE_SIGNATURE {
        return None;
    }

    let file_header_offset = pe_sig_end;
    let number_of_sections = usize::from(read_u16_le(data, file_header_offset.checked_add(2)?)?);
    let optional_header_size = usize::from(read_u16_le(data, file_header_offset.checked_add(16)?)?);
    let optional_header_offset = file_header_offset.checked_add(FILE_HEADER_SIZE)?;
    let optional_header_end = optional_header_offset.checked_add(optional_header_size)?;
    data.get(optional_header_offset..optional_header_end)?;

    let optional_magic = read_u16_le(data, optional_header_offset)?;
    let data_directory_offset = match optional_magic {
        OPTIONAL_MAGIC_PE32 => optional_header_offset.checked_add(PE32_DATA_DIRECTORY_OFFSET)?,
        OPTIONAL_MAGIC_PE32_PLUS => {
            optional_header_offset.checked_add(PE32_PLUS_DATA_DIRECTORY_OFFSET)?
        }
        _ => return None,
    };
    let resource_directory_index_offset =
        RESOURCE_DIRECTORY_INDEX.checked_mul(DATA_DIRECTORY_SIZE)?;
    let resource_directory_offset =
        data_directory_offset.checked_add(resource_directory_index_offset)?;
    let resource_rva = read_u32_le(data, resource_directory_offset)?;
    let resource_size = read_u32_le(data, resource_directory_offset.checked_add(4)?)?;
    if resource_rva == 0 || resource_size == 0 {
        return None;
    }

    let section_table_offset = optional_header_end;
    let sections = parse_sections(data, section_table_offset, number_of_sections)?;

    Some(PeView {
        resource_rva,
        resource_size,
        sections,
    })
}

/// Parses `count` section headers starting at `offset` into [`Section`]s.
///
/// Reads each 40-byte section header's virtual size, virtual address, raw size,
/// and raw data pointer.
///
/// # Arguments
///
/// * `data` - the full PE file bytes.
/// * `offset` - file offset of the section table.
/// * `count` - number of section headers to read.
///
/// # Returns
///
/// `Some` with the parsed sections, or `None` if any header is out of range or
/// an offset computation overflows.
fn parse_sections(data: &[u8], offset: usize, count: usize) -> Option<Vec<Section>> {
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let section_delta = index.checked_mul(SECTION_HEADER_SIZE)?;
        let section_offset = offset.checked_add(section_delta)?;
        let section_end = section_offset.checked_add(SECTION_HEADER_SIZE)?;
        data.get(section_offset..section_end)?;

        let virtual_size = read_u32_le(data, section_offset.checked_add(8)?)?;
        let virtual_address = read_u32_le(data, section_offset.checked_add(12)?)?;
        let raw_size = read_u32_le(data, section_offset.checked_add(16)?)?;
        let raw_offset = read_u32_le(data, section_offset.checked_add(20)?)?;
        sections.push(Section {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
        });
    }
    Some(sections)
}

/// Translates a relative virtual address to a file offset.
///
/// Finds the section whose virtual range (the larger of virtual and raw size)
/// contains `rva`, then adds the RVA's offset within the section to the
/// section's raw file offset.
///
/// # Arguments
///
/// * `rva` - the relative virtual address to translate.
/// * `sections` - the parsed section table.
///
/// # Returns
///
/// `Some` with the file offset, or `None` if no section contains the RVA or an
/// offset computation overflows.
fn rva_to_file_offset(rva: u32, sections: &[Section]) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        let end = section.virtual_address.checked_add(span)?;
        if rva >= section.virtual_address && rva < end {
            let delta = rva.checked_sub(section.virtual_address)?;
            let raw = section.raw_offset.checked_add(delta)?;
            return usize::try_from(raw).ok();
        }
    }
    None
}

/// A parsed resource directory node: where its entries start and how many.
#[derive(Debug, Clone, Copy)]
struct ResourceDirectory {
    /// File offset of the first resource entry following the header.
    entries_offset: usize,
    /// Total number of entries (named plus id-keyed).
    count: usize,
}

impl ResourceDirectory {
    /// Parses a resource directory header at `offset`.
    ///
    /// Reads the named- and id-entry counts from the 16-byte header, sums them,
    /// and bounds-checks the entry array that follows.
    ///
    /// # Arguments
    ///
    /// * `data` - the full PE file bytes.
    /// * `offset` - file offset of the directory header.
    ///
    /// # Returns
    ///
    /// `Some` with the parsed directory, or `None` if the header or entry array
    /// is out of range or a computation overflows.
    fn parse(data: &[u8], offset: usize) -> Option<Self> {
        let header_end = offset.checked_add(RESOURCE_DIRECTORY_HEADER_SIZE)?;
        data.get(offset..header_end)?;
        let named = usize::from(read_u16_le(data, offset.checked_add(12)?)?);
        let ids = usize::from(read_u16_le(data, offset.checked_add(14)?)?);
        let count = named.checked_add(ids)?;
        let entries_offset = offset.checked_add(RESOURCE_DIRECTORY_HEADER_SIZE)?;
        let entries_size = count.checked_mul(RESOURCE_ENTRY_SIZE)?;
        let entries_end = entries_offset.checked_add(entries_size)?;
        data.get(entries_offset..entries_end)?;
        Some(Self {
            entries_offset,
            count,
        })
    }

    /// Finds the entry keyed by the numeric resource `id`.
    ///
    /// # Arguments
    ///
    /// * `data` - the full PE file bytes.
    /// * `_resource_base` - resource section base (unused; kept for symmetry
    ///   with [`ResourceDirectory::find_name`]).
    /// * `id` - the numeric resource id to match.
    ///
    /// # Returns
    ///
    /// `Some` with the matching entry, or `None` if no entry has that id.
    fn find_id(self, data: &[u8], _resource_base: usize, id: u16) -> Option<ResourceEntry> {
        self.entries(data).find(|entry| entry.id() == Some(id))
    }

    /// Finds the entry whose UTF-16 name equals `name`.
    ///
    /// # Arguments
    ///
    /// * `data` - the full PE file bytes.
    /// * `resource_base` - file offset of the resource section base, used to
    ///   resolve name string pointers.
    /// * `name` - the resource name to match.
    ///
    /// # Returns
    ///
    /// `Some` with the matching entry, or `None` if no named entry matches.
    fn find_name(self, data: &[u8], resource_base: usize, name: &str) -> Option<ResourceEntry> {
        self.entries(data).find(|entry| {
            entry
                .name(resource_base, data)
                .is_some_and(|candidate| candidate == name)
        })
    }

    /// Finds the first entry that points at a data entry rather than a
    /// subdirectory.
    ///
    /// # Arguments
    ///
    /// * `data` - the full PE file bytes.
    ///
    /// # Returns
    ///
    /// `Some` with a `(language id, entry)` pair where the language id is the
    /// entry's numeric key when present, or `None` if no leaf data entry
    /// exists.
    fn first_data_entry(self, data: &[u8]) -> Option<(Option<u16>, ResourceEntry)> {
        self.entries(data)
            .find(|entry| entry.is_data())
            .map(|entry| (entry.id(), entry))
    }

    /// Returns an iterator over this directory's resource entries.
    ///
    /// # Arguments
    ///
    /// * `data` - the full PE file bytes.
    ///
    /// # Returns
    ///
    /// A [`ResourceEntryIter`] yielding each parsed [`ResourceEntry`].
    fn entries(self, data: &[u8]) -> ResourceEntryIter<'_> {
        ResourceEntryIter {
            data,
            next_offset: self.entries_offset,
            remaining: self.count,
        }
    }
}

/// A single resource directory entry: a name-or-id key and a child pointer.
#[derive(Debug, Clone, Copy)]
struct ResourceEntry {
    /// Either a numeric id or, with the high bit set, a name string offset.
    name_or_id: u32,
    /// Pointer to a child directory (high bit set) or a data entry.
    offset_to_data_or_directory: u32,
}

impl ResourceEntry {
    /// Parses an 8-byte resource entry at `offset`.
    ///
    /// # Arguments
    ///
    /// * `data` - the full PE file bytes.
    /// * `offset` - file offset of the entry.
    ///
    /// # Returns
    ///
    /// `Some` with the parsed entry, or `None` if either field is out of range.
    fn parse(data: &[u8], offset: usize) -> Option<Self> {
        let name_or_id = read_u32_le(data, offset)?;
        let offset_to_data_or_directory = read_u32_le(data, offset.checked_add(4)?)?;
        Some(Self {
            name_or_id,
            offset_to_data_or_directory,
        })
    }

    /// Returns the entry's numeric id, if it is id-keyed.
    ///
    /// # Returns
    ///
    /// `Some` with the id when the name-string flag is clear and the value fits
    /// in a `u16`; `None` when the entry is name-keyed or out of range.
    fn id(self) -> Option<u16> {
        if self.name_or_id & RESOURCE_NAME_STRING_FLAG == 0 {
            u16::try_from(self.name_or_id).ok()
        } else {
            None
        }
    }

    /// Reads the entry's UTF-16 name string, if it is name-keyed.
    ///
    /// Resolves the name string pointer relative to the resource section base
    /// and decodes it via [`read_resource_name_string`].
    ///
    /// # Arguments
    ///
    /// * `resource_base` - file offset of the resource section base.
    /// * `data` - the full PE file bytes.
    ///
    /// # Returns
    ///
    /// `Some` with the decoded name, or `None` if the entry is id-keyed or the
    /// string cannot be read.
    fn name(self, resource_base: usize, data: &[u8]) -> Option<String> {
        if self.name_or_id & RESOURCE_NAME_STRING_FLAG == 0 {
            return None;
        }
        let offset = self.name_or_id & RESOURCE_MASK;
        let string_offset = resource_base.checked_add(usize::try_from(offset).ok()?)?;
        read_resource_name_string(data, string_offset)
    }

    /// Reports whether the entry points at a child subdirectory.
    ///
    /// # Returns
    ///
    /// `true` if the high bit of the child pointer is set (a subdirectory);
    /// `false` if it points at a data entry.
    fn is_directory(self) -> bool {
        self.offset_to_data_or_directory & RESOURCE_DIRECTORY_FLAG != 0
    }

    /// Reports whether the entry points at a leaf data entry.
    ///
    /// # Returns
    ///
    /// `true` if the entry points at a data entry; `false` if it points at a
    /// subdirectory.
    fn is_data(self) -> bool {
        !self.is_directory()
    }
}

/// Iterator over the consecutive entries of a [`ResourceDirectory`].
struct ResourceEntryIter<'a> {
    /// The full PE file bytes the entries are read from.
    data: &'a [u8],
    /// File offset of the next entry to parse.
    next_offset: usize,
    /// Number of entries still to yield.
    remaining: usize,
}

impl Iterator for ResourceEntryIter<'_> {
    type Item = ResourceEntry;

    /// Parses and yields the next resource entry, advancing the cursor.
    ///
    /// # Returns
    ///
    /// `Some` with the next [`ResourceEntry`], or `None` once all entries are
    /// exhausted or an entry cannot be parsed.
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let entry = ResourceEntry::parse(self.data, self.next_offset)?;
        self.next_offset = self.next_offset.checked_add(RESOURCE_ENTRY_SIZE)?;
        self.remaining = self.remaining.checked_sub(1)?;
        Some(entry)
    }
}

/// Reads a length-prefixed UTF-16 resource name string.
///
/// The string is stored as a `u16` character count followed by that many UTF-16
/// code units.
///
/// # Arguments
///
/// * `data` - the full PE file bytes.
/// * `offset` - file offset of the length prefix.
///
/// # Returns
///
/// `Some` with the decoded string, or `None` if a read is out of range or the
/// code units are not valid UTF-16.
fn read_resource_name_string(data: &[u8], offset: usize) -> Option<String> {
    let char_count = usize::from(read_u16_le(data, offset)?);
    let mut chars = Vec::with_capacity(char_count);
    let mut cursor = offset.checked_add(2)?;
    for _ in 0..char_count {
        chars.push(read_u16_le(data, cursor)?);
        cursor = cursor.checked_add(2)?;
    }
    String::from_utf16(chars.as_slice()).ok()
}

/// Resolves the file offset of the subdirectory an entry points to.
///
/// # Arguments
///
/// * `resource_base` - file offset of the resource section base.
/// * `entry` - the entry expected to point at a subdirectory.
///
/// # Returns
///
/// `Some` with the subdirectory's file offset, or `None` if the entry is not a
/// directory or the offset overflows.
fn directory_offset(resource_base: usize, entry: ResourceEntry) -> Option<usize> {
    if !entry.is_directory() {
        return None;
    }
    let offset = entry.offset_to_data_or_directory & RESOURCE_MASK;
    resource_base.checked_add(usize::try_from(offset).ok()?)
}

/// Resolves the file offset of the data entry an entry points to.
///
/// # Arguments
///
/// * `resource_base` - file offset of the resource section base.
/// * `entry` - the entry expected to point at a data entry.
///
/// # Returns
///
/// `Some` with the data entry's file offset, or `None` if the entry is a
/// directory or the offset overflows.
fn entry_data_offset(resource_base: usize, entry: ResourceEntry) -> Option<usize> {
    if !entry.is_data() {
        return None;
    }
    let offset = entry.offset_to_data_or_directory & RESOURCE_MASK;
    resource_base.checked_add(usize::try_from(offset).ok()?)
}

/// Parses a resource data entry and resolves its payload location.
///
/// Reads the payload RVA and size, translates the RVA to a file offset via
/// [`rva_to_file_offset`], bounds-checks the payload, and probes for the AU3
/// stream offset with [`resource_stream_offset`].
///
/// # Arguments
///
/// * `data` - the full PE file bytes.
/// * `offset` - file offset of the 16-byte data entry.
/// * `sections` - the parsed section table for RVA translation.
///
/// # Returns
///
/// `Some` with the resolved [`ResourceData`], or `None` if the entry or payload
/// is out of range or the RVA cannot be translated.
fn parse_resource_data_entry(
    data: &[u8],
    offset: usize,
    sections: &[Section],
) -> Option<ResourceData> {
    let end = offset.checked_add(RESOURCE_DATA_ENTRY_SIZE)?;
    data.get(offset..end)?;
    let rva = read_u32_le(data, offset)?;
    let size = read_u32_le(data, offset.checked_add(4)?)?;
    let file_offset = rva_to_file_offset(rva, sections)?;
    let size_usize = usize::try_from(size).ok()?;
    let file_end = file_offset.checked_add(size_usize)?;
    data.get(file_offset..file_end)?;
    let stream_offset = resource_stream_offset(data, file_offset, size_usize);

    Some(ResourceData {
        rva,
        file_offset,
        size,
        stream_offset,
    })
}

/// Probes a resource payload for the start of its AU3 record stream.
///
/// AutoIt PE resources prefix the stream with a fixed leading block; the version
/// marker sits 20 bytes into the payload. When the marker is recognized
/// ([`Encoding::Ea05`], [`Encoding::Ea06`], or [`Encoding::Jb01`]) the offset is
/// resolved via [`raw::payload_offset_after_version`]; otherwise it falls back
/// to a fixed leading-bytes offset.
///
/// # Arguments
///
/// * `data` - the full PE file bytes.
/// * `file_offset` - file offset of the resource payload.
/// * `size` - resource payload size in bytes.
///
/// # Returns
///
/// `Some` with the AU3 stream offset, or `None` if the payload is too small or
/// an offset computation overflows.
fn resource_stream_offset(data: &[u8], file_offset: usize, size: usize) -> Option<usize> {
    let version_offset = file_offset.checked_add(20)?;
    let minimum_end = file_offset.checked_add(AUTOIT_RESOURCE_LEADING_BYTES)?;
    let resource_end = file_offset.checked_add(size)?;
    if minimum_end > resource_end {
        return None;
    }

    let version = data.get(version_offset..version_offset.checked_add(4)?)?;
    let encoding = if version == b"EA05" {
        Encoding::Ea05
    } else if version == b"EA06" {
        Encoding::Ea06
    } else if version == b"JB01" {
        Encoding::Jb01
    } else {
        return file_offset.checked_add(AUTOIT_RESOURCE_LEADING_BYTES);
    };

    raw::payload_offset_after_version(data, version_offset, encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_rcdata_script_resource() -> Result<(), String> {
        let data = synthetic_pe_with_script_resource()?;

        let resource = find_script_resource(&data)
            .ok_or_else(|| "SCRIPT resource was not found".to_string())?;

        check_eq(resource.resource_type_id(), RT_RCDATA, "resource type id")?;
        check_eq(
            resource.resource_type_name(),
            Some("RT_RCDATA"),
            "resource type name",
        )?;
        check_eq(resource.resource_name(), "SCRIPT", "resource name")?;
        check_eq(resource.language_id(), Some(1033), "language id")?;
        check_eq(resource.rva(), 0x1100, "resource rva")?;
        check_eq(resource.file_offset(), 0x300, "resource file offset")?;
        check_eq(resource.size(), 0x40, "resource size")?;
        check_eq(resource.stream_offset(), Some(0x318), "stream offset")?;

        let binary = crate::AutoItBinary::try_parse(&data).map_err(|err| err.to_string())?;
        check_eq(binary.input_kind(), crate::InputKind::Pe, "input kind")?;
        check_eq(binary.encoding(), None, "encoding")?;
        check_eq(
            binary.container().pe_script_resource(),
            Some(crate::PeScriptResourceInfo {
                type_id: RT_RCDATA,
                type_name: Some("RT_RCDATA"),
                name: "SCRIPT",
                language_id: Some(1033),
                rva: 0x1100,
                offset: 0x300,
                size: 0x40,
            }),
            "container resource",
        )?;
        check_eq(binary.observations().entries().len(), 3, "observation count")
    }

    fn synthetic_pe_with_script_resource() -> Result<Vec<u8>, String> {
        let mut data = vec![0; 0x800];
        write_byte(&mut data, 0, b'M')?;
        write_byte(&mut data, 1, b'Z')?;
        write_u32(&mut data, 0x3c, 0x80)?;

        write_bytes(&mut data, 0x80, b"PE\0\0")?;
        write_u16(&mut data, 0x84, 0x14c)?;
        write_u16(&mut data, 0x86, 1)?;
        write_u16(&mut data, 0x94, 0xe0)?;

        let optional = 0x98;
        write_u16(&mut data, optional, OPTIONAL_MAGIC_PE32)?;
        let resource_directory = checked_add3(optional, PE32_DATA_DIRECTORY_OFFSET, 16)?;
        write_u32(&mut data, resource_directory, 0x1000)?;
        write_u32(&mut data, checked_add(resource_directory, 4)?, 0x400)?;

        let section = checked_add(optional, 0xe0)?;
        write_bytes(&mut data, section, b".rsrc\0\0\0")?;
        write_u32(&mut data, checked_add(section, 8)?, 0x400)?;
        write_u32(&mut data, checked_add(section, 12)?, 0x1000)?;
        write_u32(&mut data, checked_add(section, 16)?, 0x400)?;
        write_u32(&mut data, checked_add(section, 20)?, 0x200)?;

        let resource_base = 0x200;
        write_resource_dir(&mut data, resource_base, 0, 1)?;
        write_u32(
            &mut data,
            checked_add(resource_base, 16)?,
            u32::from(RT_RCDATA),
        )?;
        write_u32(
            &mut data,
            checked_add(resource_base, 20)?,
            RESOURCE_DIRECTORY_FLAG | 0x20,
        )?;

        let rcdata_dir = checked_add(resource_base, 0x20)?;
        write_resource_dir(&mut data, rcdata_dir, 1, 0)?;
        write_u32(
            &mut data,
            checked_add(rcdata_dir, 16)?,
            RESOURCE_NAME_STRING_FLAG | 0x60,
        )?;
        write_u32(
            &mut data,
            checked_add(rcdata_dir, 20)?,
            RESOURCE_DIRECTORY_FLAG | 0x80,
        )?;

        write_utf16_resource_name(&mut data, checked_add(resource_base, 0x60)?, "SCRIPT")?;

        let script_dir = checked_add(resource_base, 0x80)?;
        write_resource_dir(&mut data, script_dir, 0, 1)?;
        write_u32(&mut data, checked_add(script_dir, 16)?, 1033)?;
        write_u32(&mut data, checked_add(script_dir, 20)?, 0xa0)?;

        let data_entry = checked_add(resource_base, 0xa0)?;
        write_u32(&mut data, data_entry, 0x1100)?;
        write_u32(&mut data, checked_add(data_entry, 4)?, 0x40)?;

        Ok(data)
    }

    fn write_resource_dir(
        data: &mut [u8],
        offset: usize,
        named: u16,
        ids: u16,
    ) -> Result<(), String> {
        write_u16(data, checked_add(offset, 12)?, named)?;
        write_u16(data, checked_add(offset, 14)?, ids)
    }

    fn write_utf16_resource_name(
        data: &mut [u8],
        offset: usize,
        value: &str,
    ) -> Result<(), String> {
        let chars: Vec<u16> = value.encode_utf16().collect();
        let len = u16::try_from(chars.len()).map_err(|err| err.to_string())?;
        write_u16(data, offset, len)?;
        let mut cursor = checked_add(offset, 2)?;
        for ch in chars {
            write_u16(data, cursor, ch)?;
            cursor = checked_add(cursor, 2)?;
        }
        Ok(())
    }

    fn write_byte(data: &mut [u8], offset: usize, value: u8) -> Result<(), String> {
        let slot = data
            .get_mut(offset)
            .ok_or_else(|| format!("offset {offset:#x} out of bounds"))?;
        *slot = value;
        Ok(())
    }

    fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<(), String> {
        write_bytes(data, offset, &value.to_le_bytes())
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<(), String> {
        write_bytes(data, offset, &value.to_le_bytes())
    }

    fn write_bytes(data: &mut [u8], offset: usize, value: &[u8]) -> Result<(), String> {
        let end = offset
            .checked_add(value.len())
            .ok_or_else(|| "offset overflow".to_string())?;
        let destination = data
            .get_mut(offset..end)
            .ok_or_else(|| format!("range {offset:#x}..{end:#x} out of bounds"))?;
        destination.copy_from_slice(value);
        Ok(())
    }

    fn checked_add(left: usize, right: usize) -> Result<usize, String> {
        left.checked_add(right)
            .ok_or_else(|| "offset overflow".to_string())
    }

    fn checked_add3(first: usize, second: usize, third: usize) -> Result<usize, String> {
        checked_add(checked_add(first, second)?, third)
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
