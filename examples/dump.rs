//! Dumps every piece of AutoIt extraction information for an input file.

use std::{env, fs, process::ExitCode};

use autoit::{Artifact, AutoItBinary, RecognitionFailure, Record, Script, StringFinding};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let mut path = None;
    for arg in args {
        if path.is_none() {
            path = Some(arg);
        } else {
            eprintln!("usage: dump <autoit-exe-or-a3x>");
            return ExitCode::FAILURE;
        }
    }
    let Some(path) = path else {
        eprintln!("usage: dump <autoit-exe-or-a3x>");
        return ExitCode::FAILURE;
    };

    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("failed to read input: {err}");
            return ExitCode::FAILURE;
        }
    };

    match AutoItBinary::try_parse(&data) {
        Ok(binary) => {
            print_text(&binary);
            ExitCode::SUCCESS
        }
        Err(err) if err.recognition_failure() == Some(RecognitionFailure::NotRecognized) => {
            eprintln!("not recognized as AutoIt");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("failed to parse AutoIt payload: {err}");
            ExitCode::FAILURE
        }
    }
}

fn print_text(binary: &AutoItBinary) {
    print_overview(binary);
    print_container(binary);
    print_observations(binary);
    print_records(binary.records());
    print_record_diagnostics(binary);
    print_scripts(binary.scripts());
    print_artifacts(binary.artifacts());
    print_strings(binary.strings());
}

fn print_overview(binary: &AutoItBinary) {
    section("overview");
    field("input kind", format!("{:?}", binary.input_kind()));
    field("encoding", opt_debug(binary.encoding()));
    field("records", binary.records().len().to_string());
    field("scripts", binary.scripts().len().to_string());
    field("artifacts", binary.artifacts().len().to_string());
    field("strings", binary.strings().len().to_string());
    field(
        "record diagnostics",
        binary.record_diagnostics().len().to_string(),
    );
}

fn print_container(binary: &AutoItBinary) {
    let container = binary.container();
    section("container");
    field("input kind", format!("{:?}", container.input_kind()));
    field("encoding", opt_debug(container.encoding()));
    field(
        "autoit signature offset",
        container
            .autoit_signature_offset()
            .map_or_else(|| "none".to_string(), |offset| format!("{offset}")),
    );
    field(
        "version marker",
        container.version_marker().map_or_else(
            || "none".to_string(),
            |marker| format!("{:?} @ offset {}", marker.encoding, marker.offset),
        ),
    );
    field(
        "payload stream offsets",
        if container.payload_stream_offsets().is_empty() {
            "none".to_string()
        } else {
            format!("{:?}", container.payload_stream_offsets())
        },
    );

    match container.pe_script_resource() {
        None => field("pe script resource", "none".to_string()),
        Some(resource) => {
            println!("  pe script resource:");
            subfield(
                "type",
                match resource.type_name {
                    Some(name) => format!("{} ({name})", resource.type_id),
                    None => resource.type_id.to_string(),
                },
            );
            subfield("name", escape_inline(resource.name));
            subfield(
                "language id",
                resource
                    .language_id
                    .map_or_else(|| "none".to_string(), |id| id.to_string()),
            );
            subfield("rva", format!("{:#x}", resource.rva));
            subfield("file offset", resource.offset.to_string());
            subfield("size", format!("{} bytes", resource.size));
        }
    }

    if container.packed_markers().is_empty() {
        field("packed markers", "none".to_string());
    } else {
        println!("  packed markers:");
        for marker in container.packed_markers() {
            println!("    {} @ offset {}", marker.name, marker.offset);
        }
    }
}

fn print_observations(binary: &AutoItBinary) {
    let observations = binary.observations().entries();
    section(&format!("observations ({})", observations.len()));
    for observation in observations {
        println!("  {observation:?}");
    }
}

fn print_records(records: &[Record]) {
    section(&format!("records ({})", records.len()));
    for record in records {
        println!("  #{} @ offset {}", record.index(), record.offset());
        subfield("subtype", escape_inline(record.subtype()));
        subfield("name", escape_inline(record.name()));
        let profile = record.profile();
        subfield(
            "profile",
            format!(
                "encoding={:?} encryption={:?} compression={:?}",
                profile.encoding, profile.encryption, profile.compression
            ),
        );
        subfield(
            "compressed",
            format!(
                "{} (compressed_size={}, uncompressed_size={})",
                record.compressed(),
                record.compressed_size(),
                record.uncompressed_size()
            ),
        );
        subfield(
            "checksum",
            format!(
                "{:#010x} ({})",
                record.checksum(),
                if record.checksum_valid() {
                    "valid"
                } else {
                    "invalid"
                }
            ),
        );
        subfield(
            "timestamps",
            format!(
                "created={} last_write={}",
                record.creation_time(),
                record.last_write_time()
            ),
        );
        subfield(
            "data sizes",
            format!(
                "encrypted={} decrypted={} decompressed={} payload={}",
                record.encrypted_data().len(),
                record.decrypted_data().len(),
                record
                    .decompressed_data()
                    .map_or_else(|| "none".to_string(), |data| data.len().to_string()),
                record.payload_data().len()
            ),
        );
        subfield(
            "decompression",
            format!("{:?}", record.decompression_status()),
        );
    }
}

fn print_record_diagnostics(binary: &AutoItBinary) {
    let diagnostics = binary.record_diagnostics();
    if diagnostics.is_empty() {
        return;
    }
    section(&format!("record diagnostics ({})", diagnostics.len()));
    for diagnostic in diagnostics {
        println!(
            "  record #{} @ offset {}: {:?}",
            diagnostic.record_index, diagnostic.offset, diagnostic.reason
        );
    }
}

fn print_scripts(scripts: &[Script]) {
    section(&format!("scripts ({})", scripts.len()));
    for script in scripts {
        println!(
            "  record #{} {}",
            script.record_index(),
            escape_inline(script.name())
        );
        subfield("kind", format!("{:?}", script.kind()));
        subfield("bytes", script.bytes().len().to_string());
        subfield(
            "timestamps",
            format!(
                "created={} last_write={}",
                script.creation_time(),
                script.last_write_time()
            ),
        );
        subfield(
            "text encoding",
            script.text().map_or_else(
                || "none".to_string(),
                |text| format!("{:?}", text.encoding()),
            ),
        );
        subfield("decode error", opt_debug(script.decode_error()));
        match script.token_stream() {
            None => subfield("token stream", "none".to_string()),
            Some(tokens) => subfield(
                "token stream",
                format!(
                    "line_count={} tokens={}",
                    tokens.line_count(),
                    tokens.tokens().len()
                ),
            ),
        }
        match script.source_text() {
            None => subfield("source", "<unavailable>".to_string()),
            Some(source) => {
                println!("    source ({} chars):", source.chars().count());
                print_block(source);
            }
        }
    }
}

fn print_artifacts(artifacts: &[Artifact]) {
    section(&format!("artifacts ({})", artifacts.len()));
    for artifact in artifacts {
        println!(
            "  record #{} {}",
            artifact.record_index(),
            escape_inline(artifact.name())
        );
        subfield("subtype", escape_inline(artifact.subtype()));
        subfield("bytes", artifact.bytes().len().to_string());
        subfield(
            "timestamps",
            format!(
                "created={} last_write={}",
                artifact.creation_time(),
                artifact.last_write_time()
            ),
        );
        subfield("checksum valid", artifact.checksum_valid().to_string());
        subfield(
            "decompression",
            format!("{:?}", artifact.decompression_status()),
        );
    }
}

fn print_strings(strings: &[StringFinding]) {
    section(&format!("strings ({})", strings.len()));
    for found in strings {
        println!(
            "  record #{} offset {} {:?}: {}",
            found.record_index(),
            found.offset(),
            found.encoding(),
            escape_inline(found.value())
        );
    }
}

/// Prints a section header.
fn section(title: &str) {
    println!("== {title} ==");
}

/// Prints a top-level `label: value` line.
fn field(label: &str, value: String) {
    println!("  {label}: {value}");
}

/// Prints an indented `label: value` line under a record/script/artifact entry.
fn subfield(label: &str, value: String) {
    println!("    {label}: {value}");
}

/// Prints a multi-line text block indented under its owning entry.
fn print_block(text: &str) {
    for line in text.lines() {
        println!("    | {line}");
    }
}

/// Formats an optional `Debug` value, rendering `None` as `none`.
fn opt_debug<T>(value: Option<T>) -> String
where
    T: core::fmt::Debug,
{
    value.map_or_else(|| "none".to_string(), |value| format!("{value:?}"))
}

/// Renders a string on a single line, escaping control characters so embedded
/// newlines, tabs, and other control bytes cannot corrupt the layout.
fn escape_inline(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(format!("\\u{{{:04x}}}", u32::from(ch)).as_str()),
            ch => out.push(ch),
        }
    }
    out
}
