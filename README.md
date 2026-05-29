# autoit

Extract and inspect compiled AutoIt payloads from AutoIt2Exe executables,
`.a3x` files, and carved payload streams.

This crate is focused on **information recovery**, not behavioral
interpretation. It should expose the facts present in the compiled payload:
container details, encoding family, resource records, script bytes, decoded
source text, token streams, timestamps, checksums, and embedded FileInstall
artifacts.

## Quick start

```rust
use autoit::{AutoItBinary, RecognitionFailure};

let data = std::fs::read("sample.exe")?;

let binary = match AutoItBinary::try_parse(&data) {
    Ok(binary) => binary,
    Err(err) if err.recognition_failure() == Some(RecognitionFailure::NotRecognized) => {
        return Ok(());
    }
    Err(err) => return Err(err.into()),
};

println!("input kind: {:?}", binary.input_kind());
println!("encoding:   {:?}", binary.encoding());
println!("container:  {:?}", binary.container());
println!("observations: {:?}", binary.observations().entries());
for record in binary.records() {
    println!(
        "record {}: {} {:?} {} bytes",
        record.index(),
        record.subtype(),
        record.profile(),
        record.payload_data().len()
    );
}
for diagnostic in binary.record_diagnostics() {
    println!("record diagnostic: {diagnostic:?}");
}
for script in binary.scripts() {
    println!("script {}: {} bytes", script.name(), script.bytes().len());
    if let Some(text) = script.source_text() {
        println!("{text}");
    }
    if let Some(tokens) = script.token_stream() {
        println!("tokens: {}", tokens.tokens().len());
    }
}
for artifact in binary.artifacts() {
    println!("artifact {}: {} bytes", artifact.name(), artifact.bytes().len());
}
for found in binary.strings() {
    println!("string {:?} @{}: {}", found.encoding(), found.offset(), found.value());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Scope

Extraction surfaces:

- PE, `.a3x`, and raw stream recognition
- EA04, EA05, EA06, and JB01 (AutoHotkey-classic / AutoIt v2-era) payload records
- encrypted/decrypted/decompressed record metadata
- container summaries for signatures, version markers, stream offsets, and PE
  `SCRIPT` resource type/name/language facts
- record extraction profiles for encoding, encryption, and compression wrapper
- record parse diagnostics when later malformed data stops extraction after
  earlier records were recovered
- script recovery and EA06 detokenization
- token streams for functions, keywords, macros, variables, literals, and
  operators
- checked token table data under `data/token/` with tests that keep parser
  lookup tables aligned
- FileInstall and other embedded artifact bytes
- offsets, RVAs, timestamps, checksums, and validation diagnostics

Non-goals:

- executing AutoIt code
- emulating expressions or reconstructing runtime values
- labeling behavior as malicious, suspicious, network, persistence, or process
  execution
- hiding raw bytes behind normalized decoded views

## Example tool

```sh
cargo run --example dump -- path/to/sample.exe
```

## Observations and recovery

`AutoItBinary::observations()` exposes concrete observations such as PE resource
discovery, raw AutoIt signatures, version markers, decrypted `FILE` markers, and
known script subtypes. These are facts observed during extraction, not behavior
labels.

The high-level parser keeps partial recovery results. If a later record is
truncated or malformed, earlier records, scripts, artifacts, and strings remain
available, and `record_diagnostics()` reports the failing record index, offset,
and reason.

## Common limitations

Packed or protected PE stubs may need external unpacking before their AutoIt
payload is statically visible. Detokenized EA06 output is source-like
reconstruction, not a promise of byte-for-byte original source text. Unsupported
legacy encodings are reported explicitly instead of guessed.

## Minimum Rust version

1.88 (edition 2024)

## License

Apache-2.0
