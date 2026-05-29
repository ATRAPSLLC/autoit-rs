//! Ground-truth tests over the committed AutoIt fixture set.
//!
//! These payloads are compiled from a single known source
//! (`tests/samples/src/fixture.au3`) across a band of AutoIt3 versions by
//! `tests/samples/src/generate.ps1`, and are checked into `tests/samples/`
//! (we authored the benign source, so the compiled output is redistributable).
//!
//! Because the source is known, these assert exact ground truth: container
//! kind, encoding, record/checksum status, script subtype, the `FileInstall`
//! payload bytes, and one-line-`If` rendering.

use std::{fs, path::Path};

use autoit::{AutoItBinary, Encoding, InputKind, ScriptKind};

const DIR: &str = "tests/samples";

/// Exact bytes of `tests/samples/src/payload.txt`, embedded by the
/// script's `FileInstall(...)` call and recovered as an artifact.
const PAYLOAD: &[u8] = b"AutoIt fixture payload v1";

struct Case {
    file: &'static str,
    kind: InputKind,
    encoding: Encoding,
    records: usize,
    script_kind: ScriptKind,
}

const CASES: &[Case] = &[
    // EA04 era (AutoIt 3.1.x): plain-text scripts, no per-record checksum. The
    // `.a3x` outputs are MZ stubs in this era, so they report as PE.
    Case {
        file: "v310_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea04,
        records: 2,
        script_kind: ScriptKind::PlainText,
    },
    Case {
        file: "v310.a3x",
        kind: InputKind::Pe,
        encoding: Encoding::Ea04,
        records: 2,
        script_kind: ScriptKind::PlainText,
    },
    Case {
        file: "v311_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea04,
        records: 2,
        script_kind: ScriptKind::PlainText,
    },
    Case {
        file: "v311.a3x",
        kind: InputKind::Pe,
        encoding: Encoding::Ea04,
        records: 2,
        script_kind: ScriptKind::PlainText,
    },
    // EA05 era: plain-text and UTF-16 scripts.
    Case {
        file: "v3201_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea05,
        records: 2,
        script_kind: ScriptKind::PlainText,
    },
    Case {
        file: "v3201.a3x",
        kind: InputKind::A3x,
        encoding: Encoding::Ea05,
        records: 2,
        script_kind: ScriptKind::PlainText,
    },
    Case {
        file: "v3220_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea05,
        records: 2,
        script_kind: ScriptKind::PlainText,
    },
    Case {
        file: "v3249_ansi.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea05,
        records: 2,
        script_kind: ScriptKind::PlainText,
    },
    Case {
        file: "v3249_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea05,
        records: 2,
        script_kind: ScriptKind::UnicodeText,
    },
    Case {
        file: "v3249.a3x",
        kind: InputKind::A3x,
        encoding: Encoding::Ea05,
        records: 2,
        script_kind: ScriptKind::UnicodeText,
    },
    // EA06 era: tokenized scripts. First EA06 toolchain is 3.2.6.0.
    Case {
        file: "v3260_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 2,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v3260.a3x",
        kind: InputKind::A3x,
        encoding: Encoding::Ea06,
        records: 2,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v3281_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 2,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v3381_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 2,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v3381_x64.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 2,
        script_kind: ScriptKind::Tokenized,
    },
    // Modern EA06: a `>>>AUTOIT NO CMDEXECUTE<<<` marker record raises the count.
    Case {
        file: "v33102_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 3,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v33102_x64.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 3,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v33145_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 3,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v33145_x64.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 3,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v33180_def.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 3,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v33180_x64.exe",
        kind: InputKind::Pe,
        encoding: Encoding::Ea06,
        records: 3,
        script_kind: ScriptKind::Tokenized,
    },
    Case {
        file: "v33180.a3x",
        kind: InputKind::A3x,
        encoding: Encoding::Ea06,
        records: 3,
        script_kind: ScriptKind::Tokenized,
    },
];

#[test]
fn generated_fixtures_match_ground_truth() -> Result<(), String> {
    if !Path::new(DIR).exists() {
        return Ok(());
    }
    for case in CASES {
        let path = Path::new(DIR).join(case.file);
        if !path.exists() {
            continue;
        }
        let data = fs::read(&path).map_err(|err| format!("{}: {err}", case.file))?;
        let binary = AutoItBinary::try_parse(data.as_slice())
            .map_err(|err| format!("{}: parse failed: {err}", case.file))?;

        eq(case.file, "input_kind", binary.input_kind(), case.kind)?;
        eq(
            case.file,
            "encoding",
            binary.encoding(),
            Some(case.encoding),
        )?;
        eq(case.file, "records", binary.records().len(), case.records)?;

        // Every record must validate — guards EA05 per-record key regressions.
        for record in binary.records() {
            eq(case.file, "checksum_valid", record.checksum_valid(), true)?;
        }

        // Exactly one script, of the expected subtype, with recovered text.
        eq(case.file, "scripts", binary.scripts().len(), 1)?;
        let script = binary.scripts().first().ok_or("missing script")?;
        eq(case.file, "script_kind", script.kind(), case.script_kind)?;
        eq(
            case.file,
            "script_text",
            script.source_text().is_some(),
            true,
        )?;

        // The FileInstall payload must round-trip byte-for-byte.
        let payload = binary
            .artifacts()
            .iter()
            .find(|a| a.subtype().contains("payload.txt") || a.name().contains("payload.txt"))
            .ok_or_else(|| format!("{}: payload.txt artifact missing", case.file))?;
        eq(case.file, "payload_bytes", payload.bytes(), PAYLOAD)?;
    }
    Ok(())
}

/// The one-line `If <cond> Then <stmt>` form must render on a single line and
/// must not push the following statements into a phantom indentation block.
#[test]
fn tokenized_fixture_renders_one_line_if() -> Result<(), String> {
    let path = Path::new(DIR).join("v33180.a3x");
    if !path.exists() {
        return Ok(());
    }
    let data = fs::read(&path).map_err(|err| err.to_string())?;
    let binary = AutoItBinary::try_parse(data.as_slice()).map_err(|err| err.to_string())?;
    let script = binary.scripts().first().ok_or("missing script")?;
    let text = script.source_text().ok_or("missing source text")?;

    // Both one-line `If`s render whole on one line (uppercased per EA06 tokens).
    if !text.contains("If $SWHO = \"\" Then Return") {
        return Err(format!("one-line If not rendered as expected:\n{text}"));
    }
    if !text.contains("If @Compiled Then FileInstall(") {
        return Err(format!(
            "one-line If FileInstall not rendered as expected:\n{text}"
        ));
    }
    // No runaway indentation: nothing should be nested more than a few tabs.
    let max_indent = text
        .lines()
        .map(|l| l.len() - l.trim_start_matches('\t').len())
        .max()
        .unwrap_or(0);
    if max_indent > 6 {
        return Err(format!("unexpected indentation depth {max_indent}"));
    }
    Ok(())
}

/// JB01 (AutoHotkey-classic) recovers plain-text script source via the adaptive
/// Huffman decompressor. Verifies recognition, the `>AUTOHOTKEY SCRIPT<` subtype,
/// and end-to-end decrypt + JB01-decompress against the compiler banner and
/// fixture body.
#[test]
fn jb01_recovers_autohotkey_script() -> Result<(), String> {
    let path = Path::new(DIR).join("jb01_ahk10485.exe");
    if !path.exists() {
        return Ok(());
    }
    let data = fs::read(&path).map_err(|err| err.to_string())?;
    let binary = AutoItBinary::try_parse(data.as_slice()).map_err(|err| err.to_string())?;
    eq(
        "jb01_ahk10485.exe",
        "encoding",
        binary.encoding(),
        Some(Encoding::Jb01),
    )?;
    let script = binary.scripts().first().ok_or("missing script")?;
    eq(
        "jb01_ahk10485.exe",
        "script_kind",
        script.kind(),
        ScriptKind::PlainText,
    )?;
    for record in binary.records() {
        eq(
            "jb01_ahk10485.exe",
            "checksum_valid",
            record.checksum_valid(),
            true,
        )?;
    }
    let text = script.source_text().ok_or("missing source text")?;
    if !text.contains("COMPILER: v1.0.48") {
        return Err(format!("missing AHK compiler banner:\n{text}"));
    }
    if !text.contains("MsgBox") || !text.contains("Greet(who)") {
        return Err(format!("missing fixture body:\n{text}"));
    }
    Ok(())
}

/// A large JB01 script (~44 KB) exercises the adaptive Huffman beyond its
/// `fully_active` threshold and many tree rebuilds, so the tail must still
/// decompress correctly.
#[test]
fn jb01_large_script_decompresses_fully() -> Result<(), String> {
    let path = Path::new(DIR).join("jb01_ahk10485_big.exe");
    if !path.exists() {
        return Ok(());
    }
    let data = fs::read(&path).map_err(|err| err.to_string())?;
    let binary = AutoItBinary::try_parse(data.as_slice()).map_err(|err| err.to_string())?;
    let script = binary.scripts().first().ok_or("missing script")?;
    let text = script.source_text().ok_or("missing source text")?;
    // The generator emits 401 numbered blocks; the final one must be intact.
    if !text.contains("var400 := \"value_400_a_chunk_2800\"") {
        return Err("large JB01 script tail not decompressed correctly".to_string());
    }
    if !text.trim_end().ends_with("Return") {
        return Err("large JB01 script did not end cleanly".to_string());
    }
    Ok(())
}

/// EA04 (AutoIt 3.1.x) recovers plain-text script source. Verify the
/// detokenized/decoded source carries the compiler's version banner and the
/// fixture's own code, confirming end-to-end decrypt + decompress.
#[test]
fn ea04_recovers_plaintext_script_source() -> Result<(), String> {
    let path = Path::new(DIR).join("v310_def.exe");
    if !path.exists() {
        return Ok(());
    }
    let data = fs::read(&path).map_err(|err| err.to_string())?;
    let binary = AutoItBinary::try_parse(data.as_slice()).map_err(|err| err.to_string())?;
    eq(
        "v310_def.exe",
        "encoding",
        binary.encoding(),
        Some(Encoding::Ea04),
    )?;
    let script = binary.scripts().first().ok_or("missing script")?;
    let text = script.source_text().ok_or("missing source text")?;
    if !text.contains("AUT2EXE VERSION: 3.1.0") {
        return Err(format!("missing 3.1.0 banner:\n{text}"));
    }
    if !text.contains("FileInstall(") {
        return Err(format!("missing fixture body:\n{text}"));
    }
    Ok(())
}

fn eq<T>(file: &str, what: &str, actual: T, expected: T) -> Result<(), String>
where
    T: core::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{file}: {what}: got {actual:?}, expected {expected:?}"
        ))
    }
}
