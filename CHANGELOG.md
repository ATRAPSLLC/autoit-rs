# Changelog

## 0.1.1

- Recorded ATRAPS LLC as copyright holder and added a `NOTICE` file. No functional change.
- Dropped the deprecated `authors` field and repointed `repository` at the organisation.
- Publishing now uses crates.io trusted publishing instead of a stored registry token.

## 0.1.0

Initial release. Extracts and inspects compiled AutoIt (and AutoHotkey-classic)
payloads without executing them.

### Supported formats

- **EA04** — AutoIt v3.1.x (3.1.0, 3.1.1).
- **EA05** — AutoIt v3.2.0 – v3.2.4.x.
- **EA06** — AutoIt v3.2.6 and later (through v3.3.18.0), including tokenized
  scripts.
- **JB01** — AutoHotkey-classic (1.0.x) and AutoIt v2-era payloads, including
  the adaptive-Huffman compression.

Containers: PE executables, `.a3x` files, and carved record streams.

### Capabilities

- Container recognition and an observation log of concrete recognition facts.
- Record parsing with per-record metadata: subtype, stored name/path,
  timestamps, sizes, checksum status, and encryption/compression profiles.
- Decryption (EA05/EA04/JB01 MT stream, EA06 LAME stream) and decompression
  (EA04/EA05/EA06 LZ, JB00/JB01 adaptive Huffman).
- Script recovery: plain, UTF-16, and tokenized scripts, with EA06
  detokenization to source-like text and a structured token stream.
- `FileInstall` and other embedded artifacts preserved as named byte blobs.
- Opt-in raw string extraction over recovered payload bytes.
- Tolerant parsing that preserves records recovered before a malformed one and
  reports structured diagnostics.

Packed or protected binaries (e.g. UPX) may need external unpacking first.
Password-protected EA04/JB01 scripts are not decrypted.
