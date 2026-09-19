# AutoIt Fixture Set

Benign, deterministic AutoIt payloads compiled from a single known source
(`src/fixture.au3`, with `src/payload.txt` as the `FileInstall` target) across a
broad band of AutoIt3 toolchain versions. These are the crate's primary
ground-truth corpus, exercised by `tests/generated_corpus.rs`.

The `jb01_ahk*.exe` files are the JB01 (AutoHotkey-classic) counterpart,
compiled from `ahk-src/fixture.ahk` and `ahk-src/fixture_big.ahk` with
AutoHotkey 1.0.48.05's `Ahk2Exe`. AutoHotkey was forked from AutoIt, so its
classic compiled format is JB01: the same record container with subtype
`>AUTOHOTKEY SCRIPT<` and the adaptive-Huffman `JB01` compression. The large
fixture exercises the Huffman past its `fully_active` threshold. (Toolchain:
<https://www.autohotkey.com/download/1.0/>.)

The source is authored for this project, so the compiled binaries are
redistributable and committed here. Regenerate with `src/generate.ps1` on a
Windows host (it downloads official AutoIt3 portable zips, compiles each
variant, and emits the files collected in this directory).

## Variants

- `<ver>_def.exe` - default compiler (Unicode in the EA05 era, tokenizing in EA06).
- `<ver>_ansi.exe` - ANSI compiler (`Aut2exeA.exe`), EA05 era only.
- `<ver>_x64.exe` - 64-bit compiler (`Aut2exe_x64.exe`), 3.3.8.1 and later.
- `<ver>.a3x` - standalone compiled script (an MZ stub in the EA04 era).

Toolchains: <https://www.autoitscript.com/autoit3/files/archive/autoit/>
(`autoit-v<ver>.zip`).

## Version landmarks (observed by this crate)

- **EA04 (3.1.x)**: AutoIt 3.1.0 / 3.1.1 compile to the **EA04** format - MT
  encryption with EA05's field keys, but no per-record checksum field and an
  `EA04` compression magic, embedded in the PE overlay with no `AU3!` signature.
  Supported (password-free scripts).
- **EA05 -> EA06**: 3.2.4.9 is the last EA05; **3.2.6.0** is the first EA06
  (tokenized). Tokenization begins at 3.2.6.0.
- **Script subtype**: `>AUTOIT SCRIPT<` (PlainText) from 3.1.x, 3.2.0.1 / 3.2.2.0
  and the 3.2.4.9 ANSI compiler; `>AUTOIT UNICODE SCRIPT<` (UnicodeText) is the
  3.2.4.9 default compiler.
- **`>>>AUTOIT NO CMDEXECUTE<<<`** marker record appears from ~3.3.10 (record
  count goes 2 -> 3 for this source).
- **x64 compiler** present from 3.3.8.1 onward.

## Files

| File | Kind | Enc | Records | ScriptKind | Checksums | SHA-256 |
|---|---|---|---|---|---|---|
| `v310.a3x` | Pe | Ea04 | 2 | PlainText | all-valid | `2206d9e3d5c9ccd55a40407e6700e8eb604be8f1de93358c0427055af11e9d2f` |
| `v310_def.exe` | Pe | Ea04 | 2 | PlainText | all-valid | `9e33b6b404c77a19441adf65e3d1c8de98318f87aadb926d508cae5ef1ed8e51` |
| `v311.a3x` | Pe | Ea04 | 2 | PlainText | all-valid | `cb50c0aa2de8fb242a05d9ea9407a60b7304410156145410b2245d2d8ede193e` |
| `v311_def.exe` | Pe | Ea04 | 2 | PlainText | all-valid | `a534ff7e45343b1bf47d18cd67564016e9768e7af474a44f5764bcb31e92c0af` |
| `v3201.a3x` | A3x | Ea05 | 2 | PlainText | all-valid | `3fb25cab112c003e093f831acb29797d516cbed1f4a03bc50eef0380ea63c338` |
| `v3201_def.exe` | Pe | Ea05 | 2 | PlainText | all-valid | `9ef0724437aa28bd6dc97fcb50d135bc1eca800fd4d4f5d0435af317e683c7da` |
| `v3220.a3x` | A3x | Ea05 | 2 | PlainText | all-valid | `e4f721bddf9d7d9fd5fa8dac8693193fe36497e807d8ab589fa4a585ba592372` |
| `v3220_def.exe` | Pe | Ea05 | 2 | PlainText | all-valid | `1c6feaf8c1832ff4640d80b0f3d99e326b39117aa279642a13cf9dba2e6443f1` |
| `v3249.a3x` | A3x | Ea05 | 2 | UnicodeText | all-valid | `98c6fa489b6d3e485af13001d958fab5dd04e3656625722b9f70247f5a968235` |
| `v3249_ansi.exe` | Pe | Ea05 | 2 | PlainText | all-valid | `530e484cf037857eca17c9fd843e7fdd9fe2cb7037dba971b3c6f882248f8292` |
| `v3249_def.exe` | Pe | Ea05 | 2 | UnicodeText | all-valid | `088b9d1b5c8da4080c993a32f06ce2c5c3370372b62406a7c698f8ca446c91ae` |
| `v3260.a3x` | A3x | Ea06 | 2 | Tokenized | all-valid | `88ebcee22b03245e2a66401d5c3abe44c4782c9871635034258bcae8e4dac39c` |
| `v3260_ansi.exe` | Pe | Ea06 | 2 | Tokenized | all-valid | `42abb82dc533bd583dfb42c5b8b3eab25512a7ca5bf968e83a020390e970dbb3` |
| `v3260_def.exe` | Pe | Ea06 | 2 | Tokenized | all-valid | `d0df0d12b065910f1da214219cbbf6808684f376ee1217b1ce25244f4c173e37` |
| `v3281.a3x` | A3x | Ea06 | 2 | Tokenized | all-valid | `04600fd0bd4f0adfe99012fab6195fda8461db6376312a7933436d897ab0308d` |
| `v3281_ansi.exe` | Pe | Ea06 | 2 | Tokenized | all-valid | `920f57315f28c95a56261c10ec72ac4a164c21b2637aa2da9cf944c90d4cce60` |
| `v3281_def.exe` | Pe | Ea06 | 2 | Tokenized | all-valid | `2f5489712eefbaa2b65149cde13f205e5e6ae8ea23986c05007d2144e2b59f7d` |
| `v33102.a3x` | A3x | Ea06 | 3 | Tokenized | all-valid | `ad634bbf6fea059bdeee709b7916cad9cf5c8d646792265e3fa4a813bf0fa3b9` |
| `v33102_def.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `5b262b15ff123d2a745e9e93a5cb2c27c7ff4f5c22d7f97b6454cf07a3ad1b5a` |
| `v33102_x64.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `3907a7e72da305fe6ea1870e8ddd649aa782c99786c5bd4c9e6fbbba1acf9f57` |
| `v33120.a3x` | A3x | Ea06 | 3 | Tokenized | all-valid | `c3335c49da6e2bf59eabcd683fa51518565d11064e657ac1351058239c6d7131` |
| `v33120_def.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `2a0bd54308942a77c102603bd1ff841db08f7d0a2836751418c7f627a7dd9769` |
| `v33120_x64.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `4042be4f3839f8beb6393fc1fcb8e57faa65e6ae2e05ea3c93d41c7e3847c3cf` |
| `v33140.a3x` | A3x | Ea06 | 3 | Tokenized | all-valid | `4812b788e263d871f185ba44edf05830207821565400bc8d82e5cdb8379f6e1f` |
| `v33140_def.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `75fdc591485a627b5c1f4e93f5b510a570557b9edd6ce77270738e2b3104a163` |
| `v33140_x64.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `4c7e299da8041f48b6beb491941368d2829556ceba4155936aa4b10596f9d2aa` |
| `v33145.a3x` | A3x | Ea06 | 3 | Tokenized | all-valid | `5ab0dc93bf09e0f2508dbee2bc58325402b0cee9c895e47f4641e855dba7a633` |
| `v33145_def.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `a833a5756cadf0f5304e93a780f972a4bc81ad5cf3b81bf07b5bbff4809da35b` |
| `v33145_x64.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `75c98ca3ceb888c7d6d1b60f5841c1696ea3ed3f7369f8d19f930616479b1681` |
| `v33161.a3x` | A3x | Ea06 | 3 | Tokenized | all-valid | `bf23f611543635b7ce8bf165ade92efdb92b8c57aa812f456195487e419b41ee` |
| `v33161_def.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `60aebb322f8f57e20962166442bc7d71a41c355b359c96d6a3746b7ed60776f3` |
| `v33161_x64.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `748b7af5206951232a629d92a1e2f1d3924ce38d3f3e4a1ebaeea24df978f1ad` |
| `v33180.a3x` | A3x | Ea06 | 3 | Tokenized | all-valid | `753f784cc28fbec24f2490963093f69029604d1e37615009967f07a3a5fbf52b` |
| `v33180_def.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `22a86c89f204b6b6ac3ce2f98608b36b6360d923b96dddb71037e6df29e5c20b` |
| `v33180_x64.exe` | Pe | Ea06 | 3 | Tokenized | all-valid | `af0d66c336ffe374552effd5d10cc6ec84df06784ed90e870fb4791898ffdf53` |
| `v3381.a3x` | A3x | Ea06 | 2 | Tokenized | all-valid | `c70be235e486dbae9c9f3e2c401e97c542a6c578e66faa658c31c237dabc76cc` |
| `v3381_def.exe` | Pe | Ea06 | 2 | Tokenized | all-valid | `819b143a22d5c7426b5206dfcac487ead6b4adfd5a45d5488fa9d97d9037e97f` |
| `v3381_x64.exe` | Pe | Ea06 | 2 | Tokenized | all-valid | `b2c3207457febc2ba2be7495eac856703342fb3fe7b0df2cf15534dc417c4532` |
