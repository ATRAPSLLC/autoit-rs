//! EA06 tokenized script parsing.
//!
//! Decodes the opcode-prefixed token stream of a compiled AutoIt (EA06) script
//! into a [`TokenStream`] via [`parse`], and can re-render that stream back to
//! source-like text with [`TokenStream::render_source`]. Keyword, function, and
//! macro names are resolved and case-canonicalized through the lookup tables in
//! the `tables` submodule.

mod tables;

use crate::{Error, util};

const OPCODE_KEYWORD_ID: u8 = 0x00;
const OPCODE_FUNCTION_ID: u8 = 0x01;
const OPCODE_U32: u8 = 0x05;
const OPCODE_U64: u8 = 0x10;
const OPCODE_F64: u8 = 0x20;
const OPCODE_KEYWORD_STRING: u8 = 0x30;
const OPCODE_FUNCTION_STRING: u8 = 0x31;
const OPCODE_MACRO_STRING: u8 = 0x32;
const OPCODE_VARIABLE_STRING: u8 = 0x33;
const OPCODE_BARE_STRING: u8 = 0x34;
const OPCODE_PROPERTY_STRING: u8 = 0x35;
const OPCODE_QUOTED_STRING: u8 = 0x36;
const OPCODE_RAW_STRING: u8 = 0x37;
const OPCODE_LINE_END: u8 = 0x7f;

/// Parsed token stream.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenStream {
    line_count: u32,
    tokens: Vec<Token>,
}

impl TokenStream {
    /// Returns the line count declared in the stream header.
    ///
    /// # Returns
    ///
    /// The number of source lines [`parse`] read from the leading `u32` count,
    /// which equals the number of [`Token::LineEnd`] tokens in the stream.
    #[must_use]
    pub const fn line_count(&self) -> u32 {
        self.line_count
    }

    /// Returns the parsed tokens in stream order.
    ///
    /// # Returns
    ///
    /// A slice of every [`Token`] read from the input, including the
    /// [`Token::LineEnd`] markers that terminate each source line.
    #[must_use]
    pub fn tokens(&self) -> &[Token] {
        self.tokens.as_slice()
    }

    /// Renders source-like AutoIt text from the token stream.
    ///
    /// Accumulates tokens per line until a [`Token::LineEnd`] is reached, then
    /// emits the line prefixed with tab indentation and terminated by `\r\n`.
    /// Indentation is tracked across lines: `line_indent` computes the indent
    /// to apply to the current line (dedenting block-closing keywords) and
    /// `next_indent` computes the level for the following line (indenting
    /// after block-opening keywords). Each non-`LineEnd` token contributes its
    /// `display_text`, joined by `render_line`.
    ///
    /// # Returns
    ///
    /// The reconstructed script text with CRLF line endings and tab indentation.
    #[must_use]
    pub fn render_source(&self) -> String {
        let mut out = String::new();
        let mut line = Vec::new();
        let mut indent = 0usize;
        for token in &self.tokens {
            match token {
                Token::LineEnd => {
                    let line_indent = line_indent(indent, line.as_slice());
                    out.push_str("\t".repeat(line_indent).as_str());
                    out.push_str(render_line(line.as_slice()).as_str());
                    out.push_str("\r\n");
                    indent = next_indent(indent, line.as_slice());
                    line.clear();
                }
                other => line.push(other.display_text()),
            }
        }
        out
    }
}

/// Token parser error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Input ended before a token could be read.
    Truncated,
    /// Token string bytes were malformed.
    BadString,
}

/// Parsed token.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Keyword token.
    Keyword(String),
    /// Unknown keyword id.
    UnknownKeywordId(i32),
    /// Function token.
    Function(String),
    /// Unknown function id.
    UnknownFunctionId(i32),
    /// Macro token, without the leading `@`.
    Macro(String),
    /// Variable token, without the leading `$`.
    Variable(String),
    /// Bare identifier/string token.
    BareString(String),
    /// Property/member token, without the leading `.`.
    Property(String),
    /// Quoted string literal, unescaped.
    QuotedString(String),
    /// Raw string token.
    RawString(String),
    /// Unsigned 32-bit integer literal.
    U32(u32),
    /// Unsigned 64-bit integer literal.
    U64(u64),
    /// Floating-point literal.
    F64(f64),
    /// Operator or punctuation token.
    Operator(&'static str),
    /// Unknown opcode.
    UnknownOpcode(u8),
    /// End-of-line token.
    LineEnd,
}

impl Token {
    /// Renders this token to its source-like display string.
    ///
    /// Each variant maps to its concrete syntax: sigils are re-attached
    /// (`@` for [`Token::Macro`], `$` for [`Token::Variable`], `.` for
    /// [`Token::Property`]), [`Token::QuotedString`] is wrapped in double
    /// quotes with embedded `"` doubled, and unresolved variants render as
    /// angle-bracketed placeholders (e.g. `<keyword:5>`, `<opcode:0xff>`).
    /// [`Token::LineEnd`] renders as the empty string.
    ///
    /// # Returns
    ///
    /// The display text for this token.
    fn display_text(&self) -> String {
        match self {
            Self::Keyword(value)
            | Self::Function(value)
            | Self::BareString(value)
            | Self::RawString(value) => value.clone(),
            Self::UnknownKeywordId(value) => format!("<keyword:{value}>"),
            Self::UnknownFunctionId(value) => format!("<function:{value}>"),
            Self::Macro(value) => format!("@{value}"),
            Self::Variable(value) => format!("${value}"),
            Self::Property(value) => format!(".{value}"),
            Self::QuotedString(value) => format!("\"{}\"", value.replace('"', "\"\"")),
            Self::U32(value) => value.to_string(),
            Self::U64(value) => value.to_string(),
            Self::F64(value) => value.to_string(),
            Self::Operator(value) => (*value).to_string(),
            Self::UnknownOpcode(value) => format!("<opcode:{value:#x}>"),
            Self::LineEnd => String::new(),
        }
    }
}

/// Parses a tokenized AutoIt (EA06) script into a [`TokenStream`].
///
/// Reads the leading little-endian `u32` line count, then loops reading
/// opcode-prefixed tokens until that many line-end markers have been seen. Each
/// line-end opcode increments the completed-line counter and pushes a
/// [`Token::LineEnd`]; every other opcode is decoded into its token.
///
/// # Arguments
///
/// * `data` - The raw tokenized script bytes, starting with the line count.
///
/// # Returns
///
/// A [`TokenStream`] holding the declared line count and all parsed tokens.
///
/// # Errors
///
/// Returns [`TokenError::Truncated`] if the input ends before a required field
/// can be read, or if the completed-line counter would overflow. Returns
/// [`TokenError::BadString`] if a string token's length prefix or XOR-keyed
/// UTF-16 code units are malformed.
pub fn parse(data: &[u8]) -> Result<TokenStream, TokenError> {
    let mut reader = TokenReader::new(data);
    let line_count = reader.read_u32_le()?;
    let mut completed_lines = 0u32;
    let mut tokens = Vec::new();
    while completed_lines < line_count {
        let opcode = reader.read_u8()?;
        if opcode == OPCODE_LINE_END {
            completed_lines = completed_lines
                .checked_add(1)
                .ok_or(TokenError::Truncated)?;
            tokens.push(Token::LineEnd);
        } else {
            tokens.push(read_token(opcode, &mut reader)?);
        }
    }
    Ok(TokenStream { line_count, tokens })
}

/// Decodes a single non-`LineEnd` token from the given opcode.
///
/// Dispatches on `opcode`: id opcodes read an `i32` and resolve it through
/// [`tables::keyword_by_id`] / [`tables::function_by_id`], falling back to the
/// `Unknown*Id` variants; numeric opcodes read their fixed-width literal;
/// string opcodes read an XOR-keyed UTF-16 payload (canonicalizing keyword,
/// function, and macro casing). Any unrecognized opcode is mapped to an
/// [`Token::Operator`] via [`operator`], or [`Token::UnknownOpcode`] if that
/// also fails.
///
/// # Arguments
///
/// * `opcode` - The leading opcode byte that selects the token form.
/// * `reader` - The [`TokenReader`] positioned just past the opcode.
///
/// # Returns
///
/// The decoded [`Token`].
///
/// # Errors
///
/// Returns [`TokenError::Truncated`] if the reader runs out of bytes for the
/// token's payload, or [`TokenError::BadString`] if a string payload is
/// malformed.
fn read_token(opcode: u8, reader: &mut TokenReader<'_>) -> Result<Token, TokenError> {
    match opcode {
        OPCODE_KEYWORD_ID => {
            let id = reader.read_i32_le()?;
            Ok(tables::keyword_by_id(id).map_or(Token::UnknownKeywordId(id), Token::Keyword))
        }
        OPCODE_FUNCTION_ID => {
            let id = reader.read_i32_le()?;
            Ok(tables::function_by_id(id).map_or(Token::UnknownFunctionId(id), Token::Function))
        }
        OPCODE_U32 => Ok(Token::U32(reader.read_u32_le()?)),
        OPCODE_U64 => Ok(Token::U64(reader.read_u64_le()?)),
        OPCODE_F64 => Ok(Token::F64(reader.read_f64_le()?)),
        OPCODE_KEYWORD_STRING => Ok(Token::Keyword(tables::canonical_keyword(
            reader.read_xored_utf16_string()?.as_str(),
        ))),
        OPCODE_FUNCTION_STRING => Ok(Token::Function(tables::canonical_function(
            reader.read_xored_utf16_string()?.as_str(),
        ))),
        OPCODE_MACRO_STRING => Ok(Token::Macro(tables::canonical_macro(
            reader.read_xored_utf16_string()?.as_str(),
        ))),
        OPCODE_VARIABLE_STRING => Ok(Token::Variable(reader.read_xored_utf16_string()?)),
        OPCODE_BARE_STRING => Ok(Token::BareString(reader.read_xored_utf16_string()?)),
        OPCODE_PROPERTY_STRING => Ok(Token::Property(reader.read_xored_utf16_string()?)),
        OPCODE_QUOTED_STRING => Ok(Token::QuotedString(reader.read_xored_utf16_string()?)),
        OPCODE_RAW_STRING => Ok(Token::RawString(reader.read_xored_utf16_string()?)),
        _ => operator(opcode).map_or(Ok(Token::UnknownOpcode(opcode)), |op| {
            Ok(Token::Operator(op))
        }),
    }
}

/// Computes the indentation level to render the current line at.
///
/// Block-closing keywords (`Case`, `Else`, `ElseIf`, `WEnd`, `Until`, `Next`,
/// `EndSelect`, `EndSwitch`, `EndFunc`, `EndIf`) are dedented one level
/// relative to the surrounding block; every other line keeps the current
/// `indent`. The dedent saturates at zero.
///
/// # Arguments
///
/// * `indent` - The current block indentation level.
/// * `line` - The display strings of the tokens on the line being rendered.
///
/// # Returns
///
/// The number of leading tabs to emit for this line.
fn line_indent(indent: usize, line: &[String]) -> usize {
    match first_line_token(line) {
        Some(
            "Case" | "Else" | "ElseIf" | "WEnd" | "Until" | "Next" | "EndSelect" | "EndSwitch"
            | "EndFunc" | "EndIf",
        ) => indent.saturating_sub(1),
        _ => indent,
    }
}

/// Computes the indentation level for the line following the current one.
///
/// Block-opening keywords (`While`, `Do`, `For`, `Select`, `Switch`, `Func`)
/// increase the level by one; block-closing keywords decrease it by one
/// (saturating at zero). `If` is special: it opens a block only in its
/// multi-line form, detected by `Then` being the last token on the line. A
/// one-line `If <cond> Then <stmt>` has no matching `EndIf`, so it must not
/// increase the indentation level.
///
/// # Arguments
///
/// * `indent` - The current block indentation level.
/// * `line` - The display strings of the tokens on the line just rendered.
///
/// # Returns
///
/// The indentation level to apply to the next line.
fn next_indent(indent: usize, line: &[String]) -> usize {
    match first_line_token(line) {
        // `If` opens a block only in its multi-line form, where `Then` is the
        // final token on the line. A one-line `If <cond> Then <stmt>` has no
        // matching `EndIf`, so it must not increase the indentation level.
        Some("If") if last_line_token(line) == Some("Then") => indent.saturating_add(1),
        Some("If") => indent,
        Some("While" | "Do" | "For" | "Select" | "Switch" | "Func") => indent.saturating_add(1),
        Some("WEnd" | "Until" | "Next" | "EndSelect" | "EndSwitch" | "EndFunc" | "EndIf") => {
            indent.saturating_sub(1)
        }
        _ => indent,
    }
}

/// Returns the first token's text on a line, used for indent decisions.
///
/// # Arguments
///
/// * `line` - The display strings of the tokens on a line.
///
/// # Returns
///
/// `Some` with the first token's text, or `None` if the line is empty.
fn first_line_token(line: &[String]) -> Option<&str> {
    line.first().map(String::as_str)
}

/// Returns the last token's text on a line, used to detect a trailing `Then`.
///
/// # Arguments
///
/// * `line` - The display strings of the tokens on a line.
///
/// # Returns
///
/// `Some` with the last token's text, or `None` if the line is empty.
fn last_line_token(line: &[String]) -> Option<&str> {
    line.last().map(String::as_str)
}

/// Joins a line's token display strings with spacing rules applied.
///
/// Tokens are concatenated with a single space between them, except where
/// [`has_no_space_before`] suppresses the space before the current token or
/// [`has_no_space_after`] suppresses it after the previous token (so commas
/// hug the preceding token and brackets hug their operands).
///
/// # Arguments
///
/// * `line` - The display strings of the tokens on the line to render.
///
/// # Returns
///
/// The rendered line text without leading indentation or line terminator.
fn render_line(line: &[String]) -> String {
    let mut out = String::new();
    let mut previous: Option<&str> = None;
    for token in line {
        let current = token.as_str();
        if !out.is_empty()
            && !has_no_space_before(current)
            && !previous.is_some_and(has_no_space_after)
        {
            out.push(' ');
        }
        out.push_str(current);
        previous = Some(current);
    }
    out
}

/// Reports whether no space should precede this token when rendering a line.
///
/// # Arguments
///
/// * `token` - The display text of the current token.
///
/// # Returns
///
/// `true` for `,`, `)`, `]`, `(`, and `[`, which hug the preceding token.
fn has_no_space_before(token: &str) -> bool {
    matches!(token, "," | ")" | "]" | "(" | "[")
}

/// Reports whether no space should follow this token when rendering a line.
///
/// # Arguments
///
/// * `token` - The display text of the previous token.
///
/// # Returns
///
/// `true` for `(` and `[`, so the following operand hugs the opening bracket.
fn has_no_space_after(token: &str) -> bool {
    matches!(token, "(" | "[")
}

/// Maps an operator/punctuation opcode to its source text.
///
/// Covers the contiguous `0x40`..=`0x58` opcode range, mapping each to its
/// AutoIt operator or punctuation string (comparison, arithmetic, assignment,
/// grouping, and the `?`/`:` ternary tokens).
///
/// # Arguments
///
/// * `opcode` - The opcode byte to translate.
///
/// # Returns
///
/// `Some` with the static operator text, or `None` if the opcode is not a
/// known operator.
fn operator(opcode: u8) -> Option<&'static str> {
    match opcode {
        0x40 => Some(","),
        0x41 => Some("="),
        0x42 => Some(">"),
        0x43 => Some("<"),
        0x44 => Some("<>"),
        0x45 => Some(">="),
        0x46 => Some("<="),
        0x47 => Some("("),
        0x48 => Some(")"),
        0x49 => Some("+"),
        0x4a => Some("-"),
        0x4b => Some("/"),
        0x4c => Some("*"),
        0x4d => Some("&"),
        0x4e => Some("["),
        0x4f => Some("]"),
        0x50 => Some("=="),
        0x51 => Some("^"),
        0x52 => Some("+="),
        0x53 => Some("-="),
        0x54 => Some("/="),
        0x55 => Some("*="),
        0x56 => Some("&="),
        0x57 => Some("?"),
        0x58 => Some(":"),
        _ => None,
    }
}

/// Cursor-tracking reader over the tokenized script bytes.
struct TokenReader<'a> {
    /// The full input byte slice being read.
    data: &'a [u8],
    /// The current read offset into `data`.
    cursor: usize,
}

impl<'a> TokenReader<'a> {
    /// Creates a reader positioned at the start of `data`.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice to read tokens from.
    ///
    /// # Returns
    ///
    /// A [`TokenReader`] with its cursor at offset zero.
    const fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    /// Reads one byte and advances the cursor.
    ///
    /// # Returns
    ///
    /// The byte at the current cursor position.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Truncated`] if the cursor is at or past the end of
    /// the input, or if advancing the cursor would overflow.
    fn read_u8(&mut self) -> Result<u8, TokenError> {
        let byte = *self.data.get(self.cursor).ok_or(TokenError::Truncated)?;
        self.cursor = self.cursor.checked_add(1).ok_or(TokenError::Truncated)?;
        Ok(byte)
    }

    /// Reads a little-endian `u32` and advances the cursor by four bytes.
    ///
    /// # Returns
    ///
    /// The decoded unsigned 32-bit value.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Truncated`] if fewer than four bytes remain, or if
    /// advancing the cursor would overflow.
    fn read_u32_le(&mut self) -> Result<u32, TokenError> {
        let value = util::read_u32_le(self.data, self.cursor).ok_or(TokenError::Truncated)?;
        self.cursor = self.cursor.checked_add(4).ok_or(TokenError::Truncated)?;
        Ok(value)
    }

    /// Reads a little-endian `i32` by reinterpreting a `u32`'s bit pattern.
    ///
    /// # Returns
    ///
    /// The decoded signed 32-bit value.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Truncated`] if fewer than four bytes remain.
    fn read_i32_le(&mut self) -> Result<i32, TokenError> {
        let value = self.read_u32_le()?;
        Ok(i32::from_le_bytes(value.to_le_bytes()))
    }

    /// Reads a little-endian `u64` as two consecutive `u32` halves.
    ///
    /// The first `u32` supplies the low 32 bits and the second the high bits.
    ///
    /// # Returns
    ///
    /// The decoded unsigned 64-bit value.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Truncated`] if fewer than eight bytes remain.
    fn read_u64_le(&mut self) -> Result<u64, TokenError> {
        let low = u64::from(self.read_u32_le()?);
        let high = u64::from(self.read_u32_le()?);
        Ok(low | (high << 32))
    }

    /// Reads a little-endian IEEE-754 `f64` from its raw 64-bit pattern.
    ///
    /// # Returns
    ///
    /// The decoded floating-point value.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Truncated`] if fewer than eight bytes remain.
    fn read_f64_le(&mut self) -> Result<f64, TokenError> {
        Ok(f64::from_bits(self.read_u64_le()?))
    }

    /// Reads a length-prefixed, XOR-keyed UTF-16 string token.
    ///
    /// The leading `u32` is both the UTF-16 code-unit count and the XOR key:
    /// each subsequent little-endian `u16` unit is XORed with the low 16 bits
    /// of the key before being decoded. The recovered units are then assembled
    /// into a [`String`].
    ///
    /// # Returns
    ///
    /// The decoded string.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Truncated`] if the length prefix or any code unit
    /// runs past the end of the input. Returns [`TokenError::BadString`] if the
    /// key cannot be converted to the needed width or if the decoded units are
    /// not valid UTF-16.
    fn read_xored_utf16_string(&mut self) -> Result<String, TokenError> {
        let key = self.read_u32_le()?;
        let char_count = usize::try_from(key).map_err(|_err| TokenError::BadString)?;
        // The length prefix is attacker-controlled and unbounded (up to
        // `u32::MAX`), while every code unit consumes two bytes of input. Cap
        // the up-front reservation at what the remaining input could actually
        // supply, so a tiny malformed token cannot force a multi-gigabyte
        // allocation; the loop below still fails with `Truncated` once the bytes
        // run out. For a well-formed string the units are all present, so the
        // bound never under-reserves. Mirrors the cap the JB decompressor applies.
        let max_units = self.data.len().saturating_sub(self.cursor) / 2;
        let mut units = Vec::with_capacity(char_count.min(max_units));
        for _ in 0..char_count {
            let raw = util::read_u16_le(self.data, self.cursor).ok_or(TokenError::Truncated)?;
            self.cursor = self.cursor.checked_add(2).ok_or(TokenError::Truncated)?;
            let decoded = raw ^ u16::try_from(key).map_err(|_err| TokenError::BadString)?;
            units.push(decoded);
        }
        String::from_utf16(units.as_slice()).map_err(|_err| TokenError::BadString)
    }
}

impl From<TokenError> for Error {
    /// Converts a [`TokenError`] into the crate-level [`Error`].
    ///
    /// All token-parsing failures collapse into a single token error; the
    /// specific [`TokenError`] variant is not preserved.
    ///
    /// # Arguments
    ///
    /// * `_value` - The [`TokenError`] to convert (its variant is discarded).
    ///
    /// # Returns
    ///
    /// The crate [`Error`] produced by `Error::token_error`.
    fn from(_value: TokenError) -> Self {
        Error::token_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_variable_assignment() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_VARIABLE_STRING);
        append_xored_string(&mut data, "x")?;
        data.push(0x41);
        data.push(OPCODE_U32);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(stream.line_count(), 1, "line count")?;
        check_eq(stream.render_source(), "$x = 1\r\n".to_string(), "render")
    }

    #[test]
    fn renders_simple_msgbox_call() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&248i32.to_le_bytes());
        data.push(0x47);
        data.push(OPCODE_U32);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(0x40);
        data.push(OPCODE_QUOTED_STRING);
        append_xored_string(&mut data, "title")?;
        data.push(0x40);
        data.push(OPCODE_QUOTED_STRING);
        append_xored_string(&mut data, "text")?;
        data.push(0x48);
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("MsgBox".to_string()),
                Token::Operator("("),
                Token::U32(0),
                Token::Operator(","),
                Token::QuotedString("title".to_string()),
                Token::Operator(","),
                Token::QuotedString("text".to_string()),
                Token::Operator(")"),
                Token::LineEnd,
            ],
            "tokens",
        )?;
        check_eq(
            stream.render_source(),
            "MsgBox(0, \"title\", \"text\")\r\n".to_string(),
            "render",
        )
    }

    #[test]
    fn preserves_unknown_opcode() -> Result<(), String> {
        let data = [1, 0, 0, 0, 0xff, OPCODE_LINE_END];
        let stream = parse(&data).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[Token::UnknownOpcode(0xff), Token::LineEnd],
            "tokens",
        )
    }

    #[test]
    fn oversized_string_length_fails_fast_without_overallocating() -> Result<(), String> {
        // A string token whose length prefix claims `u32::MAX` code units but is
        // backed by no actual units must fail fast with `Truncated` rather than
        // reserving gigabytes up front. The reservation is bounded by the
        // remaining input (zero here), so the read loop runs out of bytes on its
        // first iteration instead of allocating ~8 GiB.
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_VARIABLE_STRING);
        data.extend_from_slice(&u32::MAX.to_le_bytes());

        match parse(data.as_slice()) {
            Err(TokenError::Truncated) => Ok(()),
            other => Err(format!("expected Truncated, got {other:?}")),
        }
    }

    #[test]
    fn parses_quoted_macro_and_unknown_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_KEYWORD_ID);
        data.extend_from_slice(&4i32.to_le_bytes());
        data.push(OPCODE_MACRO_STRING);
        append_xored_string(&mut data, "ScriptName")?;
        data.push(OPCODE_QUOTED_STRING);
        append_xored_string(&mut data, "a\"b")?;
        data.push(OPCODE_KEYWORD_ID);
        data.extend_from_slice(&999i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&999i32.to_le_bytes());
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Keyword("If".to_string()),
                Token::Macro("ScriptName".to_string()),
                Token::QuotedString("a\"b".to_string()),
                Token::UnknownKeywordId(999),
                Token::UnknownFunctionId(999),
                Token::LineEnd,
            ],
            "tokens",
        )?;
        check_eq(
            stream.render_source(),
            "If @ScriptName \"a\"\"b\" <keyword:999> <function:999>\r\n".to_string(),
            "render",
        )
    }

    #[test]
    fn resolves_function_ids_and_canonicalizes_strings() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&248i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "runwait")?;
        data.push(OPCODE_MACRO_STRING);
        append_xored_string(&mut data, "scriptname")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("MsgBox".to_string()),
                Token::Function("RunWait".to_string()),
                Token::Macro("ScriptName".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_expanded_low_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&12i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&17i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&27i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "binarytostring")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("Beep".to_string()),
                Token::Function("BitAND".to_string()),
                Token::Function("Ceiling".to_string()),
                Token::Function("BinaryToString".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_expanded_control_and_directory_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&30i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&45i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&56i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "consolewriteerror")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("ClipGet".to_string()),
                Token::Function("ControlListView".to_string()),
                Token::Function("DirMove".to_string()),
                Token::Function("ConsoleWriteError".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_expanded_dll_drive_and_env_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&59i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&68i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&84i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&85i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&86i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "drivegetfilesystem")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("DllCallbackFree".to_string()),
                Token::Function("DllStructSetData".to_string()),
                Token::Function("EnvUpdate".to_string()),
                Token::Function("Eval".to_string()),
                Token::Function("Execute".to_string()),
                Token::Function("DriveGetFileSystem".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_expanded_file_setup_and_metadata_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&87i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&91i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&95i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&99i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&106i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "filegetshortcut")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("Exp".to_string()),
                Token::Function("FileCreateNTFSLink".to_string()),
                Token::Function("FileFindFirstFile".to_string()),
                Token::Function("FileGetEncoding".to_string()),
                Token::Function("FileGetVersion".to_string()),
                Token::Function("FileGetShortcut".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_expanded_file_io_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&107i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&111i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&113i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&123i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&126i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "filesavedialog")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("FileInstall".to_string()),
                Token::Function("FileRead".to_string()),
                Token::Function("FileReadToArray".to_string()),
                Token::Function("FileWriteLine".to_string()),
                Token::Function("FuncName".to_string()),
                Token::Function("FileSaveDialog".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_expanded_gui_http_and_inet_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&127i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&142i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&162i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&181i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&200i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&204i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&207i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "guictrlsetbkcolor")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("GUICreate".to_string()),
                Token::Function("GUICtrlCreateListView".to_string()),
                Token::Function("GUICtrlRegisterListViewSort".to_string()),
                Token::Function("GUIDelete".to_string()),
                Token::Function("HttpSetProxy".to_string()),
                Token::Function("InetGet".to_string()),
                Token::Function("InetRead".to_string()),
                Token::Function("GUICtrlSetBkColor".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_expanded_ini_type_map_mouse_and_msgbox_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&208i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&211i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&228i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&235i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&241i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&248i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "isstring")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("IniDelete".to_string()),
                Token::Function("IniReadSectionNames".to_string()),
                Token::Function("IsMap".to_string()),
                Token::Function("MapExists".to_string()),
                Token::Function("MouseClickDrag".to_string()),
                Token::Function("MsgBox".to_string()),
                Token::Function("IsString".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_expanded_object_process_registry_and_run_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&249i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&255i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&263i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&277i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&280i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&288i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&300i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "soundsetwavevolume")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("Number".to_string()),
                Token::Function("OnAutoItExitRegister".to_string()),
                Token::Function("ProcessExists".to_string()),
                Token::Function("RegRead".to_string()),
                Token::Function("Run".to_string()),
                Token::Function("ShellExecute".to_string()),
                Token::Function("StatusbarGetText".to_string()),
                Token::Function("SoundSetWaveVolume".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn resolves_final_string_network_tray_and_window_function_ids() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&301i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&310i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&325i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&339i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&368i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&393i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_ID);
        data.extend_from_slice(&404i32.to_le_bytes());
        data.push(OPCODE_FUNCTION_STRING);
        append_xored_string(&mut data, "stringtoasciiarray")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Function("StdErrRead".to_string()),
                Token::Function("StringInStr".to_string()),
                Token::Function("StringRegExp".to_string()),
                Token::Function("TCPAccept".to_string()),
                Token::Function("UBound".to_string()),
                Token::Function("WinMenuSelectItem".to_string()),
                Token::Function("WinWaitNotActive".to_string()),
                Token::Function("StringToASCIIArray".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn canonicalizes_expanded_official_macros() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_MACRO_STRING);
        append_xored_string(&mut data, "appdatacommondir")?;
        data.push(OPCODE_MACRO_STRING);
        append_xored_string(&mut data, "gui_ctrlhandle")?;
        data.push(OPCODE_MACRO_STRING);
        append_xored_string(&mut data, "sw_shownoactivate")?;
        data.push(OPCODE_MACRO_STRING);
        append_xored_string(&mut data, "tray_id")?;
        data.push(OPCODE_MACRO_STRING);
        append_xored_string(&mut data, "year")?;
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.tokens(),
            &[
                Token::Macro("AppDataCommonDir".to_string()),
                Token::Macro("GUI_CtrlHandle".to_string()),
                Token::Macro("SW_SHOWNOACTIVATE".to_string()),
                Token::Macro("TRAY_ID".to_string()),
                Token::Macro("YEAR".to_string()),
                Token::LineEnd,
            ],
            "tokens",
        )
    }

    #[test]
    fn renders_control_flow_with_indentation() -> Result<(), String> {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.push(OPCODE_KEYWORD_ID);
        data.extend_from_slice(&4i32.to_le_bytes());
        data.push(OPCODE_VARIABLE_STRING);
        append_xored_string(&mut data, "x")?;
        data.push(OPCODE_KEYWORD_ID);
        data.extend_from_slice(&5i32.to_le_bytes());
        data.push(OPCODE_LINE_END);
        data.push(OPCODE_VARIABLE_STRING);
        append_xored_string(&mut data, "x")?;
        data.push(0x41);
        data.push(OPCODE_U32);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_LINE_END);
        data.push(OPCODE_KEYWORD_ID);
        data.extend_from_slice(&8i32.to_le_bytes());
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.render_source(),
            "If $x Then\r\n\t$x = 1\r\nEndIf\r\n".to_string(),
            "render",
        )
    }

    #[test]
    fn one_line_if_does_not_increase_indentation() -> Result<(), String> {
        // `If $x Then $x = 1` is a one-line statement with no `EndIf`; the
        // following line must stay at the outer indentation level rather than
        // accumulating a phantom block indent.
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        // If $x Then $x = 1
        data.push(OPCODE_KEYWORD_ID);
        data.extend_from_slice(&4i32.to_le_bytes());
        data.push(OPCODE_VARIABLE_STRING);
        append_xored_string(&mut data, "x")?;
        data.push(OPCODE_KEYWORD_ID);
        data.extend_from_slice(&5i32.to_le_bytes());
        data.push(OPCODE_VARIABLE_STRING);
        append_xored_string(&mut data, "x")?;
        data.push(0x41);
        data.push(OPCODE_U32);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(OPCODE_LINE_END);
        // $y = 2
        data.push(OPCODE_VARIABLE_STRING);
        append_xored_string(&mut data, "y")?;
        data.push(0x41);
        data.push(OPCODE_U32);
        data.extend_from_slice(&2u32.to_le_bytes());
        data.push(OPCODE_LINE_END);

        let stream = parse(data.as_slice()).map_err(|err| format!("{err:?}"))?;

        check_eq(
            stream.render_source(),
            "If $x Then $x = 1\r\n$y = 2\r\n".to_string(),
            "render",
        )
    }

    fn append_xored_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
        let units: Vec<u16> = value.encode_utf16().collect();
        let key = u32::try_from(units.len()).map_err(|err| err.to_string())?;
        out.extend_from_slice(&key.to_le_bytes());
        let key16 = u16::try_from(key).map_err(|err| err.to_string())?;
        for unit in units {
            out.extend_from_slice(&(unit ^ key16).to_le_bytes());
        }
        Ok(())
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
