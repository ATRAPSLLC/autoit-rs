//! Error types for AutoIt extraction.

use core::fmt;

/// Crate-wide error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    /// Creates a not-recognized error.
    ///
    /// # Returns
    ///
    /// An [`Error`] wrapping [`RecognitionFailure::NotRecognized`].
    #[must_use]
    pub const fn not_recognized() -> Self {
        Self {
            kind: ErrorKind::Recognition(RecognitionFailure::NotRecognized),
        }
    }

    /// Creates an unsupported-encoding error.
    ///
    /// # Returns
    ///
    /// An [`Error`] wrapping [`RecognitionFailure::UnsupportedEncoding`].
    #[must_use]
    pub const fn unsupported_encoding() -> Self {
        Self {
            kind: ErrorKind::Recognition(RecognitionFailure::UnsupportedEncoding),
        }
    }

    /// Creates a truncated-input error.
    ///
    /// # Returns
    ///
    /// An [`Error`] wrapping [`RecognitionFailure::Truncated`].
    #[must_use]
    pub const fn truncated() -> Self {
        Self {
            kind: ErrorKind::Recognition(RecognitionFailure::Truncated),
        }
    }

    /// Creates a malformed-container error.
    ///
    /// # Returns
    ///
    /// An [`Error`] wrapping [`RecognitionFailure::MalformedContainer`].
    #[must_use]
    pub const fn malformed_container() -> Self {
        Self {
            kind: ErrorKind::Recognition(RecognitionFailure::MalformedContainer),
        }
    }

    /// Creates a limit-exceeded error.
    ///
    /// # Returns
    ///
    /// An [`Error`] wrapping [`RecognitionFailure::LimitExceeded`].
    #[must_use]
    pub const fn limit_exceeded() -> Self {
        Self {
            kind: ErrorKind::Recognition(RecognitionFailure::LimitExceeded),
        }
    }

    /// Creates a crypto-mismatch error.
    ///
    /// # Returns
    ///
    /// An [`Error`] wrapping [`RecognitionFailure::CryptoMismatch`].
    #[must_use]
    pub const fn crypto_mismatch() -> Self {
        Self {
            kind: ErrorKind::Recognition(RecognitionFailure::CryptoMismatch),
        }
    }

    /// Creates a decompression error.
    ///
    /// # Returns
    ///
    /// An [`Error`] wrapping [`RecognitionFailure::CompressionError`].
    #[must_use]
    pub const fn compression_error() -> Self {
        Self {
            kind: ErrorKind::Recognition(RecognitionFailure::CompressionError),
        }
    }

    /// Creates a token-decoding error.
    ///
    /// # Returns
    ///
    /// An [`Error`] wrapping [`RecognitionFailure::TokenError`].
    #[must_use]
    pub const fn token_error() -> Self {
        Self {
            kind: ErrorKind::Recognition(RecognitionFailure::TokenError),
        }
    }

    /// Returns the recognition failure when this error represents one.
    ///
    /// # Returns
    ///
    /// `Some` with the wrapped [`RecognitionFailure`]; currently every [`Error`]
    /// carries one, so this never returns `None`.
    #[must_use]
    pub const fn recognition_failure(&self) -> Option<RecognitionFailure> {
        match self.kind {
            ErrorKind::Recognition(failure) => Some(failure),
        }
    }
}

impl fmt::Display for Error {
    /// Formats the error by delegating to its wrapped [`RecognitionFailure`].
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter to write into.
    ///
    /// # Returns
    ///
    /// A [`fmt::Result`] propagating any formatter write error.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Recognition(failure) => write!(f, "{failure}"),
        }
    }
}

impl std::error::Error for Error {}

/// Reasons an input could not be recognized or accepted as AutoIt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecognitionFailure {
    /// No AutoIt container or payload markers were found.
    NotRecognized,
    /// AutoIt markers were found, but the encoding is not yet supported.
    UnsupportedEncoding,
    /// The outer container shape was recognized but malformed.
    MalformedContainer,
    /// The input ended before required AutoIt data could be read.
    Truncated,
    /// A configured extraction limit was exceeded.
    LimitExceeded,
    /// AutoIt data was recognized but a cryptographic validation step failed.
    CryptoMismatch,
    /// AutoIt data was recognized but decompression failed.
    CompressionError,
    /// AutoIt data was recognized but token decoding failed.
    TokenError,
}

impl fmt::Display for RecognitionFailure {
    /// Writes a human-readable description of the recognition failure.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter to write into.
    ///
    /// # Returns
    ///
    /// A [`fmt::Result`] propagating any formatter write error.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRecognized => f.write_str("input is not recognized as AutoIt"),
            Self::UnsupportedEncoding => f.write_str("AutoIt encoding is not supported"),
            Self::MalformedContainer => f.write_str("AutoIt container is malformed"),
            Self::Truncated => f.write_str("AutoIt input is truncated"),
            Self::LimitExceeded => f.write_str("AutoIt extraction limit exceeded"),
            Self::CryptoMismatch => f.write_str("AutoIt cryptographic validation failed"),
            Self::CompressionError => f.write_str("AutoIt decompression failed"),
            Self::TokenError => f.write_str("AutoIt token decoding failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    Recognition(RecognitionFailure),
}
