//! Fiat-Shamir transcript errors.

use ark_std::string::String;
use thiserror::Error;

/// Errors from the Fiat-Shamir transcript layer.
#[derive(Error, Debug)]
pub(crate) enum TranscriptError {
    /// Failed to serialize data into the transcript.
    #[error("transcript serialization error: {0}")]
    SerializationError(ark_serialize::SerializationError),
    /// The transcript state is invalid or corrupted.
    #[error("invalid transcript state: {0}")]
    InvalidTranscript(String),
}

impl From<ark_serialize::SerializationError> for TranscriptError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
