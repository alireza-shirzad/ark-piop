use ark_std::string::String;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum TranscriptError {
    #[error("transcript serialization error: {0}")]
    SerializationError(ark_serialize::SerializationError),
    #[error("invalid transcript state: {0}")]
    InvalidTranscript(String),
}

impl From<ark_serialize::SerializationError> for TranscriptError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
