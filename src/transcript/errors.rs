use ark_std::string::String;
use thiserror::Error;
/// A `enum` specifying the possible failure modes of the Transcript.

#[derive(Error, Debug)]
pub(crate) enum TranscriptError {
    #[error("Error")]
    SerializationError(ark_serialize::SerializationError),
    #[error("Error")]
    InvalidTranscript(String),
}

impl From<ark_serialize::SerializationError> for TranscriptError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
