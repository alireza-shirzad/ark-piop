use ark_serialize::SerializationError;

use crate::{arithmetic::errors::ArithErrors, transcript::errors::TranscriptError};
use thiserror::Error;
/// A `enum` specifying the possible failure modes of the PCS.
#[derive(Error, Debug)]
pub(crate) enum PCSError {
    #[error("Error")]
    InvalidProver(String),
    #[error("Erro")]
    InvalidVerifier(String),
    #[error("Error")]
    InvalidProof(String),
    #[error("Error")]
    InvalidParameters(String),
    #[error("Error")]
    SerializationError(SerializationError),
    #[error("Error")]
    TranscriptError(#[from] TranscriptError),
    #[error("Error")]
    ArithErrors(#[from] ArithErrors),
    #[error("The provided opening is not correct")]
    InvalidOpening,
}

impl From<SerializationError> for PCSError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerializationError(e)
    }
}
