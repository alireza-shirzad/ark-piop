use crate::{arithmetic::errors::ArithErrors, transcript::errors::TranscriptError};
use ark_std::string::String;
use thiserror::Error;

//TODO: Clean up this error enum
/// A `enum` specifying the possible failure modes of the PolyIOP.
#[derive(Error, Debug)]
pub(crate) enum PolyIOPErrors {
    #[error("Error")]
    TranscriptErrors(#[from] TranscriptError),
    #[error("Error")]
    ArithmeticErrors(#[from] ArithErrors),
    #[error("Error `{0}`")]
    Prover(String),
    #[error("Errorrr `{0}`")]
    InvalidVerifier(String),
    #[error("Error `{0}`")]
    InvalidParameters(String),
}
