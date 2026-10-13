use crate::{arithmetic::errors::ArithErrors, transcript::errors::TranscriptError};
use ark_std::string::String;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum PolyIOPErrors {
    #[error("transcript error: {0}")]
    TranscriptErrors(#[from] TranscriptError),
    #[error("arithmetic error: {0}")]
    ArithmeticErrors(#[from] ArithErrors),
    #[error("IOP prover error: {0}")]
    Prover(String),
    #[error("IOP verifier error: {0}")]
    InvalidVerifier(String),
    #[error("invalid IOP parameters: {0}")]
    InvalidParameters(String),
}
