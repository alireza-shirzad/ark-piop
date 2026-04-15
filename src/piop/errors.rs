//! Polynomial IOP protocol errors.

use crate::{arithmetic::errors::ArithErrors, transcript::errors::TranscriptError};
use ark_std::string::String;
use thiserror::Error;

/// Errors that can occur during polynomial IOP execution.
#[derive(Error, Debug)]
pub(crate) enum PolyIOPErrors {
    /// Transcript operation failed.
    #[error("transcript error: {0}")]
    TranscriptErrors(#[from] TranscriptError),
    /// Underlying arithmetic error.
    #[error("arithmetic error: {0}")]
    ArithmeticErrors(#[from] ArithErrors),
    /// Prover-side IOP failure.
    #[error("IOP prover error: {0}")]
    Prover(String),
    /// Verifier rejected the IOP proof.
    #[error("IOP verifier error: {0}")]
    InvalidVerifier(String),
    /// Invalid protocol parameters.
    #[error("invalid IOP parameters: {0}")]
    InvalidParameters(String),
}
