//! Top-level error types: [`SnarkError`] aggregates every subsystem's
//! failures; most functions return [`SnarkResult<T>`].

use crate::{
    arithmetic::errors::ArithErrors, pcs::errors::PCSError, piop::errors::PolyIOPErrors,
    prover::errors::ProverError, setup::errors::SetupError, transcript::errors::TranscriptError,
    verifier::errors::VerifierError,
};
use thiserror::Error;

pub type SnarkResult<T> = Result<T, SnarkError>;

#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub enum SnarkError {
    #[error("arithmetic data type error: {0}")]
    DataTypeError(#[from] crate::arithmetic::errors::DataTypeError),

    #[error("transcript error: {0}")]
    TranscriptErrors(#[from] TranscriptError),

    #[error("arithmetic error: {0}")]
    ArithmeticErrors(#[from] ArithErrors),

    #[error("PCS error: {0}")]
    PCSErrors(#[from] PCSError),

    #[error("PolyIOP error: {0}")]
    PolyIOPErrors(#[from] PolyIOPErrors),

    #[error("verifier error: {0}")]
    VerifierError(#[from] VerifierError),

    #[error("prover error: {0}")]
    ProverError(#[from] ProverError),

    #[error("setup error: {0}")]
    SetupError(#[from] SetupError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),

    /// An artifact encoding outside the core SNARK stack failed.
    #[error("artifact error: {0}")]
    Artifact(String),
}

/// A protocol input has the wrong shape.
#[derive(Error, Debug)]
pub enum InputShapeError {
    #[error("input cannot be empty")]
    EmptyInput,

    #[error("expected input length {expected}, got {actual}")]
    InputLengthMismatch { expected: usize, actual: usize },

    #[error("expected {expected} variables, got {actual}")]
    InputNumberOfVariablesMismatch { expected: usize, actual: usize },
}

/// Asserts (in tests) that `err` is a soundness error: a false-claim error
/// under the `honest-prover` feature, a verifier check failure otherwise.
pub fn assert_soundness_error(err: SnarkError) {
    #[cfg(feature = "honest-prover")]
    {
        assert!(matches!(
            err,
            SnarkError::ProverError(crate::prover::errors::ProverError::HonestProverError(
                crate::prover::errors::HonestProverError::FalseClaim
            ))
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        assert!(matches!(
            err,
            SnarkError::VerifierError(crate::verifier::errors::VerifierError::VerifierCheckFailed(
                _
            ))
        ));
    }
}
