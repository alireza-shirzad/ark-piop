//! Top-level error types for the ark-piop SNARK framework.
//!
//! [`SnarkError`] aggregates failures from every subsystem (arithmetic,
//! transcript, PCS, PIOP, prover, verifier, setup, I/O, serialization).
//! Most functions in the crate return [`SnarkResult<T>`].

use crate::{
    arithmetic::errors::ArithErrors, pcs::errors::PCSError, piop::errors::PolyIOPErrors,
    prover::errors::ProverError, setup::errors::SetupError, transcript::errors::TranscriptError,
    verifier::errors::VerifierError,
};
use thiserror::Error;

/// Convenience alias used throughout the crate.
pub type SnarkResult<T> = Result<T, SnarkError>;

/// Top-level error enum for the SNARK framework.
///
/// Each variant wraps a subsystem-specific error so that callers can match
/// on the origin of the failure when needed.
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub enum SnarkError {
    /// A data-type-level arithmetic error (overflow, mismatch, etc.).
    #[error("arithmetic data type error: {0}")]
    DataTypeError(#[from] crate::arithmetic::errors::DataTypeError),

    /// Fiat-Shamir transcript error (serialization into transcript, etc.).
    #[error("transcript error: {0}")]
    TranscriptErrors(#[from] TranscriptError),

    /// Polynomial arithmetic error (invalid parameters, serialization, etc.).
    #[error("arithmetic error: {0}")]
    ArithmeticErrors(#[from] ArithErrors),

    /// Polynomial commitment scheme error (wrong sizes, opening failures).
    #[error("PCS error: {0}")]
    PCSErrors(#[from] PCSError),

    /// Polynomial IOP protocol error.
    #[error("PolyIOP error: {0}")]
    PolyIOPErrors(#[from] PolyIOPErrors),

    /// Verifier-side failure (missing proof, oracle eval, check failed).
    #[error("verifier error: {0}")]
    VerifierError(#[from] VerifierError),

    /// Prover-side failure (honest-prover checks, etc.).
    #[error("prover error: {0}")]
    ProverError(#[from] ProverError),

    /// Key generation / setup failure.
    #[error("setup error: {0}")]
    SetupError(#[from] SetupError),

    /// Filesystem I/O error (e.g. reading/writing SRS files).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Arkworks serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),

    /// Error for artifact-specific encoding formats outside the core SNARK stack.
    #[error("artifact error: {0}")]
    Artifact(String),
}

/// Errors related to the shape of protocol inputs (empty, wrong length, etc.).
#[derive(Error, Debug)]
pub enum InputShapeError {
    /// The input collection must not be empty.
    #[error("input cannot be empty")]
    EmptyInput,

    /// The number of elements does not match what the protocol expects.
    #[error("expected input length {expected}, got {actual}")]
    InputLengthMismatch { expected: usize, actual: usize },

    /// The number of variables (log-size) does not match.
    #[error("expected {expected} variables, got {actual}")]
    InputNumberOfVariablesMismatch { expected: usize, actual: usize },
}

/// Assert that an error is a soundness error (false claim or verifier check
/// failure, depending on whether the `honest-prover` feature is enabled).
///
/// Used in tests to confirm that deliberately-invalid proofs are caught.
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
