//! Verifier-side errors.

use crate::{errors::InputShapeError, transcript::errors::TranscriptError};
use thiserror::Error;

/// Errors that can occur during SNARK verification.
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub enum VerifierError {
    /// The verifier was invoked before a proof was supplied.
    #[error("no proof received")]
    ProofNotReceived,

    /// Fiat-Shamir transcript error during verification.
    #[error("transcript error: {0}")]
    TranscriptErrors(#[from] TranscriptError),

    /// The verifier input shape is incorrect.
    #[error("input shape error: {0}")]
    VerifierInputShapeError(#[from] InputShapeError),

    /// An oracle evaluation was requested but not provided in the proof.
    #[error("oracle {0} has no evaluation at point {1}")]
    OracleEvalNotProvided(usize, String),

    /// A verifier check (sumcheck, opening, etc.) failed.
    #[error("verifier check failed: {0}")]
    VerifierCheckFailed(String),
}
