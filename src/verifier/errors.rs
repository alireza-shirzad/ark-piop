/////// Imports /////////
use crate::{errors::InputShapeError, transcript::errors::TranscriptError};
use thiserror::Error;

/// An `enum` specifying the possible failure modes of the DB-SNARK verifier
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub enum VerifierError {
    #[error("The verifier has not received any proof yet")]
    ProofNotReceived,

    #[error("Error")]
    TranscriptErrors(#[from] TranscriptError),

    #[error("Error")]
    VerifierInputShapeError(#[from] InputShapeError),

    #[error("Oracle with id `{0}` cannot be evaluated at point `{1}`")]
    OracleEvalNotProvided(usize, String),

    /// Verifier Check failed
    #[error("Verifier check failed -> Details: `{0}`")]
    VerifierCheckFailed(String),
}
