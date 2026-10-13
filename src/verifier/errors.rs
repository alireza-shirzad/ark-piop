use crate::{errors::InputShapeError, transcript::errors::TranscriptError};
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub enum VerifierError {
    #[error("no proof received")]
    ProofNotReceived,

    #[error("transcript error: {0}")]
    TranscriptErrors(#[from] TranscriptError),

    #[error("input shape error: {0}")]
    VerifierInputShapeError(#[from] InputShapeError),

    #[error("oracle {0} has no evaluation at point {1}")]
    OracleEvalNotProvided(usize, String),

    #[error("verifier check failed: {0}")]
    VerifierCheckFailed(String),
}
