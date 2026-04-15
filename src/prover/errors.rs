//! Prover-side errors.

use thiserror::Error;

use crate::errors::InputShapeError;

/// Errors that can occur during SNARK proving.
#[derive(Error, Debug)]
pub enum ProverError {
    /// The honest-prover runtime check detected a violation.
    #[error("honest prover error: {0}")]
    HonestProverError(#[from] HonestProverError),
}

/// Errors raised by the honest-prover runtime checks
/// (enabled via the `honest-prover` feature).
#[derive(Error, Debug)]
pub enum HonestProverError {
    /// The prover input does not have the expected shape.
    #[error("wrong input shape: {0}")]
    WrongInputShape(#[from] InputShapeError),

    /// The claimed relation does not hold on the provided witness.
    #[error("the witness does not satisfy the claimed relation")]
    FalseClaim,
}
