use thiserror::Error;

use crate::errors::InputShapeError;

#[derive(Error, Debug)]
pub enum ProverError {
    #[error("honest prover error: {0}")]
    HonestProverError(#[from] HonestProverError),
}

/// Errors raised by the honest-prover runtime checks
/// (enabled via the `honest-prover` feature).
#[derive(Error, Debug)]
pub enum HonestProverError {
    #[error("wrong input shape: {0}")]
    WrongInputShape(#[from] InputShapeError),

    #[error("the witness does not satisfy the claimed relation")]
    FalseClaim,
}
