/////// Imports /////////
use thiserror::Error;

use crate::errors::InputShapeError;

/// An `enum` specifying the possible failure modes of the DB-SNARK prover
#[derive(Error, Debug)]
pub enum ProverError {
    /// Error in the honest prover case
    #[error("DbSNARK Honest Prover Error")]
    HonestProverError(#[from] HonestProverError),
}

#[derive(Error, Debug)]
pub enum HonestProverError {
    /// Input shape is wrong
    #[error("Input shape error")]
    WrongInputShape(#[from] InputShapeError),

    // The claim is not true
    #[error("Input does not satisfy the relation")]
    FalseClaim,
}
