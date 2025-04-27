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
    /// Input shape error
    #[error("Input shape error")]
    ProverInputShapeError(#[from] InputShapeError),

    // Input does not satisfy the relation
    #[error("Input does not satisfy the relation")]
    ProverNonSatError,
}
