/////// Imports /////////
use std::string::String;

use thiserror::Error;

use crate::{
    arithmetic::errors::ArithErrors, pcs::errors::PCSError, piop::errors::PolyIOPErrors,
    prover::errors::ProverError, setup::errors::SetupError, transcript::errors::TranscriptError,
    verifier::errors::VerifierError,
};
/// The result type for the DB-SNARK system
pub type DbSnResult<T> = Result<T, DbSnError>;

/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
pub enum DbSnError {
    #[error("The proof system does not support the given data type")]
    DataTypeNotSupported,

    #[error("Error")]
    TranscriptErrors(#[from] TranscriptError),

    /// Error in the arithmetic
    #[error("Error")]
    ArithmeticErrors(#[from] ArithErrors),

    /// Error in the polynomial commitment scheme
    #[error("Error")]
    PCSErrors(#[from] PCSError),

    /// Error in the polynomial IOP
    #[error("Error")]
    PolyIOPErrors(#[from] PolyIOPErrors),

    /// Error in the verifier phase
    #[error("DbSNARK Verifier Error")]
    VerifierError(#[from] VerifierError),

    /// Error in the prover phase
    #[error("DbSNARK Prover Error")]
    ProverError(#[from] ProverError),

    /// Error in the setup phase
    #[error("DbSNARK Prover Error")]
    SetupError(#[from] SetupError),

    #[error("Error")]
    DummyError,
}

/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
pub enum InputShapeError {
    /// Empty input error
    #[error("Input cannot be empty")]
    EmptyInput,

    /// Input Length mismatch error
    #[error("Expected an input length of {expected} but got {actual}")]
    InputLengthMismatch { expected: usize, actual: usize },

    /// Input numebr of variables error
    #[error("Expected an input number of variables of {expected} but got {actual}")]
    InputNumberOfVariablesMismatch { expected: usize, actual: usize },
}

