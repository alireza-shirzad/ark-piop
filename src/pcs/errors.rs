//! Polynomial commitment scheme errors.

use thiserror::Error;

/// Errors from the polynomial commitment scheme layer.
#[derive(Error, Debug)]
pub(crate) enum PCSError {
    /// The polynomial exceeds the maximum degree supported by the SRS.
    #[error("polynomial size {0} exceeds maximum supported size {1}")]
    TooLargePolynomial(usize, usize),

    /// The evaluation point has the wrong number of variables.
    #[error("evaluation point has {0} variables, expected {1}")]
    EvaluationPointSizeMismatch(usize, usize),

    /// An opening failed the honest-prover check.
    #[allow(dead_code)]
    #[error("batch opening {0} is incorrect")]
    HonestProver(usize),

    /// Prover-side PCS error.
    #[error("PCS prover error: {0}")]
    ProverError(String),

    /// Verifier-side PCS error.
    #[error("PCS verifier error: {0}")]
    VerifierError(String),
}
