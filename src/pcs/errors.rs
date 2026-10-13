use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum PCSError {
    #[error("polynomial size {0} exceeds maximum supported size {1}")]
    TooLargePolynomial(usize, usize),

    #[error("evaluation point has {0} variables, expected {1}")]
    EvaluationPointSizeMismatch(usize, usize),

    /// An opening failed the honest-prover check.
    #[allow(dead_code)]
    #[error("batch opening {0} is incorrect")]
    HonestProver(usize),

    #[error("PCS prover error: {0}")]
    ProverError(String),

    #[error("PCS verifier error: {0}")]
    VerifierError(String),
}
