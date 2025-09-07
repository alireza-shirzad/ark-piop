use thiserror::Error;
/// A `enum` specifying the possible failure modes of the PCS.
#[derive(Error, Debug)]
pub(crate) enum PCSError {
    #[error("Maximum polynomial size supported is {1}, but got {0}")]
    TooLargePolynomial(usize, usize),

    #[error("The size of the evaluation point {0} does not match the expected size {1}")]
    EvaluationPointSizeMismatch(usize, usize),

    #[error("The {0}-th opening in the batch is not correct")]
    HonestProver(usize),

    #[error("PCS Prover Error `{0}`")]
    ProverError(String),

    #[error("PCS Verifier Error `{0}`")]
    VerifierError(String),
}
