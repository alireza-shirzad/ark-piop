use crate::{arithmetic::errors::ArithErrors, transcript::errors::TranscriptError};
use ark_std::string::String;
use thiserror::Error;

/// A `enum` specifying the possible failure modes of the PolyIOP.
#[derive(Error, Debug)]
pub(crate) enum PolyIOPErrors {
    #[error("Error")]
    TranscriptErrors(#[from] TranscriptError),
    #[error("Error")]
    ArithmeticErrors(#[from] ArithErrors),
    #[error("Error `{0}`")]
    Prover(String),
    #[error("Errorrr `{0}`")]
    InvalidVerifier(String),

    #[error("Error `{0}`")]
    InvalidParameters(String),
    #[error("Error `{0}`")]
    InvalidChallenge(String),
    #[error("Error")]
    ShouldNotArrive,
    #[error("Error `{0}`")]
    SerializationErrors(ark_serialize::SerializationError),
}

// impl From<ark_serialize::SerializationError> for PolyIOPErrors {
//     fn from(e: ark_serialize::SerializationError) -> Self {
//         Self::SerializationErrors(e)
//     }
// }

// impl From<TranscriptError> for PolyIOPErrors {
//     fn from(e: TranscriptError) -> Self {
//         Self::TranscriptErrors(e)
//     }
// }

// impl From<ArithErrors> for PolyIOPErrors {
//     fn from(e: ArithErrors) -> Self {
//         Self::ArithmeticErrors(e)
//     }
// }

// impl From<PCSError> for PolyIOPErrors {
//     fn from(e: PCSError) -> Self {
//         Self::PCSErrors(e)
//     }
// }
