use ark_serialize::SerializationError;
use thiserror::Error;

/// A `enum` specifying the possible failure modes of the arithmetics.
#[derive(Error, Debug)]
pub(crate) enum ArithErrors {
    #[error("Error")]
    SerializationErrors(SerializationError),
    #[error("Error")]
    InvalidParameters(String),
    #[error("Error")]
    ShouldNotArrive,
}

impl From<SerializationError> for ArithErrors {
    fn from(e: SerializationError) -> Self {
        Self::SerializationErrors(e)
    }
}
