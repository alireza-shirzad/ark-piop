use thiserror::Error;
use ark_serialize::SerializationError;
/// A `enum` specifying the possible failure modes of the arithmetics.
#[derive(Error, Debug)]
pub(crate) enum ArithErrors {
    #[error("Error")]
    SerializationErrors(SerializationError),
    #[error("Error")]
    InvalidParameters(String),

}

impl From<SerializationError> for ArithErrors {
    fn from(e: SerializationError) -> Self {
        Self::SerializationErrors(e)
    }
}
