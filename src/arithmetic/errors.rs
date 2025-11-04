use ark_serialize::SerializationError;
use thiserror::Error;

/// Data type specific arithmetic errors.
#[derive(Error, Debug, Clone)]
pub enum DataTypeError {
    #[error("Unsupported data type: {0}")]
    NotSupported(String),
    #[error("Value overflowed data type: {0}")]
    Overflow(String),
    #[error("Value underflowed data type: {0}")]
    Underflow(String),
    #[error("Expected data type {expected} but got {actual}")]
    Mismatch { expected: String, actual: String },
}

/// A `enum` specifying the possible failure modes of the arithmetics.
#[derive(Error, Debug)]
pub(crate) enum ArithErrors {
    #[error("Error")]
    SerializationErrors(SerializationError),
    #[error("Error")]
    InvalidParameters(String),
    #[error("{0}")]
    DataType(DataTypeError),
}

impl From<SerializationError> for ArithErrors {
    fn from(e: SerializationError) -> Self {
        Self::SerializationErrors(e)
    }
}

impl From<DataTypeError> for ArithErrors {
    fn from(e: DataTypeError) -> Self {
        Self::DataType(e)
    }
}
