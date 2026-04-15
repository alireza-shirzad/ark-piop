//! Arithmetic subsystem errors.

use ark_serialize::SerializationError;
use thiserror::Error;

/// Data-type-specific arithmetic errors (overflow, underflow, type mismatch).
#[derive(Error, Debug, Clone)]
pub enum DataTypeError {
    #[error("unsupported data type: {0}")]
    NotSupported(String),
    #[error("value overflowed data type: {0}")]
    Overflow(String),
    #[error("value underflowed data type: {0}")]
    Underflow(String),
    #[error("expected data type {expected}, got {actual}")]
    Mismatch { expected: String, actual: String },
}

/// Internal arithmetic errors (serialization failures, invalid parameters).
#[derive(Error, Debug)]
pub(crate) enum ArithErrors {
    #[error("arithmetic serialization error: {0}")]
    SerializationErrors(SerializationError),
    #[error("invalid arithmetic parameters: {0}")]
    InvalidParameters(String),
    #[error("data type error: {0}")]
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
