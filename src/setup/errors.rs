use std::string::String;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SetupError {
    #[error("type '{0}' has no range polynomial in the setup")]
    NoRangePoly(String),

    /// A name that stands for no lookup protocol; the string says what was
    /// named and where.
    #[error("{0} names no lookup protocol: use `logup` or `gkr`")]
    UnknownLookupProtocol(String),
}
