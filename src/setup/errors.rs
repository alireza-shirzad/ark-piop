//! Key generation / setup errors.

use std::string::String;
use thiserror::Error;

/// Errors that can occur during SNARK key generation.
#[derive(Error, Debug)]
pub(crate) enum SetupError {
    /// A required range polynomial was not found in the setup.
    #[error("type '{0}' has no range polynomial in the setup")]
    NoRangePoly(String),
}
