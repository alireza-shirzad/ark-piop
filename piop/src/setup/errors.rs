/////// Imports /////////
use std::string::String;

use thiserror::Error;
/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
pub(crate) enum SetupError {
    #[error("Type '{0}' does not have a positive range polynomial from the setup")]
    NoRangePoly(String),
}
