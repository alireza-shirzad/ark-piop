pub mod arithmetic;
pub mod errors;
pub mod pcs;
pub mod piop;
pub mod prover;
pub mod setup;
pub mod structs;
pub mod transcript;
pub mod util;
pub mod verifier;

// Make test utilities available to downstream crates' tests via a feature.
// `cfg(test)` only applies when compiling this crate's own tests, so use
// `any(test, feature = "test-utils")` to expose it for dependents' tests too.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
