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

/// Max multiplicative degree allowed per sumcheck term before reduction.
pub const SUMCHECK_TERM_DEGREE_LIMIT: usize = 6;

// Make test utilities available to downstream crates' tests via a feature.
// `cfg(test)` only applies when compiling this crate's own tests, so use
// `any(test, feature = "test-utils")` to expose it for dependents' tests too.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub trait SnarkBackend: 'static + Send + Sync {
    type F: ark_ff::PrimeField + Default;
    type MvPCS: pcs::PCS<Self::F, Poly = arithmetic::mat_poly::mle::MLE<Self::F>>
        + 'static
        + Send
        + Sync;
    type UvPCS: pcs::PCS<Self::F, Poly = arithmetic::mat_poly::lde::LDE<Self::F>>
        + 'static
        + Send
        + Sync;
}

#[cfg(any(test, feature = "test-utils"))]
use ark_bn254::Bn254;
#[cfg(any(test, feature = "test-utils"))]
pub struct DefaultSnarkBackend;
#[cfg(any(test, feature = "test-utils"))]
impl SnarkBackend for DefaultSnarkBackend {
    type F = <Bn254 as ark_ec::pairing::Pairing>::ScalarField;
    type MvPCS = pcs::pst13::PST13<Bn254>;
    type UvPCS = pcs::kzg10::KZG10<Bn254>;
}
