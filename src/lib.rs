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

pub trait SnarkBackend {
    type F: ark_ff::PrimeField;
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
use ark_test_curves::bls12_381::Bls12_381;
#[cfg(any(test, feature = "test-utils"))]
pub struct DefaultSnarkBackend;
#[cfg(any(test, feature = "test-utils"))]
impl SnarkBackend for DefaultSnarkBackend {
    type F = <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;
    type MvPCS = pcs::pst13::PST13<Bls12_381>;
    type UvPCS = pcs::kzg10::KZG10<Bls12_381>;
}
