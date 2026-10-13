//! A Polynomial Interactive Oracle Proof (PIOP) framework built on the
//! [arkworks](https://github.com/arkworks-rs) ecosystem.
//!
//! Define a [`SnarkBackend`] (field and PCS choices), generate keys with
//! [`setup::KeyGenerator`], implement [`piop::PIOP`], then prove with
//! [`prover::ArgProver`] and verify with [`verifier::ArgVerifier`]. The
//! prover and the verifier track polynomials and add claims in the same
//! order; [`tracker_core`] batches the claims on both sides.
//!
//! The readme and `tests/pipeline.rs` have end-to-end examples.

pub mod arithmetic;
pub mod errors;
pub mod pcs;
pub mod piop;
pub mod prover;
pub mod setup;
pub mod tracker_core;
pub mod transcript;
pub mod types;

pub mod verifier;

// `cfg(test)` doesn't cover dependents' tests, so also expose via the
// `test-utils` feature.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// The scalar field and the two polynomial commitment schemes of a SNARK
/// instantiation; the generic parameter `B` throughout the framework.
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
/// Default backend for testing: BN254 with PST13 (mv) and KZG10 (uv).
#[cfg(any(test, feature = "test-utils"))]
pub struct DefaultSnarkBackend;
#[cfg(any(test, feature = "test-utils"))]
impl SnarkBackend for DefaultSnarkBackend {
    type F = <Bn254 as ark_ec::pairing::Pairing>::ScalarField;
    type MvPCS = pcs::pst13::PST13<Bn254>;
    type UvPCS = pcs::kzg10::KZG10<Bn254>;
}

#[cfg(feature = "test-utils-bls12-381")]
use ark_bls12_381::Bls12_381;
/// Test backend on BLS12-381, for benchmarks against systems hard-coded to
/// that curve (e.g. QEDB).
#[cfg(feature = "test-utils-bls12-381")]
pub struct Bls12_381SnarkBackend;
#[cfg(feature = "test-utils-bls12-381")]
impl SnarkBackend for Bls12_381SnarkBackend {
    type F = <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;
    type MvPCS = pcs::pst13::PST13<Bls12_381>;
    type UvPCS = pcs::kzg10::KZG10<Bls12_381>;
}

/// Milliseconds since the UNIX epoch, the timestamp of the stats events.
pub(crate) fn wall_clock_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
