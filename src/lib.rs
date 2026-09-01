//! # ark-piop
//!
//! A general-purpose **Polynomial Interactive Oracle Proof (PIOP)** framework
//! built on the [arkworks](https://github.com/arkworks-rs) ecosystem.
//!
//! Layers: [`arithmetic`], [`transcript`], [`types`], [`errors`] (foundation);
//! [`pcs`] (commitment schemes); [`piop`] (protocols); [`setup`] (key
//! generation); [`prover`] / [`verifier`] (proof pipelines); and
//! [`tracker_core`] (claim batching shared by prover and verifier).
//!
//! Typical workflow: define a [`SnarkBackend`] (field + PCS choices), generate
//! keys via [`setup::KeyGenerator`], implement [`piop::PIOP`], then prove with
//! [`prover::ArgProver`] and verify with [`verifier::ArgVerifier`].
//!
//! ## Example
//!
//! A minimal end-to-end: commit a polynomial, claim its hypercube sum, and
//! verify.
//!
//! ```ignore
//! use ark_ff::Zero;
//! use ark_piop::{
//!     DefaultSnarkBackend, SnarkBackend,
//!     arithmetic::mat_poly::mle::MLE,
//!     test_utils::test_prelude,
//! };
//!
//! type B = DefaultSnarkBackend;
//! type F = <B as SnarkBackend>::F;
//!
//! // 1. Build a prover / verifier pair with test parameters.
//! let (mut prover, mut verifier) = test_prelude::<B>().unwrap();
//!
//! // 2. Prover: register a polynomial and add a sumcheck claim.
//! let evals: Vec<F> = (0..16).map(|i| F::from(i as u64)).collect();
//! let poly = MLE::from_evaluations_vec(4, evals.clone());
//! let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
//! let sum: F = evals.iter().copied().fold(F::zero(), |a, b| a + b);
//! prover.add_mv_sumcheck_claim(tracked.id(), sum).unwrap();
//!
//! // 3. Compile the proof.
//! let proof = prover.build_proof().unwrap();
//!
//! // 4. Verifier: receive the proof, mirror the claim, and verify.
//! verifier.set_proof(proof);
//! verifier.track_mv_com_by_id(tracked.id()).unwrap();
//! verifier.add_mv_sumcheck_claim(tracked.id(), sum);
//! verifier.verify().unwrap();
//! ```
//!
//! See `tests/pipeline.rs` in the repository for a richer example exercising
//! zerocheck and lookup claims.

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

/// Bundles the scalar field and polynomial commitment schemes used by the
/// SNARK; implemented once per cryptographic instantiation and passed as the
/// generic parameter `B` throughout the framework.
pub trait SnarkBackend: 'static + Send + Sync {
    /// The prime field used for all polynomial evaluations and proof elements.
    type F: ark_ff::PrimeField + Default;
    /// Multivariate polynomial commitment scheme (commits to MLEs).
    type MvPCS: pcs::PCS<Self::F, Poly = arithmetic::mat_poly::mle::MLE<Self::F>>
        + 'static
        + Send
        + Sync;
    /// Univariate polynomial commitment scheme (commits to LDEs).
    type UvPCS: pcs::PCS<Self::F, Poly = arithmetic::mat_poly::lde::LDE<Self::F>>
        + 'static
        + Send
        + Sync;
}

/// Default backend for testing: BN254 with PST13 (mv) and KZG10 (uv).
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

/// Test backend on BLS12-381, for benchmarks needing parity with systems
/// hard-coded to that curve (e.g. QEDB).
#[cfg(feature = "test-utils-bls12-381")]
use ark_bls12_381::Bls12_381;
#[cfg(feature = "test-utils-bls12-381")]
pub struct Bls12_381SnarkBackend;
#[cfg(feature = "test-utils-bls12-381")]
impl SnarkBackend for Bls12_381SnarkBackend {
    type F = <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;
    type MvPCS = pcs::pst13::PST13<Bls12_381>;
    type UvPCS = pcs::kzg10::KZG10<Bls12_381>;
}
