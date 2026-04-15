//! # ark-piop
//!
//! A general-purpose **Polynomial Interactive Oracle Proof (PIOP)** framework
//! built on top of the [arkworks](https://github.com/arkworks-rs) ecosystem.
//!
//! ## Architecture
//!
//! The crate is organized into layers:
//!
//! | Layer | Modules | Purpose |
//! |-------|---------|---------|
//! | **Foundation** | [`arithmetic`], [`transcript`], [`types`], [`errors`] | Field math, Fiat-Shamir transcript, shared types and serialization |
//! | **Commitment** | [`pcs`] | Polynomial commitment schemes (KZG10, PST13) |
//! | **Protocol** | [`piop`] | PIOP trait, sumcheck, lookup-check sub-protocols |
//! | **Setup** | [`setup`] | Key generation (proving key + verifying key) |
//! | **Proving** | [`prover`] | Prover tracker, proof compilation pipeline |
//! | **Verification** | [`verifier`] | Verifier tracker, proof verification pipeline |
//! | **Shared infra** | [`tracker_core`] | Generic tracker trait + claim-batching pipeline reused by prover and verifier |
//!
//! ## Usage
//!
//! A typical workflow:
//!
//! 1. Define a [`SnarkBackend`] (field + PCS choices).
//! 2. Generate keys via [`setup::KeyGenerator`].
//! 3. Implement your protocol via the [`piop::PIOP`] trait.
//! 4. Prove with [`prover::ArgProver`], verify with [`verifier::ArgVerifier`].
//!
//! ## Backend abstraction
//!
//! [`SnarkBackend`] bundles the field, multivariate PCS, and univariate PCS
//! into a single trait so that protocol code remains generic over the
//! cryptographic instantiation.
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
//! See [`tests/pipeline.rs`] in the repository for a richer example
//! exercising zerocheck and lookup claims.
//!
//! [`tests/pipeline.rs`]: https://github.com/alireza-shirzad/ark-piop/blob/master/tests/pipeline.rs

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

// Make test utilities available to downstream crates' tests via a feature.
// `cfg(test)` only applies when compiling this crate's own tests, so use
// `any(test, feature = "test-utils")` to expose it for dependents' tests too.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// Backend abstraction that bundles the scalar field and polynomial commitment
/// schemes used by the SNARK.
///
/// Implement this trait once per cryptographic instantiation (e.g. BN254 with
/// KZG10 + PST13) and pass it as the generic parameter `B` throughout the
/// framework.
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

/// Default backend for testing: BN254 with PST13 (multivariate) and KZG10
/// (univariate).
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
