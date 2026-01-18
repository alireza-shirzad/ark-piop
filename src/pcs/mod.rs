//! A General Purpose PCS abstraction and some implementations.

pub(crate) mod errors;
pub mod kzg10;
pub mod pst13;

use crate::{errors::SnarkResult, transcript::Tr};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use std::{borrow::Borrow, fmt::Debug, hash::Hash, sync::Arc};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};
use tracing::Level;

use ark_std::test_rng;
use tracing::instrument;
/// This trait defines APIs for polynomial commitment schemes.
/// Note that for our usage of PCS, we do not require the hiding property.
pub trait PCS<F: PrimeField>: Clone {
    /// Prover parameters
    type ProverParam: Clone + Sync + Send + CanonicalSerialize + CanonicalDeserialize;
    /// Verifier parameters
    type VerifierParam: Clone + CanonicalSerialize + CanonicalDeserialize;
    /// Structured reference string
    type SRS: Clone + Debug + CanonicalSerialize + CanonicalDeserialize;
    /// Polynomial and its associated types
    type Poly: Polynomial<F>
        + Clone
        + Debug
        + Hash
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize;
    /// comitments
    type Commitment: PolynomialCommitment<F>
        + Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Debug
        + PartialEq
        + Send
        + Eq;
    /// Proofs
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq + Default;
    /// Batch proofs
    type BatchProof: Clone
        + PartialEq
        + Eq
        + Debug
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    // Core methods that implementations must provide (uninstrumented).
    fn gen_srs_for_testing_inner<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> SnarkResult<Self::SRS>;

    /// Trim the universal parameters to specialize the public parameters.
    /// Input both `supported_degree` for univariate and
    /// `supported_num_vars` for multilinear.
    /// ## Note on function signature
    /// Usually, data structure like SRS and ProverParam are huge and users
    /// might wish to keep them in heap using different kinds of smart pointers
    /// (instead of only in stack) therefore our `impl Borrow<_>` interface
    /// allows for passing in any pointer type, e.g.: `trim(srs: &Self::SRS,
    /// ..)` or `trim(srs: Box<Self::SRS>, ..)` or `trim(srs: Arc<Self::SRS>,
    /// ..)` etc.
    fn trim_impl_inner(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)>;

    /// Generate a commitment for a polynomial
    /// ## Note on function signature
    /// Usually, data structure like SRS and ProverParam are huge and users
    /// might wish to keep them in heap using different kinds of smart pointers
    /// (instead of only in stack) therefore our `impl Borrow<_>` interface
    /// allows for passing in any pointer type, e.g.: `commit(prover_param:
    /// &Self::ProverParam, ..)` or `commit(prover_param:
    /// Box<Self::ProverParam>, ..)` or `commit(prover_param:
    /// Arc<Self::ProverParam>, ..)` etc.
    fn commit_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> SnarkResult<Self::Commitment>;

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    fn open_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<F>>::Point,
        commitment: Option<&Self::Commitment>,
    ) -> SnarkResult<(Self::Proof, F)>;

    /// Input a list of multilinear extensions, and a same number of points, and
    /// a transcript, compute a multi-opening for all the polynomials.
    fn multi_open_inner(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polynomials: &[Arc<Self::Poly>],
        _points: &[<Self::Poly as Polynomial<F>>::Point],
        _evals: &[F],
        _transcript: &mut Tr<F>,
    ) -> SnarkResult<Self::BatchProof> {
        unimplemented!()
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    fn verify_inner(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<F>>::Point,
        value: &F,
        proof: &Self::Proof,
    ) -> SnarkResult<bool>;

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    fn batch_verify_inner(
        _verifier_param: &Self::VerifierParam,
        _comitments: &[Self::Commitment],
        _points: &[<Self::Poly as Polynomial<F>>::Point],
        _evals: &[F],
        _batch_proof: &Self::BatchProof,
        _transcript: &mut Tr<F>,
    ) -> SnarkResult<bool> {
        unimplemented!()
    }

    #[inline(always)]
    #[tracing::instrument(level = "trace", skip(rng), fields(supported_size))]
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, supported_size: usize) -> SnarkResult<Self::SRS> {
        Self::gen_srs_for_testing_inner(rng, supported_size)
    }

    #[inline(always)]
    #[tracing::instrument(
        level = "trace",
        skip(srs),
        fields(supported_degree, supported_num_vars)
    )]
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)> {
        Self::trim_impl_inner(srs, supported_degree, supported_num_vars)
    }
    #[inline(always)]
    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> SnarkResult<Self::Commitment> {
        use tracing::Level;
        let span = tracing::span!(Level::TRACE, "pcs.commit", poly = ?poly);
        let enter_guard = span.enter();
        let res = Self::commit_impl_inner(prover_param, poly);
        drop(enter_guard);
        res
    }
    #[inline(always)]
    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<F>>::Point,
        commitment: Option<&Self::Commitment>,
    ) -> SnarkResult<(Self::Proof, F)> {
        use tracing::Level;
        let span = tracing::span!(Level::TRACE, "pcs.open", poly = ?polynomial,
                point = ?point,);
        let enter_guard = span.enter();
        let res = Self::open_impl_inner(prover_param, polynomial, point, commitment);
        drop(enter_guard);
        res
    }
    #[inline(always)]
    fn multi_open(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polynomials: &[Arc<Self::Poly>],
        _points: &[<Self::Poly as Polynomial<F>>::Point],
        _evals: &[F],
        _transcript: &mut Tr<F>,
    ) -> SnarkResult<Self::BatchProof> {
        use tracing::Level;
        let span = tracing::span!(
            Level::TRACE,
            "pcs.multi_open",
            num_polys = _polynomials.len(),
            polys = ?_polynomials,
            points = ?_points,
            evals = ?_evals
        );

        let enter_guard = span.enter();
        let res = Self::multi_open_inner(_prover_param, _polynomials, _points, _evals, _transcript);
        drop(enter_guard);
        res
    }

    #[inline(always)]
    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<F>>::Point,
        value: &F,
        proof: &Self::Proof,
    ) -> SnarkResult<bool> {
        let span = tracing::span!(
            Level::TRACE,
            "pcs.verify",
            point = ?point,
            evals = ?value
        );
        let enter_guard = span.enter();
        let res = Self::verify_inner(verifier_param, commitment, point, value, proof);
        if let Err(ref e) = res {
            tracing::error!(parent: &span, error = %e, "verify failed");
        }
        drop(enter_guard);
        res
    }

    #[inline(always)]
    fn batch_verify(
        _verifier_param: &Self::VerifierParam,
        _comitments: &[Self::Commitment],
        _points: &[<Self::Poly as Polynomial<F>>::Point],
        _evals: &[F],
        _batch_proof: &Self::BatchProof,
        _transcript: &mut Tr<F>,
    ) -> SnarkResult<bool> {
        let span = tracing::span!(
            Level::TRACE,
            "pcs.batch_verify",
            num_comitments = _comitments.len(),
            size = _comitments.len(),
            points = ?_points,
            evals = ?_evals
        );
        let enter_guard = span.enter();
        let res = Self::batch_verify_inner(
            _verifier_param,
            _comitments,
            _points,
            _evals,
            _batch_proof,
            _transcript,
        );
        if let Err(ref e) = res {
            tracing::error!(parent: &span, error = %e, "batch verify failed");
        }
        drop(enter_guard);
        res
    }
}

/// API definitions for structured reference string
pub trait StructuredReferenceString<E: Pairing>: Sized {
    /// Prover parameters
    type ProverParam;
    /// Verifier parameters
    type VerifierParam;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_size: usize) -> Self::ProverParam;
    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_size: usize) -> Self::VerifierParam;

    /// Trim the universal parameters to specialize the public parameters
    /// for polynomials to the given `supported_size`, and
    /// returns committer key and verifier key.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is 2 to the number of
    ///   variables.
    ///
    /// `supported_log_size` should be in range `1..=params.log_size`
    fn trim(&self, supported_size: usize) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, supported_size: usize) -> SnarkResult<Self>;
}

pub trait PolynomialCommitment<F: Field>: Sized {
    fn log_size(&self) -> u8;
    fn set_log_size(&mut self, nv: u8);
}

#[instrument(level = "debug", skip(srs_path))]
pub fn load_or_generate_srs<F: PrimeField, PCSImpl: PCS<F>>(
    srs_path: &Path,
    size: usize,
) -> PCSImpl::SRS {
    if srs_path.exists() {
        tracing::info!(
            srs_loading_path = ?srs_path
        );
        let mut buffer = Vec::new();
        BufReader::new(File::open(srs_path).unwrap())
            .read_to_end(&mut buffer)
            .unwrap();
        PCSImpl::SRS::deserialize_uncompressed_unchecked(&buffer[..]).unwrap_or_else(|_| {
            panic!("Failed to deserialize SRS from {:?}", srs_path);
        })
    } else {
        tracing::warn!(
            srs_saving_path = ?srs_path
        );
        let mut rng = test_rng();
        let srs = PCSImpl::gen_srs_for_testing(&mut rng, size).unwrap();
        let mut serialized = Vec::new();
        srs.serialize_uncompressed(&mut serialized).unwrap();
        if let Some(parent) = srs_path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                panic!(
                    "could not create parent directory for SRS at {:?}: {}",
                    srs_path, err
                );
            }
        }
        BufWriter::new(
            File::create(srs_path)
                .unwrap_or_else(|_| panic!("could not create file for SRS at {:?}", srs_path)),
        )
        .write_all(&serialized)
        .unwrap();
        srs
    }
}
