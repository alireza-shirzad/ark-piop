//! The [`PCS`] trait and its implementations: univariate [`kzg10`] and
//! multivariate [`pst13`].

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
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tracing::Level;

use ark_std::test_rng;
use tracing::instrument;
/// A polynomial commitment scheme. It need not be hiding.
pub trait PCS<F: PrimeField>: Clone {
    type ProverParam: Clone + Sync + Send + CanonicalSerialize + CanonicalDeserialize;
    type VerifierParam: Clone + CanonicalSerialize + CanonicalDeserialize;
    type SRS: Clone + Debug + CanonicalSerialize + CanonicalDeserialize;
    type Poly: Polynomial<F>
        + Clone
        + Debug
        + Hash
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Commitment: PolynomialCommitment<F>
        + Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Debug
        + PartialEq
        + Send
        + Eq;
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq + Default;
    type BatchProof: Clone
        + PartialEq
        + Eq
        + Debug
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Build SRS for testing. `supported_size` is the max degree (univariate) or the
    /// number of variables (multilinear).
    ///
    /// WARNING: TESTING ONLY. The output SRS must not be used in production.
    fn gen_srs_for_testing_inner<R: Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> SnarkResult<Self::SRS>;

    /// Trim the universal parameters: `supported_degree` for univariate,
    /// `supported_num_vars` for multilinear. `impl Borrow<_>` lets callers pass the
    /// (typically huge) SRS via any pointer type.
    fn trim_impl_inner(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)>;

    fn commit_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> SnarkResult<Self::Commitment>;

    fn open_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<F>>::Point,
        commitment: Option<&Self::Commitment>,
    ) -> SnarkResult<(Self::Proof, F)>;

    fn multi_open_inner(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polynomials: &[Arc<Self::Poly>],
        _points: &[<Self::Poly as Polynomial<F>>::Point],
        _evals: &[F],
        _transcript: &mut Tr<F>,
    ) -> SnarkResult<Self::BatchProof> {
        unimplemented!()
    }

    /// Verifies that `value` is the evaluation at `point` of the committed polynomial.
    fn verify_inner(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<F>>::Point,
        value: &F,
        proof: &Self::Proof,
    ) -> SnarkResult<bool>;

    /// Verifies each `value_i` against the corresponding commitment at `point_i`.
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
        let span = tracing::span!(Level::DEBUG, "pcs.commit");
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
        let span = tracing::span!(Level::DEBUG, "pcs.open");
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
            Level::DEBUG,
            "pcs.multi_open",
            num_polys = _polynomials.len(),
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

pub trait StructuredReferenceString<E: Pairing>: Sized {
    type ProverParam;
    type VerifierParam;

    fn extract_prover_param(&self, supported_size: usize) -> Self::ProverParam;
    fn extract_verifier_param(&self, supported_size: usize) -> Self::VerifierParam;

    /// Trim the universal parameters to committer and verifier keys for
    /// `supported_size`: the max degree (univariate) or the number of
    /// variables (multilinear).
    fn trim(&self, supported_size: usize) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)>;

    /// Build SRS for testing. `supported_size` is the max degree (univariate) or the
    /// number of variables (multilinear).
    ///
    /// WARNING: TESTING ONLY. The output SRS must not be used in production.
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
        if let Some(parent) = srs_path.parent()
            && let Err(err) = std::fs::create_dir_all(parent)
        {
            panic!(
                "could not create parent directory for SRS at {:?}: {}",
                srs_path, err
            );
        }
        // Write to a private temporary file and rename it into place, so a
        // concurrent caller (tests run in parallel) never reads a partial SRS.
        static NEXT_TMP: AtomicU64 = AtomicU64::new(0);
        let mut tmp_name = srs_path.as_os_str().to_owned();
        tmp_name.push(format!(
            ".tmp.{}.{}",
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let tmp_path = PathBuf::from(tmp_name);
        let mut writer = BufWriter::new(
            File::create(&tmp_path)
                .unwrap_or_else(|_| panic!("could not create file for SRS at {:?}", tmp_path)),
        );
        writer.write_all(&serialized).unwrap();
        writer.flush().unwrap();
        drop(writer);
        std::fs::rename(&tmp_path, srs_path)
            .unwrap_or_else(|_| panic!("could not move SRS into place at {:?}", srs_path));
        srs
    }
}
