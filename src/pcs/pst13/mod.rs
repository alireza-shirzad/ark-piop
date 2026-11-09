mod batch;
pub(crate) mod small_scalar_msm;
pub(crate) mod srs;
pub mod structs;
pub mod value_buckets;
use crate::arithmetic::mat_poly::mle::MLEStorage;
use crate::errors::SnarkError;
use crate::errors::SnarkResult;
use crate::pcs::errors::PCSError;
use crate::pcs::pst13::PCSError::EvaluationPointSizeMismatch;
use crate::pcs::pst13::PCSError::TooLargePolynomial;
use crate::pcs::pst13::SnarkError::PCSErrors;
use crate::pcs::pst13::structs::PST13BatchProof;
use crate::pcs::pst13::structs::PST13Commitment;
use crate::pcs::pst13::structs::PST13Proof;
use crate::{
    arithmetic::mat_poly::mle::MLE,
    pcs::{PCS, StructuredReferenceString},
    transcript::Tr,
};
use ark_ec::{
    AffineRepr, CurveGroup, ScalarMul, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::{One, Zero};
use ark_poly::Polynomial;
use ark_std::{cfg_into_iter, rand::Rng};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use srs::{Evaluations, PST13ProverParam, PST13UniversalParams, PST13VerifierParam};
use std::{borrow::Borrow, marker::PhantomData, ops::Mul, sync::Arc};

/// `Σ levels[0][start..end]` (clamped to the level) in at most `2·nv` additions. In the
/// PST13 SRS `levels[l][c] = g^{eq(t[l..], c)}` with the low bit of `c` on `t_l`, so an
/// aligned pair sums to one point of the next level (`eq(t_l, 0) + eq(t_l, 1) = 1`):
/// `levels[l][2c] + levels[l][2c+1] = levels[l+1][c]`.
fn range_sum<E: Pairing>(levels: &[Evaluations<E::G1Affine>], start: usize, end: usize) -> E::G1 {
    let mut hi = end.min(levels[0].evals.len());
    let mut lo = start.min(hi);
    let mut acc = E::G1::zero();
    for level in levels {
        if lo >= hi {
            break;
        }
        if lo & 1 == 1 {
            acc += level.evals[lo];
            lo += 1;
        }
        if hi & 1 == 1 {
            hi -= 1;
            acc += level.evals[hi];
        }
        lo >>= 1;
        hi >>= 1;
    }
    acc
}

/// Shared commit path for all `Sparse*` storage variants: rewrites `MSM(bases, values)` as
/// `default * Σ bases + Σ bases[idx] * (val - default)` over the exceptions, the latter
/// one MSM over the exceptions' bases. `levels` is the SRS from the committed level up.
/// Callers pass F-lifted values so `F::from` is paid once per exception, not per element.
fn sparse_commit<E: Pairing>(
    levels: &[Evaluations<E::G1Affine>],
    default: E::ScalarField,
    exceptions: impl Iterator<Item = (u32, E::ScalarField)>,
) -> E::G1Affine {
    let bases = &levels[0].evals;
    let mut acc: E::G1 = if default.is_zero() {
        E::G1::zero()
    } else {
        range_sum::<E>(levels, 0, bases.len()).mul(default)
    };
    let (points, deltas): (Vec<E::G1Affine>, Vec<E::ScalarField>) = exceptions
        .filter_map(|(idx, val)| {
            let delta = val - default;
            (!delta.is_zero()).then(|| (bases[idx as usize], delta))
        })
        .unzip();
    acc += E::G1::msm_unchecked(&points, &deltas);
    acc.into_affine()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PST13<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

impl<E: Pairing> PCS<E::ScalarField> for PST13<E> {
    type ProverParam = PST13ProverParam<E>;
    type VerifierParam = PST13VerifierParam<E>;
    type SRS = PST13UniversalParams<E>;
    type Poly = MLE<E::ScalarField>;
    type Commitment = PST13Commitment<E>;
    type Proof = PST13Proof<E>;
    type BatchProof = PST13BatchProof<E, Self>;

    /// `log_size` is the number of variables.
    fn gen_srs_for_testing_inner<R: Rng>(rng: &mut R, log_size: usize) -> SnarkResult<Self::SRS> {
        PST13UniversalParams::<E>::gen_srs_for_testing(rng, log_size)
    }

    /// Panics if `supported_degree` is Some or `supported_num_vars` is None.
    fn trim_impl_inner(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)> {
        if supported_degree.is_some() {
            panic!("supported_degree must be None for multilinear polynomials");
        }
        let supported_num_vars = match supported_num_vars {
            Some(p) => p,
            None => {
                panic!("supported_num_vars should be provided for multilinear polynomials")
            }
        };
        let (ml_ck, ml_vk) = srs.borrow().trim(supported_num_vars)?;

        Ok((ml_ck, ml_vk))
    }

    /// `2^num_vars` G1 scalar muls for `Field` storage. Compressed backings
    /// (`Bit`/`U8`/`U32`/`U64`) feed their raw small-scalar slice to
    /// [`small_scalar_msm`], with no dense `Vec<F>` and no full-width Pippenger MSM.
    fn commit_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Arc<Self::Poly>,
    ) -> SnarkResult<Self::Commitment> {
        let prover_param = prover_param.borrow();
        // Commit over the physically-stored hypercube only, never over virtual
        // padding, which is a cyclic repetition the SRS must not consume.
        let committed_nv = poly.storage().inner_num_vars();
        if prover_param.num_vars < committed_nv {
            return Err(PCSErrors(TooLargePolynomial(
                committed_nv,
                prover_param.num_vars,
            )));
        }
        let ignored = prover_param.num_vars - committed_nv;
        let levels = &prover_param.powers_of_g[ignored..];
        let bases = &levels[0].evals;

        let com = match poly.storage() {
            MLEStorage::Field(m) => E::G1::msm_unchecked(bases, &m.evaluations).into_affine(),
            MLEStorage::Bit { bits, .. } => {
                // Unpack on the fly (little-endian per byte, per `MLEStorage::Bit`'s
                // contract); the tail beyond `inner_len` is cut by `msm_u1`'s length-min.
                let inner_len = 1usize << committed_nv;
                let scalars: Vec<bool> = cfg_into_iter!(0..inner_len)
                    .map(|i| (bits[i >> 3] >> (i & 7)) & 1 == 1)
                    .collect();
                small_scalar_msm::msm_u1::<E::G1>(bases, &scalars).into_affine()
            }
            MLEStorage::U8 { bytes, .. } => {
                small_scalar_msm::msm_u8::<E::G1>(bases, bytes).into_affine()
            }
            MLEStorage::U32 { words, .. } => {
                small_scalar_msm::msm_u32::<E::G1>(bases, words).into_affine()
            }
            MLEStorage::U64 { words, .. } => {
                small_scalar_msm::msm_u64::<E::G1>(bases, words).into_affine()
            }
            MLEStorage::Constant { value, .. } => {
                if value.is_zero() {
                    E::G1Affine::zero()
                } else {
                    range_sum::<E>(levels, 0, bases.len())
                        .mul(*value)
                        .into_affine()
                }
            }
            MLEStorage::Rle { runs, .. } => {
                let mut acc: E::G1 = E::G1::zero();
                let mut cursor: usize = 0;
                for (value, count) in runs.iter() {
                    let count = *count as usize;
                    if !value.is_zero() {
                        acc += range_sum::<E>(levels, cursor, cursor + count).mul(*value);
                    }
                    cursor += count;
                }
                acc.into_affine()
            }
            MLEStorage::Sparse {
                default,
                exceptions,
                ..
            } => sparse_commit::<E>(levels, *default, exceptions.iter().map(|(i, v)| (*i, *v))),
            MLEStorage::SparseU8 {
                default,
                exceptions,
                ..
            } => sparse_commit::<E>(
                levels,
                E::ScalarField::from(*default as u64),
                exceptions
                    .iter()
                    .map(|(i, v)| (*i, E::ScalarField::from(*v as u64))),
            ),
            MLEStorage::SparseU32 {
                default,
                exceptions,
                ..
            } => sparse_commit::<E>(
                levels,
                E::ScalarField::from(*default as u64),
                exceptions
                    .iter()
                    .map(|(i, v)| (*i, E::ScalarField::from(*v as u64))),
            ),
            MLEStorage::SparseU64 {
                default,
                exceptions,
                ..
            } => sparse_commit::<E>(
                levels,
                E::ScalarField::from(*default),
                exceptions
                    .iter()
                    .map(|(i, v)| (*i, E::ScalarField::from(*v))),
            ),
            // `value[i] = (high[i] << 64) | low[i]`, so the commit is
            // `msm_u64(bases, low) + 2^64 * msm_u64(bases, high)`. `scale` is
            // fixed-point decoding metadata, not part of the polynomial value,
            // so it does not participate in the commit.
            MLEStorage::PackedDecimal { high, low, .. } => {
                let lo_msm = small_scalar_msm::msm_u64::<E::G1>(bases, low);
                let hi_msm = small_scalar_msm::msm_u64::<E::G1>(bases, high);
                let two_pow_64 = E::ScalarField::from(1u128 << 64);
                (lo_msm + hi_msm.mul(two_pow_64)).into_affine()
            }
            // Lazy variants are registered only after their dense form was committed
            // and dropped; committing one directly is a caller bug, and materializing
            // here (O(2^nv) inversions) would defeat the memory optimization.
            MLEStorage::LazyRatioShifted { .. } | MLEStorage::LazyInverseShiftedSum { .. } => {
                panic!(
                    "PST13::commit: cannot commit an MLE with lazy helper storage. \
                     Lazy backings are for post-commit re-registration only; commit the dense \
                     source-based MLE first, then swap in the lazy backing via \
                     `register_mat_mv_poly`."
                );
            }
        };

        Ok(PST13Commitment {
            com,
            nv: committed_nv as u8,
        })
    }

    /// Through [`value_buckets`], when its guard expects that to cost less
    /// than the MSM over the table.
    fn commit_value_lookup(
        prover_param: impl Borrow<Self::ProverParam>,
        nv: usize,
        cols: &[&[u32]],
        table: &[E::ScalarField],
    ) -> SnarkResult<Option<Self::Commitment>> {
        let _span = tracing::debug_span!("pcs.commit_value_lookup").entered();
        let prover_param = prover_param.borrow();
        if prover_param.num_vars < nv {
            return Err(PCSErrors(TooLargePolynomial(nv, prover_param.num_vars)));
        }
        let levels = &prover_param.powers_of_g[prover_param.num_vars - nv..];
        let bases = &levels[0].evals;
        assert!(
            cols.iter().all(|col| col.len() == bases.len()),
            "a column of {nv} variables has 2^{nv} entries"
        );
        let Some(histogram) = value_buckets::Histogram::of(cols, table.len()) else {
            return Ok(None);
        };
        let rows = bases.len();
        let bits = <E::ScalarField as ark_ff::PrimeField>::MODULUS_BIT_SIZE as usize;
        if !value_buckets::bucketing_pays(
            rows,
            cols.len() * rows,
            histogram.entries(),
            histogram.distinct(),
            bits,
            value_buckets::threads(),
        ) {
            return Ok(None);
        }
        let total = range_sum::<E>(levels, 0, rows);
        let com = value_buckets::commit::<E::G1>(bases, total, cols, table, &histogram);
        Ok(Some(PST13Commitment {
            com: com.into_affine(),
            nv: nv as u8,
        }))
    }

    /// The commitment is linear in the table, and a constant table commits
    /// to the constant times the sum of the level's bases.
    fn commit_linear_combination(
        prover_param: impl Borrow<Self::ProverParam>,
        nv: usize,
        terms: &[(E::ScalarField, &Self::Commitment)],
        constant: E::ScalarField,
    ) -> SnarkResult<Option<Self::Commitment>> {
        let prover_param = prover_param.borrow();
        if prover_param.num_vars < nv || terms.iter().any(|(_, comm)| comm.nv as usize != nv) {
            return Ok(None);
        }
        let levels = &prover_param.powers_of_g[prover_param.num_vars - nv..];
        let points: Vec<E::G1Affine> = terms.iter().map(|(_, comm)| comm.com).collect();
        let scalars: Vec<E::ScalarField> = terms.iter().map(|(c, _)| *c).collect();
        let com = E::G1::msm_unchecked(&points, &scalars)
            + range_sum::<E>(levels, 0, 1 << nv).mul(constant);
        Ok(Some(PST13Commitment {
            com: com.into_affine(),
            nv: nv as u8,
        }))
    }

    /// Costs ~`2^{num_var+1}` G1 scalar muls over `num_var` rounds.
    fn open_impl_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Arc<Self::Poly>,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        _commitment: Option<&Self::Commitment>,
    ) -> SnarkResult<(Self::Proof, E::ScalarField)> {
        let prover_param = prover_param.borrow();

        // The polynomial as it was committed: over its own hypercube. The
        // variables it is padded to are ones it repeats along, so of a
        // longer point it reads the first coordinates only.
        let nv = polynomial.storage().inner_num_vars();
        if nv > prover_param.num_vars {
            return Err(PCSErrors(TooLargePolynomial(nv, prover_param.num_vars)));
        }
        if point.len() < nv {
            return Err(PCSErrors(EvaluationPointSizeMismatch(point.len(), nv)));
        }
        let point = &point[..nv];

        let open_span = tracing::span!(
            tracing::Level::DEBUG,
            "pst13.open",
            nv = nv,
            total_msm_scalars = (1usize << nv).saturating_sub(1),
        );
        let _open_enter = open_span.enter();
        // The first `ignored` SRS vectors are unused for opening.
        let ignored = prover_param.num_vars - nv + 1;
        let mut f = polynomial.storage().to_evaluations_vec();

        let mut proofs = Vec::new();

        for (i, (&point_at_k, gi)) in point
            .iter()
            .zip(prover_param.powers_of_g[ignored..ignored + nv].iter())
            .enumerate()
        {
            let k = nv - 1 - i;
            let cur_dim = 1 << k;
            let round_span = tracing::span!(
                tracing::Level::DEBUG,
                "pst13.open.round",
                round = i,
                msm_size = cur_dim,
            );
            let _round_enter = round_span.enter();
            let mut q = vec![E::ScalarField::zero(); cur_dim];
            let mut r = vec![E::ScalarField::zero(); cur_dim];

            {
                let qr_span =
                    tracing::span!(tracing::Level::DEBUG, "pst13.open.round.qr", size = cur_dim,);
                let _qr_enter = qr_span.enter();
                for b in 0..(1 << k) {
                    // q[b] = f[1, b] - f[0, b]
                    q[b] = f[(b << 1) + 1] - f[b << 1];

                    // r[b] = f[0, b] + q[b] * p
                    r[b] = f[b << 1] + (q[b] * point_at_k);
                }
            }
            f = r;

            let msm_span = tracing::span!(
                tracing::Level::DEBUG,
                "pst13.open.round.msm",
                size = cur_dim,
            );
            let _msm_enter = msm_span.enter();
            proofs.push(E::G1::msm_unchecked(&gi.evals, &q).into_affine());
        }
        // Every variable is bound: what is left is the evaluation.
        let eval = f[0];
        Ok((PST13Proof { proofs }, eval))
    }

    fn multi_open_inner(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[Arc<Self::Poly>],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        evals: &[E::ScalarField],
        transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<PST13BatchProof<E, Self>> {
        #[cfg(feature = "honest-prover")]
        {
            use ark_poly::MultilinearExtension;
            for (i, ((poly, point), eval)) in polynomials
                .iter()
                .zip(points.iter())
                .zip(evals.iter())
                .enumerate()
            {
                // A polynomial reads as many coordinates as it has variables.
                let read = &point[..poly.storage().inner_num_vars().min(point.len())];
                let computed_eval = poly.fix_variables(read).evaluations()[0];
                if computed_eval != *eval {
                    return Err(SnarkError::PCSErrors(PCSError::HonestProver(i)));
                }
            }
        }
        batch::open_batch(
            prover_param.borrow(),
            polynomials,
            points,
            evals,
            transcript,
        )
    }

    /// Costs `num_var` pairing products and `num_var` MSMs.
    fn verify_inner(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> SnarkResult<bool> {
        // A commitment is to a polynomial of its own number of variables,
        // which reads the first coordinates of a longer point.
        let num_var = commitment.nv as usize;
        if point.len() < num_var {
            return Err(PCSErrors(EvaluationPointSizeMismatch(point.len(), num_var)));
        }
        let point = &point[..num_var];

        if num_var > verifier_param.num_vars {
            return Err(PCSErrors(TooLargePolynomial(
                num_var,
                verifier_param.num_vars,
            )));
        }

        // One quotient per variable. With fewer the pairing below would be
        // taken over the ones that are there.
        if proof.proofs.len() != num_var {
            return Ok(false);
        }

        let h_mul: Vec<E::G2Affine> = verifier_param.h.into_group().batch_mul(point);

        let ignored = verifier_param.num_vars - num_var;
        let h_vec: Vec<_> = (0..num_var)
            .map(|i| verifier_param.h_mask[ignored + i].into_group() - h_mul[i])
            .collect();
        let h_vec: Vec<E::G2Affine> = E::G2::normalize_batch(&h_vec);

        let mut pairings: Vec<_> = proof
            .proofs
            .iter()
            .map(|&x| E::G1Prepared::from(x))
            .zip(h_vec.into_iter().take(num_var).map(E::G2Prepared::from))
            .collect();

        pairings.push((
            E::G1Prepared::from(
                (verifier_param.g.mul(*value) - commitment.com.into_group()).into_affine(),
            ),
            E::G2Prepared::from(verifier_param.h),
        ));

        let ps = pairings.iter().map(|(p, _)| p.clone());
        let hs = pairings.iter().map(|(_, h)| h.clone());

        let res = E::multi_pairing(ps, hs) == ark_ec::pairing::PairingOutput(E::TargetField::one());

        Ok(res)
    }

    fn batch_verify_inner(
        verifier_param: &Self::VerifierParam,
        comitments: &[Self::Commitment],
        points: &[<Self::Poly as Polynomial<E::ScalarField>>::Point],
        evals: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        transcript: &mut Tr<E::ScalarField>,
    ) -> SnarkResult<bool> {
        batch::verify_batch(
            verifier_param,
            comitments,
            points,
            evals,
            batch_proof,
            transcript,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use ark_ec::pairing::Pairing;
    use ark_poly::MultilinearExtension;
    use ark_std::{UniformRand, rand::Rng, test_rng, vec::Vec};

    type E = ark_bn254::Bn254;
    type Fr = <E as Pairing>::ScalarField;

    fn test_single_helper<R: Rng>(
        params: &PST13UniversalParams<E>,
        poly: &Arc<MLE<Fr>>,
        rng: &mut R,
    ) -> SnarkResult<()> {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let (ck, vk) = PST13::trim(params, None, Some(nv))?;
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = PST13::commit(&ck, poly)?;
        let (proof, value) = PST13::open(&ck, poly, &point, None)?;

        assert!(PST13::verify(&vk, &com, &point, &value, &proof)?);

        let value = Fr::rand(rng);
        assert!(!PST13::verify(&vk, &com, &point, &value, &proof)?);

        Ok(())
    }

    #[test]
    fn value_lookup_commits_as_the_table() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 11)?;
        let (ck, _) = PST13::trim(&params, None, Some(11))?;
        let table: Vec<Fr> = (0..16).map(|_| Fr::rand(&mut rng)).collect();
        for (nv, cols) in [(11, 1), (11, 2), (10, 2)] {
            let cols: Vec<Vec<u32>> = (0..cols)
                .map(|_| (0..1 << nv).map(|_| rng.gen_range(0..16)).collect())
                .collect();
            let views: Vec<&[u32]> = cols.iter().map(Vec::as_slice).collect();
            let evals = (0..1 << nv)
                .map(|row| views.iter().map(|col| table[col[row] as usize]).sum())
                .collect();
            let dense = Arc::new(MLE::from_evaluations_vec(nv, evals));
            let expected = PST13::commit(&ck, &dense)?;
            let com = PST13::commit_value_lookup(&ck, nv, &views, &table)?;
            assert_eq!(com, Some(expected));
        }
        let distinct: Vec<u32> = (0..1 << 11).collect();
        let table: Vec<Fr> = (0..1 << 11).map(|_| Fr::rand(&mut rng)).collect();
        assert_eq!(
            PST13::commit_value_lookup(&ck, 11, &[&distinct, &distinct], &table)?,
            None
        );
        Ok(())
    }

    #[test]
    fn linear_combination_commits_as_the_combination() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 8)?;
        let (ck, _) = PST13::trim(&params, None, Some(8))?;
        for nv in [8, 5] {
            let polys: Vec<Vec<Fr>> = (0..3)
                .map(|_| (0..1 << nv).map(|_| Fr::rand(&mut rng)).collect())
                .collect();
            let coeffs: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
            let constant = Fr::rand(&mut rng);
            let comms = polys
                .iter()
                .map(|p| PST13::commit(&ck, &Arc::new(MLE::from_evaluations_vec(nv, p.clone()))))
                .collect::<SnarkResult<Vec<_>>>()?;
            let combined: Vec<Fr> = (0..1 << nv)
                .map(|x| constant + (0..3).map(|j| coeffs[j] * polys[j][x]).sum::<Fr>())
                .collect();
            let expected = PST13::commit(&ck, &Arc::new(MLE::from_evaluations_vec(nv, combined)))?;
            let terms: Vec<_> = coeffs.iter().copied().zip(comms.iter()).collect();
            assert_eq!(
                PST13::commit_linear_combination(&ck, nv, &terms, constant)?,
                Some(expected)
            );
        }
        let small = PST13::commit(&ck, &Arc::new(MLE::rand(5, &mut rng)))?;
        assert_eq!(
            PST13::commit_linear_combination(&ck, 8, &[(Fr::one(), &small)], Fr::zero())?,
            None
        );
        Ok(())
    }

    #[test]
    fn test_single_commit() -> SnarkResult<()> {
        let mut rng = test_rng();

        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;

        // normal polynomials
        let poly1 = Arc::new(MLE::rand(8, &mut rng));
        test_single_helper(&params, &poly1, &mut rng)?;

        // single-variate polynomials
        let poly2 = Arc::new(MLE::rand(1, &mut rng));
        test_single_helper(&params, &poly2, &mut rng)?;

        Ok(())
    }

    /// A polynomial padded to more variables than it was committed with,
    /// and a point longer than it: both read the first coordinates only,
    /// and the opening is the one of the committed polynomial.
    #[test]
    fn opening_reads_as_many_coordinates_as_the_commitment_has_variables() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 8)?;
        let (ck, vk) = PST13::trim(&params, None, Some(8))?;
        let inner = MLE::rand(3, &mut rng);
        let padded = Arc::new(MLE::new(inner.mat_mle().into_owned(), Some(6)));
        let inner = Arc::new(inner);
        let point: Vec<Fr> = (0..6).map(|_| Fr::rand(&mut rng)).collect();

        let com = PST13::commit(&ck, &padded)?;
        assert_eq!(com.nv, 3);
        let (proof, value) = PST13::open(&ck, &padded, &point, None)?;
        assert_eq!(
            (proof.clone(), value),
            PST13::open(&ck, &inner, &point[..3].to_vec(), None)?
        );
        assert_eq!(value, inner.evaluate(&point[..3].to_vec()));
        assert_eq!(proof.proofs.len(), 3);
        assert!(PST13::verify(&vk, &com, &point, &value, &proof)?);
        assert!(PST13::verify(
            &vk,
            &com,
            &point[..3].to_vec(),
            &value,
            &proof
        )?);

        // Another coordinate the polynomial reads, another value, a point
        // too short, and a proof with a quotient missing.
        let mut moved = point.clone();
        moved[2] += Fr::from(1u64);
        assert!(!PST13::verify(&vk, &com, &moved, &value, &proof)?);
        assert!(!PST13::verify(
            &vk,
            &com,
            &point,
            &(value + Fr::from(1u64)),
            &proof
        )?);
        assert!(PST13::verify(&vk, &com, &point[..2].to_vec(), &value, &proof).is_err());
        assert!(PST13::open(&ck, &padded, &point[..2].to_vec(), None).is_err());
        let mut short = proof.clone();
        short.proofs.pop();
        assert!(!PST13::verify(&vk, &com, &point, &value, &short)?);
        Ok(())
    }

    #[test]
    fn test_wrapped_commit_matches_inner_commit() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;
        let (ck, _) = PST13::trim(&params, None, Some(6))?;

        let inner = MLE::rand(3, &mut rng);
        let wrapped = Arc::new(MLE::new(inner.mat_mle().into_owned(), Some(6)));
        let inner = Arc::new(inner);

        let wrapped_commit = PST13::commit(&ck, &wrapped)?;
        let inner_commit = PST13::commit(&ck, &inner)?;

        assert_eq!(wrapped_commit, inner_commit);
        assert_eq!(wrapped_commit.nv, inner.num_vars() as u8);

        Ok(())
    }

    /// A sparse polynomial commits to what its table does, with a default
    /// of zero or not, and with no exception at all.
    #[test]
    fn sparse_commit_matches_the_commit_of_its_table() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 8)?;
        let (ck, _) = PST13::trim(&params, None, Some(8))?;
        let nv = 7;
        let exceptions: Vec<(u32, Fr)> = [3u32, 17, 64, 100, 127]
            .iter()
            .map(|row| (*row, Fr::rand(&mut rng)))
            .collect();
        for default in [Fr::zero(), Fr::one(), Fr::from(5u64), Fr::rand(&mut rng)] {
            for exceptions in [exceptions.clone(), Vec::new()] {
                let sparse = MLE::from_sparse(default, exceptions.clone(), nv).unwrap();
                assert!(matches!(sparse.storage(), MLEStorage::Sparse { .. }));
                let table = Arc::new(MLE::from_evaluations_vec(nv, sparse.evaluations()));
                assert_eq!(
                    PST13::commit(&ck, &Arc::new(sparse))?,
                    PST13::commit(&ck, &table)?
                );
            }
        }
        Ok(())
    }

    /// Every range of every SRS level sums to the serial sum of its points.
    #[test]
    fn range_sum_is_the_sum_of_the_range() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 5)?;
        let powers = &params.prover_param.powers_of_g;
        for ignored in 0..powers.len() {
            let levels = &powers[ignored..];
            let bases = &levels[0].evals;
            for start in 0..=bases.len() {
                for end in start..=bases.len() + 2 {
                    let serial: <E as Pairing>::G1 =
                        bases[start..end.min(bases.len())].iter().sum();
                    assert_eq!(range_sum::<E>(levels, start, end), serial);
                }
            }
        }
        Ok(())
    }

    /// Constant and run-length storage commit to what their table does, on
    /// a key trimmed below the SRS and at fewer variables than the key.
    #[test]
    fn constant_and_rle_commit_match_the_commit_of_their_table() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;
        let (ck, _) = PST13::trim(&params, None, Some(8))?;
        let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let commit_both = |nv: usize, evals: Vec<Fr>| -> SnarkResult<()> {
            let table = MLE::from_evaluations_vec(nv, evals);
            let compact = table.clone().detect_redundancy();
            assert!(matches!(
                compact.storage(),
                MLEStorage::Constant { .. } | MLEStorage::Rle { .. }
            ));
            assert_eq!(
                PST13::commit(&ck, &Arc::new(compact))?,
                PST13::commit(&ck, &Arc::new(table))?
            );
            Ok(())
        };
        for nv in [0, 1, 3, 7, 8] {
            for value in [Fr::zero(), Fr::one(), a] {
                commit_both(nv, vec![value; 1 << nv])?;
            }
        }
        let runs: [&[(Fr, usize)]; 4] = [
            &[(a, 4), (b, 4), (Fr::one(), 8), (a, 16), (b, 96)],
            &[(a, 3), (Fr::zero(), 5), (Fr::one(), 1), (b, 7), (a, 112)],
            &[(Fr::zero(), 37), (a, 90), (Fr::zero(), 1)],
            &[(b, 1), (Fr::one(), 126), (a, 1)],
        ];
        for runs in runs {
            let evals = runs
                .iter()
                .flat_map(|(v, n)| std::iter::repeat_n(*v, *n))
                .collect();
            commit_both(7, evals)?;
        }
        for (skip, active_len) in [(0, 1), (0, 77), (5, 64), (64, 64), (127, 1)] {
            let window = MLE::from_window_activator(skip, active_len, 7);
            let table = MLE::from_evaluations_vec(7, window.evaluations());
            assert_eq!(
                PST13::commit(&ck, &Arc::new(window))?,
                PST13::commit(&ck, &Arc::new(table))?
            );
        }
        Ok(())
    }

    /// The small-scalar MSMs of compressed storage give the dense MSM's
    /// commitment.
    #[test]
    fn compressed_commit_matches_the_commit_of_its_table() -> SnarkResult<()> {
        let mut rng = test_rng();
        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 8)?;
        let (ck, _) = PST13::trim(&params, None, Some(8))?;
        let bounds = [2u64, 1 << 8, 1 << 32, u64::MAX];
        for nv in [0, 2, 3, 8] {
            for bound in bounds {
                let evals: Vec<Fr> = (0..1 << nv)
                    .map(|_| Fr::from(rng.gen_range(0..bound)))
                    .collect();
                let table = Arc::new(MLE::from_evaluations_vec(nv, evals.clone()));
                let compressed = MLE::from_evaluations_vec_compressed(nv, evals);
                assert!(!compressed.storage().is_field());
                assert_eq!(
                    PST13::commit(&ck, &Arc::new(compressed))?,
                    PST13::commit(&ck, &table)?
                );
            }
        }
        Ok(())
    }
}
