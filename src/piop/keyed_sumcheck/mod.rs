//! A PIOP checking that two unions of multiset columns (each weighted by optional
//! multiplicity polynomials) are equal — a generalization of
//! [Logup](https://eprint.iacr.org/2022/1530.pdf), used heavily by other PIOPs.

mod honest_prover;
use crate::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{
        InputShapeError::{EmptyInput, InputLengthMismatch},
        SnarkError, SnarkResult,
    },
    piop::PIOP,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{
        ArgVerifier,
        errors::VerifierError::{self, VerifierInputShapeError},
        structs::oracle::TrackedOracle,
    },
};
use ark_ff::One;
use ark_ff::Zero;
use derivative::Derivative;
use either::Either;
use std::marker::PhantomData;
use std::ops::Neg;
pub struct KeyedSumcheck<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct KeyedSumcheckProverInput<B: SnarkBackend> {
    pub fxs: Vec<TrackedPoly<B>>,
    pub gxs: Vec<TrackedPoly<B>>,
    pub mfxs: Vec<Option<TrackedPoly<B>>>,
    pub mgxs: Vec<Option<TrackedPoly<B>>>,
}

pub struct KeyedSumcheckVerifierInput<B: SnarkBackend> {
    pub fxs: Vec<TrackedOracle<B>>,
    pub gxs: Vec<TrackedOracle<B>>,
    pub mfxs: Vec<Option<TrackedOracle<B>>>,
    pub mgxs: Vec<Option<TrackedOracle<B>>>,
}

impl<B: SnarkBackend> PIOP<B> for KeyedSumcheck<B> {
    type ProverInput = KeyedSumcheckProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = KeyedSumcheckVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        Self::honest_prover_check_helper(&input)
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // gamma appears in the denominator of the sum.
        let gamma = prover.get_and_append_challenge(b"gamma")?;
        // Generate subclaims; adjacent terms with equal domain size and unit
        // multiplicity (m = None) are batched into a single proxy witness commitment.
        let mut i = 0;
        while i < input.fxs.len() {
            if i + 1 < input.fxs.len()
                && input.mfxs[i].is_none()
                && input.mfxs[i + 1].is_none()
                && input.fxs[i].log_size() == input.fxs[i + 1].log_size()
            {
                Self::prove_generate_pair_subclaim(
                    prover,
                    input.fxs[i].clone(),
                    input.fxs[i + 1].clone(),
                    gamma,
                )?;
                i += 2;
                continue;
            }

            Self::prove_generate_subclaims(
                prover,
                input.fxs[i].clone(),
                input.mfxs[i].clone(),
                gamma,
            )?;
            i += 1;
        }

        let mut i = 0;
        while i < input.gxs.len() {
            if i + 1 < input.gxs.len()
                && input.mgxs[i].is_none()
                && input.mgxs[i + 1].is_none()
                && input.gxs[i].log_size() == input.gxs[i + 1].log_size()
            {
                Self::prove_generate_pair_subclaim(
                    prover,
                    input.gxs[i].clone(),
                    input.gxs[i + 1].clone(),
                    gamma,
                )?;
                i += 2;
                continue;
            }

            Self::prove_generate_subclaims(
                prover,
                input.gxs[i].clone(),
                input.mgxs[i].clone(),
                gamma,
            )?;
            i += 1;
        }
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // check input shapes are correct
        if input.fxs.is_empty() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                EmptyInput,
            )));
        }
        if input.fxs.len() != input.mfxs.len() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                InputLengthMismatch {
                    expected: input.fxs.len(),
                    actual: input.mfxs.len(),
                },
            )));
        }
        if input.gxs.is_empty() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                EmptyInput,
            )));
        }

        if input.gxs.len() != input.mgxs.len() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                InputLengthMismatch {
                    expected: input.gxs.len(),
                    actual: input.mgxs.len(),
                },
            )));
        }

        // Challenges/commitments must mirror the prover's order; proof inputs are
        // assumed to already be in the tracker.
        let gamma = verifier.get_and_append_challenge(b"gamma")?;
        // Un-scale each recorded sum by the *claim poly's* nv (max over phat =
        // col nv and the multiplicity poly — mirroring `track_virt_poly`), not
        // the col's own nv: a col whose multiplicity is materialized at a
        // larger nv registers (and is recorded) at that nv, and col-nv
        // accounting drifts by a power of two. Pair subclaims use phat alone,
        // so their claim nv is the col nv.
        let claim_nv = |p: &TrackedOracle<B>, m: &Option<TrackedOracle<B>>| -> usize {
            let mut nv = p.log_size();
            if let Some(m) = m {
                nv = nv.max(m.log_size());
            }
            nv
        };
        let max_nv_f = input
            .fxs
            .iter()
            .zip(&input.mfxs)
            .map(|(x, m)| claim_nv(x, m))
            .max()
            .unwrap();
        let max_nv_g = input
            .gxs
            .iter()
            .zip(&input.mgxs)
            .map(|(x, m)| claim_nv(x, m))
            .max()
            .unwrap();
        let max_nv = max_nv_f.max(max_nv_g);
        let mut lhs_v: B::F = B::F::zero();
        let mut rhs_v: B::F = B::F::zero();
        let mut i = 0;
        while i < input.fxs.len() {
            if i + 1 < input.fxs.len()
                && input.mfxs[i].is_none()
                && input.mfxs[i + 1].is_none()
                && input.fxs[i].log_size() == input.fxs[i + 1].log_size()
            {
                let sum_claim_v = Self::verify_generate_pair_subclaim(
                    verifier,
                    input.fxs[i].clone(),
                    input.fxs[i + 1].clone(),
                    gamma,
                )?;
                let ratio = 2_usize.pow((max_nv - input.fxs[i].log_size()) as u32);
                let sum_claim_v_adj = sum_claim_v / B::F::from(ratio as u64);
                lhs_v += sum_claim_v_adj;
                i += 2;
                continue;
            }

            let sum_claim_v = Self::verify_generate_subclaims(
                verifier,
                input.fxs[i].clone(),
                input.mfxs[i].clone(),
                gamma,
            )?;
            let ratio = 2_usize.pow((max_nv - claim_nv(&input.fxs[i], &input.mfxs[i])) as u32);
            let sum_claim_v_adj = sum_claim_v / B::F::from(ratio as u64);
            lhs_v += sum_claim_v_adj;
            i += 1;
        }

        let mut i = 0;
        while i < input.gxs.len() {
            if i + 1 < input.gxs.len()
                && input.mgxs[i].is_none()
                && input.mgxs[i + 1].is_none()
                && input.gxs[i].log_size() == input.gxs[i + 1].log_size()
            {
                let sum_claim_v = Self::verify_generate_pair_subclaim(
                    verifier,
                    input.gxs[i].clone(),
                    input.gxs[i + 1].clone(),
                    gamma,
                )?;
                let ratio = 2_usize.pow((max_nv - input.gxs[i].log_size()) as u32);
                let sum_claim_v_adj = sum_claim_v / B::F::from(ratio as u64);
                rhs_v += sum_claim_v_adj;
                i += 2;
                continue;
            }

            let sum_claim_v = Self::verify_generate_subclaims(
                verifier,
                input.gxs[i].clone(),
                input.mgxs[i].clone(),
                gamma,
            )?;
            let ratio = 2_usize.pow((max_nv - claim_nv(&input.gxs[i], &input.mgxs[i])) as u32);
            let sum_claim_v_adj = sum_claim_v / B::F::from(ratio as u64);
            rhs_v += sum_claim_v_adj;
            i += 1;
        }

        // check that the values of claimed sums are equal
        if lhs_v != rhs_v {
            tracing::debug!(
                target: "ark_piop::piop::keyed_sumcheck",
                f_ids = %format_tracked_oracle_ids(&input.fxs),
                g_ids = %format_tracked_oracle_ids(&input.gxs),
                mf_ids = %format_tracked_oracle_opt_ids(&input.mfxs),
                mg_ids = %format_tracked_oracle_opt_ids(&input.mgxs),
                lhs = %lhs_v,
                rhs = %rhs_v,
                "keyed sumcheck mismatch"
            );
            let mut err_msg = "LHS and RHS have different sums".to_string();
            err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
            return Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed(err_msg),
            ));
        }

        Ok(())
    }
}

fn format_tracked_oracle_ids<B: SnarkBackend>(oracles: &[TrackedOracle<B>]) -> String {
    let mut out = String::from("[");
    for (i, oracle) in oracles.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match oracle.id_or_const() {
            Either::Left(id) => out.push_str(&format!("{:?}", id)),
            Either::Right(_c) => out.push_str("const"),
        }
    }
    out.push(']');
    out
}

fn format_tracked_oracle_opt_ids<B: SnarkBackend>(oracles: &[Option<TrackedOracle<B>>]) -> String {
    let mut out = String::from("[");
    for (i, oracle) in oracles.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match oracle {
            Some(o) => match o.id_or_const() {
                Either::Left(id) => out.push_str(&format!("{:?}", id)),
                Either::Right(_c) => out.push_str("const"),
            },
            None => out.push_str("none"),
        }
    }
    out.push(']');
    out
}

impl<B: SnarkBackend> KeyedSumcheck<B> {
    fn prove_generate_subclaims(
        tracker: &mut ArgProver<B>,
        p: TrackedPoly<B>,
        m: Option<TrackedPoly<B>>,
        gamma: B::F,
    ) -> SnarkResult<()> {
        let nv = p.log_size();
        // phat = 1/(p(x) - gamma), the denominator of the sum. Subtract and invert
        // in place: peak transient is 1× 2^nv.
        let mut phat_evals: Vec<B::F> = p.evaluations();
        for x in phat_evals.iter_mut() {
            *x -= gamma;
        }
        ark_ff::fields::batch_inversion(phat_evals.as_mut_slice());
        let phat_mle = MLE::from_evaluations_vec(nv, phat_evals);

        // Calculate what the final sum should be.
        let mut v = B::F::zero();
        let phat = tracker.track_and_commit_mat_mv_poly(&phat_mle)?;
        let (sumcheck_challenge_poly, v) = match m {
            Some(m) => {
                let m_evals = m.evaluations();
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i] * m_evals[i];
                }
                (&phat * &m, v)
            }
            None => {
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i];
                }
                (phat.clone(), v)
            }
        };

        // If `p` is materialized, swap the dense phat (already committed above) for a
        // lazy `1/(p - γ)` backing referencing p's tracked Arc — frees ~2^nv·sizeof(F)
        // per phat; sumcheck reads it via the streaming path. When p is virtual there
        // is no Arc to reference and forcing it dense would be a wash, so keep dense.
        let p_id = p.id();
        let has_mat = tracker.tracker().borrow().has_materialized_mv_poly(p_id);
        if has_mat {
            drop(phat_mle);
            let p_source = tracker.mat_mv_poly(p_id);
            let lazy_phat = MLE::from_lazy_inverse_shifted(p_source, gamma);
            // Resolve the id *before* the mutable borrow: `phat.id()` on a
            // constant-backed poly borrows the tracker and would panic the RefCell.
            let phat_id = phat.id();
            tracker
                .tracker()
                .borrow_mut()
                .register_mat_mv_poly(phat_id, lazy_phat);
        } else {
            drop(phat_mle);
        }

        // Zerocheck that phat is well-formed: (p(x)-gamma) * phat(x) - 1 == 0.
        let phat_gamma = phat.clone() * gamma;
        let phat_check_poly = (&(&p * &phat) - &phat_gamma) + B::F::one().neg();
        tracker.add_mv_sumcheck_claim(sumcheck_challenge_poly.id(), v)?;
        tracker.add_mv_zerocheck_claim(phat_check_poly.id())?;
        Ok(())
    }

    fn prove_generate_pair_subclaim(
        tracker: &mut ArgProver<B>,
        p1: TrackedPoly<B>,
        p2: TrackedPoly<B>,
        gamma: B::F,
    ) -> SnarkResult<()> {
        let nv = p1.log_size();
        debug_assert_eq!(nv, p2.log_size());

        // phat = 1/(p1-gamma) + 1/(p2-gamma), built in place with a 2× 2^nv peak
        // transient — batch inversion needs each full vector at once.
        let mut p1_minus_gamma: Vec<B::F> = p1.evaluations();
        for x in p1_minus_gamma.iter_mut() {
            *x -= gamma;
        }
        let mut p2_minus_gamma: Vec<B::F> = p2.evaluations();
        for x in p2_minus_gamma.iter_mut() {
            *x -= gamma;
        }
        ark_ff::fields::batch_inversion(p1_minus_gamma.as_mut_slice());
        ark_ff::fields::batch_inversion(p2_minus_gamma.as_mut_slice());

        // Fuse the two inverse tables into p2's allocation, accumulating v in the
        // same pass.
        let mut v = B::F::zero();
        for (dst, add) in p2_minus_gamma.iter_mut().zip(p1_minus_gamma.iter()) {
            *dst += *add;
            v += *dst;
        }
        // Free 1× 2^nv before the MLE / tracker take over.
        drop(p1_minus_gamma);
        let phat_evals = p2_minus_gamma;
        let phat_mle = MLE::from_evaluations_vec(nv, phat_evals);
        let phat = tracker.track_and_commit_mat_mv_poly(&phat_mle)?;

        // Swap the dense phat_mle for a lazy `1/(p1 - γ) + 1/(p2 - γ)` backing, but
        // only when BOTH sources are materialized — see the single-side branch.
        let p1_id = p1.id();
        let p2_id = p2.id();
        let both_mat = {
            let tracker_rc = tracker.tracker();
            let borrow = tracker_rc.borrow();
            borrow.has_materialized_mv_poly(p1_id) && borrow.has_materialized_mv_poly(p2_id)
        };
        if both_mat {
            drop(phat_mle);
            let p1_source = tracker.mat_mv_poly(p1_id);
            let p2_source = tracker.mat_mv_poly(p2_id);
            let lazy_phat = MLE::from_lazy_inverse_shifted_sum(p1_source, p2_source, gamma);
            // See `prove_generate_subclaims`: resolve the id before the mutable borrow.
            let phat_id = phat.id();
            tracker
                .tracker()
                .borrow_mut()
                .register_mat_mv_poly(phat_id, lazy_phat);
        } else {
            drop(phat_mle);
        }

        // Zerocheck:
        // phat*(p1-gamma)*(p2-gamma) - ((p1-gamma) + (p2-gamma)) == 0
        let p1_minus_gamma_poly = p1.clone().sub_scalar_poly(gamma);
        let p2_minus_gamma_poly = p2.clone().sub_scalar_poly(gamma);
        let lhs = &(&(&phat * &p1_minus_gamma_poly) * &p2_minus_gamma_poly) - &p1_minus_gamma_poly;
        let phat_check_poly = &lhs - &p2_minus_gamma_poly;

        tracker.add_mv_sumcheck_claim(phat.id(), v)?;
        tracker.add_mv_zerocheck_claim(phat_check_poly.id())?;
        Ok(())
    }

    fn verify_generate_subclaims(
        tracker: &mut ArgVerifier<B>,
        p: TrackedOracle<B>,
        m: Option<TrackedOracle<B>>,
        gamma: B::F,
    ) -> SnarkResult<B::F> {
        let phat = tracker.track_next_mv_com()?;
        // Build the virtual comms exactly as the prover does.
        let sumcheck_challenge_comm = match m {
            Some(m) => &phat * &m,
            None => phat.clone(),
        };

        let phat_gamma = phat.clone() * gamma;
        let phat_check_poly = (&(&p * &phat) - &phat_gamma) + B::F::one().neg();
        let sum_claim_v = tracker.prover_claimed_sum(sumcheck_challenge_comm.id())?;
        tracker.add_mv_sumcheck_claim(sumcheck_challenge_comm.id(), sum_claim_v);
        tracker.add_mv_zerocheck_claim(phat_check_poly.id());

        Ok(sum_claim_v)
    }

    fn verify_generate_pair_subclaim(
        tracker: &mut ArgVerifier<B>,
        p1: TrackedOracle<B>,
        p2: TrackedOracle<B>,
        gamma: B::F,
    ) -> SnarkResult<B::F> {
        let phat = tracker.track_next_mv_com()?;

        let p1_minus_gamma_oracle = p1.clone().sub_scalar_oracle(gamma);
        let p2_minus_gamma_oracle = p2.clone().sub_scalar_oracle(gamma);
        let lhs =
            &(&(&phat * &p1_minus_gamma_oracle) * &p2_minus_gamma_oracle) - &p1_minus_gamma_oracle;
        let phat_check_poly = &lhs - &p2_minus_gamma_oracle;

        let sum_claim_v = tracker.prover_claimed_sum(phat.id())?;
        tracker.add_mv_sumcheck_claim(phat.id(), sum_claim_v);
        tracker.add_mv_zerocheck_claim(phat_check_poly.id());

        Ok(sum_claim_v)
    }
}
