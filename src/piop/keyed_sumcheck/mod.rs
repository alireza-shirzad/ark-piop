//! A PIOP to check if the mulltisets of two columns are equal considering their
//! multiplicities.
//!
//! More precisely, this PIOP checks if the union of the multisets of the activated elements in a set of columns with certain multiplicity polynomials is equal to the union of the multisets of the activated elements in another set of columns with other multiplicity polynomials. It's a genralization of the [Logup](https://eprint.iacr.org/2022/1530.pdf) protocol and is heavily used throughout other PIOPs in the `col-toolbox`.

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
    structs::TrackerID,
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
        // Get the challenge gamma for the check -- Gamma appears in the denominator of
        // the sum
        let gamma = prover.get_and_append_challenge(b"gamma")?;
        // Iterate over vector elements and generate subclaims.
        // When two adjacent terms have the same domain size and unit multiplicity
        // (m = None), batch them into a single proxy witness commitment.
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

        // create challenges and comitments in same fashion as prover
        // assumption is that proof inputs are already added to the tracker
        let gamma = verifier.get_and_append_challenge(b"gamma")?;
        // iterate over vector elements and generate subclaims:
        let max_nv_f = input.fxs.iter().map(|x| x.log_size()).max().unwrap();
        let max_nv_g = input.gxs.iter().map(|x| x.log_size()).max().unwrap();
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
            let ratio = 2_usize.pow((max_nv - input.fxs[i].log_size()) as u32);
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
            let ratio = 2_usize.pow((max_nv - input.gxs[i].log_size()) as u32);
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

fn format_tracked_oracle_opt_ids<B: SnarkBackend>(
    oracles: &[Option<TrackedOracle<B>>],
) -> String {
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
        // construct phat = 1/(p(x) - gamma), i.e. the denominator of the sum
        let mut p_evals = p.evaluations().to_vec();
        let mut p_minus_gamma: Vec<B::F> = p_evals.iter_mut().map(|x| *x - gamma).collect();
        let phat_evals = p_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(phat_evals);
        let phat_mle = MLE::from_evaluations_slice(nv, phat_evals);

        // calculate what the final sum should be
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

        // Create Zerocheck claim for proving phat(x) is created correctly,
        // i.e. ZeroCheck [(p(x)-gamma) * phat(x) - 1] = [(p * phat) - gamma * phat - 1]
        let phat_gamma = phat.clone() * gamma;
        let phat_check_poly = (&(&p * &phat) - &phat_gamma) + B::F::one().neg();
        // add the delayed prover claims to the tracker
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

        // Build phat = 1/(p1-gamma) + 1/(p2-gamma).
        let mut p1_minus_gamma: Vec<B::F> = p1
            .evaluations()
            .iter()
            .map(|x| *x - gamma)
            .collect();
        let mut p2_minus_gamma: Vec<B::F> = p2
            .evaluations()
            .iter()
            .map(|x| *x - gamma)
            .collect();
        ark_ff::fields::batch_inversion(p1_minus_gamma.as_mut_slice());
        ark_ff::fields::batch_inversion(p2_minus_gamma.as_mut_slice());

        let phat_evals = p1_minus_gamma
            .iter()
            .zip(p2_minus_gamma.iter())
            .map(|(a, b)| *a + *b)
            .collect::<Vec<_>>();
        let phat_mle = MLE::from_evaluations_vec(nv, phat_evals.clone());
        let phat = tracker.track_and_commit_mat_mv_poly(&phat_mle)?;

        // Sumcheck claim is over the paired contribution itself.
        let v = phat_evals.iter().fold(B::F::zero(), |acc, x| acc + *x);

        // Zerocheck:
        // phat*(p1-gamma)*(p2-gamma) - ((p1-gamma) + (p2-gamma)) == 0
        let p1_minus_gamma_poly = p1.clone().sub_scalar_poly(gamma);
        let p2_minus_gamma_poly = p2.clone().sub_scalar_poly(gamma);
        let lhs =
            &(&(&phat * &p1_minus_gamma_poly) * &p2_minus_gamma_poly) - &p1_minus_gamma_poly;
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
        // get phat mat comm from proof and add it to the tracker
        let phat_id: TrackerID = tracker.peek_next_id();
        let phat = tracker.track_mv_com_by_id(phat_id)?;
        // make the virtual comms as prover does
        let sumcheck_challenge_comm = match m {
            Some(m) => &phat * &m,
            None => phat.clone(),
        };

        let phat_gamma = phat.clone() * gamma;
        let phat_check_poly = (&(&p * &phat) - &phat_gamma) + B::F::one().neg();
        // add the delayed prover claims to the tracker
        let sum_claim_v = tracker.prover_claimed_sum(sumcheck_challenge_comm.id())?;
        tracker.add_sumcheck_claim(sumcheck_challenge_comm.id(), sum_claim_v);
        tracker.add_zerocheck_claim(phat_check_poly.id());

        Ok(sum_claim_v)
    }

    fn verify_generate_pair_subclaim(
        tracker: &mut ArgVerifier<B>,
        p1: TrackedOracle<B>,
        p2: TrackedOracle<B>,
        gamma: B::F,
    ) -> SnarkResult<B::F> {
        let phat_id: TrackerID = tracker.peek_next_id();
        let phat = tracker.track_mv_com_by_id(phat_id)?;

        let p1_minus_gamma_oracle = p1.clone().sub_scalar_oracle(gamma);
        let p2_minus_gamma_oracle = p2.clone().sub_scalar_oracle(gamma);
        let lhs = &(&(&phat * &p1_minus_gamma_oracle) * &p2_minus_gamma_oracle)
            - &p1_minus_gamma_oracle;
        let phat_check_poly = &lhs - &p2_minus_gamma_oracle;

        let sum_claim_v = tracker.prover_claimed_sum(phat.id())?;
        tracker.add_sumcheck_claim(phat.id(), sum_claim_v);
        tracker.add_zerocheck_claim(phat_check_poly.id());

        Ok(sum_claim_v)
    }
}
