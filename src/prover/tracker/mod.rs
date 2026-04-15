//! ProverTracker — central state manager for the proving side of the PIOP.

mod algebra;
mod claims;
mod compile;
mod core_impl;
mod evaluation;
mod tracking;

use super::structs::{
    ProcessedSNARKPk, ProverState,
    proof::{PCSSubproof, SNARKProof},
};
use crate::arithmetic::mat_poly::utils::evaluate_with_eq;
use crate::{
    SnarkBackend,
    types::claim::{TrackerLookupClaim, TrackerNoZerocheckClaim},
};
use crate::{
    arithmetic::{
        mat_poly::{lde::LDE, mle::MLE, utils::build_eq_x_r},
        virt_poly::{
            VirtualPoly,
            hp_interface::{HPVirtualPolynomial, VPAuxInfo},
        },
    },
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::{structs::SumcheckProof, sum_check::SumCheck},
    setup::{
        errors::SetupError::NoRangePoly,
        structs::{SNARKPk, SNARKVk},
    },
    types::{
        CommitmentBinding, CommitmentID, ConstantID, PCSOpeningProof, PointID, SharedArgConfig,
        SumcheckSubproof, TrackerID,
        claim::{TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
};
#[cfg(feature = "honest-prover")]
use crate::{
    errors::SnarkError::ProverError, prover::errors::HonestProverError::FalseClaim,
    prover::errors::ProverError::HonestProverError,
};
use crate::{prover::structs::TrackerEvalClaim, prover::structs::polynomial::TrackedPoly};
use ark_ec::AdditiveGroup;
use ark_ff::batch_inversion;
use ark_poly::Polynomial;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use ark_std::Zero;

use ark_std::{cfg_iter, cfg_iter_mut};
use derivative::Derivative;
use either::Either;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashSet},
    mem::take,
    panic,
    rc::Rc,
    rc::Weak,
    sync::Arc,
    time::Instant,
};
use tracing::{debug, info, instrument, trace};

#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
struct ReduceSumcheckDegreeStats {
    max_degree: usize,
    num_committed: usize,
}

#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
struct SumcheckInvocationStats {
    degree: usize,
    num_terms: usize,
    prove_time_s: f64,
}

#[derive(Clone, Debug, Default)]
struct ClaimStageStats {
    non_zero_checks_count: usize,
    non_zero_checks_degree_distribution: Vec<usize>,
    zero_checks_count: usize,
    zero_checks_degree_distribution: Vec<usize>,
    sum_checks_count: usize,
    sum_checks_degree_distribution: Vec<usize>,
}

#[derive(Clone, Copy, Debug, Default)]
struct ScCompileTimingBreakdown {
    nozerocheck_batching_time_s: f64,
    first_batch_zerocheck_time_s: f64,
    first_zerocheck_to_sumcheck_time_s: f64,
    first_batch_sumcheck_time_s: f64,
    reduce_sumcheck_time_s: f64,
    second_batch_zerocheck_time_s: f64,
    second_zerocheck_to_sumcheck_time_s: f64,
    sumcheck_time_s: f64,
}
/// The Tracker is a data structure for creating and managing virtual
/// polynomials and their comitments. It is in charge of
///  1) Recording the structure of virtual polynomials and
///     their products
///  2) Recording the structure of virtual polynomials and
///     their products
///  3) Recording the comitments of virtual polynomials and
///     their products
///  4) Providing methods for adding virtual polynomials
///     together

// Clone is only implemented if PCS satisfies the PCS<F>
// bound, which guarantees that PCS::ProverParam
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
// #[derivative(Clone(bound = "MvPCS: Clone, UvPCS: Clone"))]
pub struct ProverTracker<B>
where
    B: SnarkBackend,
{
    pub(super) pk: ProcessedSNARKPk<B>,
    pub(super) state: ProverState<B>,
    pub(super) config: SharedArgConfig,
    pub(super) self_rc: Option<Weak<RefCell<ProverTracker<B>>>>,
}

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    fn current_claim_stage_stats(&self) -> ClaimStageStats {
        let non_zero_checks_degree_distribution = self
            .state
            .mv_pcs_substate
            .no_zero_check_claims
            .iter()
            .map(|claim| self.virt_poly_degree(claim.id()))
            .collect::<Vec<_>>();
        let zero_checks_degree_distribution = self
            .state
            .mv_pcs_substate
            .zero_check_claims
            .iter()
            .map(|claim| self.virt_poly_degree(claim.id()))
            .collect::<Vec<_>>();
        let sum_checks_degree_distribution = self
            .state
            .mv_pcs_substate
            .sum_check_claims
            .iter()
            .map(|claim| self.virt_poly_degree(claim.id()))
            .collect::<Vec<_>>();

        ClaimStageStats {
            non_zero_checks_count: non_zero_checks_degree_distribution.len(),
            non_zero_checks_degree_distribution,
            zero_checks_count: zero_checks_degree_distribution.len(),
            zero_checks_degree_distribution,
            sum_checks_count: sum_checks_degree_distribution.len(),
            sum_checks_degree_distribution,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_claim_pipeline_stats(
        &self,
        before_initial: &ClaimStageStats,
        before_after_nozero_batching: &ClaimStageStats,
        before_after_zero_batching: &ClaimStageStats,
        before_after_sum_batching: &ClaimStageStats,
        after_initial: &ClaimStageStats,
        after_after_zero_batching: &ClaimStageStats,
        after_after_sum_batching: &ClaimStageStats,
    ) {
        info!(
            target: "bench_stats",
            claims_before_degree_reduction_initial_non_zero_checks_count = before_initial.non_zero_checks_count,
            claims_before_degree_reduction_initial_non_zero_checks_degree_distribution = ?before_initial.non_zero_checks_degree_distribution,
            claims_before_degree_reduction_initial_zero_checks_count = before_initial.zero_checks_count,
            claims_before_degree_reduction_initial_zero_checks_degree_distribution = ?before_initial.zero_checks_degree_distribution,
            claims_before_degree_reduction_initial_sum_checks_count = before_initial.sum_checks_count,
            claims_before_degree_reduction_initial_sum_checks_degree_distribution = ?before_initial.sum_checks_degree_distribution,
            claims_before_degree_reduction_after_nozero_batching_non_zero_checks_count = before_after_nozero_batching.non_zero_checks_count,
            claims_before_degree_reduction_after_nozero_batching_non_zero_checks_degree_distribution = ?before_after_nozero_batching.non_zero_checks_degree_distribution,
            claims_before_degree_reduction_after_nozero_batching_zero_checks_count = before_after_nozero_batching.zero_checks_count,
            claims_before_degree_reduction_after_nozero_batching_zero_checks_degree_distribution = ?before_after_nozero_batching.zero_checks_degree_distribution,
            claims_before_degree_reduction_after_nozero_batching_sum_checks_count = before_after_nozero_batching.sum_checks_count,
            claims_before_degree_reduction_after_nozero_batching_sum_checks_degree_distribution = ?before_after_nozero_batching.sum_checks_degree_distribution,
            claims_before_degree_reduction_after_zero_batching_non_zero_checks_count = before_after_zero_batching.non_zero_checks_count,
            claims_before_degree_reduction_after_zero_batching_non_zero_checks_degree_distribution = ?before_after_zero_batching.non_zero_checks_degree_distribution,
            claims_before_degree_reduction_after_zero_batching_zero_checks_count = before_after_zero_batching.zero_checks_count,
            claims_before_degree_reduction_after_zero_batching_zero_checks_degree_distribution = ?before_after_zero_batching.zero_checks_degree_distribution,
            claims_before_degree_reduction_after_zero_batching_sum_checks_count = before_after_zero_batching.sum_checks_count,
            claims_before_degree_reduction_after_zero_batching_sum_checks_degree_distribution = ?before_after_zero_batching.sum_checks_degree_distribution,
            claims_before_degree_reduction_after_sum_batching_non_zero_checks_count = before_after_sum_batching.non_zero_checks_count,
            claims_before_degree_reduction_after_sum_batching_non_zero_checks_degree_distribution = ?before_after_sum_batching.non_zero_checks_degree_distribution,
            claims_before_degree_reduction_after_sum_batching_zero_checks_count = before_after_sum_batching.zero_checks_count,
            claims_before_degree_reduction_after_sum_batching_zero_checks_degree_distribution = ?before_after_sum_batching.zero_checks_degree_distribution,
            claims_before_degree_reduction_after_sum_batching_sum_checks_count = before_after_sum_batching.sum_checks_count,
            claims_before_degree_reduction_after_sum_batching_sum_checks_degree_distribution = ?before_after_sum_batching.sum_checks_degree_distribution,
            claims_after_degree_reduction_initial_non_zero_checks_count = after_initial.non_zero_checks_count,
            claims_after_degree_reduction_initial_non_zero_checks_degree_distribution = ?after_initial.non_zero_checks_degree_distribution,
            claims_after_degree_reduction_initial_zero_checks_count = after_initial.zero_checks_count,
            claims_after_degree_reduction_initial_zero_checks_degree_distribution = ?after_initial.zero_checks_degree_distribution,
            claims_after_degree_reduction_initial_sum_checks_count = after_initial.sum_checks_count,
            claims_after_degree_reduction_initial_sum_checks_degree_distribution = ?after_initial.sum_checks_degree_distribution,
            claims_after_degree_reduction_after_zero_batching_non_zero_checks_count = after_after_zero_batching.non_zero_checks_count,
            claims_after_degree_reduction_after_zero_batching_non_zero_checks_degree_distribution = ?after_after_zero_batching.non_zero_checks_degree_distribution,
            claims_after_degree_reduction_after_zero_batching_zero_checks_count = after_after_zero_batching.zero_checks_count,
            claims_after_degree_reduction_after_zero_batching_zero_checks_degree_distribution = ?after_after_zero_batching.zero_checks_degree_distribution,
            claims_after_degree_reduction_after_zero_batching_sum_checks_count = after_after_zero_batching.sum_checks_count,
            claims_after_degree_reduction_after_zero_batching_sum_checks_degree_distribution = ?after_after_zero_batching.sum_checks_degree_distribution,
            claims_after_degree_reduction_after_sum_batching_non_zero_checks_count = after_after_sum_batching.non_zero_checks_count,
            claims_after_degree_reduction_after_sum_batching_non_zero_checks_degree_distribution = ?after_after_sum_batching.non_zero_checks_degree_distribution,
            claims_after_degree_reduction_after_sum_batching_zero_checks_count = after_after_sum_batching.zero_checks_count,
            claims_after_degree_reduction_after_sum_batching_zero_checks_degree_distribution = ?after_after_sum_batching.zero_checks_degree_distribution,
            claims_after_degree_reduction_after_sum_batching_sum_checks_count = after_after_sum_batching.sum_checks_count,
            claims_after_degree_reduction_after_sum_batching_sum_checks_degree_distribution = ?after_after_sum_batching.sum_checks_degree_distribution,
            "sc_claim_counts"
        );
    }

    fn emit_sc_compile_timing_breakdown(&self, breakdown: ScCompileTimingBreakdown) {
        info!(
            target: "bench_stats",
            snark_prover_piop_nozerocheck_batching_time_s = breakdown.nozerocheck_batching_time_s,
            snark_prover_piop_first_batch_zerocheck_time_s = breakdown.first_batch_zerocheck_time_s,
            snark_prover_piop_first_zerocheck_to_sumcheck_time_s = breakdown.first_zerocheck_to_sumcheck_time_s,
            snark_prover_piop_first_batch_sumcheck_time_s = breakdown.first_batch_sumcheck_time_s,
            snark_prover_piop_reduce_sumcheck_time_s = breakdown.reduce_sumcheck_time_s,
            snark_prover_piop_second_batch_zerocheck_time_s = breakdown.second_batch_zerocheck_time_s,
            snark_prover_piop_second_zerocheck_to_sumcheck_time_s = breakdown.second_zerocheck_to_sumcheck_time_s,
            snark_prover_piop_sumcheck_time_s = breakdown.sumcheck_time_s,
            "snark_prover_piop_breakdown"
        );
    }

    pub fn new_from_pk(pk: SNARKPk<B>) -> Self {
        Self::new_from_pk_with_config(pk, SharedArgConfig::default())
    }

    pub fn new_from_pk_with_config(pk: SNARKPk<B>, config: SharedArgConfig) -> Self {
        let mut tracker = Self {
            pk: ProcessedSNARKPk::new_from_pk(&pk),
            state: ProverState::default(),
            config,
            self_rc: None,
        };
        tracker.add_vk_to_transcript(pk.vk.clone());
        tracker
    }

    pub fn set_self_rc(&mut self, self_rc: Weak<RefCell<ProverTracker<B>>>) {
        self.self_rc = Some(self_rc);
    }

    fn add_vk_to_transcript(&mut self, vk: SNARKVk<B>) {
        self.state
            .transcript
            .append_serializable_element(b"vk", &vk)
            .unwrap();
        vk.indexed_coms.iter().for_each(|(_, comm)| {
            self.state
                .transcript
                .append_serializable_element(b"comm", comm)
                .unwrap();
        });
    }

    pub(crate) fn set_indexed_tracked_polys(
        &mut self,
        range_tr_polys: BTreeMap<String, TrackedPoly<B>>,
    ) {
        self.state.indexed_tracked_polys = range_tr_polys;
    }

    /// Get the range tracked polynomial given the data type
    pub fn indexed_tracked_poly(&self, label: String) -> SnarkResult<TrackedPoly<B>> {
        match self.state.indexed_tracked_polys.get(&label) {
            Some(poly) => Ok(poly.clone()),
            _ => Err(SnarkError::SetupError(NoRangePoly(format!("{:?}", label)))),
        }
    }

    pub fn add_indexed_tracked_poly(
        &mut self,
        label: String,
        poly: TrackedPoly<B>,
    ) -> Option<TrackedPoly<B>> {
        self.state.indexed_tracked_polys.insert(label, poly)
    }

    /// Generates a new `TrackerID`.
    ///
    /// This function increments an internal counter and returns a new
    /// `TrackerID` based on the current value of the counter. It ensures
    /// that each generated `TrackerID` is unique.
    pub fn gen_id(&mut self) -> TrackerID {
        let id = self.state.num_tracked_polys;
        self.state.num_tracked_polys += 1;
        TrackerID::from_usize(id)
    }

    /// Peek at the next `TrackerID` that will be generated by gen_id.
    pub fn next_id(&mut self) -> TrackerID {
        TrackerID::from_usize(self.state.num_tracked_polys)
    }

    // Peek at the next TrackerID without incrementing the counter
    pub(crate) fn peek_next_id(&mut self) -> TrackerID {
        TrackerID::from_usize(self.state.num_tracked_polys)
    }
}

#[cfg(test)]
mod tests {
    use crate::{DefaultSnarkBackend, setup::KeyGenerator};

    use super::*;

    type F = <DefaultSnarkBackend as SnarkBackend>::F;

    fn make_tracker() -> ProverTracker<DefaultSnarkBackend> {
        let key_generator = KeyGenerator::<DefaultSnarkBackend>::new().with_num_mv_vars(16);
        let (pk, _vk) = key_generator.gen_keys().unwrap();
        ProverTracker::new_from_pk(pk)
    }

    // Helper to make a random MLE
    fn random_mle(nv: usize) -> MLE<F> {
        let evals: Vec<F> = (0..(1 << nv)).map(|i| F::from(i as u64 + 1)).collect();
        MLE::from_evaluations_vec(nv, evals)
    }

    // ── Algebra: add / sub / mul ─────────────────────────────────────

    #[test]
    fn add_polys_sums_evaluations() {
        let mut tracker = make_tracker();
        let id_a = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(
            2,
            vec![F::from(1), F::from(2), F::from(3), F::from(4)],
        ));
        let id_b = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(
            2,
            vec![F::from(10), F::from(20), F::from(30), F::from(40)],
        ));
        let id_sum = tracker.add_polys(id_a, id_b);

        let pt = vec![F::from(5), F::from(7)];
        let eval_a = tracker.evaluate_mv(id_a, &pt).unwrap();
        let eval_b = tracker.evaluate_mv(id_b, &pt).unwrap();
        let eval_sum = tracker.evaluate_mv(id_sum, &pt).unwrap();
        assert_eq!(eval_sum, eval_a + eval_b);
    }

    #[test]
    fn sub_polys_subtracts_evaluations() {
        let mut tracker = make_tracker();
        let id_a = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(
            2,
            vec![F::from(10), F::from(20), F::from(30), F::from(40)],
        ));
        let id_b = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(
            2,
            vec![F::from(1), F::from(2), F::from(3), F::from(4)],
        ));
        let id_diff = tracker.sub_polys(id_a, id_b);

        let pt = vec![F::from(5), F::from(7)];
        let eval_a = tracker.evaluate_mv(id_a, &pt).unwrap();
        let eval_b = tracker.evaluate_mv(id_b, &pt).unwrap();
        let eval_diff = tracker.evaluate_mv(id_diff, &pt).unwrap();
        assert_eq!(eval_diff, eval_a - eval_b);
    }

    #[test]
    fn mul_polys_multiplies_evaluations() {
        let mut tracker = make_tracker();
        let id_a = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(
            2,
            vec![F::from(1), F::from(2), F::from(3), F::from(4)],
        ));
        let id_b = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(
            2,
            vec![F::from(5), F::from(6), F::from(7), F::from(8)],
        ));
        let id_prod = tracker.mul_polys(id_a, id_b);

        let pt = vec![F::from(3), F::from(11)];
        let eval_a = tracker.evaluate_mv(id_a, &pt).unwrap();
        let eval_b = tracker.evaluate_mv(id_b, &pt).unwrap();
        let eval_prod = tracker.evaluate_mv(id_prod, &pt).unwrap();
        assert_eq!(eval_prod, eval_a * eval_b);
    }

    // ── Scalar operations ──────────────────────────────────────────

    #[test]
    fn mul_scalar_scales_evaluations() {
        let mut tracker = make_tracker();
        let id = tracker.track_mat_mv_poly(random_mle(3));
        let scalar = F::from(7);
        let id_scaled = tracker.mul_scalar(id, scalar);

        let pt = vec![F::from(2), F::from(3), F::from(5)];
        let eval = tracker.evaluate_mv(id, &pt).unwrap();
        let eval_scaled = tracker.evaluate_mv(id_scaled, &pt).unwrap();
        assert_eq!(eval_scaled, eval * scalar);
    }

    #[test]
    fn add_scalar_adds_constant() {
        let mut tracker = make_tracker();
        let id = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(
            2,
            vec![F::from(1), F::from(2), F::from(3), F::from(4)],
        ));
        let scalar = F::from(100);
        let id_shifted = tracker.add_scalar(id, scalar);

        let pt = vec![F::from(5), F::from(7)];
        let eval = tracker.evaluate_mv(id, &pt).unwrap();
        let eval_shifted = tracker.evaluate_mv(id_shifted, &pt).unwrap();
        assert_eq!(eval_shifted, eval + scalar);
    }

    // ── Degree computation ─────────────────────────────────────────

    #[test]
    fn degree_of_single_materialized_poly_is_one() {
        let mut tracker = make_tracker();
        let id = tracker.track_mat_mv_poly(random_mle(3));
        assert_eq!(tracker.virt_poly_degree(id), 1);
    }

    #[test]
    fn degree_of_sum_is_max_of_degrees() {
        let mut tracker = make_tracker();
        let a = tracker.track_mat_mv_poly(random_mle(3));
        let b = tracker.track_mat_mv_poly(random_mle(3));
        let sum = tracker.add_polys(a, b);
        // sum of two degree-1 polys is still degree 1
        assert_eq!(tracker.virt_poly_degree(sum), 1);
    }

    #[test]
    fn degree_of_product_is_sum_of_degrees() {
        let mut tracker = make_tracker();
        let a = tracker.track_mat_mv_poly(random_mle(3));
        let b = tracker.track_mat_mv_poly(random_mle(3));
        let prod = tracker.mul_polys(a, b);
        assert_eq!(tracker.virt_poly_degree(prod), 2);

        let c = tracker.track_mat_mv_poly(random_mle(3));
        let triple = tracker.mul_polys(prod, c);
        assert_eq!(tracker.virt_poly_degree(triple), 3);
    }

    #[test]
    fn degree_of_complex_expression() {
        let mut tracker = make_tracker();
        let a = tracker.track_mat_mv_poly(random_mle(3));
        let b = tracker.track_mat_mv_poly(random_mle(3));
        let c = tracker.track_mat_mv_poly(random_mle(3));
        // (a * b) + c has max(2, 1) = 2
        let ab = tracker.mul_polys(a, b);
        let expr = tracker.add_polys(ab, c);
        assert_eq!(tracker.virt_poly_degree(expr), 2);
    }

    // ── Constant tracking ──────────────────────────────────────────

    #[test]
    fn constant_poly_detected_at_commit_time() {
        let mut tracker = make_tracker();
        let const_mle = MLE::from_evaluations_vec(3, vec![F::from(42); 8]);
        let result = tracker
            .track_and_commit_mat_mv_p(&const_mle, false)
            .unwrap();
        // Constants return Right(id, value)
        assert!(result.is_right(), "constant MLE should be detected");
        let (_id, val) = result.right().unwrap();
        assert_eq!(val, F::from(42));
    }

    #[test]
    fn non_constant_poly_committed_normally() {
        let mut tracker = make_tracker();
        let mle = random_mle(3);
        let result = tracker.track_and_commit_mat_mv_p(&mle, false).unwrap();
        assert!(result.is_left(), "non-constant MLE should be committed");
    }

    // ── Batch evaluate ─────────────────────────────────────────────

    #[test]
    fn test_batch_evaluate_mv_single_poly() {
        let mut tracker = make_tracker();
        let poly = random_mle(3);
        let id = tracker.track_mat_mv_poly(poly);
        let pt = vec![F::from(2), F::from(3), F::from(5)];

        let expected = tracker.evaluate_mv(id, &pt).unwrap();
        let batch = tracker.batch_evaluate_mv(&[id], &pt).unwrap();

        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0], expected, "single poly batch mismatch");
    }

    #[test]
    fn test_batch_evaluate_mv_different_nvs() {
        let mut tracker = make_tracker();

        // Three polys with different nv — exercises the eq folding path
        let id_nv2 = tracker.track_mat_mv_poly(random_mle(2));
        let id_nv3 = tracker.track_mat_mv_poly(random_mle(3));
        let id_nv4 = tracker.track_mat_mv_poly(random_mle(4));

        let pt = vec![F::from(2), F::from(3), F::from(5), F::from(7)];

        let expected_nv2 = tracker.evaluate_mv(id_nv2, &pt[..2]).unwrap();
        let expected_nv3 = tracker.evaluate_mv(id_nv3, &pt[..3]).unwrap();
        let expected_nv4 = tracker.evaluate_mv(id_nv4, &pt).unwrap();

        let ids = vec![id_nv2, id_nv3, id_nv4];
        let batch = tracker.batch_evaluate_mv(&ids, &pt).unwrap();

        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0], expected_nv2, "nv=2 mismatch");
        assert_eq!(batch[1], expected_nv3, "nv=3 mismatch");
        assert_eq!(batch[2], expected_nv4, "nv=4 mismatch");
    }

    #[test]
    fn test_batch_evaluate_mv_same_nv() {
        let mut tracker = make_tracker();

        // Two polys with same nv — eq is built once and reused
        let id_a = tracker.track_mat_mv_poly(random_mle(3));
        let id_b = tracker.track_mat_mv_poly(random_mle(3));

        let pt = vec![F::from(2), F::from(3), F::from(5)];

        let expected_a = tracker.evaluate_mv(id_a, &pt).unwrap();
        let expected_b = tracker.evaluate_mv(id_b, &pt).unwrap();

        let batch = tracker.batch_evaluate_mv(&[id_a, id_b], &pt).unwrap();

        assert_eq!(batch[0], expected_a, "first nv=3 poly mismatch");
        assert_eq!(batch[1], expected_b, "second nv=3 poly mismatch");
    }

    #[test]
    fn test_batch_evaluate_mv_constant_poly() {
        let mut tracker = make_tracker();

        // nv=0 is a special case in both evaluate_mv and eq folding
        let id_const = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(0, vec![F::from(42)]));
        let id_nv3 = tracker.track_mat_mv_poly(random_mle(3));

        let pt = vec![F::from(2), F::from(3), F::from(5)];

        let expected_const = tracker.evaluate_mv(id_const, &pt[..0]).unwrap();
        let expected_nv3 = tracker.evaluate_mv(id_nv3, &pt).unwrap();

        let batch = tracker.batch_evaluate_mv(&[id_const, id_nv3], &pt).unwrap();

        assert_eq!(batch[0], expected_const, "constant poly mismatch");
        assert_eq!(batch[1], expected_nv3, "nv=3 alongside constant mismatch");
    }

    #[test]
    fn test_batch_evaluate_mv_duplicate_ids() {
        let mut tracker = make_tracker();
        let id = tracker.track_mat_mv_poly(random_mle(3));
        let pt = vec![F::from(2), F::from(3), F::from(5)];

        let expected = tracker.evaluate_mv(id, &pt).unwrap();
        let batch = tracker.batch_evaluate_mv(&[id, id, id], &pt).unwrap();

        assert_eq!(batch.len(), 3);
        assert!(
            batch.iter().all(|v| *v == expected),
            "duplicate id mismatch"
        );
    }
}
