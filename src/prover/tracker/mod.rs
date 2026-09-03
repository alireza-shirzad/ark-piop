//! ProverTracker — central state manager for the proving side of the PIOP.

mod algebra;
mod claims;
mod compile;
mod core_impl;
mod evaluation;
mod tracking;

// Re-exported for out-of-tree `bench_stats` subscribers, which need the
// span-name → record-key table to turn the subproof spans into timings.
pub use compile::{
    SC_BUCKET_SPAN, SC_REGION_SPANS, SNARK_PROVER_SPAN_TARGET, SNARK_PROVER_TIMED_SPANS,
    is_sc_region_span, snark_prover_timing_key,
};

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
        SumcheckBucketProof, SumcheckSubproof, TrackerID,
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
use ark_ff::{PrimeField, batch_inversion};
use ark_poly::Polynomial;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use ark_std::Zero;

use ark_std::{cfg_iter, cfg_iter_mut};
use derivative::Derivative;
use either::Either;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::tracker_core::bucketing::SumcheckBucket;
use ark_piop_macros::piop_stage;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashSet},
    mem::take,
    panic,
    rc::Rc,
    rc::Weak,
    sync::Arc,
};
use tracing::{debug, info, instrument, trace};

#[derive(Clone, Debug, Default)]
struct ClaimStageStats {
    non_zero_checks_count: usize,
    non_zero_checks_degree_distribution: Vec<usize>,
    zero_checks_count: usize,
    zero_checks_degree_distribution: Vec<usize>,
    sum_checks_count: usize,
    sum_checks_degree_distribution: Vec<usize>,
}

impl ClaimStageStats {
    /// Merge `other` into `self` by summing counts and concatenating degree
    /// distributions. Used to build aggregate claim stats across buckets so
    /// the dashboard's Claims tab (single-stage view) shows totals rather
    /// than only the last bucket's snapshot.
    fn merge(&mut self, other: &ClaimStageStats) {
        self.non_zero_checks_count += other.non_zero_checks_count;
        self.non_zero_checks_degree_distribution
            .extend_from_slice(&other.non_zero_checks_degree_distribution);
        self.zero_checks_count += other.zero_checks_count;
        self.zero_checks_degree_distribution
            .extend_from_slice(&other.zero_checks_degree_distribution);
        self.sum_checks_count += other.sum_checks_count;
        self.sum_checks_degree_distribution
            .extend_from_slice(&other.sum_checks_degree_distribution);
    }
}

/// Everything the bucket loop produces, so `compile_piop_subproof` reads as a
/// sequence of phases instead of threading three parallel accumulators
/// through a loop body.
struct BucketRun<F: PrimeField> {
    proofs: Vec<SumcheckBucketProof<F>>,
    /// Pre-batching claim sums, all rescaled to the run's common
    /// `global_max_nv` frame. See `ProverTracker::merge_bucket_claims`.
    claims: BTreeMap<TrackerID, F>,
    stats: Vec<BucketRunStats>,
}

impl<F: PrimeField> BucketRun<F> {
    fn with_capacity(n: usize) -> Self {
        Self {
            proofs: Vec::with_capacity(n),
            claims: BTreeMap::new(),
            stats: Vec::with_capacity(n),
        }
    }

    /// A run that produced no bucket proofs contributes no subproof — a
    /// bucket short-circuits when its claims collapse before any sumcheck
    /// is needed, and every bucket may do so.
    fn into_subproof(self) -> Option<SumcheckSubproof<F>> {
        (!self.proofs.is_empty()).then(|| SumcheckSubproof::new(self.proofs, self.claims))
    }
}

/// Per-bucket claim shape collected in [`ProverTracker::run_bucket`];
/// emitted by the caller so multi-bucket compiles don't overwrite each
/// other in the subscriber's flat field map. No timings — the subscriber
/// splices span durations in by `bucket_index`.
#[derive(Clone, Debug, Default)]
struct BucketRunStats {
    bucket_index: usize,
    target_nv: usize,
    included_nvs: Vec<usize>,
    n_zerocheck_claims: usize,
    n_sumcheck_claims: usize,
    n_nozerocheck_claims: usize,
    before_initial: ClaimStageStats,
    before_after_nozero_batching: ClaimStageStats,
    before_after_zero_batching: ClaimStageStats,
    before_after_sum_batching: ClaimStageStats,
    after_initial: ClaimStageStats,
    after_after_zero_batching: ClaimStageStats,
    after_after_sum_batching: ClaimStageStats,
}

fn wall_clock_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
/// Central prover-side state manager: records the structure of virtual
/// polynomials and their products, their commitments, and provides the
/// algebra for combining them.
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

    /// Emit a snapshot of live materialized polys (count, byte size, top-K)
    /// on the `bench_stats` target — streamed so it survives an OOM kill.
    /// `phase` is a free-form label the dashboard correlates against the
    /// RSS-over-time curve.
    fn emit_tracker_snapshot(&self, phase: &str) {
        // Physical heap bytes of each poly's storage backing. The `storage`
        // enum captures small-scalar variants (`Bit` = 1/8 byte per point,
        // `U8` = 1 byte, `U32` = 4, `U64` = 8) alongside the traditional
        // `Field` (32-byte) variant, so this now reflects true memory use
        // rather than a virtual field-element upper bound.
        let materialized = &self.state.mv_pcs_substate.materialized_polys;
        let mut entries: Vec<(TrackerID, u64, usize, &'static str)> = materialized
            .iter()
            .map(|(id, mle)| {
                let bytes = mle.storage().heap_bytes();
                let nv = mle.num_vars();
                let kind = mle.storage().kind_tag();
                (*id, bytes, nv, kind)
            })
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        let total_bytes: u64 = entries.iter().map(|(_, sz, _, _)| *sz).sum();
        let top_polys: Vec<_> = entries
            .iter()
            .take(10)
            .map(|(id, sz, nv, kind)| {
                serde_json::json!({
                    "id": id.to_int(),
                    "num_vars": nv,
                    "bytes": sz,
                    "kind": kind,
                })
            })
            .collect();
        // Per-storage-kind roll-up so the dashboard can plot compression
        // effectiveness at a glance.
        let mut by_kind: std::collections::BTreeMap<&'static str, (usize, u64)> =
            std::collections::BTreeMap::new();
        for (_, sz, _, kind) in &entries {
            let entry = by_kind.entry(*kind).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += *sz;
        }
        let kind_rollup: Vec<_> = by_kind
            .into_iter()
            .map(|(k, (count, bytes))| {
                serde_json::json!({ "kind": k, "count": count, "bytes": bytes })
            })
            .collect();
        let payload = serde_json::json!({
            "phase": phase,
            "wall_ms": wall_clock_ms(),
            "materialized_polys_count": materialized.len(),
            "materialized_polys_total_bytes": total_bytes,
            "top_polys": top_polys,
            "by_kind": kind_rollup,
        });
        info!(
            target: "bench_stats",
            tracker_snapshot_json = %payload.to_string(),
            "tracker_snapshot"
        );
        // TT_MEMSNAP=1: fallback dump to stderr, bypassing the tracing
        // subscriber, flushed even if the process is later OOM-killed.
        if std::env::var("TT_MEMSNAP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            eprintln!("[TT_MEMSNAP] {}", payload);
        }
    }

    /// Emit the `sc_claim_counts` event aggregated across every bucket
    /// (summed counts, concatenated degree distributions) in the shape the
    /// dashboard's Claims tab renders.
    fn emit_aggregate_bucket_stats(&self, buckets: &[BucketRunStats]) {
        if buckets.is_empty() {
            return;
        }
        let mut before_initial = ClaimStageStats::default();
        let mut before_after_nozero_batching = ClaimStageStats::default();
        let mut before_after_zero_batching = ClaimStageStats::default();
        let mut before_after_sum_batching = ClaimStageStats::default();
        let mut after_initial = ClaimStageStats::default();
        let mut after_after_zero_batching = ClaimStageStats::default();
        let mut after_after_sum_batching = ClaimStageStats::default();
        for b in buckets {
            before_initial.merge(&b.before_initial);
            before_after_nozero_batching.merge(&b.before_after_nozero_batching);
            before_after_zero_batching.merge(&b.before_after_zero_batching);
            before_after_sum_batching.merge(&b.before_after_sum_batching);
            after_initial.merge(&b.after_initial);
            after_after_zero_batching.merge(&b.after_after_zero_batching);
            after_after_sum_batching.merge(&b.after_after_sum_batching);
        }
        self.emit_claim_pipeline_stats(
            &before_initial,
            &before_after_nozero_batching,
            &before_after_zero_batching,
            &before_after_sum_batching,
            &after_initial,
            &after_after_zero_batching,
            &after_after_sum_batching,
        );
    }

    /// Emit every bucket's claim shape as one JSON blob (tracing field names
    /// must be static, so per-bucket fields can't stream). The subscriber
    /// adds each entry's timing by matching `index` against the
    /// [`SC_BUCKET_SPAN`] spans it timed.
    fn emit_per_bucket_stats(&self, buckets: &[BucketRunStats]) {
        let payload = serde_json::json!({
            "count": buckets.len(),
            "buckets": buckets.iter().map(|b| {
                serde_json::json!({
                    "index": b.bucket_index,
                    "target_nv": b.target_nv,
                    "included_nvs": b.included_nvs,
                    "n_zerocheck_claims": b.n_zerocheck_claims,
                    "n_sumcheck_claims": b.n_sumcheck_claims,
                    "n_nozerocheck_claims": b.n_nozerocheck_claims,
                    "n_claims_total": b.n_zerocheck_claims + b.n_sumcheck_claims + b.n_nozerocheck_claims,
                    "claims": {
                        "before_degree_reduction": {
                            "initial": Self::claim_stage_json(&b.before_initial),
                            "after_nozero_batching": Self::claim_stage_json(&b.before_after_nozero_batching),
                            "after_zero_batching": Self::claim_stage_json(&b.before_after_zero_batching),
                            "after_sum_batching": Self::claim_stage_json(&b.before_after_sum_batching),
                        },
                        "after_degree_reduction": {
                            "initial": Self::claim_stage_json(&b.after_initial),
                            "after_zero_batching": Self::claim_stage_json(&b.after_after_zero_batching),
                            "after_sum_batching": Self::claim_stage_json(&b.after_after_sum_batching),
                        },
                    },
                })
            }).collect::<Vec<_>>(),
        });
        let json_str = serde_json::to_string(&payload)
            .unwrap_or_else(|_| "{\"count\":0,\"buckets\":[]}".to_string());
        info!(
            target: "bench_stats",
            sc_buckets_json = %json_str,
            "sc_buckets_summary"
        );
    }

    fn claim_stage_json(stage: &ClaimStageStats) -> serde_json::Value {
        serde_json::json!({
            "non_zero_checks": {
                "count": stage.non_zero_checks_count,
                "degree_distribution": stage.non_zero_checks_degree_distribution,
            },
            "zero_checks": {
                "count": stage.zero_checks_count,
                "degree_distribution": stage.zero_checks_degree_distribution,
            },
            "sum_checks": {
                "count": stage.sum_checks_count,
                "degree_distribution": stage.sum_checks_degree_distribution,
            },
        })
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

    /// `add_scalar` must not materialize a fresh `2^n`-sized `Vec<F>` for
    /// the scalar — that was the memory bug the empty-product convention
    /// fixed. This test guards against a regression by asserting the
    /// tracker's materialized_polys count is unchanged after `add_scalar`.
    #[test]
    fn add_scalar_does_not_materialize_scalar_mle() {
        let mut tracker = make_tracker();
        let id = tracker.track_mat_mv_poly(random_mle(4));
        let before = tracker.state.mv_pcs_substate.materialized_polys.len();
        let _shifted = tracker.add_scalar(id, F::from(42));
        let after = tracker.state.mv_pcs_substate.materialized_polys.len();
        assert_eq!(
            before, after,
            "add_scalar should not create any new materialized poly; \
             expected empty-product convention (c, vec![]) not a materialized scalar MLE"
        );
    }

    /// Adding a constant does not change the max multiplicative degree
    /// of the polynomial. Under the empty-product convention the extra
    /// term has factor-list length 0 (degree 0), so `max` is unchanged.
    #[test]
    fn add_scalar_preserves_multiplicative_degree() {
        let mut tracker = make_tracker();
        let a = tracker.track_mat_mv_poly(random_mle(3));
        let b = tracker.track_mat_mv_poly(random_mle(3));
        // A degree-2 expression: a * b
        let ab = tracker.mul_polys(a, b);
        assert_eq!(tracker.virt_poly_degree(ab), 2);
        // Adding a scalar should preserve degree 2.
        let ab_shifted = tracker.add_scalar(ab, F::from(99));
        assert_eq!(tracker.virt_poly_degree(ab_shifted), 2);
    }

    /// `add_scalar` must compose correctly with `mul_polys` — the classic
    /// `(p + c) * q = p*q + c*q` identity when evaluated at a point.
    #[test]
    fn add_scalar_composes_with_multiplication() {
        let mut tracker = make_tracker();
        let p = tracker.track_mat_mv_poly(random_mle(3));
        let q = tracker.track_mat_mv_poly(random_mle(3));
        let c = F::from(17);

        let p_plus_c = tracker.add_scalar(p, c);
        let prod = tracker.mul_polys(p_plus_c, q);

        let pt = vec![F::from(2), F::from(3), F::from(5)];
        let eval_p = tracker.evaluate_mv(p, &pt).unwrap();
        let eval_q = tracker.evaluate_mv(q, &pt).unwrap();
        let eval_prod = tracker.evaluate_mv(prod, &pt).unwrap();
        assert_eq!(eval_prod, (eval_p + c) * eval_q);
    }

    /// Chained `add_scalar` calls must accumulate. `add_scalar(add_scalar(p, c1), c2)`
    /// should equal `p + (c1 + c2)` at every point. Under the empty-product
    /// convention this materializes as two separate constant terms in the
    /// virtual poly — the evaluator sums them.
    #[test]
    fn add_scalar_chained_composes() {
        let mut tracker = make_tracker();
        let p = tracker.track_mat_mv_poly(random_mle(3));
        let c1 = F::from(5);
        let c2 = F::from(11);
        let step1 = tracker.add_scalar(p, c1);
        let step2 = tracker.add_scalar(step1, c2);

        let pt = vec![F::from(2), F::from(3), F::from(5)];
        let eval_p = tracker.evaluate_mv(p, &pt).unwrap();
        let eval_step2 = tracker.evaluate_mv(step2, &pt).unwrap();
        assert_eq!(eval_step2, eval_p + c1 + c2);
    }

    /// `add_scalar(p, 0)` must be a semantic no-op — no constant term
    /// should be appended, otherwise `optimize_linear_terms` at compile
    /// time would emit a spurious nv=0 MLE for a zero constant.
    #[test]
    fn add_scalar_with_zero_is_semantic_noop() {
        let mut tracker = make_tracker();
        let p = tracker.track_mat_mv_poly(random_mle(3));
        let shifted = tracker.add_scalar(p, F::zero());

        let pt = vec![F::from(2), F::from(3), F::from(5)];
        let eval_p = tracker.evaluate_mv(p, &pt).unwrap();
        let eval_shifted = tracker.evaluate_mv(shifted, &pt).unwrap();
        assert_eq!(eval_shifted, eval_p);

        // Structural check: the virt poly should have exactly one term
        // (the original poly's wrapper), no bare-constant term for 0.
        let vp = tracker.virt_poly(shifted).unwrap();
        assert_eq!(vp.len(), 1, "zero scalar must not emit a constant term");
        assert!(
            !vp[0].1.is_empty(),
            "the single term should not be empty-product"
        );
    }

    /// The virt-poly built by `add_scalar` on a materialized poly must
    /// have exactly the shape `[(1, [poly_id]), (c, vec![])]` — one wrapper
    /// term for the input and one bare-constant term.
    #[test]
    fn add_scalar_produces_expected_virt_poly_shape() {
        let mut tracker = make_tracker();
        let p = tracker.track_mat_mv_poly(random_mle(3));
        let c = F::from(42);
        let shifted = tracker.add_scalar(p, c);

        let vp = tracker.virt_poly(shifted).unwrap();
        assert_eq!(vp.len(), 2, "expected wrapper + constant term");
        // First term: (1, [p]) — the input wrapped
        assert_eq!(vp[0].0, F::one());
        assert_eq!(vp[0].1, vec![p]);
        // Second term: (c, []) — the bare constant via empty product
        assert_eq!(vp[1].0, c);
        assert!(
            vp[1].1.is_empty(),
            "constant term must have empty factor list"
        );
    }

    // ── Contig-one activator storage ────────────────────────────────

    /// The activator MLE from `get_or_build_contig_one_poly` must stay
    /// RLE-compressed (or Constant), never a full Field `Vec<F>` — at nv 24
    /// that would be 512 MiB per gadget instance vs ~72 bytes.
    #[test]
    fn contig_one_poly_uses_compact_storage_not_field_vec() {
        use crate::arithmetic::mat_poly::mle::MLEStorage;
        use std::cell::RefCell;
        use std::rc::Rc;

        let tracker_rc = Rc::new(RefCell::new(make_tracker()));
        tracker_rc
            .borrow_mut()
            .set_self_rc(Rc::downgrade(&tracker_rc));

        // Non-trivial partial window at a large nv: 100k active out of 1M slots.
        let nv = 20;
        let active_rows = 100_000;
        let tracked = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(nv, active_rows)
            .unwrap();
        let id = tracked.id();
        let tracker = tracker_rc.borrow();
        let mle = tracker
            .mat_mv_poly(id)
            .expect("activator should be materialized");

        // Storage must be compact — an Rle (or Constant for edge cases), never Field.
        let bytes = mle.storage().heap_bytes();
        assert!(
            !matches!(mle.storage(), MLEStorage::Field { .. }),
            "activator storage must not be Field-vec (would be 32 MiB at nv=20)"
        );
        assert!(
            matches!(
                mle.storage(),
                MLEStorage::Rle { .. } | MLEStorage::Constant { .. }
            ),
            "activator storage must be Rle or Constant"
        );
        // 2-run RLE on BN254: ~72 bytes. Compare against the Field-vec
        // alternative which would be (1 << 20) * 32 = 32 MiB.
        assert!(
            bytes < 500,
            "compact activator should be <500 bytes, got {bytes}"
        );
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
