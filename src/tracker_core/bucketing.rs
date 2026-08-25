//! Cost-model-based partitioner for the sumcheck bucketing pipeline.
//!
//! Claims are grouped by `num_vars`, and adjacent nvs may share a bucket —
//! but only by lifting the smaller ones to the bucket's `target_nv`. That is
//! the tension: merging pays one bucket's fixed cost instead of two, while
//! every merged-up claim pays a `2^Δnv` blow-up. Prover and verifier run the
//! same model over the same stats, so they land on the same partition with
//! no wire-format hint.
//!
//! ```text
//! cost(bucket) = 2^target_nv * (2*D^2 + Σ batch_weight + per_bucket_overhead)
//!
//! D            = min(max_i(degree_i) + 1, degree_limit - 1)
//! batch_weight = Σ over claims in bucket of (degree_i + 1)
//! ```
//!
//! Units are one field multiplication per hypercube point. The crux is that
//! the two claim statistics aggregate differently:
//!
//! - **`2*D^2` is a `max`.** A bucket folds all its claims into a *single*
//!   sumcheck by random linear combination, and a sum of polynomials has the
//!   max of their degrees — so this term ignores claim count entirely, which
//!   is why merging equal-degree nvs is nearly free. Squared because each
//!   round evaluates at `D + 1` points and each is a product over `D` MLEs;
//!   doubled because rounds halve, so `≈ 2 * 2^target_nv` point-visits.
//! - **`batch_weight` is a `sum`.** Each claim still gets its own batching
//!   pass over its terms at `2^target_nv`.
//!
//! Getting that backwards — summing degrees — over-prices merges by roughly
//! the claim count and cost LIKE-nation 25% of its wall clock.
//!
//! # Degree reduction
//!
//! The degrees here are **pre-reduction**: bucketing runs before any bucket
//! executes, while `reduce_sumcheck_dgree` runs inside one and caps term
//! degree at `degree_limit - 1`. The two terms treat that cap differently on
//! purpose. `D` is clamped, because reduction really does stop the sumcheck's
//! degree growing. `batch_weight` is not, because the excess becomes
//! chunk-poly commits and link constraints — roughly linear in the excess,
//! and paid at `2^target_nv` all the same.
//!
//! # Not modelled
//!
//! The ratios above come from operation counts, not measurement, and cannot
//! be fitted from the current benches: `D` only spans 3-5 across the large
//! buckets and correlates with nv, while measured per-point cost is U-shaped
//! in nv for unrelated reasons (thread starvation below nv ~18, memory
//! bandwidth at nv 24). Only the resulting *plans* have been validated,
//! against LIKE-nation and LIKE-lineitem. Fitting the coefficients needs a
//! sweep varying claim count and degree independently at a fixed nv.
//!
//! Also absent: the post-reduction chunk count; the difference between
//! zerocheck, sumcheck and nozerocheck claims (LIKE-lineitem's nv-24 bucket
//! splits 35.6 s nozerocheck-batching against 153.9 s sumcheck); MLE work
//! shared between claims over overlapping trees; commitment vs field
//! arithmetic, lumped into one constant; memory pressure; and parallelism,
//! since buckets run sequentially and the objective is a sum rather than a
//! makespan.

use crate::{
    SnarkBackend,
    tracker_core::TrackerCore,
    types::claim::{TrackerNoZerocheckClaim, TrackerSumcheckClaim, TrackerZerocheckClaim},
};
use std::collections::{BTreeMap, BTreeSet};
use tracing::{debug, info};

/// One planned sumcheck bucket: the nvs merged into it, the `target_nv` they
/// all run at, and the two stats [`CostModel::cost_of`] prices it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketPlan {
    pub target_nv: usize,
    pub included_nvs: Vec<usize>,
    pub batch_weight: usize,
    pub max_degree: usize,
}

impl BucketPlan {
    /// The bucket that merging `group` (ascending) would produce.
    ///
    /// This is the merge rule: widest nv, summed batch weight, **maxed**
    /// degree. Merging equal-degree claims adds no degree at all — see the
    /// module docs for why that distinction matters.
    fn from_group(group: &[NvClaimStats]) -> BucketPlan {
        BucketPlan {
            target_nv: group.last().expect("bucket group is never empty").nv,
            included_nvs: group.iter().map(|s| s.nv).collect(),
            batch_weight: group.iter().map(|s| s.batch_weight).sum(),
            max_degree: group.iter().map(|s| s.max_degree).max().unwrap_or(0),
        }
    }
}

/// Default [`CostModel::per_bucket_overhead`]: aux/chunk poly commits and
/// transcript rounds.
///
/// Also the merge/split threshold — for adjacent nvs of equal degree,
/// `merge - split = 2^(n-1) * (w_lo - 2*D^2 - per_bucket_overhead)`, so the
/// model merges when `w_lo < 2*D^2 + per_bucket_overhead`. Only meaningful
/// relative to the weight unit: an earlier reweighting moved this threshold
/// without moving the constant and cost LIKE-nation 25% of its wall clock.
///
/// Fitted, not derived. The explicit `2*D^2` term now carries most of what
/// it used to stand in for, so plans are no longer sensitive to it — on the
/// measured workloads merging nvs 15/16 holds for any value, splitting 16
/// from 20 needs `< 72`, and splitting 20 from 24 needs `< 1228`.
pub const DEFAULT_PER_BUCKET_OVERHEAD: usize = 12;

/// The claims at one `num_vars`, as the cost model sees them. Two numbers
/// rather than one because they aggregate differently on merge: batching
/// sums, sumcheck degree maxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvClaimStats {
    pub nv: usize,
    /// `Σ (degree + 1)` over the claims at `nv`.
    pub batch_weight: usize,
    /// `max degree` over the claims at `nv`.
    pub max_degree: usize,
}

/// The two tunable numbers in the cost formula.
///
/// [`CostModel::cost_of`] prices a [`BucketPlan`] with them and
/// [`pick_bucket_plan`] keeps the cheapest partition, so between them these
/// decide every merge. Prover and verifier build the model from the same
/// shared config, which is what makes their partitions agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostModel {
    /// Caps `D`, mirroring the cap `reduce_sumcheck_dgree` applies for real.
    /// From `SharedArgConfig::sumcheck_term_degree_limit`.
    pub degree_limit: usize,
    /// A bucket's fixed cost: commits and transcript rounds. Doubles as the
    /// merge/split threshold — see [`DEFAULT_PER_BUCKET_OVERHEAD`].
    pub per_bucket_overhead: usize,
}

impl CostModel {
    /// The model as production uses it: the config's degree limit, and the
    /// calibrated default overhead.
    pub fn new(degree_limit: usize) -> CostModel {
        CostModel {
            degree_limit,
            per_bucket_overhead: DEFAULT_PER_BUCKET_OVERHEAD,
        }
    }

    /// Cost of running `bucket`, in field multiplications per hypercube
    /// point. Only meaningful compared against another plan's total.
    ///
    /// ```text
    /// cost = 2^target_nv * (2*D^2 + batch_weight + per_bucket_overhead)
    /// D    = min(max_degree + 1, degree_limit - 1)
    /// ```
    ///
    /// See the module docs for why the sumcheck term is a capped square over
    /// the max degree while the batching term is an uncapped sum.
    fn cost_of(&self, bucket: &BucketPlan) -> u128 {
        // `+1` for the `eq(x, r)` factor a zerocheck picks up on conversion;
        // `.max(1)` so a bucket never looks free.
        let agg_degree = bucket
            .max_degree
            .saturating_add(1)
            .min(self.degree_limit.saturating_sub(1))
            .max(1);
        let sumcheck_weight = 2 * agg_degree * agg_degree;
        ((sumcheck_weight + bucket.batch_weight + self.per_bucket_overhead) as u128)
            .saturating_mul(1u128 << bucket.target_nv)
    }
}

/// Record what the planner saw and what it chose, for offline calibration.
///
/// The per-bucket stats emitted later carry only the *resulting* buckets, so a
/// merged bucket reports one summed `batch_weight` and the per-nv weights that
/// drove the decision are gone — which is exactly what replaying a candidate
/// cost model against a past run needs. Emitting the planner's input alongside
/// its output makes those replays exact.
///
/// Fires on both prover and verifier, which run the same model over the same
/// stats; `side` distinguishes the two copies.
fn emit_plan_input_stats(nv_stats: &[NvClaimStats], plan: &[BucketPlan], model: &CostModel) {
    let payload = serde_json::json!({
        "model": {
            "degree_limit": model.degree_limit,
            "per_bucket_overhead": model.per_bucket_overhead,
        },
        "nv_stats": nv_stats.iter().map(|s| serde_json::json!({
            "nv": s.nv,
            "batch_weight": s.batch_weight,
            "max_degree": s.max_degree,
        })).collect::<Vec<_>>(),
        "plan": plan.iter().map(|b| serde_json::json!({
            "target_nv": b.target_nv,
            "included_nvs": b.included_nvs,
            "batch_weight": b.batch_weight,
            "max_degree": b.max_degree,
        })).collect::<Vec<_>>(),
    });
    let json_str = serde_json::to_string(&payload)
        .unwrap_or_else(|_| "{\"nv_stats\":[],\"plan\":[]}".to_string());
    info!(
        target: "bench_stats",
        sc_plan_input_json = %json_str,
        "sc_plan_input"
    );
}

/// Min-cost plan over every *contiguous* partition of the ascending
/// `nv_stats`. Contiguous only: merging `{a, c}` while `b` is separate would
/// run `a`'s claims at `c`'s width for no gain over `{a}` or `{a, b}`.
/// Practical nv count is 1-4, so brute-forcing the `2^(k-1)` cut masks is
/// fine.
///
/// Empty when there are no claims — callers treat that as "nothing to prove".
pub fn pick_bucket_plan(nv_stats: &[NvClaimStats], model: &CostModel) -> Vec<BucketPlan> {
    let k = nv_stats.len();
    if k == 0 {
        return Vec::new();
    }
    debug_assert!(
        nv_stats.windows(2).all(|w| w[0].nv < w[1].nv),
        "nv_stats must be sorted strictly ascending by nv"
    );

    let mut best_cost = u128::MAX;
    let mut best_plan: Vec<BucketPlan> = Vec::new();

    let n_cuts = k - 1;
    for mask in 0u32..(1u32 << n_cuts) {
        let mut plan: Vec<BucketPlan> = Vec::new();
        let mut cost: u128 = 0;
        let mut start = 0usize;
        for i in 0..n_cuts {
            if (mask >> i) & 1 == 1 {
                push_bucket(&nv_stats[start..=i], &mut plan, &mut cost, model);
                start = i + 1;
            }
        }
        push_bucket(&nv_stats[start..], &mut plan, &mut cost, model);
        // A `target_nv == 0` bucket cannot run: its sumcheck has no variables,
        // so `z_check_claim_to_s_check_claim` samples an empty `r` and
        // `build_eq_x_r` rejects it. nv-0 claims are real — a scalar aggregate
        // such as TPC-H Q6 produces several — so they have to ride along in a
        // wider bucket, lifted like any other under-width claim. Rejecting the
        // plan here rather than filtering the claims keeps prover and verifier
        // in step, since both run this same search.
        //
        // Only the first bucket can be nv 0 (stats are ascending), and only
        // when it is the singleton `{0}`. Skipping those masks is exactly the
        // "merge nv 0 upward" rule, and it costs nothing to state as a filter.
        if plan.len() > 1 && plan[0].target_nv == 0 {
            continue;
        }
        if cost < best_cost {
            best_cost = cost;
            best_plan = plan;
        }
    }

    best_plan
}

fn push_bucket(
    group: &[NvClaimStats],
    plan: &mut Vec<BucketPlan>,
    cost: &mut u128,
    model: &CostModel,
) {
    let bucket = BucketPlan::from_group(group);
    *cost = cost.saturating_add(model.cost_of(&bucket));
    plan.push(bucket);
}

/// One bucket ready to run: the claims that landed in it plus the
/// `target_nv` they are all lifted to. Owning the claims — rather than
/// leaving them in an nv-keyed map — keeps planning and running independent.
#[derive(Clone, Debug)]
pub struct SumcheckBucket<B: SnarkBackend> {
    pub target_nv: usize,
    pub included_nvs: Vec<usize>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim>,
    pub sum_check_claims: Vec<TrackerSumcheckClaim<B::F>>,
    pub no_zero_check_claims: Vec<TrackerNoZerocheckClaim>,
}

/// Group the claims by nv, run the cost model, and hand back one
/// [`SumcheckBucket`] per planned bucket. Empty when there are no claims.
///
/// Shared by both sides on purpose: prover and verifier must land on
/// identical partitions or the transcripts diverge, so every
/// partition-determining input is read through [`TrackerCore`] rather than
/// passed in, and there is one implementation to change.
pub fn build_buckets<B, T>(
    tracker: &T,
    zero_check_claims: Vec<TrackerZerocheckClaim>,
    sum_check_claims: Vec<TrackerSumcheckClaim<B::F>>,
    no_zero_check_claims: Vec<TrackerNoZerocheckClaim>,
) -> Vec<SumcheckBucket<B>>
where
    B: SnarkBackend,
    T: TrackerCore<F = B::F> + ?Sized,
{
    let nv_of = |id| tracker.poly_nv(id);
    let degree_of = |id| tracker.virt_poly_degree(id);
    let model = CostModel::new(tracker.config().sumcheck_term_degree_limit);

    let mut zc_by_nv: BTreeMap<usize, Vec<TrackerZerocheckClaim>> = BTreeMap::new();
    let mut sc_by_nv: BTreeMap<usize, Vec<TrackerSumcheckClaim<B::F>>> = BTreeMap::new();
    let mut nzc_by_nv: BTreeMap<usize, Vec<TrackerNoZerocheckClaim>> = BTreeMap::new();

    for c in zero_check_claims {
        zc_by_nv.entry(nv_of(c.id())).or_default().push(c);
    }
    for c in sum_check_claims {
        sc_by_nv.entry(nv_of(c.id())).or_default().push(c);
    }
    for c in no_zero_check_claims {
        nzc_by_nv.entry(nv_of(c.id())).or_default().push(c);
    }

    // Ascending set of nvs that have at least one claim, together with the
    // total claim count at each nv (feeds the cost model).
    let mut nvs: BTreeSet<usize> = BTreeSet::new();
    nvs.extend(zc_by_nv.keys().copied());
    nvs.extend(sc_by_nv.keys().copied());
    nvs.extend(nzc_by_nv.keys().copied());

    // Collect both statistics the cost model needs per nv. They are gathered
    // in one pass over the same claims but aggregated differently — summed
    // for batching work, maxed for the aggregated sumcheck's degree — so
    // they cannot be collapsed into a single number. See [`bucket_cost`].
    let nv_stats: Vec<NvClaimStats> = nvs
        .iter()
        .map(|nv| {
            let mut degrees = Vec::new();
            if let Some(v) = zc_by_nv.get(nv) {
                degrees.extend(v.iter().map(|c| degree_of(c.id())));
            }
            if let Some(v) = sc_by_nv.get(nv) {
                degrees.extend(v.iter().map(|c| degree_of(c.id())));
            }
            if let Some(v) = nzc_by_nv.get(nv) {
                degrees.extend(v.iter().map(|c| degree_of(c.id())));
            }
            NvClaimStats {
                nv: *nv,
                batch_weight: degrees.iter().map(|d| d + 1).sum(),
                max_degree: degrees.iter().copied().max().unwrap_or(0),
            }
        })
        .collect();

    if nv_stats.is_empty() {
        return Vec::new();
    }

    let plan = pick_bucket_plan(&nv_stats, &model);
    debug!(
        plan = ?plan.iter().map(|b| (b.target_nv, b.included_nvs.clone())).collect::<Vec<_>>(),
        "sumcheck bucketing plan"
    );
    emit_plan_input_stats(&nv_stats, &plan, &model);

    // `remove` rather than `get`: the plan partitions the nvs, so each one is
    // claimed exactly once and anything left behind would be a claim the plan
    // forgot. Asserted below, on every call rather than in one unit test —
    // a dropped claim is unprovable rather than merely slow.
    let buckets: Vec<SumcheckBucket<B>> = plan
        .into_iter()
        .map(|bucket| {
            let mut zero_check_claims = Vec::new();
            let mut sum_check_claims = Vec::new();
            let mut no_zero_check_claims = Vec::new();
            for nv in &bucket.included_nvs {
                if let Some(v) = zc_by_nv.remove(nv) {
                    zero_check_claims.extend(v);
                }
                if let Some(v) = sc_by_nv.remove(nv) {
                    sum_check_claims.extend(v);
                }
                if let Some(v) = nzc_by_nv.remove(nv) {
                    no_zero_check_claims.extend(v);
                }
            }
            SumcheckBucket {
                target_nv: bucket.target_nv,
                included_nvs: bucket.included_nvs,
                zero_check_claims,
                sum_check_claims,
                no_zero_check_claims,
            }
        })
        .collect();

    debug_assert!(
        zc_by_nv.is_empty() && sc_by_nv.is_empty() && nzc_by_nv.is_empty(),
        "bucket plan did not cover every nv — {} zerocheck, {} sumcheck, {} nozerocheck \
         claim group(s) left unbucketed and would be silently dropped",
        zc_by_nv.len(),
        sc_by_nv.len(),
        nzc_by_nv.len(),
    );
    buckets
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SharedArgConfig::sumcheck_term_degree_limit`'s default.
    const LIMIT: usize = 6;

    /// The production model, as `build_buckets` would construct it.
    fn model() -> CostModel {
        CostModel::new(LIMIT)
    }

    fn stats(nv: usize, batch_weight: usize, max_degree: usize) -> NvClaimStats {
        NvClaimStats {
            nv,
            batch_weight,
            max_degree,
        }
    }

    #[test]
    fn empty_input_returns_empty_plan() {
        assert!(pick_bucket_plan(&[], &model()).is_empty());
    }

    #[test]
    fn single_nv_yields_single_bucket() {
        let plan = pick_bucket_plan(&[stats(19, 25, 2)], &model());
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].target_nv, 19);
        assert_eq!(plan[0].included_nvs, vec![19]);
    }

    /// The merge threshold is `2*D^2 + per_bucket_overhead`, and it is
    /// unit-sensitive: a reweighting once moved it unnoticed until a bench
    /// regressed 25%. Pin both sides.
    #[test]
    fn adjacent_nvs_merge_exactly_below_the_degree_aware_threshold() {
        // max_degree 2 => D = 3 => 2*D^2 = 18, threshold 18 + 12 = 30.
        let threshold = 2 * 3 * 3 + model().per_bucket_overhead;
        assert_eq!(threshold, 30);

        let below = pick_bucket_plan(&[stats(15, threshold - 1, 2), stats(16, 6, 2)], &model());
        assert_eq!(below.len(), 1, "below threshold must merge, got {below:?}");

        let above = pick_bucket_plan(&[stats(15, threshold + 1, 2), stats(16, 6, 2)], &model());
        assert_eq!(above.len(), 2, "above threshold must split, got {above:?}");
    }

    /// Same buckets, two overheads, opposite decisions — the point of
    /// [`CostModel`] holding its parameters instead of reading a `const`.
    #[test]
    fn per_bucket_overhead_moves_the_threshold() {
        let group = [stats(15, 20, 2), stats(16, 6, 2)];

        // 2*D^2 = 18, so weight 20 splits under an overhead of 1 ...
        let stingy = CostModel {
            degree_limit: LIMIT,
            per_bucket_overhead: 1,
        };
        assert_eq!(pick_bucket_plan(&group, &stingy).len(), 2);

        // ... and merges once the fixed cost outweighs it.
        let generous = CostModel {
            degree_limit: LIMIT,
            per_bucket_overhead: 40,
        };
        assert_eq!(pick_bucket_plan(&group, &generous).len(), 1);
    }

    /// Higher degree should make merging **more** attractive: a neighbour
    /// already paying `D` absorbs the claims free, while running them alone
    /// pays `D^2` twice. Same weight, two degrees, opposite decisions.
    #[test]
    fn higher_degree_raises_the_merge_threshold() {
        let weight = 40;

        // D = 3 => threshold 30 < 40 => split.
        let low = pick_bucket_plan(&[stats(15, weight, 2), stats(16, 6, 2)], &model());
        assert_eq!(low.len(), 2, "expected split at low degree, got {low:?}");

        // D = 5 => threshold 2*25 + 12 = 62 > 40 => merge.
        let high = pick_bucket_plan(&[stats(15, weight, 4), stats(16, 6, 4)], &model());
        assert_eq!(high.len(), 1, "expected merge at high degree, got {high:?}");
    }

    /// The quadratic must stop at the reduction limit rather than charge a
    /// degree the prover never runs at; above it, cost rises through the
    /// linear term instead.
    #[test]
    fn quadratic_term_is_capped_at_the_reduction_limit() {
        let at_cap = model().cost_of(&BucketPlan::from_group(&[stats(20, 10, LIMIT - 2)]));
        let way_over = model().cost_of(&BucketPlan::from_group(&[stats(20, 10, 40)]));
        assert_eq!(
            at_cap, way_over,
            "degree above the reduction limit must not grow the quadratic term"
        );

        let under_cap = model().cost_of(&BucketPlan::from_group(&[stats(20, 10, 1)]));
        assert!(
            under_cap < at_cap,
            "below the limit the quadratic term must still respond to degree"
        );
    }

    /// The merge rule is where the sum-vs-max distinction lives, so pin it
    /// directly rather than only through the plans it produces.
    #[test]
    fn from_group_sums_batch_weight_and_maxes_degree() {
        let bucket = BucketPlan::from_group(&[stats(15, 6, 2), stats(16, 10, 5), stats(18, 4, 3)]);
        assert_eq!(bucket.target_nv, 18, "bucket runs at the widest nv");
        assert_eq!(bucket.included_nvs, vec![15, 16, 18]);
        assert_eq!(bucket.batch_weight, 20, "batching passes are additive");
        assert_eq!(
            bucket.max_degree, 5,
            "one aggregated sumcheck, so degree is the max and never the sum"
        );
    }

    /// A one-nv bucket must price the same as not merging at all.
    #[test]
    fn from_group_is_identity_on_a_single_row() {
        let row = stats(20, 86, 4);
        let bucket = BucketPlan::from_group(&[row]);
        assert_eq!(bucket.target_nv, row.nv);
        assert_eq!(bucket.included_nvs, vec![row.nv]);
        assert_eq!(bucket.batch_weight, row.batch_weight);
        assert_eq!(bucket.max_degree, row.max_degree);
    }

    /// LIKE-nation as measured: merging nvs 15/16 takes 0.249 s, splitting
    /// 0.373 s. The nv-16 bucket costs the same holding two claims as four,
    /// which is what the `max`-aggregated term exists to reproduce.
    #[test]
    fn like_nation_shape_prefers_merge() {
        let plan = pick_bucket_plan(&[stats(15, 6, 2), stats(16, 6, 2)], &model());
        assert_eq!(plan.len(), 1, "expected merge, got {plan:?}");
        assert_eq!(plan[0].target_nv, 16);
        assert_eq!(plan[0].included_nvs, vec![15, 16]);
    }

    /// LIKE-lineitem's heavy buckets: 3.0 s at nv 20, 189.5 s at nv 24.
    /// Merging would lift all 28 nv-20 claims to `2^24`.
    #[test]
    fn far_apart_nvs_stay_split() {
        let plan = pick_bucket_plan(&[stats(20, 86, 4), stats(24, 193, 4)], &model());
        assert_eq!(plan.len(), 2, "expected split, got {plan:?}");
        assert_eq!(plan[0].target_nv, 20);
        assert_eq!(plan[1].target_nv, 24);
    }

    /// The full LIKE-lineitem nv set — regression guard for the whole model
    /// rather than one decision.
    #[test]
    fn like_lineitem_shape_reproduces_measured_plan() {
        let plan = pick_bucket_plan(
            &[
                stats(1, 12, 2),
                stats(15, 6, 2),
                stats(16, 6, 2),
                stats(20, 86, 4),
                stats(24, 193, 4),
            ],
            &model(),
        );
        let shape: Vec<_> = plan.iter().map(|b| b.included_nvs.clone()).collect();
        assert_eq!(shape, vec![vec![1], vec![15, 16], vec![20], vec![24]]);
    }

    #[test]
    fn tightly_packed_nvs_prefer_merge() {
        // Claim weights small relative to the per-bucket sumcheck and commit
        // cost: splitting can't recoup the setup, so merging should win.
        let plan = pick_bucket_plan(
            &[stats(20, 1, 1), stats(21, 1, 1), stats(22, 1, 1)],
            &model(),
        );
        assert_eq!(plan.len(), 1, "expected merge, got {plan:?}");
        assert_eq!(plan[0].target_nv, 22);
        assert_eq!(plan[0].included_nvs, vec![20, 21, 22]);
    }

    /// A wide gap splits even for light claims: `2^Δnv` dominates.
    #[test]
    fn wide_gap_splits_even_for_light_low_nv_claims() {
        let plan = pick_bucket_plan(&[stats(10, 2, 1), stats(24, 2, 1)], &model());
        assert_eq!(plan.len(), 2, "expected split, got {plan:?}");
    }
}

/// Prover/verifier agreement on the degrees [`build_buckets`] partitions by.
///
/// The two sides compute degree by genuinely different means — the prover
/// walks the virtual-poly tree, the verifier reads a map maintained
/// incrementally with an `unwrap_or(0)` fallback. Nothing forces them to stay
/// in step, and a disagreement on one claim changes the partition on one side
/// and fails verification with no hint at the cause. So drive both trackers
/// through the same script of algebra ops and compare.
// `clone_underlying_tracker`, which these tests use to drive a prover and a
// verifier through the same plan, only exists under `test-utils`.
#[cfg(all(test, feature = "test-utils"))]
mod degree_agreement_tests {
    use crate::{
        DefaultSnarkBackend, errors::SnarkResult, tracker_core::TrackerCore, types::TrackerID,
    };

    const NV: usize = 4;

    /// A fixed script of algebra ops, returning the degree reported after
    /// each. Generic over [`TrackerCore`] so both sides provably run the
    /// *same* sequence; a hand-mirrored pair could drift and still pass.
    fn degree_trace<T: TrackerCore>(t: &mut T) -> SnarkResult<Vec<(&'static str, usize)>> {
        let r1: Vec<T::F> = (0..NV).map(|i| T::F::from(i as u64 + 3)).collect();
        let r2: Vec<T::F> = (0..NV).map(|i| T::F::from(i as u64 * 7 + 1)).collect();

        let mut trace: Vec<(&'static str, usize)> = Vec::new();
        macro_rules! rec {
            ($label:literal, $id:expr) => {{
                let id: TrackerID = $id;
                trace.push(($label, t.virt_poly_degree(id)));
                id
            }};
        }

        // `track_eq_x_r` is the only leaf constructor in `TrackerCore`, and
        // differs materially between the sides — a real MLE on the prover, a
        // closure oracle on the verifier — so it is the right leaf.
        let empty = rec!("empty", t.track_empty_virtual_poly());
        let a = rec!("a", t.track_eq_x_r(&r1, NV)?);
        let b = rec!("b", t.track_eq_x_r(&r2, NV)?);

        // Products accumulate degree; sums take the max.
        let ab = rec!("a*b", t.mul_polys(a, b));
        let ab2 = rec!("a*b*a", t.mul_polys(ab, a));
        let sum = rec!("a*b + b", t.add_polys(ab, b));
        let diff = rec!("a*b*a - (a*b + b)", t.sub_polys(ab2, sum));

        // Scalars must not move the degree. `add_scalar` is the subtle one:
        // it appends a zero-length product term.
        let scaled = rec!("5 * diff", t.mul_scalar(diff, T::F::from(5u64)));
        let shifted = rec!("scaled + 7", t.add_scalar(scaled, T::F::from(7u64)));

        // Push past the degree limit, where the two sides feed reduction.
        let big = rec!("scaled * shifted", t.mul_polys(scaled, shifted));
        rec!("big * big", t.mul_polys(big, big));

        // Identity edges, where `unwrap_or(0)` and max-over-no-terms can
        // plausibly disagree.
        let e_plus_a = rec!("empty + a", t.add_polys(empty, a));
        rec!("empty + empty", t.add_polys(empty, empty));
        rec!("(empty + a) * b", t.mul_polys(e_plus_a, b));

        Ok(trace)
    }

    /// Must match op-for-op: an intermediate disagreement is a claim degree
    /// waiting to be wrong.
    #[test]
    fn prover_and_verifier_report_identical_degrees() {
        let (prover, verifier) =
            crate::test_utils::prelude_with_vars::<DefaultSnarkBackend>(NV).unwrap();

        let mut prover_tracker = prover.clone_underlying_tracker();
        let mut verifier_tracker = verifier.clone_underlying_tracker();

        // Comparing proves nothing unless both scripts get the same ids.
        assert_eq!(
            prover_tracker.peek_next_id(),
            verifier_tracker.peek_next_id(),
            "prover and verifier tracker id counters diverged before the script ran"
        );

        let prover_trace = degree_trace(&mut prover_tracker).unwrap();
        let verifier_trace = degree_trace(&mut verifier_tracker).unwrap();

        assert_eq!(
            prover_trace, verifier_trace,
            "prover and verifier disagree on virtual-poly degree; \
             `build_buckets` would partition differently on the two sides \
             and verification would fail with no indication of the cause"
        );
        assert_eq!(
            prover_tracker.peek_next_id(),
            verifier_tracker.peek_next_id(),
            "the two sides allocated a different number of ids for the same script"
        );
    }

    /// Without this, both sides regressing to a constant would still agree
    /// and the comparison above would pass while the model went blind.
    #[test]
    fn degree_trace_matches_hand_computed_degrees() {
        let (prover, _verifier) =
            crate::test_utils::prelude_with_vars::<DefaultSnarkBackend>(NV).unwrap();
        let mut prover_tracker = prover.clone_underlying_tracker();
        let trace = degree_trace(&mut prover_tracker).unwrap();

        assert_eq!(
            trace,
            vec![
                ("empty", 0),
                ("a", 1),
                ("b", 1),
                ("a*b", 2),
                ("a*b*a", 3),
                ("a*b + b", 2),
                ("a*b*a - (a*b + b)", 3),
                ("5 * diff", 3),
                ("scaled + 7", 3),
                ("scaled * shifted", 6),
                ("big * big", 12),
                ("empty + a", 1),
                ("empty + empty", 0),
                ("(empty + a) * b", 2),
            ]
        );
    }
}
