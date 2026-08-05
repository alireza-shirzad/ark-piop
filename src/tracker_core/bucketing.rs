//! Cost-model-based partitioner for the sumcheck bucketing pipeline.
//!
//! Every proof compile picks its own bucket layout from the sorted-ascending
//! set of distinct `num_vars` values present among the pending sumcheck /
//! zerocheck / nozerocheck claims. Since prover and verifier both feed the
//! same nv-and-count vector into [`pick_bucket_plan`] (prover from
//! `state.num_vars`, verifier from `state.poly_log_sizes`), they land on the
//! same partition without any wire-format hint.
//!
//! The cost model treats each bucket as
//!   `cost(bucket) = 2^target_nv * (n_claims + PER_BUCKET_OVERHEAD)`
//! where `n_claims` is the total pending-claim count across every nv merged
//! into the bucket. `PER_BUCKET_OVERHEAD` folds the fixed-per-bucket work
//! (aux/chunk poly commits, batching RLCs, transcript rounds) into an
//! equivalent number of extra claim slots — larger values discourage
//! splitting, smaller values encourage it. The constant below is calibrated
//! against the LIKE-nation benches (Single 434 ms vs 2-bucket 170 ms with
//! nvs {19, 22}) and matches the observed crossover on many-nv joins.

/// One planned sumcheck bucket. `included_nvs` lists every distinct claim
/// `num_vars` that lands in this bucket, sorted ascending; `target_nv` is
/// `included_nvs.last()` (the size the bucket's aggregated sumcheck actually
/// runs at).
#[derive(Debug, Clone)]
pub struct BucketPlan {
    pub target_nv: usize,
    pub included_nvs: Vec<usize>,
}

/// Fixed per-bucket cost, expressed as an equivalent number of claim slots
/// (each slot ≈ one full folding pass of size `2^target_nv`). Roughly
/// captures the aux/chunk poly commits and batching-RLC work each bucket
/// incurs before its aggregated sumcheck starts. Calibrated from LIKE
/// benches; see module docs.
const PER_BUCKET_OVERHEAD: usize = 4;

/// Enumerate every *contiguous* partition of the sorted-ascending
/// `nv_claim_counts` and return the min-cost plan. Contiguous only: merging
/// non-adjacent nvs (e.g. `{a, c}` while `b` is separate) would run the
/// low-nv `a` claims on a bucket sized for `c`, which is strictly worse
/// than keeping `{a}` alone or merging into `{a, b}`. Practical `k` (distinct
/// nv count) is 1–4, so brute-forcing the `2^(k-1)` cut masks is fine.
///
/// Returns an empty plan when there are no claims — callers should treat
/// that as "nothing to prove" and skip the sumcheck subproof entirely.
pub fn pick_bucket_plan(nv_claim_counts: &[(usize, usize)]) -> Vec<BucketPlan> {
    let k = nv_claim_counts.len();
    if k == 0 {
        return Vec::new();
    }
    debug_assert!(
        nv_claim_counts.windows(2).all(|w| w[0].0 < w[1].0),
        "nv_claim_counts must be sorted strictly ascending by nv"
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
                push_bucket(&nv_claim_counts[start..=i], &mut plan, &mut cost);
                start = i + 1;
            }
        }
        push_bucket(&nv_claim_counts[start..], &mut plan, &mut cost);
        if cost < best_cost {
            best_cost = cost;
            best_plan = plan;
        }
    }

    best_plan
}

fn push_bucket(group: &[(usize, usize)], plan: &mut Vec<BucketPlan>, cost: &mut u128) {
    let target_nv = group.last().unwrap().0;
    let n_claims: usize = group.iter().map(|(_, n)| *n).sum();
    let bucket_cost = (n_claims as u128 + PER_BUCKET_OVERHEAD as u128)
        .saturating_mul(1u128 << target_nv);
    *cost = cost.saturating_add(bucket_cost);
    plan.push(BucketPlan {
        target_nv,
        included_nvs: group.iter().map(|(nv, _)| *nv).collect(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty_plan() {
        assert!(pick_bucket_plan(&[]).is_empty());
    }

    #[test]
    fn single_nv_yields_single_bucket() {
        let plan = pick_bucket_plan(&[(19, 25)]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].target_nv, 19);
        assert_eq!(plan[0].included_nvs, vec![19]);
    }

    #[test]
    fn like_shape_prefers_split() {
        // LIKE-nation approximate shape: many row claims at nv=19, few char
        // claims at nv=22. Two-bucket split should beat single.
        let plan = pick_bucket_plan(&[(19, 20), (22, 5)]);
        assert_eq!(plan.len(), 2, "expected split, got {:?}", plan);
        assert_eq!(plan[0].target_nv, 19);
        assert_eq!(plan[1].target_nv, 22);
    }

    #[test]
    fn tightly_packed_nvs_prefer_merge() {
        // When nvs are close and claim counts small relative to the fixed
        // per-bucket overhead, splitting can't recoup the setup cost and
        // merging should win.
        let plan = pick_bucket_plan(&[(20, 1), (21, 1), (22, 1)]);
        assert_eq!(plan.len(), 1, "expected merge, got {:?}", plan);
        assert_eq!(plan[0].target_nv, 22);
        assert_eq!(plan[0].included_nvs, vec![20, 21, 22]);
    }
}
