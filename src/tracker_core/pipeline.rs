//! Generic claim-batching pipeline, shared by prover and verifier trackers
//! via [`TrackerCore`].

use std::collections::BTreeMap;

use ark_std::Zero;
use tracing::debug;

use crate::{errors::SnarkResult, types::TrackerID};

use super::TrackerCore;

/// Batch all pending zerocheck claims into one via random linear combination.
/// No-op when there are none; afterwards at most one claim remains.
pub fn batch_z_check_claims<T: TrackerCore>(tracker: &mut T) -> SnarkResult<()> {
    let num_claims = tracker.zerocheck_claims_len();

    if num_claims == 0 {
        debug!("No zerocheck claims to batch");
        return Ok(());
    }

    let mut agg = tracker.track_empty_virtual_poly();

    let claims = tracker.take_zerocheck_claims();
    for claim in claims {
        let ch = tracker.get_and_append_challenge(b"zerocheck challenge")?;
        let cp = tracker.mul_scalar(claim.id(), ch);
        agg = tracker.add_polys(agg, cp);
    }

    tracker.push_zerocheck_claim(crate::types::claim::TrackerZerocheckClaim::new(agg));

    debug!(
        "{} zerocheck claims were batched into 1 zerocheck claim with degree {}",
        num_claims,
        tracker.virt_poly_degree(agg),
    );

    Ok(())
}

/// Batch all pending sumcheck claims into one via random linear combination.
/// Returns the individual claims (id -> claimed sum); the prover embeds this
/// map in the proof, the verifier can ignore it.
pub fn batch_s_check_claims<T: TrackerCore>(
    tracker: &mut T,
) -> SnarkResult<BTreeMap<TrackerID, T::F>> {
    let num_claims = tracker.sumcheck_claims_len();

    if num_claims == 0 {
        debug!("No sumcheck claims to batch");
        return Ok(BTreeMap::new());
    }

    let mut agg = tracker.track_empty_virtual_poly();
    let mut sc_sum = T::F::zero();

    let claims = tracker.take_sumcheck_claims();
    let individual: BTreeMap<TrackerID, T::F> =
        claims.iter().map(|c| (c.id(), c.claim())).collect();

    for claim in claims {
        let ch = tracker.get_and_append_challenge(b"sumcheck challenge")?;
        let cp = tracker.mul_scalar(claim.id(), ch);
        sc_sum += claim.claim() * ch;
        agg = tracker.add_polys(agg, cp);
    }

    tracker.push_sumcheck_claim(agg, sc_sum);

    debug!(
        "{} sumcheck claims were batched into 1 sumcheck claim",
        num_claims,
    );

    Ok(individual)
}

/// Convert every pending zerocheck claim into a sumcheck claim, batching and
/// converting each `num_vars` group at its own width. Run before bucketing so
/// the partitioner sees a homogeneous list with the `eq` factor already in
/// each degree. Costs one `eq` per distinct nv (single digits in practice).
///
/// Groups are walked in ascending nv so both sides sample challenges in the
/// same order — the transcript is what makes their partitions agree.
pub fn convert_zerochecks_by_nv<T: TrackerCore>(tracker: &mut T) -> SnarkResult<()> {
    let claims = tracker.take_zerocheck_claims();
    if claims.is_empty() {
        debug!("No zerocheck claims to convert ahead of bucketing");
        return Ok(());
    }

    let mut by_nv: BTreeMap<usize, Vec<crate::types::claim::TrackerZerocheckClaim>> =
        BTreeMap::new();
    for claim in claims {
        by_nv
            .entry(tracker.poly_nv(claim.id()))
            .or_default()
            .push(claim);
    }

    for (nv, group) in by_nv {
        let group_len = group.len();
        for claim in group {
            tracker.push_zerocheck_claim(claim);
        }
        batch_z_check_claims(tracker)?;

        if nv == 0 {
            // "This constant is zero" is already a sumcheck claim over an
            // empty hypercube; the general path would sample an empty `r`,
            // which `build_eq_x_r` rejects.
            let id = tracker.last_zerocheck_id();
            tracker.clear_zerocheck_claims();
            tracker.push_sumcheck_claim(id, T::F::zero());
        } else {
            z_check_claim_to_s_check_claim(tracker, nv)?;
        }
        debug!("converted {group_len} zerocheck claims at nv {nv} to one sumcheck claim");
    }

    Ok(())
}

/// Convert the single batched zerocheck claim to a sumcheck claim: reduce
/// `p(x) == 0` to `sum_x p(x) * eq(x, r) == 0` for a random `r`. Afterwards
/// the zerocheck list is empty and one sumcheck claim has been appended.
pub fn z_check_claim_to_s_check_claim<T: TrackerCore>(
    tracker: &mut T,
    max_nv: usize,
) -> SnarkResult<()> {
    if tracker.zerocheck_claims_is_empty() {
        debug!("No zerocheck claims to convert to sumcheck claims");
        return Ok(());
    }

    debug_assert_eq!(
        tracker.zerocheck_claims_len(),
        1,
        "z_check_claim_to_s_check_claim expects exactly one batched zerocheck claim"
    );

    let r = tracker.get_and_append_challenge_vectors(b"0check r", max_nv)?;
    let z_check_aggr_id = tracker.last_zerocheck_id();
    // eq(x, r) is built via the side-specific seam: materialized MLE on the
    // prover, succinct oracle on the verifier.
    let eq_x_r_id = tracker.track_eq_x_r(&r, max_nv)?;
    let new_sc_claim_poly = tracker.mul_polys(z_check_aggr_id, eq_x_r_id);
    tracker.push_sumcheck_claim(new_sc_claim_poly, T::F::zero());
    tracker.clear_zerocheck_claims();

    debug!(
        "The only zerocheck claim was converted to a sumcheck claim with degree {}",
        tracker.virt_poly_degree(new_sc_claim_poly),
    );

    Ok(())
}
