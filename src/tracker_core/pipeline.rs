//! Generic claim-batching pipeline functions.
//!
//! These functions contain the shared logic for batching zerocheck and sumcheck
//! claims, as well as converting a zerocheck claim into a sumcheck claim.  They
//! are generic over any [`TrackerCore`] implementor, so both
//! [`ProverTracker`](crate::prover::tracker::ProverTracker) and
//! [`VerifierTracker`](crate::verifier::tracker::VerifierTracker) can delegate
//! to them.

use std::collections::BTreeMap;

use ark_std::Zero;
use tracing::debug;

use crate::{errors::SnarkResult, types::TrackerID};

use super::TrackerCore;

/// Batch all pending zerocheck claims into a single aggregated zerocheck claim
/// via a random linear combination.
///
/// If there are no pending zerocheck claims this is a no-op.  After this
/// function returns, at most one zerocheck claim remains.
pub fn batch_z_check_claims<T: TrackerCore>(tracker: &mut T) -> SnarkResult<()> {
    let num_claims = tracker.zerocheck_claims_len();

    if num_claims == 0 {
        debug!("No zerocheck claims to batch");
        return Ok(());
    }

    // Build the running aggregate polynomial.
    let mut agg = tracker.track_empty_virtual_poly();

    // Drain claims and fold via random linear combination.
    let claims = tracker.take_zerocheck_claims();
    for claim in claims {
        let ch = tracker.get_and_append_challenge(b"zerocheck challenge")?;
        let cp = tracker.mul_scalar(claim.id(), ch);
        agg = tracker.add_polys(agg, cp);
    }

    // Push the single aggregated zerocheck claim.
    tracker.push_zerocheck_claim(crate::types::claim::TrackerZerocheckClaim::new(agg));

    debug!(
        "{} zerocheck claims were batched into 1 zerocheck claim with degree {}",
        num_claims,
        tracker.virt_poly_degree(agg),
    );

    Ok(())
}

/// Batch all pending sumcheck claims into a single aggregated sumcheck claim
/// via a random linear combination.
///
/// Returns the individual sumcheck claims (polynomial ID -> claimed sum) that
/// were aggregated.  The prover uses this map to embed in the proof; the
/// verifier can ignore it.
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

    // Record individual claims before aggregation.
    let claims = tracker.take_sumcheck_claims();
    let individual: BTreeMap<TrackerID, T::F> =
        claims.iter().map(|c| (c.id(), c.claim())).collect();

    // Fold via random linear combination.
    for claim in claims {
        let ch = tracker.get_and_append_challenge(b"sumcheck challenge")?;
        let cp = tracker.mul_scalar(claim.id(), ch);
        sc_sum += claim.claim() * ch;
        agg = tracker.add_polys(agg, cp);
    }

    // Push the single aggregated sumcheck claim.
    tracker.push_sumcheck_claim(agg, sc_sum);

    debug!(
        "{} sumcheck claims were batched into 1 sumcheck claim",
        num_claims,
    );

    Ok(individual)
}

/// Convert the single batched zerocheck claim to a sumcheck claim.
///
/// Technique: reduce `p(x) == 0` to `sum_x p(x) * eq(x, r) == 0` for a
/// random challenge `r`.
///
/// After this function returns the zerocheck claim list is empty and a new
/// sumcheck claim has been appended.
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

    // Sample the random challenge r.
    let r = tracker.get_and_append_challenge_vectors(b"0check r", max_nv)?;

    // Get the batched zerocheck polynomial id.
    let z_check_aggr_id = tracker.last_zerocheck_id();

    // Build eq(x, r) via the side-specific seam.
    let eq_x_r_id = tracker.track_eq_x_r(&r, max_nv)?;

    // f'(x) = f(x) * eq(x, r)
    let new_sc_claim_poly = tracker.mul_polys(z_check_aggr_id, eq_x_r_id);

    // Add the new sumcheck claim with claimed sum = 0.
    tracker.push_sumcheck_claim(new_sc_claim_poly, T::F::zero());

    // Clear the zerocheck claim: it has been converted.
    tracker.clear_zerocheck_claims();

    debug!(
        "The only zerocheck claim was converted to a sumcheck claim with degree {}",
        tracker.virt_poly_degree(new_sc_claim_poly),
    );

    Ok(())
}
