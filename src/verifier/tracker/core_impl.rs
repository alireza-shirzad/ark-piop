//! [`TrackerCore`] implementation for [`VerifierTracker`].
//!
//! Each method delegates to the existing `VerifierTracker` API. The
//! verifier-side seam methods (`track_eq_x_r`) create succinct oracle
//! closures rather than materializing polynomial data.

use ark_ff::Zero;
use std::mem::take;

use crate::{
    SnarkBackend,
    arithmetic::{mat_poly::utils::eq_eval, virt_poly::VirtualPoly},
    errors::SnarkResult,
    tracker_core::TrackerCore,
    types::{
        SharedArgConfig, TrackerID,
        claim::{TrackerNoZerocheckClaim, TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
    verifier::structs::oracle::Oracle,
};

use super::VerifierTracker;

impl<B: SnarkBackend> TrackerCore for VerifierTracker<B> {
    type F = B::F;

    // ── Transcript ──────────────────────────────────────────────────

    fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<Self::F> {
        VerifierTracker::get_and_append_challenge(self, label)
    }

    fn get_and_append_challenge_vectors(
        &mut self,
        label: &'static [u8],
        n: usize,
    ) -> SnarkResult<Vec<Self::F>> {
        self.state
            .transcript
            .get_and_append_challenge_vectors(label, n)
            .map_err(crate::errors::SnarkError::from)
    }

    // ── Virtual polynomial operations ───────────────────────────────

    fn track_empty_virtual_poly(&mut self) -> TrackerID {
        VerifierTracker::track_empty_virtual_poly(
            self,
            0,
            crate::verifier::structs::oracle::OracleKind::Multivariate,
        )
    }

    fn add_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID {
        VerifierTracker::add_polys(self, p1, p2)
    }

    fn sub_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID {
        VerifierTracker::sub_polys(self, p1, p2)
    }

    fn mul_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID {
        VerifierTracker::mul_polys(self, p1, p2)
    }

    fn mul_scalar(&mut self, id: TrackerID, c: Self::F) -> TrackerID {
        VerifierTracker::mul_scalar(self, id, c)
    }

    fn add_scalar(&mut self, id: TrackerID, c: Self::F) -> TrackerID {
        VerifierTracker::add_scalar(self, id, c)
    }

    fn poly_nv(&self, id: TrackerID) -> usize {
        self.state.poly_log_sizes.get(&id).copied().unwrap_or(0)
    }

    fn virt_poly_degree(&self, id: TrackerID) -> usize {
        VerifierTracker::virt_poly_degree(self, id)
    }

    fn virtual_poly(&self, id: TrackerID) -> Option<&VirtualPoly<Self::F>> {
        self.state.virtual_polys.get(&id)
    }

    // ── Materialization query ───────────────────────────────────────

    fn is_material(&self, id: TrackerID) -> bool {
        self.state
            .poly_is_material
            .get(&id)
            .copied()
            .unwrap_or(false)
    }

    // ── Zerocheck claims ────────────────────────────────────────────

    fn take_zerocheck_claims(&mut self) -> Vec<TrackerZerocheckClaim> {
        take(&mut self.state.mv_pcs_substate.zero_check_claims)
    }

    fn push_zerocheck_claim(&mut self, claim: TrackerZerocheckClaim) {
        self.state.mv_pcs_substate.zero_check_claims.push(claim);
    }

    fn zerocheck_claims_len(&self) -> usize {
        self.state.mv_pcs_substate.zero_check_claims.len()
    }

    fn zerocheck_claims_is_empty(&self) -> bool {
        self.state.mv_pcs_substate.zero_check_claims.is_empty()
    }

    fn clear_zerocheck_claims(&mut self) {
        self.state.mv_pcs_substate.zero_check_claims.clear();
    }

    fn last_zerocheck_id(&self) -> TrackerID {
        self.state
            .mv_pcs_substate
            .zero_check_claims
            .last()
            .expect("expected at least one zerocheck claim")
            .id()
    }

    // ── Sumcheck claims ─────────────────────────────────────────────

    fn take_sumcheck_claims(&mut self) -> Vec<TrackerSumcheckClaim<Self::F>> {
        take(&mut self.state.mv_pcs_substate.sum_check_claims)
    }

    fn push_sumcheck_claim(&mut self, id: TrackerID, claimed_sum: Self::F) {
        self.state
            .mv_pcs_substate
            .sum_check_claims
            .push(TrackerSumcheckClaim::new(id, claimed_sum));
    }

    fn sumcheck_claims_len(&self) -> usize {
        self.state.mv_pcs_substate.sum_check_claims.len()
    }

    fn sumcheck_claims_is_empty(&self) -> bool {
        self.state.mv_pcs_substate.sum_check_claims.is_empty()
    }

    // ── Nozerocheck claims ──────────────────────────────────────────

    fn take_nozerocheck_claims(&mut self) -> Vec<TrackerNoZerocheckClaim> {
        take(&mut self.state.mv_pcs_substate.no_zero_check_claims)
    }

    // ── Configuration ───────────────────────────────────────────────

    fn config(&self) -> &SharedArgConfig {
        &self.config
    }

    fn peek_next_id(&self) -> TrackerID {
        TrackerID::from_usize(self.state.num_tracked_polys)
    }

    // ── Seam: verifier-specific ─────────────────────────────────────

    fn track_eq_x_r(&mut self, r: &[Self::F], max_nv: usize) -> SnarkResult<TrackerID> {
        // This oracle can be queried at a point longer than `r`, from two
        // directions: a downstream pass extends eval-claim points up to the
        // proof-global max, and a zerocheck converted before bucketing builds
        // its `eq` at the claim's own nv and is then lifted to its bucket's
        // `target_nv`.
        //
        // Match how the prover lifts it. `equalize_mat_poly_nv_to` bumps a
        // materialized poly's virtual nv, and `MLE::set_virtual_nv` expands by
        // *cyclic repeat*, so a lifted `eq` is constant in the added
        // variables — `eq_lifted(p) = eq(p[..r.len()], r)`. Truncating the
        // point reproduces exactly that. Zero-extending `r` instead would
        // multiply in a spurious `Π (1 - p_i)` over the added coordinates,
        // which is 1 only when they happen to be zero; that held while `eq`
        // was always born at `target_nv` and never lifted, and stops holding
        // at a random sumcheck point.
        let r = r.to_vec();
        let eq_x_r_closure = move |pt: Vec<B::F>| -> SnarkResult<B::F> {
            let mut pt = pt;
            if pt.len() < r.len() {
                pt.resize(r.len(), B::F::zero());
            } else {
                pt.truncate(r.len());
            }
            eq_eval(&pt, &r)
        };
        let eq_x_r_oracle = Oracle::new_multivariate(max_nv, eq_x_r_closure);
        Ok(self.track_base_oracle(eq_x_r_oracle))
    }
}
