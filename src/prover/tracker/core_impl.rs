//! [`TrackerCore`] implementation for [`ProverTracker`].
//!
//! Each method delegates to the existing `ProverTracker` API. The prover-side
//! seam methods (`track_eq_x_r`) materialize concrete MLE data.

use std::mem::take;

use crate::{
    SnarkBackend,
    arithmetic::{mat_poly::utils::build_eq_x_r, virt_poly::VirtualPoly},
    errors::SnarkResult,
    tracker_core::TrackerCore,
    types::{
        SharedArgConfig, TrackerID,
        claim::{TrackerNoZerocheckClaim, TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
};

use super::ProverTracker;

impl<B: SnarkBackend> TrackerCore for ProverTracker<B> {
    type F = B::F;

    // ── Transcript ──────────────────────────────────────────────────

    fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<Self::F> {
        // Delegate to the existing method on ProverTracker.
        ProverTracker::get_and_append_challenge(self, label)
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
        self.track_virt_poly(VirtualPoly::new())
    }

    fn add_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID {
        ProverTracker::add_polys(self, p1, p2)
    }

    fn sub_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID {
        ProverTracker::sub_polys(self, p1, p2)
    }

    fn mul_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID {
        ProverTracker::mul_polys(self, p1, p2)
    }

    fn mul_scalar(&mut self, id: TrackerID, c: Self::F) -> TrackerID {
        ProverTracker::mul_scalar(self, id, c)
    }

    fn add_scalar(&mut self, id: TrackerID, c: Self::F) -> TrackerID {
        ProverTracker::add_scalar(self, id, c)
    }

    fn virt_poly_degree(&self, id: TrackerID) -> usize {
        ProverTracker::virt_poly_degree(self, id)
    }

    fn virtual_poly(&self, id: TrackerID) -> Option<&VirtualPoly<Self::F>> {
        self.virt_poly(id)
    }

    // ── Materialization query ───────────────────────────────────────

    fn is_material(&self, id: TrackerID) -> bool {
        self.mat_mv_poly(id).is_some()
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

    // ── Seam: prover-specific ───────────────────────────────────────

    fn track_eq_x_r(&mut self, r: &[Self::F], _max_nv: usize) -> SnarkResult<TrackerID> {
        Ok(self.track_mat_arc_mv_poly(build_eq_x_r(r)?))
    }
}
