//! Shared trait and pipeline logic for prover and verifier trackers.
//!
//! [`TrackerCore`] captures the minimal interface that both
//! [`ProverTracker`](crate::prover::tracker::ProverTracker) and
//! [`VerifierTracker`](crate::verifier::tracker::VerifierTracker) expose, so
//! that the claim-batching pipeline (`batch_z_check_claims`,
//! `batch_s_check_claims`, `z_check_claim_to_s_check_claim`) can be written
//! once in generic form.

pub mod pipeline;

use crate::{
    arithmetic::virt_poly::VirtualPoly,
    errors::SnarkResult,
    types::{
        SharedArgConfig, TrackerID,
        claim::{TrackerNoZerocheckClaim, TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
};

/// Minimal interface shared by both the prover and verifier trackers.
///
/// Each method corresponds to an existing method on one or both tracker types.
/// The implementations simply delegate to the concrete tracker.
pub trait TrackerCore {
    /// The prime field used for polynomial evaluations.
    type F: ark_ff::PrimeField;

    // ── Transcript ──────────────────────────────────────────────────

    /// Sample a single Fiat-Shamir challenge and append it to the transcript.
    fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<Self::F>;

    /// Sample `n` Fiat-Shamir challenges and append them to the transcript.
    fn get_and_append_challenge_vectors(
        &mut self,
        label: &'static [u8],
        n: usize,
    ) -> SnarkResult<Vec<Self::F>>;

    // ── Virtual polynomial operations ───────────────────────────────

    /// Create an empty virtual polynomial (identity for addition).
    fn track_empty_virtual_poly(&mut self) -> TrackerID;

    /// Compute the sum of two tracked polynomials and return its ID.
    fn add_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID;

    /// Compute the difference of two tracked polynomials and return its ID.
    fn sub_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID;

    /// Compute the product of two tracked polynomials and return its ID.
    fn mul_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID;

    /// Scale a tracked polynomial by a scalar and return the new ID.
    fn mul_scalar(&mut self, id: TrackerID, c: Self::F) -> TrackerID;

    /// Add a constant to a tracked polynomial and return the new ID.
    fn add_scalar(&mut self, id: TrackerID, c: Self::F) -> TrackerID;

    /// Return the multiplicative degree of the polynomial tree rooted at `id`.
    fn virt_poly_degree(&self, id: TrackerID) -> usize;

    /// Return a reference to the virtual polynomial for `id`, if it exists.
    fn virtual_poly(&self, id: TrackerID) -> Option<&VirtualPoly<Self::F>>;

    // ── Materialization query ───────────────────────────────────────

    /// Return `true` if `id` refers to a materialized (non-virtual) polynomial.
    fn is_material(&self, id: TrackerID) -> bool;

    // ── Zerocheck claims ────────────────────────────────────────────

    /// Drain all zerocheck claims, returning them as a `Vec`.
    fn take_zerocheck_claims(&mut self) -> Vec<TrackerZerocheckClaim>;

    /// Append a single zerocheck claim.
    fn push_zerocheck_claim(&mut self, claim: TrackerZerocheckClaim);

    /// Number of pending zerocheck claims.
    fn zerocheck_claims_len(&self) -> usize;

    /// Returns `true` when there are no pending zerocheck claims.
    fn zerocheck_claims_is_empty(&self) -> bool;

    /// Remove all pending zerocheck claims without returning them.
    fn clear_zerocheck_claims(&mut self);

    /// Return the `TrackerID` of the last (most recent) zerocheck claim.
    fn last_zerocheck_id(&self) -> TrackerID;

    // ── Sumcheck claims ─────────────────────────────────────────────

    /// Drain all sumcheck claims, returning them as a `Vec`.
    fn take_sumcheck_claims(&mut self) -> Vec<TrackerSumcheckClaim<Self::F>>;

    /// Append a sumcheck claim with the given polynomial ID and claimed sum.
    fn push_sumcheck_claim(&mut self, id: TrackerID, claimed_sum: Self::F);

    /// Number of pending sumcheck claims.
    fn sumcheck_claims_len(&self) -> usize;

    /// Returns `true` when there are no pending sumcheck claims.
    fn sumcheck_claims_is_empty(&self) -> bool;

    // ── Nozerocheck claims ──────────────────────────────────────────

    /// Drain all no-zerocheck claims, returning them as a `Vec`.
    fn take_nozerocheck_claims(&mut self) -> Vec<TrackerNoZerocheckClaim>;

    // ── Configuration ───────────────────────────────────────────────

    /// Return the shared argument configuration.
    fn config(&self) -> &SharedArgConfig;

    /// Peek at the next `TrackerID` that will be generated, without consuming it.
    fn peek_next_id(&self) -> TrackerID;

    // ── Seam: side-specific operations ──────────────────────────────

    /// Build the polynomial `eq(x, r)` and return its `TrackerID`.
    ///
    /// On the prover side this materializes the MLE; on the verifier side this
    /// creates a succinct oracle closure.
    fn track_eq_x_r(&mut self, r: &[Self::F], max_nv: usize) -> SnarkResult<TrackerID>;
}
