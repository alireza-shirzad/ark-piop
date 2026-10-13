//! [`TrackerCore`] is the interface that
//! [`ProverTracker`](crate::prover::tracker::ProverTracker) and
//! [`VerifierTracker`](crate::verifier::tracker::VerifierTracker) share, so
//! that the claim-batching [`pipeline`] and the [`bucketing`] are written
//! once for both sides.

pub mod bucketing;
pub mod pipeline;

use crate::{
    arithmetic::virt_poly::VirtualPoly,
    errors::SnarkResult,
    types::{
        SharedArgConfig, TrackerID,
        claim::{TrackerNoZerocheckClaim, TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
};

pub trait TrackerCore {
    type F: ark_ff::PrimeField;

    fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<Self::F>;

    fn get_and_append_challenge_vectors(
        &mut self,
        label: &'static [u8],
        n: usize,
    ) -> SnarkResult<Vec<Self::F>>;

    /// Append a field element the prover sends to the transcript, where
    /// both sides have it.
    fn append_field_element(&mut self, label: &'static [u8], element: &Self::F) -> SnarkResult<()>;

    /// An empty virtual polynomial (identity for addition).
    fn track_empty_virtual_poly(&mut self) -> TrackerID;

    fn add_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID;

    fn sub_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID;

    fn mul_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID;

    fn mul_scalar(&mut self, id: TrackerID, c: Self::F) -> TrackerID;

    fn add_scalar(&mut self, id: TrackerID, c: Self::F) -> TrackerID;

    /// Number of variables of the polynomial `id`, or 0 if unknown. With
    /// [`TrackerCore::virt_poly_degree`] and the config's degree limit, this
    /// is everything bucketing partitions on, and so everything the two
    /// sides must agree on for their partitions to match.
    fn poly_nv(&self, id: TrackerID) -> usize;

    fn virt_poly_degree(&self, id: TrackerID) -> usize;

    fn virtual_poly(&self, id: TrackerID) -> Option<&VirtualPoly<Self::F>>;

    fn is_material(&self, id: TrackerID) -> bool;

    fn take_zerocheck_claims(&mut self) -> Vec<TrackerZerocheckClaim>;

    fn push_zerocheck_claim(&mut self, claim: TrackerZerocheckClaim);

    /// Append a zerocheck claim on `id` that a protocol makes on both
    /// sides. Fallible because an honest prover checks the claim.
    fn add_zerocheck_claim(&mut self, id: TrackerID) -> SnarkResult<()>;

    fn zerocheck_claims_len(&self) -> usize;

    fn zerocheck_claims_is_empty(&self) -> bool;

    fn clear_zerocheck_claims(&mut self);

    fn last_zerocheck_id(&self) -> TrackerID;

    fn take_sumcheck_claims(&mut self) -> Vec<TrackerSumcheckClaim<Self::F>>;

    /// Group sumcheck claims by their polynomial's `num_vars`. Callers rely
    /// on the `BTreeMap`'s ascending order to keep both transcripts in step.
    fn group_sumcheck_claims_by_nv(
        &self,
        claims: Vec<TrackerSumcheckClaim<Self::F>>,
    ) -> std::collections::BTreeMap<usize, Vec<TrackerSumcheckClaim<Self::F>>> {
        let mut by_nv: std::collections::BTreeMap<usize, Vec<TrackerSumcheckClaim<Self::F>>> =
            std::collections::BTreeMap::new();
        for c in claims {
            by_nv.entry(self.poly_nv(c.id())).or_default().push(c);
        }
        by_nv
    }

    fn push_sumcheck_claim(&mut self, id: TrackerID, claimed_sum: Self::F);

    /// Append a sumcheck claim whose sum, over the polynomial's own
    /// hypercube, the protocol fixes on both sides. The verifier lifts it to
    /// its bucket itself and the prover sends nothing for it, where an
    /// ordinary claim is matched against the proof's claim map. Fallible
    /// because an honest prover checks the sum.
    fn push_raw_sumcheck_claim(&mut self, id: TrackerID, claimed_sum: Self::F) -> SnarkResult<()>;

    fn sumcheck_claims_len(&self) -> usize;

    fn sumcheck_claims_is_empty(&self) -> bool;

    fn take_nozerocheck_claims(&mut self) -> Vec<TrackerNoZerocheckClaim>;

    fn config(&self) -> &SharedArgConfig;

    fn peek_next_id(&self) -> TrackerID;

    /// Track `eq(x, r)`. The prover materializes the MLE; the verifier makes
    /// a succinct oracle closure.
    fn track_eq_x_r(&mut self, r: &[Self::F], max_nv: usize) -> SnarkResult<TrackerID>;
}
