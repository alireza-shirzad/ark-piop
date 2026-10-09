//! VerifierTracker — central state manager for the verifying side of the PIOP.

mod algebra;
mod claims;
mod core_impl;
mod evaluation;
#[cfg(test)]
mod tests;
mod tracking;
mod verify;

use crate::tracker_core::bucketing::SumcheckBucket;
use crate::{
    SnarkBackend,
    arithmetic::{f_vec_short_str, mat_poly::mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::{PCS, PolynomialCommitment},
    piop::{
        errors::PolyIOPErrors,
        logup_gkr::{GkrClaims, GkrShape, verify_batch},
        sum_check::SumCheck,
    },
    prover::structs::proof::SNARKProof,
    setup::{errors::SetupError::NoRangePoly, structs::SNARKVk},
    types::{
        CommitmentBinding, CommitmentID, LookupProtocol, PCSOpeningProof, SharedArgConfig,
        TrackerID,
        claim::{
            TrackerLookupClaim, TrackerNoZerocheckClaim, TrackerSumcheckClaim,
            TrackerZerocheckClaim,
        },
    },
    verifier::structs::oracle::InnerOracle,
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_std::{One, Zero};
use either::Either;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    mem::take,
    rc::{Rc, Weak},
};
use tracing::trace;
use tracing::{debug, instrument};

use super::{
    TrackedOracle,
    errors::VerifierError,
    structs::{
        ProcessedSNARKVk,
        oracle::{Oracle, VirtualOracle},
        state::{ProcessedProof, VerifierState},
    },
};
use derivative::Derivative;
use indexmap::IndexMap;

fn eval_lt_bound<F: PrimeField>(point: &[F], bits_lsb: &[bool], nv: usize) -> F {
    debug_assert_eq!(point.len(), nv);
    debug_assert_eq!(bits_lsb.len(), nv);
    let one = F::one();
    let mut prefix = one;
    let mut acc = F::zero();
    for i in (0..nv).rev() {
        let bit = bits_lsb[i];
        let xi = point[i];
        if bit {
            acc += prefix * (one - xi);
            prefix *= xi;
        } else {
            prefix *= one - xi;
        }
    }
    acc
}

/// Central verifier-side state manager: records the structure of virtual
/// polynomials (as commitment oracles) and their products, and provides the
/// algebra for combining them.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct VerifierTracker<B: SnarkBackend> {
    pub(super) vk: ProcessedSNARKVk<B>,
    pub(super) state: VerifierState<B>,
    pub(super) proof: Option<ProcessedProof<B>>,
    /// As it was when the tracker was made, which is when its lookup
    /// protocol went into the transcript: read through
    /// [`crate::tracker_core::TrackerCore::config`], never changed.
    pub(super) config: SharedArgConfig,
    pub(super) self_rc: Option<Weak<RefCell<VerifierTracker<B>>>>,
}

impl<B: SnarkBackend> VerifierTracker<B> {
    /// A tracker with clean state under `config`, which has to be the
    /// prover's. Fails if the environment names a lookup protocol that does
    /// not exist, as the prover's tracker does.
    pub(crate) fn new_from_vk_with_config(
        vk: SNARKVk<B>,
        config: SharedArgConfig,
    ) -> SnarkResult<Self> {
        LookupProtocol::from_env()?;
        let mut tracker = Self {
            vk: ProcessedSNARKVk::new_from_vk(&vk),
            state: VerifierState::default(),
            proof: None,
            config,
            self_rc: None,
        };
        tracker
            .config
            .lookup_protocol
            .bind(&mut tracker.state.transcript)?;
        tracker.add_vk_to_transcript(vk);
        Ok(tracker)
    }

    pub fn set_self_rc(&mut self, self_rc: Weak<RefCell<VerifierTracker<B>>>) {
        self.self_rc = Some(self_rc);
    }

    fn add_vk_to_transcript(&mut self, vk: SNARKVk<B>) {
        self.state
            .transcript
            .append_serializable_element(b"vk", &vk)
            .unwrap();
    }

    // Set the proof for the tracker
    pub fn set_proof(&mut self, proof: SNARKProof<B>) {
        self.set_proof_ref(&proof);
    }

    // Set the proof for the tracker from a borrowed proof. One made with
    // another lookup protocol is refused by whatever reads it first
    // (`proof_or_err`): there is no error to return from here.
    pub fn set_proof_ref(&mut self, proof: &SNARKProof<B>) {
        self.proof = Some(ProcessedProof::new_from_proof(proof));
        // The counts belong to the proof they were advanced on.
        self.state.logup_gkr_subproofs_consumed = 0;
        self.state.logup_sums_consumed = 0;
        self.state.claimed_sums_read.clear();
    }

    /// Verify the next LogUp-GKR subproof of the proof against `shape`, on
    /// the tracker's transcript. Subproofs are consumed in order, so both
    /// sides must run their batches in the same sequence. The returned
    /// claims still have to be discharged by the caller.
    pub(crate) fn verify_logup_gkr(&mut self, shape: &[GkrShape]) -> SnarkResult<GkrClaims<B::F>> {
        let next = self.state.logup_gkr_subproofs_consumed;
        // Direct field access so the borrow of self.proof doesn't conflict
        // with the &mut borrow of self.state.transcript.
        let subproof = self
            .proof
            .as_ref()
            .ok_or(SnarkError::VerifierError(VerifierError::ProofNotReceived))?
            .logup_gkr_subproofs
            .get(next)
            .ok_or_else(|| {
                SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                    "proof has no LogUp-GKR subproof at index {next}"
                )))
            })?;
        let claims = verify_batch(shape, subproof, &mut self.state.transcript)?;
        self.state.logup_gkr_subproofs_consumed = next + 1;
        Ok(claims)
    }

    /// The proof's next term sum of LogUp. Sums are read in order, so both
    /// sides must reach their terms in the same sequence. Binding the sum
    /// to the transcript is left to the caller, in the code it shares with
    /// the prover.
    pub(crate) fn next_logup_sum(&mut self) -> SnarkResult<B::F> {
        let next = self.state.logup_sums_consumed;
        let sum = *self
            .proof_or_err()?
            .lookup_messages
            .sums()
            .get(next)
            .ok_or_else(|| {
                SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                    "proof has no LogUp sum at index {next}"
                )))
            })?;
        self.state.logup_sums_consumed = next + 1;
        Ok(sum)
    }

    /// Refuses a proof made with another lookup protocol than the one this
    /// verifier is configured for. The proof names its protocol so that
    /// this can be said plainly; which protocol the verifier runs is its
    /// configuration's alone.
    pub(crate) fn check_lookup_protocol(&self) -> SnarkResult<()> {
        self.proof_or_err().map(drop)
    }

    /// Makes every later [`Self::verify`] fail. For the caller of a check
    /// that is not a claim of this tracker, such as the comparison of the
    /// two sides of a keyed sum: once it has failed, the claims the tracker
    /// holds may all be true, and the caller's error is the only record.
    pub(crate) fn reject(&mut self) {
        self.state.rejected = true;
    }

    /// Return the currently-set proof, or `VerifierError::ProofNotReceived`.
    /// Prefer this over `self.proof.as_ref().unwrap()` in verify paths.
    ///
    /// A proof made with another lookup protocol than this verifier's is
    /// refused here, from the first read after it is set: read as a proof
    /// of the verifier's protocol, it would fail on whatever it lacks
    /// first, with an error about that.
    pub(super) fn proof_or_err(&self) -> SnarkResult<&ProcessedProof<B>> {
        let proof = self
            .proof
            .as_ref()
            .ok_or(SnarkError::VerifierError(VerifierError::ProofNotReceived))?;
        let proved = proof.lookup_messages.protocol();
        let configured = self.config.lookup_protocol;
        if proved != configured {
            return Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed(format!(
                    "proof was made with {proved}, verifier is configured for {configured}"
                )),
            ));
        }
        Ok(proof)
    }

    // Generate a new TrackerID
    pub(crate) fn gen_id(&mut self) -> TrackerID {
        let id = self.state.num_tracked_polys;
        self.state.num_tracked_polys += 1;
        TrackerID::from_usize(id)
    }

    /// Peek at the next TrackerID without incrementing the counter. `pub`
    /// so tt-core expr nodes without an `ArgVerifier` reference can mirror
    /// the prover's commit order.
    pub fn peek_next_id(&mut self) -> TrackerID {
        TrackerID::from_usize(self.state.num_tracked_polys)
    }

    /// Check if a TrackerID refers to a constant in the proof.
    pub fn proof_mv_constant(&self, id: TrackerID) -> Option<B::F> {
        self.proof
            .as_ref()
            .and_then(|p| p.mv_pcs_subproof.constants.get(&id).copied())
    }
}
