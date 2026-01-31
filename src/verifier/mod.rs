pub mod errors;
pub mod structs;
mod tracker;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use either::Either;
use indexmap::IndexMap;
use structs::oracle::{Oracle, TrackedOracle};
use tracing::{Span, field::debug, instrument, trace};

use crate::{
    SnarkBackend, errors::SnarkResult, pcs::PolynomialCommitment, prover::structs::proof::SNARKProof,
    piop::{PIOP, lookup_check},
    setup::structs::SNARKVk, structs::TrackerID,
};

use crate::pcs::PCS;
use derivative::Derivative;

use tracker::VerifierTracker;

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ArgVerifier<B>
where
    B: SnarkBackend,
{
    tracker_rc: Rc<RefCell<VerifierTracker<B>>>,
}
impl<B> PartialEq for ArgVerifier<B>
where
    B: SnarkBackend,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl<B> ArgVerifier<B>
where
    B: SnarkBackend,
{
    // TODO: See if you can shorten this function
    #[instrument(level = "debug", skip_all)]
    pub fn new_from_vk(vk: SNARKVk<B>) -> Self {
        let verifier = Self::new_from_tracker(VerifierTracker::new_from_vk(vk.clone()));
        let range_tr_polys: BTreeMap<String, TrackedOracle<B>> = vk
            .indexed_coms
            .iter()
            .map(|(data_type, mle)| {
                let tr_poly = verifier.track_mat_mv_com(mle.clone()).unwrap();
                (data_type.clone(), tr_poly)
            })
            .collect();
        verifier
            .tracker_rc
            .borrow_mut()
            .set_indexed_oracles(range_tr_polys);
        verifier
    }

    #[instrument(level = "debug", skip_all)]
    pub fn new_from_tracker_rc(tracker_rc: Rc<RefCell<VerifierTracker<B>>>) -> Self {
        Self { tracker_rc }
    }

    #[instrument(level = "debug", skip_all)]
    pub fn new_from_tracker(tracker: VerifierTracker<B>) -> Self {
        Self::new_from_tracker_rc(Rc::new(RefCell::new(tracker)))
    }

    /// Get the range tracked oracle given the label
    #[instrument(level = "debug", skip_all)]
    pub fn indexed_oracle(&self, label: String) -> SnarkResult<TrackedOracle<B>> {
        RefCell::borrow(&self.tracker_rc).indexed_oracle(label)
    }

    /// Insert or update an indexed tracked oracle.
    #[instrument(level = "debug", skip_all)]
    pub fn add_indexed_tracked_oracle(
        &mut self,
        label: String,
        oracle: TrackedOracle<B>,
    ) -> Option<TrackedOracle<B>> {
        self.tracker_rc
            .borrow_mut()
            .add_indexed_tracked_oracle(label, oracle)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn track_mat_mv_com(
        &self,
        comm: <B::MvPCS as PCS<B::F>>::Commitment,
    ) -> SnarkResult<TrackedOracle<B>> {
        let nv = comm.log_size();
        let tracked_oracle = TrackedOracle::new(
            Either::Left(self.tracker_rc.borrow_mut().track_mat_mv_com(comm)?),
            self.tracker_rc.clone(),
            nv as usize,
        );
        trace!("assigned id {}", tracked_oracle.id());
        Ok(tracked_oracle)
    }

    /// Track a materialized multivariate polynomial
    /// moves the multivariate polynomial to heap, assigns a TracckerID to it in
    /// map and returns the TrackerID
    #[instrument(level = "debug", skip(self))]
    pub fn track_mat_mv_cnst_oracle(&mut self, nv: usize, cnst: B::F) -> TrackedOracle<B> {
        if tracing::level_enabled!(tracing::Level::TRACE) {
            Span::current().record("cnst", debug(&cnst));
        }
        let _ = self.tracker_rc.borrow_mut().gen_id();
        TrackedOracle::new(Either::Right(cnst), self.tracker_rc.clone(), nv)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn track_oracle(&self, oracle: Oracle<B::F>) -> TrackedOracle<B> {
        let log_size = oracle.log_size();
        TrackedOracle::new(
            Either::Left(self.tracker_rc.borrow_mut().track_oracle(oracle)),
            self.tracker_rc.clone(),
            log_size,
        )
    }

    #[instrument(level = "debug", skip_all)]
    pub fn peek_next_id(&mut self) -> TrackerID {
        self.tracker_rc.borrow_mut().peek_next_id()
    }

    #[instrument(level = "debug", skip_all)]
    pub fn gen_id(&mut self) -> TrackerID {
        self.tracker_rc.borrow_mut().gen_id()
    }

    #[instrument(level = "debug", skip_all)]
    pub fn set_proof(&mut self, proof: SNARKProof<B>) {
        self.tracker_rc.borrow_mut().set_proof(proof);
    }

    #[instrument(level = "debug", skip(self))]
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<B::F> {
        let res = self.tracker_rc.borrow_mut().get_and_append_challenge(label);
        trace!("challenge {:?}", res);
        res
    }

    #[instrument(level = "debug", skip(self))]
    pub fn miscellaneous_field_element(&self, label: &str) -> SnarkResult<B::F> {
        RefCell::borrow(&self.tracker_rc).miscellaneous_field_element(label)
    }

    pub fn add_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: B::F) {
        self.tracker_rc
            .borrow_mut()
            .add_mv_sumcheck_claim(poly_id, claimed_sum);
    }
    #[instrument(level = "debug", skip(self))]
    pub fn add_zerocheck_claim(&mut self, poly_id: TrackerID) {
        self.tracker_rc.borrow_mut().add_mv_zerocheck_claim(poly_id);
    }

    #[instrument(level = "debug", skip(self))]
    pub fn add_nozerocheck_claim(&mut self, poly_id: TrackerID) {
        self.tracker_rc
            .borrow_mut()
            .add_mv_nozerocheck_claim(poly_id);
    }

    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_lookup_claim(
        &mut self,
        super_id: TrackerID,
        sub_id: TrackerID,
    ) -> SnarkResult<()> {
        self.tracker_rc.borrow_mut().add_mv_lookup_claim(super_id, sub_id)
    }

    #[instrument(level = "debug", skip(self))]
    pub fn query_mv(&mut self, poly_id: TrackerID, point: Vec<B::F>) -> SnarkResult<B::F> {
        self.tracker_rc.borrow_mut().query_mv(poly_id, point)
    }

    #[instrument(level = "debug", skip(self))]
    pub fn query_uv(&mut self, poly_id: TrackerID, point: B::F) -> SnarkResult<B::F> {
        self.tracker_rc.borrow_mut().query_uv(poly_id, point)
    }

    //TODO: This function is only used in the multiplicity-check and should be removed in the future. it should not be a part of this library, but should be optionally implemented by the used
    #[instrument(level = "debug", skip(self))]
    pub fn prover_claimed_sum(&self, id: TrackerID) -> SnarkResult<B::F> {
        self.tracker_rc.borrow().prover_claimed_sum(id)
    }

    #[instrument(level = "debug", skip(self))]
    pub fn commitment_num_vars(&self, id: TrackerID) -> SnarkResult<usize> {
        self.tracker_rc.borrow_mut().commitment_num_vars(id)
    }

    // TODO: Rename to get oracle
    #[instrument(level = "debug", skip(self))]
    pub fn track_mv_com_by_id(&mut self, id: TrackerID) -> SnarkResult<TrackedOracle<B>> {
        let (nv, tracker_id) = self.tracker_rc.borrow_mut().track_mv_com_by_id(id)?;
        Ok(TrackedOracle::new(
            Either::Left(tracker_id),
            self.tracker_rc.clone(),
            nv,
        ))
    }

    #[instrument(level = "debug", skip(self))]
    pub fn track_uv_com_by_id(&mut self, id: TrackerID) -> SnarkResult<TrackedOracle<B>> {
        let (degree, tracker_id) = self.tracker_rc.borrow_mut().track_uv_com_by_id(id)?;
        Ok(TrackedOracle::new(
            Either::Left(tracker_id),
            self.tracker_rc.clone(),
            degree,
        ))
    }

    #[instrument(level = "debug", skip_all)]
    fn tracked_oracle_from_id(&mut self, id: TrackerID) -> SnarkResult<TrackedOracle<B>> {
        if let Some(log_size) = self.tracker_rc.borrow().oracle_log_size(id) {
            Ok(TrackedOracle::new(
                Either::Left(id),
                self.tracker_rc.clone(),
                log_size,
            ))
        } else {
            self.track_mv_com_by_id(id)
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn reduce_lookup_claims(&mut self) -> SnarkResult<()> {
        let lookup_claims = self.tracker_rc.borrow_mut().take_lookup_claims();
        if lookup_claims.is_empty() {
            return Ok(());
        }

        let mut by_super: IndexMap<TrackerID, Vec<TrackerID>> = IndexMap::new();
        for claim in lookup_claims {
            by_super
                .entry(claim.super_poly())
                .or_default()
                .push(claim.sub_poly());
        }

        for (super_id, sub_ids) in by_super {
            let super_col = self.tracked_oracle_from_id(super_id)?;
            let included_cols = sub_ids
                .into_iter()
                .map(|sub_id| self.tracked_oracle_from_id(sub_id))
                .collect::<SnarkResult<Vec<_>>>()?;
            let lookup_verifier_input = lookup_check::LookupCheckVerifierInput {
                included_tracked_col_oracles: included_cols,
                super_tracked_col_oracle: super_col,
            };
            lookup_check::LookupCheckPIOP::verify(self, lookup_verifier_input)?;
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn verify(&self) -> SnarkResult<()> {
        let mut verifier = self.clone();
        verifier.reduce_lookup_claims()?;
        self.tracker_rc.borrow_mut().verify()
    }

    #[instrument(level = "debug", skip_all)]
    #[cfg(feature = "test-utils")]
    pub fn clone_underlying_tracker(&self) -> VerifierTracker<B> {
        RefCell::borrow(&self.tracker_rc).clone()
    }
    #[instrument(level = "debug", skip_all)]
    #[cfg(feature = "test-utils")]
    pub fn deep_copy(&self) -> ArgVerifier<B> {
        ArgVerifier::new_from_tracker((*RefCell::borrow(&self.tracker_rc)).clone())
    }
}
