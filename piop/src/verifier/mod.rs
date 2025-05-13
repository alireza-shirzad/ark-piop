pub mod errors;
pub mod structs;
mod tracker;
use std::{borrow::Borrow, cell::RefCell, collections::BTreeMap, rc::Rc};
use macros::timed;
use structs::oracle::{Oracle, TrackedOracle};

use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    prover::structs::proof::Proof,
    setup::structs::VerifyingKey,
    structs::TrackerID,
};
use ark_ff::PrimeField;

use crate::pcs::PCS;
use derivative::Derivative;

use tracker::VerifierTracker;

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"))]
#[derivative(Clone(bound = "UvPCS: PCS<F>"))]
pub struct Verifier<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    tracker_rc: Rc<RefCell<VerifierTracker<F, MvPCS, UvPCS>>>,
}
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> PartialEq for Verifier<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> Verifier<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    // TODO: See if you can shorten this function
    #[timed]
    pub fn new_from_vk(vk: VerifyingKey<F, MvPCS, UvPCS>) -> Self {
        let verifier = Self::new_from_tracker(VerifierTracker::new_from_vk(vk.clone()));
        let range_tr_polys: BTreeMap<String, TrackedOracle<F, MvPCS, UvPCS>> = vk
            .indexed_coms
            .iter()
            .map(|(data_type, mle)| {
                let tr_poly = verifier.track_mat_mv_com(mle.clone()).unwrap();
                (data_type.clone(), tr_poly)
            })
            .collect();
        let tracker_ref_cell: &RefCell<VerifierTracker<F, MvPCS, UvPCS>> =
            verifier.tracker_rc.borrow();
        tracker_ref_cell
            .borrow_mut()
            .set_indexed_oracles(range_tr_polys);
        verifier
    }

    pub fn new_from_tracker_rc(tracker_rc: Rc<RefCell<VerifierTracker<F, MvPCS, UvPCS>>>) -> Self {
        Self { tracker_rc }
    }

    pub fn new_from_tracker(tracker: VerifierTracker<F, MvPCS, UvPCS>) -> Self {
        Self::new_from_tracker_rc(Rc::new(RefCell::new(tracker)))
    }

    /// Get the range tracked polynomial given the data type
    pub fn get_indexed_oracle(
        &self,
        data_type: String,
    ) -> SnarkResult<TrackedOracle<F, MvPCS, UvPCS>> {
        RefCell::borrow(&self.tracker_rc).get_indexed_oracle(data_type)
    }

    pub fn track_mat_mv_com(
        &self,
        comm: MvPCS::Commitment,
    ) -> SnarkResult<TrackedOracle<F, MvPCS, UvPCS>> {
        Ok(TrackedOracle::new(
            self.tracker_rc.borrow_mut().track_mat_mv_com(comm)?,
            self.tracker_rc.clone(),
        ))
    }

    pub fn track_oracle(&self, eval_fn: Oracle<F>) -> TrackedOracle<F, MvPCS, UvPCS> {
        TrackedOracle::new(
            self.tracker_rc.borrow_mut().track_oracle(eval_fn),
            self.tracker_rc.clone(),
        )
    }

    pub fn peek_next_id(&mut self) -> TrackerID {
        self.tracker_rc.borrow_mut().peek_next_id()
    }

    pub fn gen_id(&mut self) -> TrackerID {
        self.tracker_rc.borrow_mut().gen_id()
    }

    pub fn set_proof(&mut self, proof: Proof<F, MvPCS, UvPCS>) {
        self.tracker_rc.borrow_mut().set_proof(proof);
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<F> {
        self.tracker_rc.borrow_mut().get_and_append_challenge(label)
    }

    pub fn add_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: F) {
        self.tracker_rc
            .borrow_mut()
            .add_mv_sumcheck_claim(poly_id, claimed_sum);
    }
    pub fn add_zerocheck_claim(&mut self, poly_id: TrackerID) {
        self.tracker_rc.borrow_mut().add_mv_zerocheck_claim(poly_id);
    }

    pub fn query_mv(&mut self, poly_id: TrackerID, point: Vec<F>) -> SnarkResult<F> {
        self.tracker_rc.borrow_mut().query_mv(poly_id, point)
    }

    pub fn query_uv(&mut self, poly_id: TrackerID, point: F) -> SnarkResult<F> {
        self.tracker_rc.borrow_mut().query_uv(poly_id, point)
    }

    //TODO: This function is only used in the multiplicity-check and should be removed in the future. it should not be a part of this library, but should be optionally implemented by the used
    pub fn get_prover_claimed_sum(&self, id: TrackerID) -> SnarkResult<F> {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, MvPCS, UvPCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_prover_claimed_sum(id)
    }

    pub fn get_commitment_num_vars(&self, id: TrackerID) -> SnarkResult<usize> {
        self.tracker_rc.borrow_mut().get_commitment_num_vars(id)
    }

    // TODO: Rename to get oracle
    pub fn track_mv_com_by_id(
        &mut self,
        id: TrackerID,
    ) -> SnarkResult<TrackedOracle<F, MvPCS, UvPCS>> {
        Ok(TrackedOracle::new(
            self.tracker_rc.borrow_mut().track_mv_com_by_id(id)?,
            self.tracker_rc.clone(),
        ))
    }
    pub fn track_uv_com_by_id(
        &mut self,
        id: TrackerID,
    ) -> SnarkResult<TrackedOracle<F, MvPCS, UvPCS>> {
        Ok(TrackedOracle::new(
            self.tracker_rc.borrow_mut().track_uv_com_by_id(id)?,
            self.tracker_rc.clone(),
        ))
    }

    pub fn verify(&self) -> SnarkResult<()> {
        self.tracker_rc.borrow_mut().verify()
    }

    /// TODO: See if you can make this function available only in test
    pub fn clone_underlying_tracker(&self) -> VerifierTracker<F, MvPCS, UvPCS> {
        RefCell::borrow(&self.tracker_rc).clone()
    }
    /// TODO: See if you can make this function available only in test
    pub fn deep_copy(&self) -> Verifier<F, MvPCS, UvPCS> {
        Verifier::new_from_tracker((*RefCell::borrow(&self.tracker_rc)).clone())
    }
}
