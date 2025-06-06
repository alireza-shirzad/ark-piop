use crate::{
    add_trace,
    arithmetic::{
        f_short_str, f_vec_short_str,
        mat_poly::{lde::LDE, mle::MLE, utils::eq_eval},
    },
    errors::{SnarkError, SnarkResult},
    pcs::{PCS, PolynomialCommitment},
    piop::{
        errors::PolyIOPErrors,
        sum_check::{SumCheck, SumCheckSubClaim},
    },
    prover::structs::proof::Proof,
    setup::{errors::SetupError::NoRangePoly, structs::VerifyingKey},
    structs::{
        PCSOpeningProof, TrackerID,
        claim::{TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
};
use ark_ff::PrimeField;
use ark_std::{cfg_iter, end_timer, start_timer};
use itertools::MultiUnzip;
use macros::timed;
use std::{
    borrow::{Borrow, BorrowMut},
    collections::BTreeMap,
    mem::take,
    sync::Arc,
};

use derivative::Derivative;

use super::{
    TrackedOracle,
    errors::VerifierError,
    structs::{
        ProcessedVerifyingKey,
        oracle::Oracle,
        state::{ProcessedProof, VerifierState},
    },
};

/// The Tracker is a data structure for creating and managing virtual
/// commnomials and their commitments. It is in charge of  
///                      1) Recording the structure of virtual commnomials and
///                         their products
///                      2) Recording the structure of virtual commnomials and
///                         their products
///                      3) Recording the commitments of virtual commnomials and
///                         their products
///                      4) Providing methods for adding virtual commnomials
///                         together
#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"))]
#[derivative(Clone(bound = "UvPCS: PCS<F>"))]
pub struct VerifierTracker<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> where
    F: PrimeField,
{
    vk: ProcessedVerifyingKey<F, MvPCS, UvPCS>,
    state: VerifierState<F, MvPCS, UvPCS>,
    proof: Option<ProcessedProof<F, MvPCS, UvPCS>>,
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> VerifierTracker<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    // Create new verifier tracker with clean state given a verifying key
    pub(crate) fn new_from_vk(vk: VerifyingKey<F, MvPCS, UvPCS>) -> Self {
        let mut tracker = Self {
            vk: ProcessedVerifyingKey::new_from_vk(&vk),
            state: VerifierState::default(),
            proof: None,
        };
        tracker.add_vk_to_transcript(vk);
        tracker
    }

    fn add_vk_to_transcript(&mut self, vk: VerifyingKey<F, MvPCS, UvPCS>) {
        self.state
            .transcript
            .append_serializable_element(b"vk", &vk)
            .unwrap();
    }

    // Set the proof for the tracker
    pub fn set_proof(&mut self, proof: Proof<F, MvPCS, UvPCS>) {
        self.proof = Some(ProcessedProof::new_from_proof(&proof));
    }

    // Generate a new TrackerID
    pub(crate) fn gen_id(&mut self) -> TrackerID {
        let id = self.state.num_tracked_polys;
        self.state.num_tracked_polys += 1;
        TrackerID(id)
    }

    // Peek at the next TrackerID without incrementing the counter
    pub(crate) fn peek_next_id(&mut self) -> TrackerID {
        TrackerID(self.state.num_tracked_polys)
    }

    pub fn track_mv_com_by_id(&mut self, id: TrackerID) -> SnarkResult<TrackerID> {
        add_trace!("track_mv_com_by_id", "id = {:?}", id);

        let comm: MvPCS::Commitment;
        {
            // Scope the immutable borrow
            let comm_opt: Option<&MvPCS::Commitment> = self
                .proof
                .as_ref()
                .unwrap()
                .mv_pcs_subproof
                .commitments
                .get(&id);
            match comm_opt {
                Some(value) => {
                    comm = value.clone();
                }
                None => {
                    panic!(
                        "VerifierTracker Error: attempted to transfer prover comm, but id not found: {}",
                        id
                    );
                }
            }
        }
        let new_id: TrackerID = self.track_mat_mv_com(comm).unwrap();

        #[cfg(debug_assertions)]
        {
            assert_eq!(
                id, new_id,
                "VerifierTracker Error: attempted to transfer prover comm, but ids don't match: {}, {}",
                id, new_id
            );
        }
        Ok(new_id)
    }

    pub fn track_uv_com_by_id(&mut self, id: TrackerID) -> SnarkResult<TrackerID> {
        add_trace!("track_uv_com_by_id", "id = {:?}", id);

        let comm: UvPCS::Commitment;
        {
            // Scope the immutable borrow
            let proof = self.proof.as_ref().unwrap();
            let comm_opt: Option<&UvPCS::Commitment> = proof.uv_pcs_subproof.commitments.get(&id);
            match comm_opt {
                Some(value) => {
                    comm = value.clone();
                }
                None => {
                    panic!(
                        "VerifierTracker Error: attempted to transfer prover comm, but id not found: {}",
                        id
                    );
                }
            }
        }
        let new_id: TrackerID = self.track_mat_uv_com(comm).unwrap();

        #[cfg(debug_assertions)]
        {
            assert_eq!(
                id, new_id,
                "VerifierTracker Error: attempted to transfer prover comm, but ids don't match: {}, {}",
                id, new_id
            );
        }
        Ok(new_id)
    }

    /// Track a materiazlied multivariate commitment
    pub(crate) fn track_mat_mv_com(&mut self, comm: MvPCS::Commitment) -> SnarkResult<TrackerID> {
        // Create the new TrackerID
        let id = self.gen_id();

        match self.proof.as_ref() {
            Some(proof) => {
                let mv_queries_clone = proof.mv_pcs_subproof.query_map.clone();

                self.state.virtual_oracles.insert(
                    id,
                    Oracle::Multivariate(Arc::new(move |point: Vec<F>| {
                        let query_res = *mv_queries_clone.get(&(id, point.clone())).ok_or(
                            SnarkError::VerifierError(VerifierError::OracleEvalNotProvided(
                                id.0,
                                f_vec_short_str(&point),
                            )),
                        )?;
                        Ok(query_res)
                    })),
                );
            }
            None => {
                self.state.virtual_oracles.insert(
                    id,
                    Oracle::Multivariate(Arc::new(move |_point: Vec<F>| {
                        panic!("Should not be called");
                    })),
                );
            }
        }

        self.state
            .transcript
            .append_serializable_element(b"comm", &comm)?;
        self.state
            .mv_pcs_substate
            .materialized_comms
            .insert(id, comm);

        // return the new TrackerID
        Ok(id)
    }

    // Track a materiazlied univariate commitment
    pub fn track_mat_uv_com(&mut self, comm: UvPCS::Commitment) -> SnarkResult<TrackerID> {
        // Create the new TrackerID
        let id = self.gen_id();

        match self.proof.as_ref() {
            Some(proof) => {
                let uv_queries_clone = proof.uv_pcs_subproof.query_map.clone();
                self.state.virtual_oracles.insert(
                    id,
                    Oracle::Univariate(Arc::new(move |point: F| {
                        let query_res = uv_queries_clone.get(&(id, point)).unwrap();
                        Ok(*query_res)
                    })),
                );
            }
            None => {
                self.state.virtual_oracles.insert(
                    id,
                    Oracle::Univariate(Arc::new(move |_point: F| {
                        panic!("Should not be called");
                    })),
                );
            }
        }

        self.state
            .transcript
            .append_serializable_element(b"comm", &comm)?;
        self.state
            .uv_pcs_substate
            .materialized_comms
            .insert(id, comm);

        // return the new TrackerID
        Ok(id)
    }

    /// Track an oracle
    pub fn track_oracle(&mut self, oracle: Oracle<F>) -> TrackerID {
        let id = self.gen_id();
        self.state.virtual_oracles.borrow_mut().insert(id, oracle);
        id
    }

    // TODO: Lots of code duplication here for add, sub, mul, etc. need to refactor.
    pub fn add_oracles(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        // Get the references for the virtual oracles corresponding to the operands
        let o1_eval_box = self.state.virtual_oracles.get(&o1_id).unwrap();
        let o2_eval_box = self.state.virtual_oracles.get(&o2_id).unwrap();

        // Create the new virtual oracle
        let res_oracle = match (o1_eval_box, o2_eval_box) {
            (Oracle::Multivariate(o1), Oracle::Multivariate(o2)) => {
                let o1_cloned = o1.clone();
                let o2_cloned = o2.clone();
                Oracle::Multivariate(Arc::new(move |point: Vec<F>| {
                    Ok(o1_cloned(point.clone())? + o2_cloned(point.clone())?)
                }))
            }
            (Oracle::Univariate(o1), Oracle::Univariate(o2)) => {
                let o1_cloned = o1.clone();
                let o2_cloned = o2.clone();
                Oracle::Univariate(Arc::new(Box::new(move |point: F| -> SnarkResult<F> {
                    Ok(o1_cloned(point)? + o2_cloned(point)?)
                })))
            }
            _ => panic!("Mismatched oracle types"),
        };
        // Insert the new virtual oracle into the state
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_oracle);
        // Return the new TrackerID
        res_id
    }

    pub fn sub_oracles(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        // Get the references for the virtual oracles corresponding to the operands
        let o1_eval_box = self.state.virtual_oracles.get(&o1_id).unwrap();
        let o2_eval_box = self.state.virtual_oracles.get(&o2_id).unwrap();

        // Create the new virtual oracle
        let res_oracle = match (o1_eval_box, o2_eval_box) {
            (Oracle::Multivariate(o1), Oracle::Multivariate(o2)) => {
                let o1_cloned = o1.clone();
                let o2_cloned = o2.clone();
                Oracle::Multivariate(Arc::new(move |point: Vec<F>| {
                    Ok(o1_cloned(point.clone())? - o2_cloned(point.clone())?)
                }))
            }
            (Oracle::Univariate(o1), Oracle::Univariate(o2)) => {
                let o1_cloned = o1.clone();
                let o2_cloned = o2.clone();
                Oracle::Univariate(Arc::new(Box::new(move |point: F| -> SnarkResult<F> {
                    Ok(o1_cloned(point)? - o2_cloned(point)?)
                })))
            }
            _ => panic!("Mismatched oracle types"),
        };
        // Insert the new virtual oracle into the state
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_oracle);
        // Return the new TrackerID
        res_id
    }

    pub fn mul_oracles(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        // Get the references for the virtual oracles corresponding to the operands
        let o1_eval_box = self.state.virtual_oracles.get(&o1_id).unwrap();
        let o2_eval_box = self.state.virtual_oracles.get(&o2_id).unwrap();

        // Create the new virtual oracle
        let res_oracle = match (o1_eval_box, o2_eval_box) {
            (Oracle::Multivariate(o1), Oracle::Multivariate(o2)) => {
                let o1_cloned = o1.clone();
                let o2_cloned = o2.clone();
                Oracle::Multivariate(Arc::new(move |point: Vec<F>| {
                    Ok(o1_cloned(point.clone())? * o2_cloned(point.clone())?)
                }))
            }
            (Oracle::Univariate(o1), Oracle::Univariate(o2)) => {
                let o1_cloned = o1.clone();
                let o2_cloned = o2.clone();
                Oracle::Univariate(Arc::new(Box::new(move |point: F| -> SnarkResult<F> {
                    Ok(o1_cloned(point)? * o2_cloned(point)?)
                })))
            }
            _ => panic!("Mismatched oracle types"),
        };
        // Insert the new virtual oracle into the state
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_oracle);
        // Return the new TrackerID
        res_id
    }

    pub fn add_scalar(&mut self, o1_id: TrackerID, scalar: F) -> TrackerID {
        let _ = self.gen_id(); // burn a tracker id to match how prover::add_scalar works

        // Get the references for the virtual oracles corresponding to the operands
        let o1_eval_box = self.state.virtual_oracles.get(&o1_id).unwrap();

        // Create the new virtual oracle
        let res_oracle = match o1_eval_box {
            Oracle::Multivariate(o1) => {
                let o1_cloned = o1.clone();
                Oracle::Multivariate(Arc::new(move |point: Vec<F>| {
                    Ok(o1_cloned(point.clone())? + scalar)
                }))
            }
            Oracle::Univariate(o1) => {
                let o1_cloned = o1.clone();
                Oracle::Univariate(Arc::new(Box::new(move |point: F| -> SnarkResult<F> {
                    Ok(o1_cloned(point)? + scalar)
                })))
            }
        };
        // Insert the new virtual oracle into the state
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_oracle);
        // Return the new TrackerID
        res_id
    }

    pub fn sub_scalar(&mut self, o1_id: TrackerID, scalar: F) -> TrackerID {
        self.add_scalar(o1_id, -scalar)
    }

    pub fn mul_scalar(&mut self, o1_id: TrackerID, scalar: F) -> TrackerID {
        // Get the references for the virtual oracles corresponding to the operands
        let o1_eval_box = self.state.virtual_oracles.get(&o1_id).unwrap();

        // Create the new virtual oracle
        let res_oracle = match o1_eval_box {
            Oracle::Multivariate(o1) => {
                let o1_cloned = o1.clone();
                Oracle::Multivariate(Arc::new(move |point: Vec<F>| {
                    Ok(o1_cloned(point.clone())? * scalar)
                }))
            }
            Oracle::Univariate(o1) => {
                let o1_cloned = o1.clone();
                Oracle::Univariate(Arc::new(Box::new(move |point: F| -> SnarkResult<F> {
                    Ok(o1_cloned(point)? * scalar)
                })))
            }
        };
        // Insert the new virtual oracle into the state
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_oracle);
        // Return the new TrackerID
        res_id
    }
    //TODO: This function is only used in the multiplicity-check and should be removed in the future. it should not be a part of this library, but should be optionally implemented by the used
    pub fn get_prover_claimed_sum(&self, id: TrackerID) -> SnarkResult<F> {
        self.proof
            .as_ref()
            .unwrap()
            .sc_subproof
            .get_sumcheck_claims()
            .get(&id)
            .cloned()
            .ok_or(SnarkError::DummyError)
    }
    pub fn query_mv(&self, oracle_id: TrackerID, point: Vec<F>) -> SnarkResult<F> {
        let mut equalized_point = point.clone();
        equalized_point.resize(
            self.proof
                .as_ref()
                .unwrap()
                .sc_subproof
                .get_sc_aux_info()
                .num_variables,
            F::zero(),
        );
        let oracle = self.state.virtual_oracles.get(&oracle_id).unwrap();
        match oracle {
            Oracle::Multivariate(f) => f(equalized_point),
            _ => Err(SnarkError::DummyError),
        }
    }
    pub fn query_uv(&self, oracle_id: TrackerID, point: F) -> SnarkResult<F> {
        let oracle = self.state.virtual_oracles.get(&oracle_id).unwrap();
        match oracle {
            Oracle::Univariate(f) => f(point),
            _ => Err(SnarkError::DummyError),
        }
    }
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<F> {
        self.state
            .transcript
            .get_and_append_challenge(label)
            .map_err(SnarkError::from)
    }

    pub fn add_mv_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: F) {
        add_trace!("add_mv_sumcheck_claim", "poly_id {:?}", poly_id.0);
        self.state
            .mv_pcs_substate
            .sum_check_claims
            .push(TrackerSumcheckClaim::new(poly_id, claimed_sum));
    }
    pub fn add_mv_zerocheck_claim(&mut self, poly_id: TrackerID) {
        add_trace!("add_mv_zerocheck_claim", "poly_id {:?}", poly_id.0);
        self.state
            .mv_pcs_substate
            .zero_check_claims
            .push(TrackerZerocheckClaim::new(poly_id));
    }

    #[timed(
        "poly_id:",
        poly_id,
        ", point:",
        f_vec_short_str(point),
        ", eval:",
        f_short_str(eval)
    )]
    pub fn add_mv_eval_claim(
        &mut self,
        poly_id: TrackerID,
        point: &[F],
        eval: F,
    ) -> SnarkResult<()> {
        add_trace!("add_mv_eval_claim", "poly_id {:?}", poly_id.0);
        self.state
            .mv_pcs_substate
            .eval_claims
            .insert(((poly_id, point.to_vec()), eval));
        Ok(())
    }

    // Set range commitments for the tracker
    pub(crate) fn set_indexed_oracles(
        &mut self,
        range_tr_comms: BTreeMap<String, TrackedOracle<F, MvPCS, UvPCS>>,
    ) {
        self.vk.range_comms = range_tr_comms;
    }
    // Get a range commitment for the given data type
    pub(crate) fn get_indexed_oracle(
        &self,
        data_type: String,
    ) -> SnarkResult<TrackedOracle<F, MvPCS, UvPCS>> {
        match self.vk.range_comms.get(&data_type) {
            Some(poly) => Ok(poly.clone()),
            _ => Err(SnarkError::SetupError(NoRangePoly(format!(
                "{:?}",
                data_type
            )))),
        }
    }

    pub fn get_prover_comm(&self, id: TrackerID) -> Option<MvPCS::Commitment> {
        self.proof
            .as_ref()
            .unwrap()
            .mv_pcs_subproof
            .commitments
            .get(&id)
            .cloned()
    }

    // TODO: See if we can remove this
    pub fn get_commitment_num_vars(&self, id: TrackerID) -> SnarkResult<usize> {
        match self
            .proof
            .as_ref()
            .unwrap()
            .mv_pcs_subproof
            .commitments
            .get(&id)
            .cloned()
        {
            Some(comm) => Ok(comm.num_vars()),
            None => Err(SnarkError::from(PolyIOPErrors::InvalidVerifier(
                "Commitment not found".to_string(),
            ))),
        }
    }

    #[timed]
    fn batch_z_check_claims(&mut self) -> SnarkResult<()> {
        let zero_closure = |_: Vec<F>| -> SnarkResult<F> { Ok(F::zero()) };
        let zero_oracle = Oracle::Multivariate(Arc::new(zero_closure));
        let mut agg = self.track_oracle(zero_oracle);
        agg = take(&mut self.state.mv_pcs_substate.zero_check_claims)
            .into_iter()
            .fold(agg, |acc, claim| {
                let ch = self
                    .get_and_append_challenge(b"zerocheck challenge")
                    .unwrap();
                let cp = self.mul_scalar(claim.get_id(), ch);
                self.add_oracles(acc, cp)
            });
        self.add_mv_zerocheck_claim(agg);
        Ok(())
    }

    #[timed]
    fn z_check_claim_to_s_check_claim(&mut self, max_nv: usize) -> SnarkResult<()> {
        // Check at this point there should be only one batched zero check claim
        debug_assert_eq!(self.state.mv_pcs_substate.zero_check_claims.len(), 1);
        // sample the random challenge r
        let r = self
            .state
            .transcript
            .get_and_append_challenge_vectors(b"0check r", max_nv)
            .unwrap();
        // Get the zero check claim polynomial id
        let z_check_aggr_id = self
            .state
            .mv_pcs_substate
            .zero_check_claims
            .last()
            .unwrap()
            .get_id();
        // create the succint eq(x, r) closure and virtual comm
        let eq_x_r_closure = move |pt: Vec<F>| -> SnarkResult<F> { Ok(eq_eval(&pt, r.as_ref())?) };
        let eq_x_r_oracle = Oracle::Multivariate(Arc::new(eq_x_r_closure));
        let eq_x_r_comm = self.track_oracle(eq_x_r_oracle);
        // create the relevant sumcheck claim, reduce the zero check claim to a sumcheck claim
        let new_sc_claim_comm = self.mul_oracles(z_check_aggr_id, eq_x_r_comm);
        // Add this new sumcheck claim to other sumcheck claims
        self.add_mv_sumcheck_claim(new_sc_claim_comm, F::zero());
        Ok(())
    }

    // Aggregate the sumcheck claims, instead of verifying p_1 = s_1, p_2 = s_2, ...
    // p_n = s_n, we verify c_1 * p_1 + c_2 * p_2 + ... + c_n * p_n = c_1 *
    // s_1 + c_2 * s_2 + ... + c_n * s_n where c_i-s are random challenges
    #[timed]
    fn batch_s_check_claims(&mut self) -> SnarkResult<()> {
        // Aggreage te the sumcheck claims
        let zero_closure = |_: Vec<F>| -> SnarkResult<F> { Ok(F::zero()) };
        let zero_oracle = Oracle::Multivariate(Arc::new(zero_closure));
        let mut agg = self.track_oracle(zero_oracle);
        let mut sc_sum = F::zero();
        // Iterate over the sumcheck claims and aggregate them
        // Order matters here, DO NOT PARALLELIZE
        agg = take(&mut self.state.mv_pcs_substate.sum_check_claims)
            .into_iter()
            .fold(agg, |acc, claim| {
                let ch = self
                    .get_and_append_challenge(b"sumcheck challenge")
                    .unwrap();
                let cp = self.mul_scalar(claim.get_id(), ch);
                sc_sum += claim.get_claim() * ch;
                self.add_oracles(acc, cp)
            });
        // Now the sumcheck claims are empty
        // Add the new aggregated sumcheck claim to the list of claims
        self.add_mv_sumcheck_claim(agg, sc_sum);
        Ok(())
    }

    #[timed]
    fn perform_single_sumcheck(&mut self) -> SnarkResult<()> {
        debug_assert_eq!(self.state.mv_pcs_substate.sum_check_claims.len(), 1);

        let sumcheck_aggr_claim = self.state.mv_pcs_substate.sum_check_claims.last().unwrap();

        let sc_subclaim = SumCheck::verify(
            sumcheck_aggr_claim.get_claim(),
            self.proof.as_ref().unwrap().sc_subproof.get_sc_proof(),
            self.proof.as_ref().unwrap().sc_subproof.get_sc_aux_info(),
            &mut self.state.transcript,
        )?;
        self.add_mv_eval_claim(
            sumcheck_aggr_claim.get_id(),
            &sc_subclaim.point,
            sc_subclaim.expected_evaluation,
        )?;

        Ok(())
    }

    #[timed(
        "num_claims:",
        self.state.mv_pcs_substate.eval_claims.len()
    )]
    fn perform_eval_check(&mut self) -> SnarkResult<()> {
        for ((id, point), expected_eval) in &self.state.mv_pcs_substate.eval_claims {
            add_trace!(
                "perform_eval_check",
                "id: {}, point: {:?}, expected_eval: {:?}",
                id,
                f_vec_short_str(point),
                f_short_str(*expected_eval)
            );
            if self.query_mv(*id, point.clone()).unwrap() != *expected_eval {
                return Err(SnarkError::VerifierError(
                    crate::verifier::errors::VerifierError::VerifierCheckFailed(format!(
                        "Evaluation check failed for id: {}, point: {:?}, expected eval: {:?}",
                        id, point, expected_eval
                    )),
                ));
            }
        }
        Ok(())
    }

    #[timed]
    fn verify_sc_proofs(&mut self, max_nv: usize) -> SnarkResult<()> {
        // Batch all the zero check claims into one
        self.batch_z_check_claims()?;
        // Convert the only zero check claim to a sumcheck claim
        self.z_check_claim_to_s_check_claim(max_nv)?;
        // aggregate the sumcheck claims
        self.batch_s_check_claims()?;
        // verify the sumcheck proof
        self.perform_single_sumcheck()?;
        // Verify the evaluation claims
        self.perform_eval_check()?;

        Ok(())
    }

    #[timed("num_claims:",  &self.proof.as_ref().unwrap().mv_pcs_subproof.query_map.len())]
    fn verify_mv_pcs_proof(&mut self, max_nv: usize) -> SnarkResult<bool> {
        // Fetch the evaluation claims in the verifier state
        let eval_claims = &self.proof.as_ref().unwrap().mv_pcs_subproof.query_map;
        // Prepare the input for calling the batch verify function
        let (mat_coms, points): (Vec<_>, Vec<_>) = eval_claims
            .iter()
            .map(|((id, point), _eval)| {
                let com = self.state.mv_pcs_substate.materialized_comms[id].clone();
                (com, point.clone())
            })
            .multiunzip();
        // Invoke the batch verify function
        let mut pcs_res: bool;
        if mat_coms.len() == 1 {
            let opening_proof = match self.proof.as_ref().unwrap().mv_pcs_subproof.opening_proof {
                PCSOpeningProof::SingleProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::DummyError);
                }
            };
            pcs_res = MvPCS::verify(
                &self.vk.mv_pcs_param,
                &mat_coms[0],
                &points[0],
                self.proof
                    .as_ref()
                    .unwrap()
                    .mv_pcs_subproof
                    .query_map
                    .values()
                    .next()
                    .unwrap(),
                opening_proof,
            )?;
        } else if mat_coms.len() > 1 {
            let opening_proof = match self.proof.as_ref().unwrap().mv_pcs_subproof.opening_proof {
                PCSOpeningProof::BatchProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::DummyError);
                }
            };

            pcs_res = MvPCS::batch_verify(
                &self.vk.mv_pcs_param,
                &mat_coms,
                points.as_slice(),
                &self
                    .proof
                    .as_ref()
                    .unwrap()
                    .mv_pcs_subproof
                    .query_map
                    .values()
                    .cloned()
                    .collect::<Vec<F>>(),
                opening_proof,
                &mut self.state.transcript,
            )?;
        } else {
            pcs_res = true;
        }

        Ok(pcs_res)
    }
    #[timed("num_claims:", self.proof.as_ref().unwrap().uv_pcs_subproof.query_map.len())]
    fn verify_uv_pcs_proof(&mut self) -> SnarkResult<bool> {
        // Fetch the evaluation claims in the verifier state
        let eval_claims = &self.proof.as_ref().unwrap().uv_pcs_subproof.query_map;
        // Prepare the input for calling the batch verify function
        let (mat_coms, points, evals): (Vec<_>, Vec<_>, Vec<_>) = eval_claims
            .iter()
            .map(|((id, point), eval)| {
                let com = self.state.uv_pcs_substate.materialized_comms[id].clone();
                (com, *point, *eval)
            })
            .multiunzip();
        // Invoke the batch verify function
        let mut pcs_res: bool;
        if mat_coms.len() == 1 {
            let opening_proof = match self.proof.as_ref().unwrap().uv_pcs_subproof.opening_proof {
                PCSOpeningProof::SingleProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::DummyError);
                }
            };
            pcs_res = UvPCS::verify(
                &self.vk.uv_pcs_param,
                &mat_coms[0],
                &points[0],
                &evals[0],
                opening_proof,
            )?;
        } else if mat_coms.len() > 1 {
            let opening_proof = match self.proof.as_ref().unwrap().uv_pcs_subproof.opening_proof {
                PCSOpeningProof::BatchProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::DummyError);
                }
            };

            pcs_res = UvPCS::batch_verify(
                &self.vk.uv_pcs_param,
                &mat_coms,
                points.as_slice(),
                &evals,
                opening_proof,
                &mut self.state.transcript,
            )?;
        } else {
            pcs_res = true;
        }

        Ok(pcs_res)
    }

    // Get the max_nv which is the number of variabels for the sumchekck protocol
    // TODO: The aux info should be derivable by the verifier looking at the sql
    // query and io tables
    fn equalize_mat_com_nv(&self) -> usize {
        self.proof
            .as_ref()
            .unwrap()
            .sc_subproof
            .get_sc_aux_info()
            .num_variables
    }

    /// Verify the claims of the proof
    /// 1. Verify the sumcheck proofs
    /// 2. Verify the multivariate evaluation claims using the multivariate PCS
    /// 3. Verify the univariate evaluation claims using the univariate PCS
    #[timed]
    pub fn verify(&mut self) -> SnarkResult<()> {
        let max_nv = self.equalize_mat_com_nv();
        // Verify the sumcheck proofs
        self.verify_sc_proofs(max_nv)?;
        // Verify the multivariate pcs proofs
        // assert!(self.verify_mv_pcs_proof(max_nv)?);
        self.verify_mv_pcs_proof(max_nv)?;
        // Verify the multivariate pcs proofs
        // assert!(self.verify_uv_pcs_proof()?);
        self.verify_uv_pcs_proof()?;
        Ok(())
    }
}
