use crate::{
    SnarkBackend,
    arithmetic::{f_vec_short_str, mat_poly::utils::eq_eval},
    errors::{SnarkError, SnarkResult},
    pcs::{PCS, PolynomialCommitment},
    piop::{errors::PolyIOPErrors, sum_check::SumCheck},
    prover::structs::proof::SNARKProof,
    setup::{errors::SetupError::NoRangePoly, structs::SNARKVk},
    structs::{
        PCSOpeningProof, TrackerID,
        claim::{
            TrackerLookupClaim, TrackerNoZerocheckClaim, TrackerSumcheckClaim,
            TrackerZerocheckClaim,
        },
    },
    verifier::structs::oracle::InnerOracle,
};
use ark_std::{One, Zero};
use itertools::MultiUnzip;
use std::{borrow::BorrowMut, collections::{BTreeMap, BTreeSet}, mem::take};
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

/// The Tracker is a data structure for creating and managing virtual
/// commnomials and their comitments. It is in charge of  
///                      1) Recording the structure of virtual commnomials and
///                         their products
///                      2) Recording the structure of virtual commnomials and
///                         their products
///                      3) Recording the comitments of virtual commnomials and
///                         their products
///                      4) Providing methods for adding virtual commnomials
///                         together
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct VerifierTracker<B: SnarkBackend> {
    vk: ProcessedSNARKVk<B>,
    state: VerifierState<B>,
    proof: Option<ProcessedProof<B>>,
}

impl<B: SnarkBackend> VerifierTracker<B> {
    // Create new verifier tracker with clean state given a verifying key
    pub(crate) fn new_from_vk(vk: SNARKVk<B>) -> Self {
        let mut tracker = Self {
            vk: ProcessedSNARKVk::new_from_vk(&vk),
            state: VerifierState::default(),
            proof: None,
        };
        tracker.add_vk_to_transcript(vk);
        tracker
    }

    fn add_vk_to_transcript(&mut self, vk: SNARKVk<B>) {
        self.state
            .transcript
            .append_serializable_element(b"vk", &vk)
            .unwrap();
    }

    // Set the proof for the tracker
    pub fn set_proof(&mut self, proof: SNARKProof<B>) {
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

    pub fn track_mv_com_by_id(&mut self, id: TrackerID) -> SnarkResult<(usize, TrackerID)> {
        let comm: <B::MvPCS as PCS<B::F>>::Commitment;
        {
            // Scope the immutable borrow
            let comm_opt: Option<&<B::MvPCS as PCS<B::F>>::Commitment> = self
                .proof
                .as_ref()
                .unwrap()
                .mv_pcs_subproof
                .comitments
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
        let nv = comm.log_size();
        let new_id: TrackerID = self.track_mat_mv_com(comm).unwrap();

        #[cfg(debug_assertions)]
        {
            assert_eq!(
                id, new_id,
                "VerifierTracker Error: attempted to transfer prover comm, but ids don't match: {}, {}",
                id, new_id
            );
        }
        Ok((nv as usize, new_id))
    }

    pub fn mv_commitment(&self, id: TrackerID) -> Option<<B::MvPCS as PCS<B::F>>::Commitment> {
        self.state
            .mv_pcs_substate
            .materialized_comms
            .get(&id)
            .cloned()
    }

    /// Return the max multiplicative degree of the oracle rooted at `id`.
    pub fn virt_oracle_degree(&self, id: TrackerID) -> usize {
        self.state.oracle_degrees.get(&id).copied().unwrap_or(0)
    }

    fn oracle_kind_from_inner(
        inner: &InnerOracle<B::F>,
    ) -> crate::verifier::structs::oracle::OracleKind {
        use crate::verifier::structs::oracle::OracleKind;
        match inner {
            InnerOracle::Univariate(_) => OracleKind::Univariate,
            InnerOracle::Multivariate(_) => OracleKind::Multivariate,
            InnerOracle::Constant(_) => OracleKind::Constant,
        }
    }

    fn combine_kinds(
        &self,
        k1: crate::verifier::structs::oracle::OracleKind,
        k2: crate::verifier::structs::oracle::OracleKind,
    ) -> crate::verifier::structs::oracle::OracleKind {
        use crate::verifier::structs::oracle::OracleKind;
        match (k1, k2) {
            (OracleKind::Constant, k) | (k, OracleKind::Constant) => k,
            (OracleKind::Univariate, OracleKind::Univariate) => OracleKind::Univariate,
            (OracleKind::Multivariate, OracleKind::Multivariate) => OracleKind::Multivariate,
            _ => panic!("Mismatched oracle types"),
        }
    }

    fn eval_base_mv(&self, oracle_id: TrackerID, point: &Vec<B::F>) -> SnarkResult<B::F> {
        let oracle = self
            .state
            .base_oracles
            .get(&oracle_id)
            .ok_or(SnarkError::DummyError)?;
        match oracle.inner() {
            InnerOracle::Multivariate(f) => f(point.clone()),
            InnerOracle::Constant(c) => Ok(*c),
            _ => Err(SnarkError::DummyError),
        }
    }

    fn eval_base_uv(&self, oracle_id: TrackerID, point: B::F) -> SnarkResult<B::F> {
        let oracle = self
            .state
            .base_oracles
            .get(&oracle_id)
            .ok_or(SnarkError::DummyError)?;
        match oracle.inner() {
            InnerOracle::Univariate(f) => f(point),
            InnerOracle::Constant(c) => Ok(*c),
            _ => Err(SnarkError::DummyError),
        }
    }

    fn eval_virtual_mv(&self, oracle_id: TrackerID, point: &Vec<B::F>) -> SnarkResult<B::F> {
        let terms = self
            .state
            .virtual_oracles
            .get(&oracle_id)
            .ok_or(SnarkError::DummyError)?;
        let mut acc = B::F::zero();
        for (coeff, term_ids) in terms.iter() {
            let mut term_val = *coeff;
            for id in term_ids {
                term_val *= self.eval_base_mv(*id, point)?;
            }
            acc += term_val;
        }
        Ok(acc)
    }

    fn eval_virtual_uv(&self, oracle_id: TrackerID, point: B::F) -> SnarkResult<B::F> {
        let terms = self
            .state
            .virtual_oracles
            .get(&oracle_id)
            .ok_or(SnarkError::DummyError)?;
        let mut acc = B::F::zero();
        for (coeff, term_ids) in terms.iter() {
            let mut term_val = *coeff;
            for id in term_ids {
                term_val *= self.eval_base_uv(*id, point)?;
            }
            acc += term_val;
        }
        Ok(acc)
    }

    fn track_empty_virtual_oracle(
        &mut self,
        log_size: usize,
        kind: crate::verifier::structs::oracle::OracleKind,
    ) -> TrackerID {
        let id = self.gen_id();
        self.state.virtual_oracles.insert(id, VirtualOracle::new());
        self.state.oracle_log_sizes.insert(id, log_size);
        self.state.oracle_kinds.insert(id, kind);
        self.state.oracle_is_material.insert(id, false);
        self.state.oracle_degrees.insert(id, 0);
        id
    }

    pub fn track_uv_com_by_id(&mut self, id: TrackerID) -> SnarkResult<(usize, TrackerID)> {
        let comm: <B::UvPCS as PCS<B::F>>::Commitment;
        {
            // Scope the immutable borrow
            let proof = self.proof.as_ref().unwrap();
            let comm_opt: Option<&<B::UvPCS as PCS<B::F>>::Commitment> =
                proof.uv_pcs_subproof.comitments.get(&id);
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
        let log_degree = comm.log_size();
        let new_id: TrackerID = self.track_mat_uv_com(comm).unwrap();

        #[cfg(debug_assertions)]
        {
            assert_eq!(
                id, new_id,
                "VerifierTracker Error: attempted to transfer prover comm, but ids don't match: {}, {}",
                id, new_id
            );
        }
        Ok((log_degree as usize, new_id))
    }

    /// Track a materiazlied multivariate commitment
    pub(crate) fn track_mat_mv_com(
        &mut self,
        comm: <B::MvPCS as PCS<B::F>>::Commitment,
    ) -> SnarkResult<TrackerID> {
        // Create the new TrackerID
        let id = self.gen_id();

        match self.proof.as_ref() {
            Some(proof) => {
                let mv_queries_clone = proof.mv_pcs_subproof.query_map.clone();

                let oracle =
                    Oracle::new_multivariate(comm.log_size() as usize, move |point: Vec<B::F>| {
                        let query_res = *mv_queries_clone.get(&(id, point.clone())).ok_or(
                            SnarkError::VerifierError(VerifierError::OracleEvalNotProvided(
                                id.0,
                                f_vec_short_str(&point),
                            )),
                        )?;
                        Ok(query_res)
                    });
                let mut terms = VirtualOracle::new();
                terms.push((B::F::one(), vec![id]));
                self.state.base_oracles.insert(id, oracle);
                self.state.virtual_oracles.insert(id, terms);
                self.state
                    .oracle_log_sizes
                    .insert(id, comm.log_size() as usize);
                self.state.oracle_kinds.insert(
                    id,
                    crate::verifier::structs::oracle::OracleKind::Multivariate,
                );
                self.state.oracle_is_material.insert(id, true);
            }
            None => {
                panic!("Should not be called");
            }
        }

        self.state
            .transcript
            .append_serializable_element(b"comm", &comm)?;
        self.state
            .mv_pcs_substate
            .materialized_comms
            .insert(id, comm);
        self.state.oracle_degrees.insert(id, 1);

        // return the new TrackerID
        Ok(id)
    }

    // Track a materiazlied univariate commitment
    pub fn track_mat_uv_com(
        &mut self,
        comm: <B::UvPCS as PCS<B::F>>::Commitment,
    ) -> SnarkResult<TrackerID> {
        // Create the new TrackerID
        let id = self.gen_id();

        match self.proof.as_ref() {
            Some(proof) => {
                let uv_queries_clone = proof.uv_pcs_subproof.query_map.clone();
                let oracle =
                    Oracle::new_univariate(comm.log_size() as usize, move |point: B::F| {
                        let query_res = uv_queries_clone.get(&(id, point)).unwrap();
                        Ok(*query_res)
                    });
                let mut terms = VirtualOracle::new();
                terms.push((B::F::one(), vec![id]));
                self.state.base_oracles.insert(id, oracle);
                self.state.virtual_oracles.insert(id, terms);
                self.state
                    .oracle_log_sizes
                    .insert(id, comm.log_size() as usize);
                self.state
                    .oracle_kinds
                    .insert(id, crate::verifier::structs::oracle::OracleKind::Univariate);
                self.state.oracle_is_material.insert(id, true);
            }
            None => {
                panic!("Should not be called");
            }
        }

        self.state
            .transcript
            .append_serializable_element(b"comm", &comm)?;
        self.state
            .uv_pcs_substate
            .materialized_comms
            .insert(id, comm);
        self.state.oracle_degrees.insert(id, 1);

        // return the new TrackerID
        Ok(id)
    }

    /// Track an oracle
    pub fn track_oracle(&mut self, oracle: Oracle<B::F>) -> TrackerID {
        let id = self.gen_id();
        let log_size = oracle.log_size();
        let kind = Self::oracle_kind_from_inner(oracle.inner());
        let degree = match oracle.inner() {
            InnerOracle::Constant(_) => 0,
            InnerOracle::Multivariate(_) | InnerOracle::Univariate(_) => 1,
        };
        let mut terms = VirtualOracle::new();
        terms.push((B::F::one(), vec![id]));
        self.state.base_oracles.insert(id, oracle);
        self.state.virtual_oracles.insert(id, terms);
        self.state.oracle_log_sizes.insert(id, log_size);
        self.state.oracle_kinds.insert(id, kind);
        self.state.oracle_is_material.insert(id, true);
        self.state.oracle_degrees.insert(id, degree);
        id
    }

    // TODO: Lots of code duplication here for add, sub, mul, etc. need to refactor.
    pub fn add_oracles(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        let o1_terms = self.state.virtual_oracles.get(&o1_id).unwrap().clone();
        let o2_terms = self.state.virtual_oracles.get(&o2_id).unwrap().clone();
        let o1_degree = self.state.oracle_degrees.get(&o1_id).copied().unwrap_or(0);
        let o2_degree = self.state.oracle_degrees.get(&o2_id).copied().unwrap_or(0);
        let o1_kind = *self.state.oracle_kinds.get(&o1_id).unwrap();
        let o2_kind = *self.state.oracle_kinds.get(&o2_id).unwrap();
        let res_kind = self.combine_kinds(o1_kind, o2_kind);
        let o1_mat = *self.state.oracle_is_material.get(&o1_id).unwrap_or(&false);
        let o2_mat = *self.state.oracle_is_material.get(&o2_id).unwrap_or(&false);

        let log_size = self
            .state
            .oracle_log_sizes
            .get(&o1_id)
            .copied()
            .unwrap_or(0)
            .max(
                self.state
                    .oracle_log_sizes
                    .get(&o2_id)
                    .copied()
                    .unwrap_or(0),
            );

        let mut res_terms = VirtualOracle::new();
        if !o1_mat && o2_mat {
            res_terms.extend(o2_terms.into_iter());
            res_terms.extend(o1_terms.into_iter());
        } else {
            res_terms.extend(o1_terms.into_iter());
            res_terms.extend(o2_terms.into_iter());
        }
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_terms);
        self.state.oracle_log_sizes.insert(res_id, log_size);
        self.state.oracle_kinds.insert(res_id, res_kind);
        self.state.oracle_is_material.insert(res_id, false);
        self.state
            .oracle_degrees
            .insert(res_id, o1_degree.max(o2_degree));
        res_id
    }

    pub fn sub_oracles(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        let o1_terms = self.state.virtual_oracles.get(&o1_id).unwrap().clone();
        let o2_terms = self.state.virtual_oracles.get(&o2_id).unwrap().clone();
        let o1_degree = self.state.oracle_degrees.get(&o1_id).copied().unwrap_or(0);
        let o2_degree = self.state.oracle_degrees.get(&o2_id).copied().unwrap_or(0);
        let o1_kind = *self.state.oracle_kinds.get(&o1_id).unwrap();
        let o2_kind = *self.state.oracle_kinds.get(&o2_id).unwrap();
        let res_kind = self.combine_kinds(o1_kind, o2_kind);
        let o1_mat = *self.state.oracle_is_material.get(&o1_id).unwrap_or(&false);
        let o2_mat = *self.state.oracle_is_material.get(&o2_id).unwrap_or(&false);

        let log_size = self
            .state
            .oracle_log_sizes
            .get(&o1_id)
            .copied()
            .unwrap_or(0)
            .max(
                self.state
                    .oracle_log_sizes
                    .get(&o2_id)
                    .copied()
                    .unwrap_or(0),
            );

        let mut res_terms = VirtualOracle::new();
        if !o1_mat && o2_mat {
            res_terms.extend(o2_terms.into_iter().map(|(coeff, ids)| (-coeff, ids)));
            res_terms.extend(o1_terms.into_iter());
        } else {
            res_terms.extend(o1_terms.into_iter());
            res_terms.extend(o2_terms.into_iter().map(|(coeff, ids)| (-coeff, ids)));
        }
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_terms);
        self.state.oracle_log_sizes.insert(res_id, log_size);
        self.state.oracle_kinds.insert(res_id, res_kind);
        self.state.oracle_is_material.insert(res_id, false);
        self.state
            .oracle_degrees
            .insert(res_id, o1_degree.max(o2_degree));
        res_id
    }

    pub fn mul_oracles(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        let o1_terms = self.state.virtual_oracles.get(&o1_id).unwrap().clone();
        let o2_terms = self.state.virtual_oracles.get(&o2_id).unwrap().clone();
        let o1_degree = self.state.oracle_degrees.get(&o1_id).copied().unwrap_or(0);
        let o2_degree = self.state.oracle_degrees.get(&o2_id).copied().unwrap_or(0);
        let o1_kind = *self.state.oracle_kinds.get(&o1_id).unwrap();
        let o2_kind = *self.state.oracle_kinds.get(&o2_id).unwrap();
        let res_kind = self.combine_kinds(o1_kind, o2_kind);
        let o1_mat = *self.state.oracle_is_material.get(&o1_id).unwrap_or(&false);
        let o2_mat = *self.state.oracle_is_material.get(&o2_id).unwrap_or(&false);

        let log_size = self
            .state
            .oracle_log_sizes
            .get(&o1_id)
            .copied()
            .unwrap_or(0)
            .max(
                self.state
                    .oracle_log_sizes
                    .get(&o2_id)
                    .copied()
                    .unwrap_or(0),
            );

        let mut res_terms = VirtualOracle::new();
        if o1_mat && o2_mat {
            let coeff1 = o1_terms.get(0).map(|(c, _)| *c).unwrap_or(B::F::one());
            let coeff2 = o2_terms.get(0).map(|(c, _)| *c).unwrap_or(B::F::one());
            res_terms.push((coeff1 * coeff2, vec![o1_id, o2_id]));
        } else if o1_mat && !o2_mat {
            let coeff1 = o1_terms.get(0).map(|(c, _)| *c).unwrap_or(B::F::one());
            for (coeff2, prod2) in o2_terms.iter() {
                let mut ids = prod2.clone();
                ids.push(o1_id);
                res_terms.push((coeff1 * *coeff2, ids));
            }
        } else if !o1_mat && o2_mat {
            let coeff2 = o2_terms.get(0).map(|(c, _)| *c).unwrap_or(B::F::one());
            for (coeff1, prod1) in o1_terms.iter() {
                let mut ids = prod1.clone();
                ids.push(o2_id);
                res_terms.push((*coeff1 * coeff2, ids));
            }
        } else {
            for (coeff1, prod1) in o1_terms.iter() {
                for (coeff2, prod2) in o2_terms.iter() {
                    let mut ids = prod1.clone();
                    ids.extend_from_slice(prod2);
                    res_terms.push((*coeff1 * *coeff2, ids));
                }
            }
        }
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_terms);
        self.state.oracle_log_sizes.insert(res_id, log_size);
        self.state.oracle_kinds.insert(res_id, res_kind);
        self.state.oracle_is_material.insert(res_id, false);
        self.state
            .oracle_degrees
            .insert(res_id, o1_degree + o2_degree);
        res_id
    }

    pub fn add_scalar(&mut self, o1_id: TrackerID, scalar: B::F) -> TrackerID {
        let o1_terms = self.state.virtual_oracles.get(&o1_id).unwrap().clone();
        let o1_degree = self.state.oracle_degrees.get(&o1_id).copied().unwrap_or(0);
        let log_size = self
            .state
            .oracle_log_sizes
            .get(&o1_id)
            .copied()
            .unwrap_or(0);
        let o1_kind = *self.state.oracle_kinds.get(&o1_id).unwrap();

        let scalar_id = self.gen_id();
        let scalar_oracle = match o1_kind {
            crate::verifier::structs::oracle::OracleKind::Multivariate => {
                Oracle::new_multivariate(log_size, move |_pt: Vec<B::F>| Ok(scalar))
            }
            crate::verifier::structs::oracle::OracleKind::Univariate => {
                Oracle::new_univariate(log_size, move |_pt: B::F| Ok(scalar))
            }
            crate::verifier::structs::oracle::OracleKind::Constant => {
                Oracle::new_constant(log_size, scalar)
            }
        };
        let mut scalar_terms = VirtualOracle::new();
        scalar_terms.push((B::F::one(), vec![scalar_id]));
        self.state.base_oracles.insert(scalar_id, scalar_oracle);
        self.state.virtual_oracles.insert(scalar_id, scalar_terms);
        self.state.oracle_log_sizes.insert(scalar_id, log_size);
        self.state.oracle_kinds.insert(scalar_id, o1_kind);
        self.state.oracle_is_material.insert(scalar_id, true);
        self.state.oracle_degrees.insert(scalar_id, 1);

        let o1_mat = *self.state.oracle_is_material.get(&o1_id).unwrap_or(&false);
        let mut res_terms = VirtualOracle::new();
        if o1_mat {
            res_terms.extend(o1_terms.into_iter());
            res_terms.push((B::F::one(), vec![scalar_id]));
        } else {
            res_terms.push((B::F::one(), vec![scalar_id]));
            res_terms.extend(o1_terms.into_iter());
        }
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_terms);
        self.state.oracle_log_sizes.insert(res_id, log_size);
        self.state.oracle_kinds.insert(res_id, o1_kind);
        self.state.oracle_is_material.insert(res_id, false);
        self.state.oracle_degrees.insert(res_id, o1_degree.max(1));
        // Return the new TrackerID
        res_id
    }

    pub fn sub_scalar(&mut self, o1_id: TrackerID, scalar: B::F) -> TrackerID {
        self.add_scalar(o1_id, -scalar)
    }

    pub fn mul_scalar(&mut self, o1_id: TrackerID, scalar: B::F) -> TrackerID {
        let o1_terms = self.state.virtual_oracles.get(&o1_id).unwrap().clone();
        let o1_degree = self.state.oracle_degrees.get(&o1_id).copied().unwrap_or(0);
        let log_size = self
            .state
            .oracle_log_sizes
            .get(&o1_id)
            .copied()
            .unwrap_or(0);
        let o1_kind = *self.state.oracle_kinds.get(&o1_id).unwrap();

        let mut res_terms = VirtualOracle::new();
        for (coeff, ids) in o1_terms.into_iter() {
            res_terms.push((coeff * scalar, ids));
        }
        let res_id = self.gen_id();
        self.state.virtual_oracles.insert(res_id, res_terms);
        self.state.oracle_log_sizes.insert(res_id, log_size);
        self.state.oracle_kinds.insert(res_id, o1_kind);
        self.state.oracle_is_material.insert(res_id, false);
        self.state.oracle_degrees.insert(res_id, o1_degree);
        // Return the new TrackerID
        res_id
    }
    //TODO: This function is only used in the multiplicity-check and should be removed in the future. it should not be a part of this library, but should be optionally implemented by the used
    pub fn prover_claimed_sum(&self, id: TrackerID) -> SnarkResult<B::F> {
        self.proof
            .as_ref()
            .unwrap()
            .sc_subproof
            .as_ref()
            .expect("No sumcheck subproof in the proof")
            .sumcheck_claims()
            .get(&id)
            .cloned()
            .ok_or(SnarkError::DummyError)
    }
    pub fn query_mv(&self, oracle_id: TrackerID, point: Vec<B::F>) -> SnarkResult<B::F> {
        let mut equalized_point = point.clone();
        equalized_point.resize(
            self.proof
                .as_ref()
                .unwrap()
                .sc_subproof
                .as_ref()
                .expect("No sumcheck subproof in the proof")
                .sc_aux_info()
                .num_variables,
            B::F::zero(),
        );
        self.eval_virtual_mv(oracle_id, &equalized_point)
    }
    pub fn query_uv(&self, oracle_id: TrackerID, point: B::F) -> SnarkResult<B::F> {
        self.eval_virtual_uv(oracle_id, point)
    }
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<B::F> {
        self.state
            .transcript
            .get_and_append_challenge(label)
            .map_err(SnarkError::from)
    }

    pub fn miscellaneous_field_element(&self, label: &str) -> SnarkResult<B::F> {
        self.proof
            .as_ref()
            .and_then(|proof| proof.miscellaneous_field_elements.get(label).cloned())
            .ok_or(SnarkError::DummyError)
    }

    pub fn add_mv_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: B::F) {
        self.state
            .mv_pcs_substate
            .sum_check_claims
            .push(TrackerSumcheckClaim::new(poly_id, claimed_sum));
    }
    pub fn add_mv_zerocheck_claim(&mut self, poly_id: TrackerID) {
        if let Some(terms) = self.state.virtual_oracles.get(&poly_id) {
            trace!(?poly_id, ?terms, "add_mv_zerocheck_claim virtual");
        } else {
            trace!(?poly_id, "add_mv_zerocheck_claim materialized");
        }
        self.state
            .mv_pcs_substate
            .zero_check_claims
            .push(TrackerZerocheckClaim::new(poly_id));
    }

    /// Adds a nozerocheck claim to the verifier state.
    pub fn add_mv_nozerocheck_claim(&mut self, poly_id: TrackerID) {
        if let Some(terms) = self.state.virtual_oracles.get(&poly_id) {
            trace!(?poly_id, ?terms, "add_mv_nozerocheck_claim virtual");
        } else {
            trace!(?poly_id, "add_mv_nozerocheck_claim materialized");
        }
        self.state
            .mv_pcs_substate
            .no_zero_check_claims
            .push(TrackerNoZerocheckClaim::new(poly_id));
    }
    pub fn add_mv_lookup_claim(
        &mut self,
        super_id: TrackerID,
        sub_id: TrackerID,
    ) -> SnarkResult<()> {
        self.state
            .mv_pcs_substate
            .lookup_claims
            .push(TrackerLookupClaim::new(super_id, sub_id));
        Ok(())
    }

    pub(crate) fn take_lookup_claims(&mut self) -> Vec<TrackerLookupClaim> {
        take(&mut self.state.mv_pcs_substate.lookup_claims)
    }

    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_eval_claim(
        &mut self,
        poly_id: TrackerID,
        point: &[B::F],
        eval: B::F,
    ) -> SnarkResult<()> {
        self.state
            .mv_pcs_substate
            .eval_claims
            .insert(((poly_id, point.to_vec()), eval));
        Ok(())
    }

    // Set range comitments for the tracker
    pub(crate) fn set_indexed_oracles(
        &mut self,
        range_tr_comms: BTreeMap<String, TrackedOracle<B>>,
    ) {
        self.state.indexed_tracked_oracles = range_tr_comms;
    }

    pub fn add_indexed_tracked_oracle(
        &mut self,
        label: String,
        oracle: TrackedOracle<B>,
    ) -> Option<TrackedOracle<B>> {
        self.state.indexed_tracked_oracles.insert(label, oracle)
    }

    // Get a range commitment for the given label
    pub(crate) fn indexed_oracle(&self, label: String) -> SnarkResult<TrackedOracle<B>> {
        match self.state.indexed_tracked_oracles.get(&label) {
            Some(poly) => Ok(poly.clone()),
            _ => Err(SnarkError::SetupError(NoRangePoly(format!("{:?}", label)))),
        }
    }

    pub fn prover_comm(&self, id: TrackerID) -> Option<<B::MvPCS as PCS<B::F>>::Commitment> {
        self.proof
            .as_ref()
            .unwrap()
            .mv_pcs_subproof
            .comitments
            .get(&id)
            .cloned()
    }

    // TODO: See if we can remove this
    pub fn commitment_num_vars(&self, id: TrackerID) -> SnarkResult<usize> {
        match self
            .proof
            .as_ref()
            .unwrap()
            .mv_pcs_subproof
            .comitments
            .get(&id)
            .cloned()
        {
            Some(comm) => Ok(comm.log_size() as usize),
            None => Err(SnarkError::from(PolyIOPErrors::InvalidVerifier(
                "Commitment not found".to_string(),
            ))),
        }
    }

    pub(crate) fn oracle_log_size(&self, id: TrackerID) -> Option<usize> {
        self.state.oracle_log_sizes.get(&id).copied()
    }

    #[instrument(level = "debug", skip_all)]
    fn batch_z_check_claims(&mut self, max_nv: usize) -> SnarkResult<()> {
        let num_claims = self.state.mv_pcs_substate.zero_check_claims.len();

        if (num_claims == 0) {
            debug!("No zerocheck claims to batch",);
            return Ok(());
        }

        let mut agg = self.track_empty_virtual_oracle(
            max_nv,
            crate::verifier::structs::oracle::OracleKind::Multivariate,
        );

        agg = take(&mut self.state.mv_pcs_substate.zero_check_claims)
            .into_iter()
            .fold(agg, |acc, claim| {
                let ch = self
                    .get_and_append_challenge(b"zerocheck challenge")
                    .unwrap();
                let cp = self.mul_scalar(claim.id(), ch);
                self.add_oracles(acc, cp)
            });
        self.add_mv_zerocheck_claim(agg);
        debug!(
            "{} zerocheck claims were batched into 1 zerocheck claim",
            num_claims
        );

        Ok(())
    }

    #[instrument(level = "debug", skip(self))]
    fn batch_nozero_check_claims(&mut self, _max_nv: usize) -> SnarkResult<()> {
        const NOZERO_CHUNK_SIZE: usize = 1;
        let nozero_claims = take(&mut self.state.mv_pcs_substate.no_zero_check_claims);
        if nozero_claims.is_empty() {
            return Ok(());
        }

        let num_claims = nozero_claims.len();
        let mut chunk_comm_ids = Vec::new();
        let mut master_prod_id = None;

        for chunk in nozero_claims.chunks(NOZERO_CHUNK_SIZE) {
            let mut iter = chunk.iter();
            let first = iter
                .next()
                .expect("nozero_claims chunk should be non-empty");
            let mut chunk_prod_id = first.id();
            for claim in iter {
                chunk_prod_id = self.mul_oracles(chunk_prod_id, claim.id());
            }

            // Track the committed chunk product and link it via a zerocheck.
            let chunk_comm_id = self.peek_next_id();
            let _ = self.track_mv_com_by_id(chunk_comm_id)?;
            let diff_id = self.sub_oracles(chunk_comm_id, chunk_prod_id);
            self.add_mv_zerocheck_claim(diff_id);

            master_prod_id = Some(match master_prod_id {
                None => chunk_comm_id,
                Some(acc) => self.mul_oracles(acc, chunk_comm_id),
            });
            chunk_comm_ids.push(chunk_comm_id);
        }

        let master_prod_id = master_prod_id.expect("nozero_claims should be non-empty");

        // Track the committed inverse polynomial by id provided in the proof.
        let inverses_poly_id = self.peek_next_id();
        let _ = self.track_mv_com_by_id(inverses_poly_id)?;

        debug!(
            "{} nozerocheck polynomials chunked into {}; final degree {}",
            num_claims,
            chunk_comm_ids.len(),
            self.virt_oracle_degree(master_prod_id)
        );

        let prod_inv_id = self.mul_oracles(master_prod_id, inverses_poly_id);
        let diff_id = self.add_scalar(prod_inv_id, -B::F::one());
        self.add_mv_zerocheck_claim(diff_id);

        Ok(())
    }

    #[instrument(level = "debug", skip(self))]
    fn z_check_claim_to_s_check_claim(&mut self, max_nv: usize) -> SnarkResult<()> {
        if (self.state.mv_pcs_substate.zero_check_claims.is_empty()) {
            debug!("No zerocheck claims to convert to sumcheck claims",);
            return Ok(());
        }

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
            .id();
        // create the succint eq(x, r) closure and virtual comm
        let eq_x_r_closure = move |pt: Vec<B::F>| -> SnarkResult<B::F> { eq_eval(&pt, r.as_ref()) };
        let eq_x_r_oracle = Oracle::new_multivariate(max_nv, eq_x_r_closure);
        let eq_x_r_comm = self.track_oracle(eq_x_r_oracle);
        // create the relevant sumcheck claim, reduce the zero check claim to a sumcheck claim
        let new_sc_claim_comm = self.mul_oracles(z_check_aggr_id, eq_x_r_comm);
        // Add this new sumcheck claim to other sumcheck claims
        self.add_mv_sumcheck_claim(new_sc_claim_comm, B::F::zero());
        // Clear the zerocheck claim: it has been converted into a sumcheck claim.
        self.state.mv_pcs_substate.zero_check_claims.clear();
        debug!("The only zerocheck claim was converted to a sumcheck claim",);
        Ok(())
    }

    // Aggregate the sumcheck claims, instead of verifying p_1 = s_1, p_2 = s_2, ...
    // p_n = s_n, we verify c_1 * p_1 + c_2 * p_2 + ... + c_n * p_n = c_1 *
    // s_1 + c_2 * s_2 + ... + c_n * s_n where c_i-s are random challenges
    #[instrument(level = "debug", skip_all)]
    fn batch_s_check_claims(&mut self, max_nv: usize) -> SnarkResult<()> {
        let num_claims = self.state.mv_pcs_substate.sum_check_claims.len();

        if num_claims == 0 {
            debug!("No sumcheck claims to batch",);
            return Ok(());
        }

        // Aggreage te the sumcheck claims
        let mut agg = self.track_empty_virtual_oracle(
            max_nv,
            crate::verifier::structs::oracle::OracleKind::Multivariate,
        );
        let mut sc_sum = B::F::zero();
        // Iterate over the sumcheck claims and aggregate them
        // Order matters here, DO NOT PARALLELIZE

        agg = take(&mut self.state.mv_pcs_substate.sum_check_claims)
            .into_iter()
            .fold(agg, |acc, claim| {
                let ch = self
                    .get_and_append_challenge(b"sumcheck challenge")
                    .unwrap();
                let cp = self.mul_scalar(claim.id(), ch);
                sc_sum += claim.claim() * ch;
                self.add_oracles(acc, cp)
            });
        // Now the sumcheck claims are empty
        // Add the new aggregated sumcheck claim to the list of claims
        self.add_mv_sumcheck_claim(agg, sc_sum);
        debug!(
            "{} sumcheck claims were batched into 1 sumcheck claim",
            num_claims
        );
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn perform_single_sumcheck(&mut self) -> SnarkResult<()> {
        if (self.state.mv_pcs_substate.sum_check_claims.is_empty()) {
            debug!("No sumcheck claims to verify",);
            return Ok(());
        }
        assert_eq!(self.state.mv_pcs_substate.sum_check_claims.len(), 1);

        let sumcheck_aggr_claim = self.state.mv_pcs_substate.sum_check_claims.last().unwrap();
        if let Some(terms) = self.state.virtual_oracles.get(&sumcheck_aggr_claim.id()) {
            let degree = self.virt_oracle_degree(sumcheck_aggr_claim.id());
            let num_vars = self
                .state
                .oracle_log_sizes
                .get(&sumcheck_aggr_claim.id())
                .copied()
                .unwrap_or(0);
            debug!(
                "Sumcheck oracle stats (verifier): terms={}, degree={}, num_vars={}",
                terms.len(),
                degree,
                num_vars
            );
        }

        let sc_subclaim = SumCheck::verify(
            sumcheck_aggr_claim.claim(),
            self.proof
                .as_ref()
                .unwrap()
                .sc_subproof
                .as_ref()
                .expect("No sumcheck subproof in the proof")
                .sc_proof(),
            self.proof
                .as_ref()
                .unwrap()
                .sc_subproof
                .as_ref()
                .expect("No sumcheck subproof in the proof")
                .sc_aux_info(),
            &mut self.state.transcript,
        )?;
        self.add_mv_eval_claim(
            sumcheck_aggr_claim.id(),
            &sc_subclaim.point,
            sc_subclaim.expected_evaluation,
        )?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn perform_eval_check(&mut self) -> SnarkResult<()> {
        for ((id, point), expected_eval) in &self.state.mv_pcs_substate.eval_claims {
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

    #[instrument(level = "debug", skip_all)]
    fn equalize_sumcheck_claims(&mut self, max_nv: usize) -> SnarkResult<()> {
        let oracle_log_sizes: IndexMap<TrackerID, usize> = self.state.oracle_log_sizes.clone();
        let proof_claims = self
            .proof
            .as_ref()
            .and_then(|proof| proof.sc_subproof.as_ref())
            .map(|subproof| subproof.sumcheck_claims().clone());

        for claim in &mut self.state.mv_pcs_substate.sum_check_claims {
            if let Some(proof_claims) = proof_claims.as_ref() {
                if let Some(proof_claim) = proof_claims.get(&claim.id()) {
                    if claim.claim() == *proof_claim {
                        continue;
                    }
                }
            }

            let nv = oracle_log_sizes.get(&claim.id()).copied().unwrap_or(max_nv);
            if nv < max_nv {
                claim.set_claim(claim.claim() * B::F::from(1 << (max_nv - nv)));
            }
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn verify_sc_proofs(&mut self, max_nv: usize) -> SnarkResult<()> {
        self.batch_nozero_check_claims(max_nv)?;
        // Batch all the zero check claims into one
        self.batch_z_check_claims(max_nv)?;
        // Convert the only zero check claim to a sumcheck claim
        self.z_check_claim_to_s_check_claim(max_nv)?;
        // Ensure sumcheck claims are consistent with the max nv used in the protocol
        self.equalize_sumcheck_claims(max_nv)?;
        // aggregate the sumcheck claims
        self.batch_s_check_claims(max_nv)?;
        // Reduce high-degree terms deterministically before sumcheck.
        self.reduce_sumcheck_dgree()?;
        // Batch all the zero check claims into one
        self.batch_z_check_claims(max_nv)?;
        // Convert the only zero check claim to a sumcheck claim
        self.z_check_claim_to_s_check_claim(max_nv)?;
        // Ensure sumcheck claims are consistent with the max nv used in the protocol
        // self.equalize_sumcheck_claims(max_nv)?;
        // aggregate the sumcheck claims
        self.batch_s_check_claims(max_nv)?;
        // verify the sumcheck proof
        self.perform_single_sumcheck()?;
        // Verify the evaluation claims
        self.perform_eval_check()?;

        Ok(())
    }

    /// Reduce high-degree product terms in the single aggregated sumcheck oracle.
    ///
    /// Deterministic two-pass reduction:
    /// 1) Factor-aware contraction: if a term references a virtual oracle
    ///    directly, track its commitment and replace its id. This preserves
    ///    factorized structure when present.
    /// 2) Reuse-first chunking on remaining oversized terms.
    ///
    /// This keeps the process deterministic, fast, and in sync with the prover.
    fn reduce_sumcheck_dgree(&mut self) -> SnarkResult<()> {
        const MAX_TERM_DEGREE: usize = crate::SUMCHECK_TERM_DEGREE_LIMIT;

        debug_assert!(
            self.state.mv_pcs_substate.zero_check_claims.is_empty(),
            "reduce_sumcheck_dgree expects no zerocheck claims"
        );
        debug_assert_eq!(
            self.state.mv_pcs_substate.sum_check_claims.len(),
            1,
            "reduce_sumcheck_dgree expects exactly one sumcheck claim"
        );

        let mut cache: BTreeMap<Vec<TrackerID>, TrackerID> = BTreeMap::new();
        let mut extra_zero_claims: Vec<TrackerID> = Vec::new();
        let mut committed_chunks: usize = 0;
        let mut oversized_terms_reduced: usize = 0;
        let mut claims_reduced: usize = 0;
        let mut total_terms: usize = 0;

        fn reduce_poly<B: SnarkBackend>(
            tracker: &mut VerifierTracker<B>,
            poly_id: TrackerID,
            cache: &mut BTreeMap<Vec<TrackerID>, TrackerID>,
            extra_zero_claims: &mut Vec<TrackerID>,
            committed_chunks: &mut usize,
            oversized_terms_reduced: &mut usize,
        ) -> SnarkResult<TrackerID> {
            let terms = match tracker.state.virtual_oracles.get(&poly_id) {
                Some(terms) => terms.clone(),
                None => return Ok(poly_id),
            };

            let mut term_ids: Vec<Vec<TrackerID>> =
                terms.iter().map(|(_, ids)| ids.clone()).collect();
            for ids in term_ids.iter_mut() {
                ids.sort();
            }
            let claim_term_count = term_ids.len();
            let claim_oversized = term_ids
                .iter()
                .filter(|ids| ids.len() > MAX_TERM_DEGREE)
                .count();
            let claim_max_degree = term_ids.iter().map(|ids| ids.len()).max().unwrap_or(0);
            *oversized_terms_reduced += claim_oversized;
            debug!(
                claim_id = ?poly_id,
                claim_term_count,
                claim_oversized,
                claim_max_degree,
                "sumcheck degree reduction claim stats"
            );

            // Pass 1: factor-aware contraction of virtual oracles referenced in terms.
            let mut virtual_ids: BTreeSet<TrackerID> = BTreeSet::new();
            for ids in term_ids.iter() {
                for id in ids.iter() {
                    if !tracker.state.oracle_is_material.get(id).copied().unwrap_or(false) {
                        virtual_ids.insert(*id);
                    }
                }
            }
            for vid in virtual_ids.into_iter() {
                if cache.contains_key(&vec![vid]) {
                    continue;
                }
                let committed_id = tracker.peek_next_id();
                let _ = tracker.track_mv_com_by_id(committed_id)?;
                cache.insert(vec![vid], committed_id);
                let neg_committed = tracker.mul_scalar(committed_id, -B::F::one());
                let diff_id = tracker.add_oracles(vid, neg_committed);
                extra_zero_claims.push(diff_id);
                for ids in term_ids.iter_mut() {
                    for id in ids.iter_mut() {
                        if *id == vid {
                            *id = committed_id;
                        }
                    }
                    ids.sort();
                }
            }

            // Pass 2: Build a global frequency map of size-MAX_TERM_DEGREE chunks across oversized terms.
            let mut freq: BTreeMap<Vec<TrackerID>, usize> = BTreeMap::new();
            for ids in term_ids.iter() {
                if ids.len() <= MAX_TERM_DEGREE {
                    continue;
                }
                for window in ids.windows(MAX_TERM_DEGREE) {
                    let key = window.to_vec();
                    *freq.entry(key).or_insert(0) += 1;
                }
            }

            // Order candidates by descending frequency, then lexicographic order.
            let mut candidates: Vec<(Vec<TrackerID>, usize)> = freq.into_iter().collect();
            candidates.sort_by(|(a_ids, a_cnt), (b_ids, b_cnt)| {
                b_cnt.cmp(a_cnt).then_with(|| a_ids.cmp(b_ids))
            });

            // Helper: find the first candidate chunk that is a subset of `ids`.
            fn find_best_chunk(
                ids: &[TrackerID],
                candidates: &[(Vec<TrackerID>, usize)],
            ) -> Option<Vec<TrackerID>> {
                for (chunk, _) in candidates.iter() {
                    // Two-pointer subset check (both sorted).
                    let mut i = 0usize;
                    let mut j = 0usize;
                    while i < ids.len() && j < chunk.len() {
                        if ids[i] == chunk[j] {
                            i += 1;
                            j += 1;
                        } else if ids[i] < chunk[j] {
                            i += 1;
                        } else {
                            break;
                        }
                    }
                    if j == chunk.len() {
                        return Some(chunk.clone());
                    }
                }
                None
            }

            // Helper: remove the first occurrence of each element in `chunk` from `ids`.
            fn remove_chunk(ids: &mut Vec<TrackerID>, chunk: &[TrackerID]) {
                let mut write = 0usize;
                let mut j = 0usize;
                for i in 0..ids.len() {
                    if j < chunk.len() && ids[i] == chunk[j] {
                        j += 1;
                    } else {
                        ids[write] = ids[i];
                        write += 1;
                    }
                }
                ids.truncate(write);
            }

            // Track a committed chunk (if needed) and register its zerocheck constraint.
            fn track_chunk<B: SnarkBackend>(
                tracker: &mut VerifierTracker<B>,
                chunk: &[TrackerID],
                cache: &mut BTreeMap<Vec<TrackerID>, TrackerID>,
                extra_zero_claims: &mut Vec<TrackerID>,
                committed_chunks: &mut usize,
            ) -> SnarkResult<TrackerID> {
                if let Some(id) = cache.get(chunk).copied() {
                    return Ok(id);
                }

                let chunk_len = chunk.len();
                let chunk_log_size = chunk
                    .iter()
                    .filter_map(|id| tracker.state.oracle_log_sizes.get(id).copied())
                    .max()
                    .unwrap_or(0);
                let new_id = tracker.peek_next_id();
                let _ = tracker.track_mv_com_by_id(new_id)?;
                cache.insert(chunk.to_vec(), new_id);
                *committed_chunks += 1;

                // Add zerocheck: committed - product(chunk) == 0.
                let prod_id = {
                    let id = tracker.gen_id();
                    let mut prod_terms = VirtualOracle::new();
                    prod_terms.push((B::F::one(), chunk.to_vec()));
                    tracker.state.virtual_oracles.insert(id, prod_terms);
                    tracker.state.oracle_log_sizes.insert(id, chunk_log_size);
                    tracker.state.oracle_kinds.insert(
                        id,
                        crate::verifier::structs::oracle::OracleKind::Multivariate,
                    );
                    tracker.state.oracle_is_material.insert(id, false);
                    tracker.state.oracle_degrees.insert(id, chunk_len);
                    id
                };
                let neg_committed = tracker.mul_scalar(new_id, -B::F::one());
                let diff_id = tracker.add_oracles(prod_id, neg_committed);
                extra_zero_claims.push(diff_id);

                Ok(new_id)
            }

            // Greedily reduce each term using globally frequent chunks.
            for ids in term_ids.iter_mut() {
                while ids.len() > MAX_TERM_DEGREE {
                    // Pick the most frequent matching chunk; otherwise fallback to the
                    // lexicographically smallest size-MAX chunk from this term.
                    let chunk = find_best_chunk(ids, &candidates)
                        .or_else(|| ids.get(..MAX_TERM_DEGREE).map(|s| s.to_vec()))
                        .expect("term must be non-empty");

                    let committed_id =
                        track_chunk(tracker, &chunk, cache, extra_zero_claims, committed_chunks)?;
                    remove_chunk(ids, &chunk);
                    let insert_at = ids.binary_search(&committed_id).unwrap_or_else(|i| i);
                    ids.insert(insert_at, committed_id);
                }
            }

            let new_log_size = term_ids
                .iter()
                .flat_map(|ids| {
                    ids.iter()
                        .filter_map(|id| tracker.state.oracle_log_sizes.get(id).copied())
                })
                .max()
                .unwrap_or(0);
            let mut new_terms = VirtualOracle::new();
            for ((coeff, _old_ids), ids) in terms.iter().zip(term_ids.into_iter()) {
                new_terms.push((*coeff, ids));
            }
            let new_id = tracker.gen_id();
            tracker.state.virtual_oracles.insert(new_id, new_terms);
            tracker.state.oracle_log_sizes.insert(new_id, new_log_size);
            tracker.state.oracle_kinds.insert(
                new_id,
                crate::verifier::structs::oracle::OracleKind::Multivariate,
            );
            tracker.state.oracle_is_material.insert(new_id, false);
            let new_degree = tracker.state.virtual_oracles[&new_id]
                .iter()
                .map(|(_, ids)| ids.len())
                .max()
                .unwrap_or(0);
            tracker.state.oracle_degrees.insert(new_id, new_degree);

            Ok(new_id)
        }

        let reduce_span = tracing::debug_span!("reduce_sumcheck_degree");
        let _reduce_guard = reduce_span.enter();

        let sum_claims = take(&mut self.state.mv_pcs_substate.sum_check_claims);
        for claim in sum_claims.into_iter() {
            claims_reduced += 1;
            let new_id = reduce_poly(
                self,
                claim.id(),
                &mut cache,
                &mut extra_zero_claims,
                &mut committed_chunks,
                &mut oversized_terms_reduced,
            )?;
            self.state
                .mv_pcs_substate
                .sum_check_claims
                .push(TrackerSumcheckClaim::new(new_id, claim.claim()));
            if let Some(terms) = self.state.virtual_oracles.get(&new_id) {
                total_terms += terms.len();
            }
        }

        let extra_zero_claims_len = extra_zero_claims.len();
        for id in extra_zero_claims {
            self.add_mv_zerocheck_claim(id);
        }

        debug!(
            committed_chunks,
            extra_zerochecks_added = extra_zero_claims_len,
            oversized_terms_reduced,
            claims_reduced,
            total_terms,
            "sumcheck degree reduction stats"
        );

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn verify_mv_pcs_proof(&mut self) -> SnarkResult<bool> {
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
        let pcs_res: bool;
        if mat_coms.len() == 1 {
            let opening_proof = match self.proof.as_ref().unwrap().mv_pcs_subproof.opening_proof {
                PCSOpeningProof::SingleProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::DummyError);
                }
            };
            pcs_res = <B::MvPCS as PCS<B::F>>::verify(
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

            pcs_res = <B::MvPCS as PCS<B::F>>::batch_verify(
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
                    .collect::<Vec<B::F>>(),
                opening_proof,
                &mut self.state.transcript,
            )?;
        } else {
            pcs_res = true;
        }

        Ok(pcs_res)
    }
    #[instrument(level = "debug", skip_all)]
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
        let pcs_res: bool;
        if mat_coms.len() == 1 {
            let opening_proof = match self.proof.as_ref().unwrap().uv_pcs_subproof.opening_proof {
                PCSOpeningProof::SingleProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::DummyError);
                }
            };
            pcs_res = <B::UvPCS as PCS<B::F>>::verify(
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

            pcs_res = <B::UvPCS as PCS<B::F>>::batch_verify(
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
    #[instrument(level = "debug", skip_all)]
    fn equalize_mat_com_nv(&self) -> usize {
        self.state
            .mv_pcs_substate
            .materialized_comms
            .values()
            .map(|p| p.log_size() as usize)
            .max()
            .ok_or(1)
            .unwrap()
    }

    /// Verify the claims of the proof
    /// 1. Verify the sumcheck proofs
    /// 2. Verify the multivariate evaluation claims using the multivariate PCS
    /// 3. Verify the univariate evaluation claims using the univariate PCS
    #[instrument(level = "debug", skip_all)]
    pub fn verify(&mut self) -> SnarkResult<()> {
        let max_nv = self.equalize_mat_com_nv();
        // Verify the sumcheck proofs
        self.verify_sc_proofs(max_nv)?;
        // Verify the multivariate pcs proofs
        // assert!(self.verify_mv_pcs_proof(max_nv)?);
        self.verify_mv_pcs_proof()?;
        // Verify the multivariate pcs proofs
        // assert!(self.verify_uv_pcs_proof()?);
        self.verify_uv_pcs_proof()?;
        Ok(())
    }
}
