use crate::prover::structs::proof::PCSSubproof;
use ark_ff::PrimeField;
use derivative::Derivative;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use super::oracle::Oracle;
use crate::{
    arithmetic::{LDE, mle::mat::MLE},
    pcs::PCS,
    prover::structs::proof::Proof,
    structs::{
        EvalClaimMap, QueryMap, SumcheckSubproof, TrackerID,
        claim::{TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
    transcript::Tr,
};

// Clone is only implemented if PCS satisfies the PCS<F>
// bound, which guarantees that PCS::ProverParam
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Default(bound = ""))]
pub struct VerifierState<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub transcript: Tr<F>,
    pub num_tracked_polys: usize,
    pub virtual_oracles: HashMap<TrackerID, Oracle<F>>,
    pub mv_pcs_substate: VerifierPCSubstate<F, MvPCS>,
    pub uv_pcs_substate: VerifierPCSubstate<F, UvPCS>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Default(bound = ""))]
pub struct VerifierPCSubstate<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    pub materialized_comms: BTreeMap<TrackerID, PC::Commitment>,
    pub eval_claims: EvalClaimMap<F, PC>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim>,
    pub sum_check_claims: Vec<TrackerSumcheckClaim<F>>,
}

/// The proof of a SNARK for the ZKSQL protocol.
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    Default(bound = "MvPCS: PCS<F>"),
    Debug(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    Default(bound = "UvPCS: PCS<F>"),
    Debug(bound = "UvPCS: PCS<F>")
)]
pub struct ProcessedProof<F, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
{
    pub sc_subproof: SumcheckSubproof<F>,
    pub mv_pcs_subproof: ProcessedPCSSubproof<F, MvPCS>,
    pub uv_pcs_subproof: ProcessedPCSSubproof<F, UvPCS>,
}

impl<F, MvPCS, UvPCS> ProcessedProof<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F>,
    UvPCS: PCS<F>,
{
    pub fn new_from_proof(proof: &Proof<F, MvPCS, UvPCS>) -> Self {
        Self {
            sc_subproof: proof.sc_subproof.clone(),
            mv_pcs_subproof: ProcessedPCSSubproof::new_from_pcs_subproof(&proof.mv_pcs_subproof),
            uv_pcs_subproof: ProcessedPCSSubproof::new_from_pcs_subproof(&proof.uv_pcs_subproof),
        }
    }
}

/// The PCS subproof of a SNARK for the ZKSQL protocol.
#[derive(Derivative)]
#[derivative(
    Clone(bound = "PC: PCS<F>"),
    Default(bound = "PC: PCS<F>"),
    Debug(bound = "PC: PCS<F>")
)]
pub struct ProcessedPCSSubproof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    pub batch_proof: <PC as PCS<F>>::BatchProof,
    pub commitments: BTreeMap<TrackerID, <PC as PCS<F>>::Commitment>,
    pub query_map: Arc<QueryMap<F, PC>>,
}

impl<F, PC> ProcessedPCSSubproof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    pub fn new_from_pcs_subproof(pcs_subproof: &PCSSubproof<F, PC>) -> Self {
        Self {
            batch_proof: pcs_subproof.batch_proof.clone(),
            commitments: pcs_subproof.commitments.clone(),
            query_map: Arc::new(pcs_subproof.query_map.clone()),
        }
    }
}
