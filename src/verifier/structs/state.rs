use crate::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    prover::structs::proof::PCSSubproof,
    structs::PCSOpeningProof,
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
use std::{collections::BTreeMap, sync::Arc};

use super::{VerifierEvalClaimMap, oracle::Oracle};
use crate::{
    pcs::PCS,
    prover::structs::proof::SNARKProof,
    structs::{
        QueryMap, SumcheckSubproof, TrackerID,
        claim::{TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
    transcript::Tr,
};
use indexmap::IndexMap;
// Clone is only implemented if PCS satisfies the PCS<F>
// bound, which guarantees that PCS::ProverParam
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Default(bound = ""))]
pub struct VerifierState<B>
where
    B: SnarkBackend,
{
    pub transcript: Tr<B::F>,
    pub num_tracked_polys: usize,
    pub virtual_oracles: IndexMap<TrackerID, Oracle<B::F>>,
    pub mv_pcs_substate: VerifierPCSubstate<B::F, B::MvPCS>,
    pub uv_pcs_substate: VerifierPCSubstate<B::F, B::UvPCS>,
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
    pub eval_claims: VerifierEvalClaimMap<F, PC>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim>,
    pub sum_check_claims: Vec<TrackerSumcheckClaim<F>>,
}

/// The proof of a SNARK for the ZKSQL protocol.
#[derive(Derivative)]
#[derivative(Clone(bound = ""), Default(bound = ""), Debug(bound = ""))]
pub struct ProcessedProof<B>
where
    B: SnarkBackend,
{
    pub sc_subproof: Option<SumcheckSubproof<B::F>>,
    pub mv_pcs_subproof: ProcessedPCSSubproof<B::F, B::MvPCS>,
    pub uv_pcs_subproof: ProcessedPCSSubproof<B::F, B::UvPCS>,
    pub miscellaneous_field_elements: BTreeMap<String, B::F>,
}

impl<B> ProcessedProof<B>
where
    B: SnarkBackend,
    <<B::MvPCS as PCS<B::F>>::Poly as Polynomial<B::F>>::Point:
        CanonicalSerialize + CanonicalDeserialize,
    <<B::UvPCS as PCS<B::F>>::Poly as Polynomial<B::F>>::Point:
        CanonicalSerialize + CanonicalDeserialize,
{
    pub fn new_from_proof(proof: &SNARKProof<B>) -> Self {
        Self {
            sc_subproof: proof.sc_subproof.clone(),
            mv_pcs_subproof: ProcessedPCSSubproof::new_from_pcs_subproof(&proof.mv_pcs_subproof),
            uv_pcs_subproof: ProcessedPCSSubproof::new_from_pcs_subproof(&proof.uv_pcs_subproof),
            miscellaneous_field_elements: proof.miscellaneous_field_elements.clone(),
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
    pub opening_proof: PCSOpeningProof<F, PC>,
    pub comitments: BTreeMap<TrackerID, <PC as PCS<F>>::Commitment>,
    pub query_map: Arc<QueryMap<F, PC>>,
}

impl<F, PC> ProcessedPCSSubproof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
    <PC::Poly as Polynomial<F>>::Point: CanonicalSerialize + CanonicalDeserialize,
{
    pub fn new_from_pcs_subproof(pcs_subproof: &PCSSubproof<F, PC>) -> Self {
        Self {
            opening_proof: pcs_subproof.opening_proof.clone(),
            comitments: pcs_subproof.comitments.clone(),
            query_map: Arc::new(pcs_subproof.query_map.clone()),
        }
    }
}
