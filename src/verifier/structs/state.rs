use crate::{
    SnarkBackend,
    prover::structs::proof::PCSSubproof,
    types::{PCSOpeningProof, claim::TrackerLookupClaim},
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
use std::{collections::BTreeMap, collections::BTreeSet, sync::Arc};

use super::{
    VerifierEvalClaimMap,
    oracle::{Oracle, OracleKind, TrackedOracle, VirtualOracle},
};
use crate::{
    pcs::PCS,
    prover::structs::proof::SNARKProof,
    transcript::Tr,
    types::{
        CommitmentID, PointID, PointMap, QueryMap, SumcheckSubproof, TrackerID,
        claim::{TrackerNoZerocheckClaim, TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
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
    pub base_oracles: IndexMap<TrackerID, Oracle<B::F>>,
    pub virtual_polys: IndexMap<TrackerID, VirtualOracle<B::F>>,
    pub poly_log_sizes: IndexMap<TrackerID, usize>,
    pub poly_kinds: IndexMap<TrackerID, OracleKind>,
    pub poly_is_material: IndexMap<TrackerID, bool>,
    pub poly_degrees: IndexMap<TrackerID, usize>,
    /// Mutable indexed tracked oracles for protocol-time updates.
    pub indexed_tracked_polys: BTreeMap<String, TrackedOracle<B>>,
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
    // External commitments mirror prover-side context commitments. They are
    // tracked so claims can reference them, but they are not expected to be
    // present in the proof's serialized commitment map.
    pub external_materialized_comm_ids: BTreeSet<TrackerID>,
    pub eval_claims: VerifierEvalClaimMap<F, PC>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim>,
    pub no_zero_check_claims: Vec<TrackerNoZerocheckClaim>,
    pub sum_check_claims: Vec<TrackerSumcheckClaim<F>>,
    pub lookup_claims: Vec<TrackerLookupClaim>,
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
    pub constants: BTreeMap<TrackerID, F>,
    pub point_map: Arc<PointMap<F, PC>>,
    /// TrackerID-keyed query map, reconstructed for oracle evaluation closures.
    pub query_map: Arc<QueryMap<F>>,
    /// CommitmentID-keyed query map, used directly for PCS batch verification.
    pub deduped_query_map: Arc<BTreeMap<CommitmentID, BTreeMap<PointID, F>>>,
    /// TrackerID → CommitmentID mapping for PCS verification lookups.
    pub comitment_map: BTreeMap<TrackerID, CommitmentID>,
    /// CommitmentID → Commitment map for PCS verification (includes only
    /// proof-owned commitments — one per unique CommitmentID).
    pub unique_comitments: BTreeMap<CommitmentID, <PC as PCS<F>>::Commitment>,
}

impl<F, PC> ProcessedPCSSubproof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
    <PC::Poly as Polynomial<F>>::Point: CanonicalSerialize + CanonicalDeserialize,
{
    pub fn new_from_pcs_subproof(pcs_subproof: &PCSSubproof<F, PC>) -> Self {
        // Reconstruct the full TrackerID → Commitment map from the deduplicated
        // representation in the proof. Only proof-owned commitments appear in
        // unique_comitments; external ones are skipped (loaded from context).
        let comitments = pcs_subproof
            .comitment_map
            .iter()
            .filter_map(|(tracker_id, comm_id)| {
                pcs_subproof
                    .unique_comitments
                    .get(comm_id)
                    .map(|comm| (*tracker_id, comm.clone()))
            })
            .collect();

        // Reconstruct the full TrackerID → F map from the deduplicated constants.
        let constants = pcs_subproof
            .constant_map
            .iter()
            .map(|(tracker_id, const_id)| {
                let cnst = *pcs_subproof
                    .unique_constants
                    .get(const_id)
                    .expect("ConstantID in constant_map must exist in unique_constants");
                (*tracker_id, cnst)
            })
            .collect();

        // Reconstruct TrackerID-keyed query map for oracle closures:
        // each TrackerID gets the evaluations from its CommitmentID.
        let mut query_map: BTreeMap<TrackerID, BTreeMap<PointID, F>> = BTreeMap::new();
        for (tracker_id, comm_id) in &pcs_subproof.comitment_map {
            if let Some(evals) = pcs_subproof.query_map.get(comm_id) {
                query_map.insert(*tracker_id, evals.clone());
            }
        }

        Self {
            opening_proof: pcs_subproof.opening_proof.clone(),
            comitments,
            constants,
            point_map: Arc::new(pcs_subproof.point_map.clone()),
            query_map: Arc::new(query_map),
            deduped_query_map: Arc::new(pcs_subproof.query_map.clone()),
            comitment_map: pcs_subproof.comitment_map.clone(),
            unique_comitments: pcs_subproof.unique_comitments.clone(),
        }
    }
}
