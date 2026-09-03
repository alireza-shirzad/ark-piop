pub mod polynomial;
pub mod proof;
use std::collections::BTreeSet;
use std::{collections::BTreeMap, sync::Arc};

use crate::types::claim::TrackerNoZerocheckClaim;
use crate::{
    SnarkBackend,
    arithmetic::virt_poly::VirtualPoly,
    pcs::PCS,
    prover::structs::polynomial::TrackedPoly,
    setup::structs::SNARKPk,
    transcript::Tr,
    types::{
        TrackerID,
        claim::{TrackerLookupClaim, TrackerSumcheckClaim, TrackerZerocheckClaim},
    },
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_std::fmt::Debug;
use derivative::Derivative;
/// A claim about the evaluation of a tracked polynomial at a point.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derive(Debug, PartialEq, Eq, PartialOrd)]
pub struct TrackerEvalClaim<F: PrimeField, PC: PCS<F>> {
    id: TrackerID,
    point: <PC::Poly as Polynomial<F>>::Point,
}

impl<F: PrimeField, PC: PCS<F>> TrackerEvalClaim<F, PC> {
    pub fn new(id: TrackerID, point: <PC::Poly as Polynomial<F>>::Point) -> Self {
        Self { id, point }
    }
    pub fn id(&self) -> TrackerID {
        self.id
    }
    pub fn point(&self) -> &<PC::Poly as Polynomial<F>>::Point {
        &self.point
    }
    pub fn set_point(&mut self, point: <PC::Poly as Polynomial<F>>::Point) {
        self.point = point;
    }
}

// Clone(bound = "") is sound: the PCS<F> bound already makes components clonable.
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Default(bound = ""))]
pub struct ProverState<B>
where
    B: SnarkBackend,
{
    /// The transcript for the PIOP
    pub transcript: Tr<B::F>,

    /// number of the tracked polynomials (Univariate and Multivariate)
    // TODO: See if we should split this into two fields
    pub num_tracked_polys: usize,

    /// Virtual polynomials by TrackerID: `sum_i c_i * prod_j p_ij`, where each
    /// `p_ij` points to another materialized or virtual polynomial.
    pub virtual_polys: BTreeMap<TrackerID, VirtualPoly<B::F>>,

    /// Mutable indexed tracked polynomials for protocol-time updates.
    pub indexed_tracked_polys: BTreeMap<String, TrackedPoly<B>>,

    pub mv_pcs_substate: ProverPCSubstate<B::F, B::MvPCS>,
    pub uv_pcs_substate: ProverPCSubstate<B::F, B::UvPCS>,
    pub miscellaneous_field_elements: BTreeMap<String, B::F>,
    pub miscellaneous_field_vectors: BTreeMap<String, Vec<B::F>>,
    pub num_vars: BTreeMap<TrackerID, usize>,
    pub bench_lookup_claims_pre_reduction: usize,
    /// Bench stat from `reduce_lookup_claims`: subset count per superset
    /// (len = distinct supersets, sum = lookup claims before reduction).
    pub bench_lookup_subset_counts_per_superset: Vec<usize>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Default(bound = ""))]
pub struct ProverPCSubstate<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    pub materialized_polys: BTreeMap<TrackerID, Arc<PC::Poly>>,
    pub materialized_comms: BTreeMap<TrackerID, PC::Commitment>,
    // BLAKE3(evaluation bytes) -> commitment, so identical polynomials reuse
    // one (expensive) MSM result.
    pub commitment_cache: BTreeMap<[u8; 32], PC::Commitment>,
    // Constants detected during track_and_commit: bypass commitment/opening —
    // only the scalar is sent in the proof and transcript-bound.
    pub constants: BTreeMap<TrackerID, F>,
    // `num_vars` for `constants` entries, emitted so the verifier can mirror
    // `poly_log_sizes` — see `PROOF_ENCODING_VERSION = 2`.
    pub constants_num_vars: BTreeMap<TrackerID, usize>,
    // Commitments reused from external context (e.g. base tables): tracked for
    // openings but not emitted as proof-owned in the PCS subproof.
    pub external_materialized_comm_ids: BTreeSet<TrackerID>,
    pub eval_claims: Vec<TrackerEvalClaim<F, PC>>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim>,
    pub no_zero_check_claims: Vec<TrackerNoZerocheckClaim>,
    pub sum_check_claims: Vec<TrackerSumcheckClaim<F>>,
    pub lookup_claims: Vec<TrackerLookupClaim>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ProcessedSNARKPk<B>
where
    B: SnarkBackend,
{
    pub log_size: usize,
    pub mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    pub uv_pcs_param: Arc<<B::UvPCS as PCS<B::F>>::ProverParam>,
}

impl<B> ProcessedSNARKPk<B>
where
    B: SnarkBackend,
{
    pub fn new_from_pk(pk: &SNARKPk<B>) -> Self {
        Self {
            log_size: pk.log_size,
            mv_pcs_param: Arc::clone(&pk.mv_pcs_param),
            uv_pcs_param: Arc::clone(&pk.uv_pcs_param),
        }
    }
}
