use std::collections::BTreeMap;

use crate::SnarkBackend;
use crate::structs::PCSOpeningProof;
use crate::{
    pcs::PCS,
    structs::{QueryMap, SumcheckSubproof, TrackerID},
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
/// The proof of a SNARK for the ZKSQL protocol.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = ""), Default(bound = ""), Debug(bound = ""))]
pub struct SNARKProof<B>
where
    B: SnarkBackend,
{
    pub sc_subproof: Option<SumcheckSubproof<B::F>>,
    pub mv_pcs_subproof: PCSSubproof<B::F, B::MvPCS>,
    pub uv_pcs_subproof: PCSSubproof<B::F, B::UvPCS>,
    pub miscellaneous_field_elements: BTreeMap<String, B::F>,
}

/// The PCS subproof of a SNARK for the ZKSQL protocol.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = "PC: PCS<F>"),
    Default(bound = "PC: PCS<F>"),
    Debug(bound = "PC: PCS<F>")
)]
pub struct PCSSubproof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
    <PC::Poly as Polynomial<F>>::Point: CanonicalSerialize + CanonicalDeserialize,
{
    pub opening_proof: PCSOpeningProof<F, PC>,
    pub comitments: BTreeMap<TrackerID, <PC as PCS<F>>::Commitment>,
    pub query_map: QueryMap<F, PC>,
}
