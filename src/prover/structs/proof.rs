use std::collections::BTreeMap;

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
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    Default(bound = "MvPCS: PCS<F>"),
    Debug(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    Default(bound = "UvPCS: PCS<F>"),
    Debug(bound = "UvPCS: PCS<F>")
)]
pub struct Proof<F, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    <MvPCS::Poly as Polynomial<F>>::Point: CanonicalSerialize + CanonicalDeserialize,
    <UvPCS::Poly as Polynomial<F>>::Point: CanonicalSerialize + CanonicalDeserialize,
{
    pub sc_subproof: Option<SumcheckSubproof<F>>,
    pub mv_pcs_subproof: PCSSubproof<F, MvPCS>,
    pub uv_pcs_subproof: PCSSubproof<F, UvPCS>,
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
    pub commitments: BTreeMap<TrackerID, <PC as PCS<F>>::Commitment>,
    pub query_map: QueryMap<F, PC>,
}
