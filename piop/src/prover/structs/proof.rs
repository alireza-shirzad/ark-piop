use std::{collections::BTreeMap, sync::Arc};

use ark_ff::PrimeField;
use derivative::Derivative;

use crate::{
    pcs::PCS,
    structs::{QueryMap, SumcheckSubproof, TrackerID},
};

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
pub struct Proof<F, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
{
    pub sc_subproof: SumcheckSubproof<F>,
    pub mv_pcs_subproof: PCSSubproof<F, MvPCS>,
    pub uv_pcs_subproof: PCSSubproof<F, UvPCS>,
}

/// The PCS subproof of a SNARK for the ZKSQL protocol.
#[derive(Derivative)]
#[derivative(
    Clone(bound = "PC: PCS<F>"),
    Default(bound = "PC: PCS<F>"),
    Debug(bound = "PC: PCS<F>")
)]
pub struct PCSSubproof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    pub batch_proof: <PC as PCS<F>>::BatchProof,
    pub commitments: BTreeMap<TrackerID, <PC as PCS<F>>::Commitment>,
    pub query_map: QueryMap<F, PC>,
}
