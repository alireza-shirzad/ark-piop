/////////// modules ///////////
pub mod claim;
/////////// Imports ///////////
use crate::{
    arithmetic::virt_poly::hp_interface::VPAuxInfo, pcs::PCS, piop::structs::SumcheckProof,
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use derivative::Derivative;
use std::{
    collections::{BTreeMap, HashSet},
    fmt::Display,
};
/////////// Types ///////////
pub type QueryMap<F, PC> = BTreeMap<(TrackerID, <<PC as PCS<F>>::Poly as Polynomial<F>>::Point), F>;

/////////// Structs ///////////
/// A unique identifier for a polynomial, or a commitment to a polynomial.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TrackerID(pub usize);
impl TrackerID {
    pub fn to_int(self) -> usize {
        self.0
    }
}

impl Display for TrackerID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// The sumcheck subproof of a SNARK for the ZKSQL protocol.
#[derive(Clone, Debug, Default)]
pub struct SumcheckSubproof<F>
where
    F: PrimeField,
{
    sc_proof: SumcheckProof<F>,
    sc_aux_info: VPAuxInfo<F>,
    //TODO: This sumcheck_claims map is not used in all the protocols using this library, so it should not be in the proof.
    //TODO: Suggestion: Add a field to the proof for the optional and non-constant elements sent via the proof.
    sumcheck_claims: BTreeMap<TrackerID, F>,
}

impl<F: PrimeField> SumcheckSubproof<F> {
    pub fn new(
        sc_proof: SumcheckProof<F>,
        sc_aux_info: VPAuxInfo<F>,
        sumcheck_claims: BTreeMap<TrackerID, F>,
    ) -> Self {
        Self {
            sc_proof,
            sc_aux_info,
            sumcheck_claims,
        }
    }
    pub fn get_sumcheck_claims(&self) -> &BTreeMap<TrackerID, F> {
        &self.sumcheck_claims
    }

    pub fn get_sc_proof(&self) -> &SumcheckProof<F> {
        &self.sc_proof
    }

    pub fn get_sc_aux_info(&self) -> &VPAuxInfo<F> {
        &self.sc_aux_info
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "PC: PCS<F>"), Debug(bound = "PC: PCS<F>"))]
pub enum PCSOpeningProof<F: PrimeField, PC: PCS<F>> {
    Empty,
    SingleProof(<PC as PCS<F>>::Proof),
    BatchProof(<PC as PCS<F>>::BatchProof),
}

impl<F: PrimeField, PC: PCS<F>> Default for PCSOpeningProof<F, PC>
where
    <PC as PCS<F>>::Proof: Default,
{
    fn default() -> Self {
        Self::Empty
    }
}
