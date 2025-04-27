/////////// modules ///////////
pub mod claim;
/////////// Imports ///////////
use crate::{arithmetic::mle::virt::VPAuxInfo, pcs::PCS, piop::structs::SumcheckProof};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use std::{
    collections::{BTreeMap, HashSet},
    fmt::Display,
};

/////////// Types ///////////
pub type QueryMap<F, PC> = BTreeMap<(TrackerID, <<PC as PCS<F>>::Poly as Polynomial<F>>::Point), F>;
pub type EvalClaimMap<F, PC> = HashSet<(TrackerID, <<PC as PCS<F>>::Poly as Polynomial<F>>::Point)>;

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
    pub sumcheck_claims: BTreeMap<TrackerID, F>, // id -> [ sum_{i=0}^n p(i) ]
    pub sc_proof: SumcheckProof<F>,
    pub sc_aux_info: VPAuxInfo<F>,
}
