pub mod oracle;
pub mod state;
////////////////// Imports ////////////////
use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    setup::structs::SNARKVk,
    structs::TrackerID,
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use derivative::Derivative;
use oracle::TrackedOracle;
use std::collections::{BTreeMap, HashSet};
///////////// Structs & Enums ///////////

pub type VerifierEvalClaimMap<F, PC> = HashSet<(
    (TrackerID, <<PC as PCS<F>>::Poly as Polynomial<F>>::Point),
    F,
)>;
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ProcessedSNARKVk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    pub log_size: usize,
    pub mv_pcs_param: MvPCS::VerifierParam,
    pub uv_pcs_param: UvPCS::VerifierParam,
    pub range_comms: BTreeMap<String, TrackedOracle<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> ProcessedSNARKVk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    pub fn new_from_vk(vk: &SNARKVk<F, MvPCS, UvPCS>) -> Self {
        Self {
            log_size: vk.log_size,
            mv_pcs_param: vk.mv_pcs_vk.clone(),
            uv_pcs_param: vk.uv_pcs_vk.clone(),
            range_comms: BTreeMap::new(),
        }
    }
}
