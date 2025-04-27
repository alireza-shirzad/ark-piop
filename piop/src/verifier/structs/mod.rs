pub mod oracle;
pub mod state;
////////////////// Imports ////////////////
use crate::{
    arithmetic::{LDE, mle::mat::MLE},
    pcs::PCS,
    setup::structs::VerifyingKey,
};
use ark_ff::PrimeField;
use derivative::Derivative;
use oracle::TrackedOracle;
use std::collections::BTreeMap;

///////////// Structs & Enums ///////////

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ProcessedVerifyingKey<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub log_db_size: usize,
    pub mv_pcs_param: MvPCS::VerifierParam,
    pub uv_pcs_param: UvPCS::VerifierParam,
    pub range_comms: BTreeMap<String, TrackedOracle<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> ProcessedVerifyingKey<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new_from_vk(vk: &VerifyingKey<F, MvPCS, UvPCS>) -> Self {
        Self {
            log_db_size: vk.log_db_size,
            mv_pcs_param: vk.mv_pcs_vk.clone(),
            uv_pcs_param: vk.uv_pcs_vk.clone(),
            range_comms: BTreeMap::new(),
        }
    }
}
