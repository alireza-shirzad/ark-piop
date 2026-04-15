pub mod oracle;
pub mod state;
////////////////// Imports ////////////////
use crate::{SnarkBackend, pcs::PCS, setup::structs::SNARKVk, types::TrackerID};
use ark_poly::Polynomial;
use derivative::Derivative;
use indexmap::IndexSet;
///////////// Structs & Enums ///////////

pub type VerifierEvalClaimMap<F, PC> = IndexSet<(
    (TrackerID, <<PC as PCS<F>>::Poly as Polynomial<F>>::Point),
    F,
)>;
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ProcessedSNARKVk<B>
where
    B: SnarkBackend,
{
    pub log_size: usize,
    pub mv_pcs_param: <B::MvPCS as PCS<B::F>>::VerifierParam,
    pub uv_pcs_param: <B::UvPCS as PCS<B::F>>::VerifierParam,
}

impl<B> ProcessedSNARKVk<B>
where
    B: SnarkBackend,
{
    pub fn new_from_vk(vk: &SNARKVk<B>) -> Self {
        Self {
            log_size: vk.log_size,
            mv_pcs_param: vk.mv_pcs_vk.clone(),
            uv_pcs_param: vk.uv_pcs_vk.clone(),
        }
    }
}
