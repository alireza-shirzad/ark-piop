use crate::{arithmetic::mat_poly::mle::MLE, pcs::PCS};
use ark_ff::PrimeField;
use derivative::Derivative;
use std::collections::BTreeMap;

// Clone is only implemented if PCS satisfies the PCS<F>
// bound, which guarantees that PCS::ProverParam

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
// #[derivative(Clone(bound = "MvPCS: Clone, UvPCS: Clone"))]
pub struct ProvingKey<F, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
{
    pub log_db_size: usize,
    pub mv_pcs_param: MvPCS::ProverParam,
    pub uv_pcs_param: UvPCS::ProverParam,
    pub indexed_mles: BTreeMap<String, MLE<F>>,
    pub vk: VerifyingKey<F, MvPCS, UvPCS>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct VerifyingKey<F, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
{
    pub log_db_size: usize,
    pub mv_pcs_vk: MvPCS::VerifierParam,
    pub uv_pcs_vk: UvPCS::VerifierParam,
    pub indexed_coms: BTreeMap<String, MvPCS::Commitment>,
}
