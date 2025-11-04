use crate::{arithmetic::mat_poly::mle::MLE, pcs::PCS};
use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use derivative::Derivative;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    sync::Arc,
};
// Clone is only implemented if PCS satisfies the PCS<F>
// bound, which guarantees that PCS::ProverParam

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
// #[derivative(Clone(bound = "MvPCS: Clone, UvPCS: Clone"))]
pub struct SNARKPk<F, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
{
    pub log_size: usize,
    pub mv_pcs_param: Arc<MvPCS::ProverParam>,
    pub uv_pcs_param: Arc<UvPCS::ProverParam>,
    pub indexed_mles: BTreeMap<String, MLE<F>>,
    pub vk: SNARKVk<F, MvPCS, UvPCS>,
}

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = ""))]
pub struct SNARKVk<F, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
{
    pub log_size: usize,
    pub mv_pcs_vk: MvPCS::VerifierParam,
    pub uv_pcs_vk: UvPCS::VerifierParam,
    pub indexed_coms: BTreeMap<String, MvPCS::Commitment>,
}

impl<F, MvPCS, UvPCS> CanonicalSerialize for SNARKPk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F>,
    UvPCS: PCS<F>,
    MvPCS::ProverParam: CanonicalSerialize,
    UvPCS::ProverParam: CanonicalSerialize,
    MvPCS::Commitment: CanonicalSerialize,
    MLE<F>: CanonicalSerialize,
    SNARKVk<F, MvPCS, UvPCS>: CanonicalSerialize,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.log_size.serialize_with_mode(&mut writer, compress)?;
        self.mv_pcs_param
            .as_ref()
            .serialize_with_mode(&mut writer, compress)?;
        self.uv_pcs_param
            .as_ref()
            .serialize_with_mode(&mut writer, compress)?;
        self.indexed_mles
            .serialize_with_mode(&mut writer, compress)?;
        self.vk.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut size = self.log_size.serialized_size(compress);
        size += self.mv_pcs_param.as_ref().serialized_size(compress);
        size += self.uv_pcs_param.as_ref().serialized_size(compress);
        size += self.indexed_mles.serialized_size(compress);
        size += self.vk.serialized_size(compress);
        size
    }
}

impl<F, MvPCS, UvPCS> CanonicalDeserialize for SNARKPk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F>,
    UvPCS: PCS<F>,
    MvPCS::ProverParam: CanonicalDeserialize,
    UvPCS::ProverParam: CanonicalDeserialize,
    MvPCS::Commitment: CanonicalDeserialize,
    MLE<F>: CanonicalDeserialize,
    SNARKVk<F, MvPCS, UvPCS>: CanonicalDeserialize,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let log_size = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let mv_param = MvPCS::ProverParam::deserialize_with_mode(&mut reader, compress, validate)?;
        let uv_param = UvPCS::ProverParam::deserialize_with_mode(&mut reader, compress, validate)?;
        let indexed_mles =
            BTreeMap::<String, MLE<F>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let vk = SNARKVk::<F, MvPCS, UvPCS>::deserialize_with_mode(reader, compress, validate)?;

        Ok(Self {
            log_size,
            mv_pcs_param: Arc::new(mv_param),
            uv_pcs_param: Arc::new(uv_param),
            indexed_mles,
            vk,
        })
    }
}

impl<F, MvPCS, UvPCS> Valid for SNARKPk<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F>,
    UvPCS: PCS<F>,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
