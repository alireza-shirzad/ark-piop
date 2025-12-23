use crate::{SnarkBackend, arithmetic::mat_poly::mle::MLE, pcs::PCS};
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
pub struct SNARKPk<B>
where
    B: SnarkBackend,
{
    pub log_size: usize,
    pub mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    pub uv_pcs_param: Arc<<B::UvPCS as PCS<B::F>>::ProverParam>,
    pub indexed_tracked_polys: BTreeMap<String, MLE<B::F>>,
    pub vk: SNARKVk<B>,
}

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = ""))]
pub struct SNARKVk<B>
where
    B: SnarkBackend,
{
    pub log_size: usize,
    pub mv_pcs_vk: <B::MvPCS as PCS<B::F>>::VerifierParam,
    pub uv_pcs_vk: <B::UvPCS as PCS<B::F>>::VerifierParam,
    pub indexed_coms: BTreeMap<String, <B::MvPCS as PCS<B::F>>::Commitment>,
}

impl<B> CanonicalSerialize for SNARKPk<B>
where
    B: SnarkBackend,
    <B::MvPCS as PCS<B::F>>::ProverParam: CanonicalSerialize,
    <B::UvPCS as PCS<B::F>>::ProverParam: CanonicalSerialize,
    <B::MvPCS as PCS<B::F>>::Commitment: CanonicalSerialize,
    MLE<B::F>: CanonicalSerialize,
    SNARKVk<B>: CanonicalSerialize,
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
        self.indexed_tracked_polys
            .serialize_with_mode(&mut writer, compress)?;
        self.vk.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut size = self.log_size.serialized_size(compress);
        size += self.mv_pcs_param.as_ref().serialized_size(compress);
        size += self.uv_pcs_param.as_ref().serialized_size(compress);
        size += self.indexed_tracked_polys.serialized_size(compress);
        size += self.vk.serialized_size(compress);
        size
    }
}

impl<B> CanonicalDeserialize for SNARKPk<B>
where
    B: SnarkBackend,
    <B::MvPCS as PCS<B::F>>::ProverParam: CanonicalDeserialize,
    <B::UvPCS as PCS<B::F>>::ProverParam: CanonicalDeserialize,
    <B::MvPCS as PCS<B::F>>::Commitment: CanonicalDeserialize,
    MLE<B::F>: CanonicalDeserialize,
    SNARKVk<B>: CanonicalDeserialize,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let log_size = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let mv_param = <B::MvPCS as PCS<B::F>>::ProverParam::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        let uv_param = <B::UvPCS as PCS<B::F>>::ProverParam::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        let indexed_tracked_polys =
            BTreeMap::<String, MLE<B::F>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let vk = SNARKVk::<B>::deserialize_with_mode(reader, compress, validate)?;

        Ok(Self {
            log_size,
            mv_pcs_param: Arc::new(mv_param),
            uv_pcs_param: Arc::new(uv_param),
            indexed_tracked_polys,
            vk,
        })
    }
}

impl<B> Valid for SNARKPk<B>
where
    B: SnarkBackend,
{
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
