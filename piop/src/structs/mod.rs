/////////// modules ///////////
pub mod claim;
/////////// Imports ///////////
use crate::{
    arithmetic::virt_poly::hp_interface::VPAuxInfo, pcs::PCS, piop::structs::SumcheckProof,
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use derivative::Derivative;
use std::{
    collections::{BTreeMap, HashSet},
    fmt::{Display, Write},
    io::Read,
};
/////////// Types ///////////
pub type QueryMap<F, PC> = BTreeMap<(TrackerID, <<PC as PCS<F>>::Poly as Polynomial<F>>::Point), F>;

/////////// Structs ///////////
/// A unique identifier for a polynomial, or a commitment to a polynomial.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    CanonicalDeserialize,
    CanonicalSerialize,
)]
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
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
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

impl<F: PrimeField, PC: PCS<F>> CanonicalSerialize for PCSOpeningProof<F, PC>
where
    PC::Proof: CanonicalSerialize,
    PC::BatchProof: CanonicalSerialize,
{
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            PCSOpeningProof::Empty => {
                0u8.serialize_with_mode(&mut writer, compress)?;
            }
            PCSOpeningProof::SingleProof(proof) => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                proof.serialize_with_mode(&mut writer, compress)?;
            }
            PCSOpeningProof::BatchProof(batch) => {
                2u8.serialize_with_mode(&mut writer, compress)?;
                batch.serialize_with_mode(&mut writer, compress)?;
            }
        }
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        1 + match self {
            PCSOpeningProof::Empty => 0,
            PCSOpeningProof::SingleProof(proof) => proof.serialized_size(compress),
            PCSOpeningProof::BatchProof(batch) => batch.serialized_size(compress),
        }
    }
}

impl<F: PrimeField, PC: PCS<F>> CanonicalDeserialize for PCSOpeningProof<F, PC>
where
    PC::Proof: CanonicalDeserialize,
    PC::BatchProof: CanonicalDeserialize,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            0 => Ok(PCSOpeningProof::Empty),
            1 => {
                let proof = PC::Proof::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(PCSOpeningProof::SingleProof(proof))
            }
            2 => {
                let batch = PC::BatchProof::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(PCSOpeningProof::BatchProof(batch))
            }
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl<F, PC> Valid for PCSOpeningProof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
    PC::Proof: CanonicalDeserialize,
    PC::BatchProof: CanonicalDeserialize,
{
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            PCSOpeningProof::Empty => Ok(()),
            PCSOpeningProof::SingleProof(proof) => proof.check(),
            PCSOpeningProof::BatchProof(batch) => batch.check(),
        }
    }
}

impl<F: PrimeField, PC: PCS<F>> Default for PCSOpeningProof<F, PC>
where
    <PC as PCS<F>>::Proof: Default,
{
    fn default() -> Self {
        Self::Empty
    }
}
