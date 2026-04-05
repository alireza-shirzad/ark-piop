use std::collections::BTreeMap;

use crate::{
    artifact::{Artifact, SizeBreakdown},
    errors::SnarkResult,
    SnarkBackend,
};
use crate::structs::PCSOpeningProof;
use crate::{
    pcs::PCS,
    structs::{PointMap, QueryMap, SumcheckSubproof, TrackerID},
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use derivative::Derivative;
/// The proof of a SNARK for the ZKSQL protocol.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = ""), Default(bound = ""), Debug(bound = ""))]
pub struct SNARKProof<B>
where
    B: SnarkBackend,
{
    pub sc_subproof: Option<SumcheckSubproof<B::F>>,
    pub mv_pcs_subproof: PCSSubproof<B::F, B::MvPCS>,
    pub uv_pcs_subproof: PCSSubproof<B::F, B::UvPCS>,
    pub miscellaneous_field_elements: BTreeMap<String, B::F>,
}

/// The PCS subproof of a SNARK for the ZKSQL protocol.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = "PC: PCS<F>"),
    Default(bound = "PC: PCS<F>"),
    Debug(bound = "PC: PCS<F>")
)]
pub struct PCSSubproof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
    <PC::Poly as Polynomial<F>>::Point: CanonicalSerialize + CanonicalDeserialize,
{
    pub opening_proof: PCSOpeningProof<F, PC>,
    pub comitments: BTreeMap<TrackerID, <PC as PCS<F>>::Commitment>,
    pub point_map: PointMap<F, PC>,
    pub query_map: QueryMap<F>,
}

impl<B> Artifact for SNARKProof<B>
where
    B: SnarkBackend,
    SNARKProof<B>: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_bytes(&self) -> SnarkResult<Vec<u8>> {
        let mut buffer = Vec::new();
        self.serialize_compressed(&mut buffer)?;
        Ok(buffer)
    }

    fn from_bytes(bytes: &[u8]) -> SnarkResult<Self> {
        let mut cursor = std::io::Cursor::new(bytes);
        match Self::deserialize_compressed_unchecked(&mut cursor) {
            Ok(proof) => Ok(proof),
            Err(_) => {
                let mut fallback_cursor = std::io::Cursor::new(bytes);
                Ok(Self::deserialize_uncompressed_unchecked(
                    &mut fallback_cursor,
                )?)
            }
        }
    }

    fn size_breakdown(&self) -> Option<SizeBreakdown> {
        let sc_subproof = self.sc_subproof.serialized_size(Compress::Yes);

        let mv_opening_proof = self.mv_pcs_subproof.opening_proof.serialized_size(Compress::Yes);
        let mv_commitments = self.mv_pcs_subproof.comitments.serialized_size(Compress::Yes);
        let mv_query_map = self.mv_pcs_subproof.query_map.serialized_size(Compress::Yes);
        let mv_pcs_subproof = self.mv_pcs_subproof.serialized_size(Compress::Yes);

        let uv_opening_proof = self.uv_pcs_subproof.opening_proof.serialized_size(Compress::Yes);
        let uv_commitments = self.uv_pcs_subproof.comitments.serialized_size(Compress::Yes);
        let uv_query_map = self.uv_pcs_subproof.query_map.serialized_size(Compress::Yes);
        let uv_pcs_subproof = self.uv_pcs_subproof.serialized_size(Compress::Yes);

        let miscellaneous_field_elements = self.miscellaneous_field_elements.serialized_size(Compress::Yes);
        let total = self.serialized_size(Compress::Yes);

        Some(SizeBreakdown::node(
            total,
            [
                ("sc_subproof", SizeBreakdown::leaf(sc_subproof)),
                (
                    "mv_pcs_subproof",
                    SizeBreakdown::node(
                        mv_pcs_subproof,
                        [
                            ("opening_proof", SizeBreakdown::leaf(mv_opening_proof)),
                            ("commitments", SizeBreakdown::leaf(mv_commitments)),
                            ("query_map", SizeBreakdown::leaf(mv_query_map)),
                        ],
                    ),
                ),
                (
                    "uv_pcs_subproof",
                    SizeBreakdown::node(
                        uv_pcs_subproof,
                        [
                            ("opening_proof", SizeBreakdown::leaf(uv_opening_proof)),
                            ("commitments", SizeBreakdown::leaf(uv_commitments)),
                            ("query_map", SizeBreakdown::leaf(uv_query_map)),
                        ],
                    ),
                ),
                (
                    "miscellaneous_field_elements",
                    SizeBreakdown::leaf(miscellaneous_field_elements),
                ),
            ],
        ))
    }
}
