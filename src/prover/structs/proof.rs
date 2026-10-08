use std::collections::BTreeMap;

use crate::types::PCSOpeningProof;
use crate::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    types::artifact::{Artifact, SizeBreakdown},
};

/// One-byte version tag prepended to every serialized [`SNARKProof`]. Bump on
/// wire-format changes so mismatched clients fail fast with
/// [`SnarkError::Artifact`] instead of silently decoding garbage.
///
/// v2: `PCSSubproof.constant_num_vars` carries per-constant `num_vars` so the
/// verifier mirrors `poly_log_sizes`; v1 hardcoded 0, causing gen_id drift.
///
/// v3: `SNARKProof.logup_gkr_subproofs` carries the LogUp-GKR runs. Their
/// message shapes are part of the format: changing what a
/// [`LogupGkrProof`] holds per round or per layer is another bump.
///
/// v4: a LogUp-GKR run is one flat list of messages: the first layer of
/// every instance in place of its root, two coefficients per sumcheck round
/// in place of three evaluations, and each gate where its instance runs out
/// of variables. The lookups and keyed sums of a batch share its instances,
/// each under a `gamma` of its own.
///
/// v5: `SNARKProof.lookup_messages` names the lookup protocol the proof was
/// made with and carries the term sums of LogUp.
pub const PROOF_ENCODING_VERSION: u8 = 5;
use crate::{
    pcs::PCS,
    piop::logup_gkr::LogupGkrProof,
    types::{
        CommitmentID, ConstantID, LookupMessages, PointID, PointMap, SumcheckSubproof, TrackerID,
    },
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
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
    pub miscellaneous_field_vectors: BTreeMap<String, Vec<B::F>>,
    /// One proof per LogUp-GKR run, in the order the protocol ran them.
    pub logup_gkr_subproofs: Vec<LogupGkrProof<B::F>>,
    /// The lookup protocol of the proof and its messages. New fields go
    /// last: wrappers that serialize a proof without the version tag then
    /// fail to decode an older layout instead of misreading it.
    pub lookup_messages: LookupMessages<B::F>,
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
    /// Deduplicated commitments: each unique commitment is stored once.
    pub unique_comitments: BTreeMap<CommitmentID, <PC as PCS<F>>::Commitment>,
    /// Maps each TrackerID to its CommitmentID in `unique_comitments`.
    pub comitment_map: BTreeMap<TrackerID, CommitmentID>,
    /// Deduplicated constants: each unique field element is stored once.
    pub unique_constants: BTreeMap<ConstantID, F>,
    /// Maps each TrackerID to its ConstantID in `unique_constants`.
    pub constant_map: BTreeMap<TrackerID, ConstantID>,
    /// Per-TrackerID `num_vars` for constants; the verifier mirrors these into
    /// `poly_log_sizes` so both sides compute identical sizes (pre-v2 the
    /// verifier assumed 0, causing gen_id drift for `num_vars > 0` constants).
    pub constant_num_vars: BTreeMap<TrackerID, u32>,
    pub point_map: PointMap<F, PC>,
    /// One evaluation per unique (commitment, point) pair, avoiding duplicate
    /// openings when multiple TrackerIDs share the same polynomial.
    pub query_map: BTreeMap<CommitmentID, BTreeMap<PointID, F>>,
}

impl<B> Artifact for SNARKProof<B>
where
    B: SnarkBackend,
    SNARKProof<B>: CanonicalSerialize + CanonicalDeserialize,
{
    fn to_bytes(&self) -> SnarkResult<Vec<u8>> {
        let mut buffer = Vec::with_capacity(1 + self.serialized_size(Compress::Yes));
        buffer.push(PROOF_ENCODING_VERSION);
        self.serialize_compressed(&mut buffer)?;
        Ok(buffer)
    }

    fn from_bytes(bytes: &[u8]) -> SnarkResult<Self> {
        let (version, payload) = bytes.split_first().ok_or_else(|| {
            SnarkError::Artifact("empty proof buffer (missing version tag)".into())
        })?;
        if *version != PROOF_ENCODING_VERSION {
            return Err(SnarkError::Artifact(format!(
                "unsupported proof encoding version: got {}, this build understands {}",
                version, PROOF_ENCODING_VERSION
            )));
        }
        // The payload is a proof and nothing after it. The fields that
        // say how long the rest is come from the prover: bytes left over
        // would be ones no check of the verifier looks at, such as the
        // sums of a LogUp proof whose tag was changed to LogUp-GKR's.
        let decode = |compress: Compress| {
            let mut cursor = std::io::Cursor::new(payload);
            Self::deserialize_with_mode(&mut cursor, compress, Validate::No)
                .map(|proof| (proof, payload.len() - cursor.position() as usize))
        };
        let left_over = match decode(Compress::Yes) {
            Ok((proof, 0)) => return Ok(proof),
            Ok((_, left_over)) => Some(left_over),
            Err(_) => None,
        };
        // `to_bytes` writes compressed; a payload written uncompressed is
        // read as well, on the same terms. It is the longer of the two,
        // which may be what the bytes left over were.
        let left_over = match (decode(Compress::No), left_over) {
            (Ok((proof, 0)), _) => return Ok(proof),
            (_, Some(left_over)) | (Ok((_, left_over)), None) => left_over,
            (Err(error), None) => return Err(error.into()),
        };
        Err(SnarkError::Artifact(format!(
            "{left_over} bytes follow the proof in its buffer"
        )))
    }

    fn size_breakdown(&self) -> Option<SizeBreakdown> {
        let sc_subproof = self.sc_subproof.serialized_size(Compress::Yes);

        let mv_opening_proof = self
            .mv_pcs_subproof
            .opening_proof
            .serialized_size(Compress::Yes);
        let mv_commitments = self
            .mv_pcs_subproof
            .unique_comitments
            .serialized_size(Compress::Yes)
            + self
                .mv_pcs_subproof
                .comitment_map
                .serialized_size(Compress::Yes);
        let mv_constants = self
            .mv_pcs_subproof
            .unique_constants
            .serialized_size(Compress::Yes)
            + self
                .mv_pcs_subproof
                .constant_map
                .serialized_size(Compress::Yes)
            + self
                .mv_pcs_subproof
                .constant_num_vars
                .serialized_size(Compress::Yes);
        let mv_query_map = self
            .mv_pcs_subproof
            .query_map
            .serialized_size(Compress::Yes);
        let mv_pcs_subproof = self.mv_pcs_subproof.serialized_size(Compress::Yes);

        let uv_opening_proof = self
            .uv_pcs_subproof
            .opening_proof
            .serialized_size(Compress::Yes);
        let uv_commitments = self
            .uv_pcs_subproof
            .unique_comitments
            .serialized_size(Compress::Yes)
            + self
                .uv_pcs_subproof
                .comitment_map
                .serialized_size(Compress::Yes);
        let uv_constants = self
            .uv_pcs_subproof
            .unique_constants
            .serialized_size(Compress::Yes)
            + self
                .uv_pcs_subproof
                .constant_map
                .serialized_size(Compress::Yes)
            + self
                .uv_pcs_subproof
                .constant_num_vars
                .serialized_size(Compress::Yes);
        let uv_query_map = self
            .uv_pcs_subproof
            .query_map
            .serialized_size(Compress::Yes);
        let uv_pcs_subproof = self.uv_pcs_subproof.serialized_size(Compress::Yes);

        let miscellaneous_field_elements = self
            .miscellaneous_field_elements
            .serialized_size(Compress::Yes);
        let miscellaneous_field_vectors = self
            .miscellaneous_field_vectors
            .serialized_size(Compress::Yes);
        let logup_gkr_subproofs = self.logup_gkr_subproofs.serialized_size(Compress::Yes);
        let lookup_messages = self.lookup_messages.serialized_size(Compress::Yes);
        // +1 for the version byte `to_bytes` prepends, matching on-disk size.
        let total = self.serialized_size(Compress::Yes) + 1;

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
                            ("constants", SizeBreakdown::leaf(mv_constants)),
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
                            ("constants", SizeBreakdown::leaf(uv_constants)),
                            ("query_map", SizeBreakdown::leaf(uv_query_map)),
                        ],
                    ),
                ),
                (
                    "miscellaneous_field_elements",
                    SizeBreakdown::leaf(miscellaneous_field_elements),
                ),
                (
                    "miscellaneous_field_vectors",
                    SizeBreakdown::leaf(miscellaneous_field_vectors),
                ),
                (
                    "logup_gkr_subproofs",
                    SizeBreakdown::leaf(logup_gkr_subproofs),
                ),
                ("lookup_messages", SizeBreakdown::leaf(lookup_messages)),
            ],
        ))
    }
}
