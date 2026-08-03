//! Core types shared across the prover and verifier.
//!
//! This module defines the lightweight identifier types ([`TrackerID`],
//! [`PointID`], [`CommitmentID`], [`ConstantID`]) used throughout the
//! framework, as well as the [`SharedArgConfig`] and proof-level structs.

pub mod artifact;
pub mod claim;

/// Shared configuration for ArgProver and ArgVerifier.
///
/// Protocol-level parameters that must be identical on both sides.
/// Pass the same instance to both the prover and verifier.
#[derive(Clone, Debug)]
pub struct SharedArgConfig {
    /// Max multiplicative degree allowed per sumcheck term before the prover
    /// splits high-degree products into committed sub-products.
    pub sumcheck_term_degree_limit: usize,
    /// Chunk size for batching no-zero-check claims. Larger values reduce
    /// the number of committed chunks but increase the degree of each chunk.
    pub nozero_chunk_size: usize,
    /// How the final sumcheck stage partitions its claims into rounds.
    /// [`SumcheckBucketing::Single`] matches the historical behaviour — every
    /// claim is padded to the global max `num_vars` and batched into one
    /// sumcheck. [`SumcheckBucketing::ByClaimNumVars`] groups claims by
    /// their pre-batch `num_vars` and runs one sumcheck per distinct size,
    /// ascending, so proofs that mix row-size and char-size claims stop
    /// paying padding overhead on the smaller-size claims.
    pub sumcheck_bucketing: SumcheckBucketing,
}

/// Partitioning strategy for the final aggregated sumcheck stage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SumcheckBucketing {
    /// One sumcheck at global max `num_vars`. Original behaviour.
    #[default]
    Single,
    /// One sumcheck per distinct claim `num_vars`, ascending. Requires that
    /// no virtual polynomial mixes constituents of different `num_vars` —
    /// which the tracker enforces implicitly by only ever creating virtual
    /// polys whose leaves share a hypercube (any attempted mixed-size
    /// evaluation trips MLE's `point.len() == num_vars()` assertion).
    ByClaimNumVars,
}

impl Default for SharedArgConfig {
    fn default() -> Self {
        // `ARK_PIOP_SUMCHECK_BUCKETING` lets an operator flip bucketing
        // without threading a custom `SharedArgConfig` through every
        // downstream caller. Values: `single` (default) or `by_claim_num_vars`.
        // Both prover and verifier read the env var during `default()` so
        // they land on the same policy without any explicit plumbing.
        let sumcheck_bucketing = match std::env::var("ARK_PIOP_SUMCHECK_BUCKETING")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("by_claim_num_vars") | Some("bucketed") | Some("by_num_vars") => {
                SumcheckBucketing::ByClaimNumVars
            }
            _ => SumcheckBucketing::Single,
        };
        Self {
            sumcheck_term_degree_limit: 6,
            nozero_chunk_size: 1,
            sumcheck_bucketing,
        }
    }
}

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
use std::{collections::BTreeMap, fmt::Display};
/////////// Types ///////////
//TODO: Check a map from point id to (polynomial,F)
pub type QueryMap<F> = BTreeMap<TrackerID, BTreeMap<PointID, F>>;
//TODO: Double check uniqueness
pub type PointMap<F, PC> = BTreeMap<PointID, <<PC as PCS<F>>::Poly as Polynomial<F>>::Point>;

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
pub struct TrackerID(pub u16);
impl TrackerID {
    pub fn from_usize(id: usize) -> Self {
        Self(u16::try_from(id).expect("TrackerID overflow: exceeds u16::MAX"))
    }

    pub fn to_int(self) -> usize {
        usize::from(self.0)
    }
}

/// A compact identifier for an evaluation point used in query maps.
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
pub struct PointID(pub u16);

impl PointID {
    pub fn from_usize(id: usize) -> Self {
        Self(u16::try_from(id).expect("PointID overflow: exceeds u16::MAX"))
    }

    pub fn to_int(self) -> usize {
        usize::from(self.0)
    }
}

impl Display for TrackerID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A compact identifier for a unique commitment in the proof.
/// Multiple TrackerIDs can share the same CommitmentID when they commit to
/// identical polynomials.
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
pub struct CommitmentID(pub u16);

impl CommitmentID {
    pub fn from_usize(id: usize) -> Self {
        Self(u16::try_from(id).expect("CommitmentID overflow: exceeds u16::MAX"))
    }
}

/// A compact identifier for a unique constant value in the proof.
/// Multiple TrackerIDs can share the same ConstantID when they represent the
/// same constant polynomial.
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
pub struct ConstantID(pub u16);

impl ConstantID {
    pub fn from_usize(id: usize) -> Self {
        Self(u16::try_from(id).expect("ConstantID overflow: exceeds u16::MAX"))
    }
}

/// Describes whether a tracked commitment is emitted by this proof or reused
/// from external context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentBinding {
    /// Bind the commitment into the transcript and include it in proof-owned
    /// commitment collections.
    ProofEmitted,
    /// Reuse a commitment supplied by context without re-emitting it as part of
    /// this proof.
    External,
}

/// One sumcheck round emitted by the prover. In [`SumcheckBucketing::Single`]
/// mode the subproof carries exactly one of these; in `ByClaimNumVars` mode
/// it carries one per distinct claim `num_vars`, ordered ascending.
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumcheckBucketProof<F>
where
    F: PrimeField,
{
    sc_proof: SumcheckProof<F>,
    sc_aux_info: VPAuxInfo<F>,
}

impl<F: PrimeField> SumcheckBucketProof<F> {
    pub(crate) fn new(sc_proof: SumcheckProof<F>, sc_aux_info: VPAuxInfo<F>) -> Self {
        Self { sc_proof, sc_aux_info }
    }
    pub fn sc_proof(&self) -> &SumcheckProof<F> {
        &self.sc_proof
    }
    pub(crate) fn sc_aux_info(&self) -> &VPAuxInfo<F> {
        &self.sc_aux_info
    }
    pub fn num_vars(&self) -> usize {
        self.sc_aux_info.num_variables
    }
}

// The sumcheck subproof of a SNARK for the ZKSQL protocol.
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumcheckSubproof<F>
where
    F: PrimeField,
{
    // One entry per bucket; ascending num_vars when bucketing is enabled.
    // For historical `Single` mode this always has length 1.
    buckets: Vec<SumcheckBucketProof<F>>,
    //TODO: This sumcheck_claims map is not used in all the protocols using this library, so it should not be in the proof.
    //TODO: Suggestion: Add a field to the proof for the optional and non-constant elements sent via the proof.
    sumcheck_claims: BTreeMap<TrackerID, F>,
}

impl<F: PrimeField> SumcheckSubproof<F> {
    pub(crate) fn new(
        buckets: Vec<SumcheckBucketProof<F>>,
        sumcheck_claims: BTreeMap<TrackerID, F>,
    ) -> Self {
        Self {
            buckets,
            sumcheck_claims,
        }
    }
    pub fn sumcheck_claims(&self) -> &BTreeMap<TrackerID, F> {
        &self.sumcheck_claims
    }

    pub fn buckets(&self) -> &[SumcheckBucketProof<F>] {
        &self.buckets
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "PC: PCS<F>"), Debug(bound = "PC: PCS<F>"))]
#[derive(Default)]
pub enum PCSOpeningProof<F: PrimeField, PC: PCS<F>> {
    #[default]
    Empty,
    SingleProof(<PC as PCS<F>>::Proof),
    BatchProof(<PC as PCS<F>>::BatchProof),
}

impl<F: PrimeField, PC: PCS<F>> CanonicalSerialize for PCSOpeningProof<F, PC>
where
    PC::Proof: CanonicalSerialize,
    PC::BatchProof: CanonicalSerialize,
{
    fn serialize_with_mode<W: ark_serialize::Write>(
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
    fn deserialize_with_mode<R: ark_serialize::Read>(
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
