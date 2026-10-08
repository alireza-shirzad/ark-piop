//! Core types shared by prover and verifier: identifier types ([`TrackerID`],
//! [`PointID`], [`CommitmentID`], [`ConstantID`]), [`SharedArgConfig`], and
//! proof-level structs.

pub mod artifact;
pub mod claim;

/// The argument that proves lookup claims and keyed sums.
///
/// Both prove the same relations. They differ in what the prover pays and
/// what the proof carries, and they are not interchangeable: the choice is
/// part of what the two sides agree on, like the rest of
/// [`SharedArgConfig`], and a proof made with one is rejected by a verifier
/// configured for the other.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LookupProtocol {
    /// LogUp with a committed helper `1/(column - gamma)` per column, or per
    /// two adjacent columns of one size. Small proofs; the prover commits to
    /// every helper.
    LogUp,
    /// LogUp-GKR: the sums of fractions are proved by a GKR protocol without
    /// any helper commitment. A faster prover; the proof carries the GKR
    /// messages.
    #[default]
    LogUpGkr,
}

/// Names the [`LookupProtocol`] of a default [`SharedArgConfig`]: `logup` or
/// `gkr`, in any case. Meant for switching a whole run, such as a benchmark,
/// without touching code; both sides have to run under the same value.
pub const LOOKUP_PROTOCOL_ENV: &str = "ARK_PIOP_LOOKUP_PROTOCOL";

impl LookupProtocol {
    /// The protocol [`LOOKUP_PROTOCOL_ENV`] names, or `None` when the
    /// variable is not set. The environment is read once per process.
    ///
    /// A value that names no protocol is an error, here and in every
    /// constructor of a prover or verifier that takes a configuration:
    /// [`SharedArgConfig::default`] cannot report it and falls back to the
    /// built-in default, so the constructors refuse to go on with it.
    pub fn from_env() -> SnarkResult<Option<Self>> {
        static FROM_ENV: OnceLock<Result<Option<LookupProtocol>, String>> = OnceLock::new();
        FROM_ENV
            .get_or_init(|| match std::env::var(LOOKUP_PROTOCOL_ENV) {
                Ok(value) => value.parse().map(Some).map_err(|_| value),
                Err(VarError::NotPresent) => Ok(None),
                Err(VarError::NotUnicode(value)) => Err(value.to_string_lossy().into_owned()),
            })
            .clone()
            .map_err(|value| {
                let named = format!("{value:?}, the value of {LOOKUP_PROTOCOL_ENV},");
                SetupError::UnknownLookupProtocol(named).into()
            })
    }

    /// The byte that stands for the protocol in a proof and in the
    /// transcript.
    pub(crate) fn tag(self) -> u8 {
        match self {
            LookupProtocol::LogUp => 0,
            LookupProtocol::LogUpGkr => 1,
        }
    }

    /// Opens `transcript` with the protocol. Both trackers do this before
    /// anything else, so no challenge of a proof is one the other protocol
    /// would have drawn, whatever protocol the proof claims to have been
    /// made with.
    pub(crate) fn bind<F: PrimeField>(self, transcript: &mut Tr<F>) -> SnarkResult<()> {
        transcript.append_message(b"lookup protocol", &[self.tag()])?;
        Ok(())
    }
}

impl FromStr for LookupProtocol {
    type Err = SnarkError;

    fn from_str(name: &str) -> SnarkResult<Self> {
        if name.eq_ignore_ascii_case("logup") {
            Ok(LookupProtocol::LogUp)
        } else if name.eq_ignore_ascii_case("gkr") {
            Ok(LookupProtocol::LogUpGkr)
        } else {
            Err(SetupError::UnknownLookupProtocol(format!("{name:?}")).into())
        }
    }
}

impl Display for LookupProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LookupProtocol::LogUp => "LogUp",
            LookupProtocol::LogUpGkr => "LogUp-GKR",
        })
    }
}

/// The part of a proof that belongs to its lookup protocol alone: which
/// protocol it is and what that protocol sends besides commitments and
/// subproofs. Serialized as the protocol's tag byte followed by the
/// messages, so a proof of the protocol without any is one byte longer for
/// it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum LookupMessages<F: PrimeField> {
    /// The sum of every term of every keyed sum, each over the term's own
    /// hypercube, in the order the protocol reaches them. The verifier
    /// reads them in that order and binds each to the transcript before it
    /// draws anything further.
    LogUp { sums: Vec<F> },
    /// LogUp-GKR sends its messages in
    /// [`SNARKProof::logup_gkr_subproofs`](crate::prover::structs::proof::SNARKProof::logup_gkr_subproofs).
    #[default]
    LogUpGkr,
}

impl<F: PrimeField> LookupMessages<F> {
    /// The protocol the proof was made with.
    pub fn protocol(&self) -> LookupProtocol {
        match self {
            LookupMessages::LogUp { .. } => LookupProtocol::LogUp,
            LookupMessages::LogUpGkr => LookupProtocol::LogUpGkr,
        }
    }
}

impl<F: PrimeField> CanonicalSerialize for LookupMessages<F> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.protocol()
            .tag()
            .serialize_with_mode(&mut writer, compress)?;
        match self {
            LookupMessages::LogUp { sums } => sums.serialize_with_mode(&mut writer, compress),
            LookupMessages::LogUpGkr => Ok(()),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        1 + match self {
            LookupMessages::LogUp { sums } => sums.serialized_size(compress),
            LookupMessages::LogUpGkr => 0,
        }
    }
}

impl<F: PrimeField> CanonicalDeserialize for LookupMessages<F> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        if tag == LookupProtocol::LogUp.tag() {
            let sums = Vec::deserialize_with_mode(&mut reader, compress, validate)?;
            Ok(LookupMessages::LogUp { sums })
        } else if tag == LookupProtocol::LogUpGkr.tag() {
            Ok(LookupMessages::LogUpGkr)
        } else {
            Err(SerializationError::InvalidData)
        }
    }
}

impl<F: PrimeField> Valid for LookupMessages<F> {
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            LookupMessages::LogUp { sums } => sums.check(),
            LookupMessages::LogUpGkr => Ok(()),
        }
    }
}

/// Shared configuration for ArgProver and ArgVerifier: these parameters must
/// be identical on both sides, so pass the same instance to each.
///
/// The sumcheck stage buckets claims automatically at compile time; the cost
/// model in [`crate::tracker_core::bucketing::build_buckets`] decides between
/// one merged sumcheck and per-nv buckets.
#[derive(Clone, Debug)]
pub struct SharedArgConfig {
    /// Max multiplicative degree allowed per sumcheck term before the prover
    /// splits high-degree products into committed sub-products.
    pub sumcheck_term_degree_limit: usize,
    /// Chunk size for batching no-zero-check claims. Larger values reduce
    /// the number of committed chunks but increase the degree of each chunk.
    pub nozero_chunk_size: usize,
    /// Size limit of one LogUp-GKR run, in field elements of prover memory:
    /// an input fraction costs 3 when its numerator is the constant 1 and 4
    /// otherwise. A batch over the limit is split into runs, each a subproof
    /// of its own, which bounds the prover's peak at the price of a longer
    /// proof. An instance joins the first run with room for it, so the runs
    /// need not be consecutive stretches of the batch.
    ///
    /// Columns of one size on one side of a batch are stacked into one
    /// instance a power of two of them at a time, whichever lookups or keyed
    /// sums they belong to, and no more of them than the limit has room for:
    /// `2^s` unit-numerator columns of `2^n` rows share an instance only
    /// while `3 * 2^(n + s)` is within it, and a taller group becomes
    /// several instances. So a run holds more than the limit only when it
    /// is a single column that does so by itself, which is never cut and is
    /// proved alone. Under the default that is a column of more than `2^26`
    /// rows.
    ///
    /// The limit is on what a run builds. It does not bound the evaluations
    /// of the columns themselves: those of a lookup are read out before the
    /// first run, and each is held until the last run that reads it.
    ///
    /// Both the stacks and the runs are part of the proof's shape: a proof
    /// made under a limit that gives another layout than the verifier's is
    /// rejected.
    pub logup_gkr_run_budget: usize,
    /// The argument behind lookup claims and keyed sums. The proof names
    /// the one it was made with, and the verifier refuses any other than
    /// its own.
    pub lookup_protocol: LookupProtocol,
}

impl Default for SharedArgConfig {
    /// The lookup protocol is the one [`LOOKUP_PROTOCOL_ENV`] names, and
    /// LogUp-GKR when the variable is not set. A value that names no
    /// protocol leaves LogUp-GKR here as well, and makes every constructor
    /// that takes a configuration fail; see [`LookupProtocol::from_env`].
    fn default() -> Self {
        Self {
            sumcheck_term_degree_limit: 6,
            nozero_chunk_size: 1,
            logup_gkr_run_budget: 1 << 28,
            lookup_protocol: LookupProtocol::from_env()
                .ok()
                .flatten()
                .unwrap_or_default(),
        }
    }
}

use crate::{
    arithmetic::virt_poly::hp_interface::VPAuxInfo,
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::structs::SumcheckProof,
    setup::errors::SetupError,
    transcript::Tr,
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use derivative::Derivative;
use std::{collections::BTreeMap, env::VarError, fmt::Display, str::FromStr, sync::OnceLock};
//TODO: Check a map from point id to (polynomial,F)
pub type QueryMap<F> = BTreeMap<TrackerID, BTreeMap<PointID, F>>;
//TODO: Double check uniqueness
pub type PointMap<F, PC> = BTreeMap<PointID, <<PC as PCS<F>>::Poly as Polynomial<F>>::Point>;

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
    /// Bound into the transcript and included in proof-owned collections.
    ProofEmitted,
    /// Reused from external context, not re-emitted as part of this proof.
    External,
}

/// One sumcheck round emitted by the prover. The subproof carries one of
/// these per bucket produced by the compile-time picker (see
/// [`crate::tracker_core::bucketing`]), ordered by ascending `target_nv`.
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
        Self {
            sc_proof,
            sc_aux_info,
        }
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
    // One entry per bucket, ordered by ascending `target_nv` (bucket count is
    // decided by the compile-time picker in `tracker_core::bucketing`).
    buckets: Vec<SumcheckBucketProof<F>>,
    //TODO: not all protocols use sumcheck_claims; move it into an optional
    // proof-elements field instead of keeping it in every proof.
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
