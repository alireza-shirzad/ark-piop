use ark_ff::{Field, Zero};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Valid, Validate};
use ark_std::{cfg_chunks, cfg_iter, rand::Rng};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::{
    borrow::Cow,
    cmp::Ordering,
    fmt::{self, Formatter},
    ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign},
    slice::IterMut,
};

/// The evaluation-table backing for an [`MLE`]. `Field` is the traditional
/// full-fat backing where every hypercube point already sits in `F` (32 bytes
/// per element for the BN254/BLS12-381-sized scalars we use). The compressed
/// variants let natively-typed data emitted by upstream gadgets (bits, ASCII
/// bytes, row indices) live in memory at its natural width until a caller
/// actually needs field-form evaluations.
///
/// Semantic contract: for storage kind `S`, the value at inner evaluation index
/// `i` (0-indexed into the inner hypercube of size `1 << inner_num_vars`) lifts
/// to `F` according to:
///
/// - `Field(inner)` → `inner.evaluations[i]`
/// - `Bit { bits, .. }` → `F::one()` if the i-th packed bit is set, else `F::zero()`
/// - `U8 { bytes, .. }` → `F::from(bytes[i] as u64)`
/// - `U32 { words, .. }` → `F::from(words[i] as u64)`
/// - `U64 { words, .. }` → `F::from(words[i] as u64)`
///
/// `MLE`'s virtual-padding (`nv`) sits on top of this: after resolving the
/// inner index via `index % (1 << inner_num_vars)`, the compressed variant
/// lifts as above.
///
/// The packing convention for `Bit` is little-endian per byte: bit `i` lives at
/// `bits[i / 8] >> (i % 8) & 1`. `bits.len() == inner_len().div_ceil(8)`.
///
/// `CanonicalSerialize` / `CanonicalDeserialize` are hand-implemented below
/// because arkworks' derive macros only support structs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum MLEStorage<F: Field> {
    Field(DenseMultilinearExtension<F>),
    Bit {
        bits: Vec<u8>,
        inner_num_vars: usize,
    },
    U8 {
        bytes: Vec<u8>,
        inner_num_vars: usize,
    },
    U32 {
        words: Vec<u32>,
        inner_num_vars: usize,
    },
    U64 {
        words: Vec<u64>,
        inner_num_vars: usize,
    },
}

impl<F: Field> Default for MLEStorage<F> {
    fn default() -> Self {
        Self::Field(DenseMultilinearExtension::default())
    }
}

// Hand-written canonical (de)serialization: arkworks' derive macros only
// support structs, so we encode a 1-byte discriminant tag followed by the
// variant payload. The inner-num-vars is stored as `u64` for platform
// independence.
impl<F: Field> CanonicalSerialize for MLEStorage<F> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Field(m) => {
                0u8.serialize_with_mode(&mut writer, compress)?;
                m.serialize_with_mode(&mut writer, compress)?;
            }
            Self::Bit {
                bits,
                inner_num_vars,
            } => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                bits.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::U8 {
                bytes,
                inner_num_vars,
            } => {
                2u8.serialize_with_mode(&mut writer, compress)?;
                bytes.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::U32 {
                words,
                inner_num_vars,
            } => {
                3u8.serialize_with_mode(&mut writer, compress)?;
                words.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::U64 {
                words,
                inner_num_vars,
            } => {
                4u8.serialize_with_mode(&mut writer, compress)?;
                words.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
        }
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let payload = match self {
            Self::Field(m) => m.serialized_size(compress),
            Self::Bit {
                bits,
                inner_num_vars,
            } => bits.serialized_size(compress) + (*inner_num_vars as u64).serialized_size(compress),
            Self::U8 {
                bytes,
                inner_num_vars,
            } => {
                bytes.serialized_size(compress) + (*inner_num_vars as u64).serialized_size(compress)
            }
            Self::U32 {
                words,
                inner_num_vars,
            } => {
                words.serialized_size(compress) + (*inner_num_vars as u64).serialized_size(compress)
            }
            Self::U64 {
                words,
                inner_num_vars,
            } => {
                words.serialized_size(compress) + (*inner_num_vars as u64).serialized_size(compress)
            }
        };
        1u8.serialized_size(compress) + payload
    }
}

impl<F: Field> Valid for MLEStorage<F> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Field(m) => m.check(),
            Self::Bit { bits, .. } => bits.check(),
            Self::U8 { bytes, .. } => bytes.check(),
            Self::U32 { words, .. } => words.check(),
            Self::U64 { words, .. } => words.check(),
        }
    }
}

impl<F: Field> CanonicalDeserialize for MLEStorage<F> {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            0 => Ok(Self::Field(
                DenseMultilinearExtension::deserialize_with_mode(&mut reader, compress, validate)?,
            )),
            1 => {
                let bits = Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                Ok(Self::Bit {
                    bits,
                    inner_num_vars: n,
                })
            }
            2 => {
                let bytes = Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                Ok(Self::U8 {
                    bytes,
                    inner_num_vars: n,
                })
            }
            3 => {
                let words = Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                Ok(Self::U32 {
                    words,
                    inner_num_vars: n,
                })
            }
            4 => {
                let words = Vec::<u64>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                Ok(Self::U64 {
                    words,
                    inner_num_vars: n,
                })
            }
            _ => Err(ark_serialize::SerializationError::InvalidData),
        }
    }
}

impl<F: Field> MLEStorage<F> {
    /// The `num_vars` of the *inner* (unpadded) hypercube. For `Field`, this is
    /// the inner `DenseMultilinearExtension::num_vars`; for compressed variants
    /// this is the tagged `inner_num_vars`.
    #[inline]
    pub fn inner_num_vars(&self) -> usize {
        match self {
            Self::Field(m) => m.num_vars,
            Self::Bit { inner_num_vars, .. }
            | Self::U8 { inner_num_vars, .. }
            | Self::U32 { inner_num_vars, .. }
            | Self::U64 { inner_num_vars, .. } => *inner_num_vars,
        }
    }

    /// The number of inner evaluation slots (`1 << inner_num_vars`).
    #[inline]
    pub fn inner_len(&self) -> usize {
        1usize << self.inner_num_vars()
    }

    /// Lift the i-th inner evaluation to `F`. `i` must satisfy `i < inner_len()`.
    #[inline]
    pub fn lift(&self, i: usize) -> F {
        match self {
            Self::Field(m) => m.evaluations[i],
            Self::Bit { bits, .. } => {
                let byte = bits[i >> 3];
                if (byte >> (i & 7)) & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            }
            Self::U8 { bytes, .. } => F::from(bytes[i] as u64),
            Self::U32 { words, .. } => F::from(words[i] as u64),
            Self::U64 { words, .. } => F::from(words[i]),
        }
    }

    /// Heap footprint in bytes of the storage payload only (does not count the
    /// `MLEStorage` discriminant itself). Used by tracker snapshots.
    pub fn heap_bytes(&self) -> u64 {
        match self {
            Self::Field(m) => (m.evaluations.len() as u64) * (std::mem::size_of::<F>() as u64),
            Self::Bit { bits, .. } => bits.len() as u64,
            Self::U8 { bytes, .. } => bytes.len() as u64,
            Self::U32 { words, .. } => (words.len() as u64) * 4,
            Self::U64 { words, .. } => (words.len() as u64) * 8,
        }
    }

    /// True if this storage is the `Field` variant.
    #[inline]
    pub fn is_field(&self) -> bool {
        matches!(self, Self::Field(_))
    }

    /// Materialize the storage into a `DenseMultilinearExtension<F>`. For
    /// `Field` this returns a `Cow::Borrowed`; for compressed variants this
    /// allocates the full field-element evaluation vector as `Cow::Owned`.
    pub fn to_field(&self) -> Cow<'_, DenseMultilinearExtension<F>> {
        match self {
            Self::Field(m) => Cow::Borrowed(m),
            _ => {
                let n = self.inner_num_vars();
                let len = self.inner_len();
                let evals: Vec<F> = (0..len).map(|i| self.lift(i)).collect();
                Cow::Owned(DenseMultilinearExtension::from_evaluations_vec(n, evals))
            }
        }
    }

    /// Materialize into an owned `Vec<F>` of the full inner hypercube.
    pub fn to_evaluations_vec(&self) -> Vec<F> {
        match self {
            Self::Field(m) => m.evaluations.clone(),
            _ => (0..self.inner_len()).map(|i| self.lift(i)).collect(),
        }
    }
}

/// A wrapper around `DenseMultilinearExtension` that allows for a modified
/// hypercube size. If the nv is not set, the size of the hypercube is 2^{mat_mle.num_vars}.
/// If the nv is set, the size of the hypercube is 2^nv, and the evaluation vector is (virtually) the repetition
/// of the original evaluation vector to fit the new size. This is useful when we want to increase the number of variables
/// of a multilinear polynomial without actually changing the underlying polynomial and its memory usage.
///
/// The storage of the inner evaluations is discriminated by [`MLEStorage`]:
/// small-scalar variants (`Bit`, `U8`, `U32`, `U64`) let natively-typed data
/// stay compressed in memory until a caller genuinely needs field-form
/// evaluations, cutting the per-poly footprint by 8× to 256× depending on the
/// underlying type.
///
/// Every functionality supported by `DenseMultilinearExtension` is also
/// supported by `MLE`.
#[derive(Clone, PartialEq, Eq, Hash, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct MLE<F: Field> {
    storage: MLEStorage<F>,
    nv: Option<usize>,
}

impl<F: Field> MLE<F> {
    pub fn new(mat_mle: DenseMultilinearExtension<F>, nv: Option<usize>) -> Self {
        Self {
            storage: MLEStorage::Field(mat_mle),
            nv,
        }
    }

    /// Construct an `MLE` from a bit-packed backing (little-endian per byte).
    /// `bits.len()` must equal `(1 << inner_num_vars).div_ceil(8)`. If
    /// `num_vars > inner_num_vars`, the inner hypercube is virtually repeated
    /// cyclically to fit the requested outer size (same semantics as
    /// [`MLE::from_evaluations_vec`]).
    pub fn from_bit_backing(bits: Vec<u8>, num_vars: usize) -> Self {
        let expected = (1usize << num_vars).div_ceil(8).max(1);
        assert!(
            bits.len() <= expected,
            "bit backing too long: len={}, expected at most {} for num_vars={}",
            bits.len(),
            expected,
            num_vars
        );
        let inner_bits = bits.len() * 8;
        let inner_num_vars = inner_bits.checked_ilog2().unwrap_or_default() as usize;
        Self {
            storage: MLEStorage::Bit {
                bits,
                inner_num_vars,
            },
            nv: (num_vars > inner_num_vars).then_some(num_vars),
        }
    }

    /// Build a bit-packed `MLE` from an iterator of booleans. The iterator must
    /// yield exactly `1 << num_vars` items (the length is checked). Consumes
    /// the iterator and returns a compressed-storage MLE.
    pub fn from_bits<I: IntoIterator<Item = bool>>(iter: I, num_vars: usize) -> Self {
        let len = 1usize << num_vars;
        let mut bits = vec![0u8; len.div_ceil(8)];
        let mut count = 0usize;
        for (i, b) in iter.into_iter().enumerate() {
            assert!(i < len, "from_bits: iterator yields more than 2^num_vars items");
            if b {
                bits[i >> 3] |= 1u8 << (i & 7);
            }
            count += 1;
        }
        assert_eq!(count, len, "from_bits: iterator yielded {} items, expected {}", count, len);
        Self {
            storage: MLEStorage::Bit {
                bits,
                inner_num_vars: num_vars,
            },
            nv: None,
        }
    }

    /// Build a bit-packed `MLE` whose first `active_len` bits are set and the
    /// rest are zero. This matches the semantics of a "contiguous-one
    /// activator" mask: bits `[0, active_len)` are 1, bits `[active_len, 2^num_vars)`
    /// are 0. `active_len` must satisfy `active_len <= 1 << num_vars`.
    pub fn from_prefix_activator(active_len: usize, num_vars: usize) -> Self {
        let len = 1usize << num_vars;
        assert!(active_len <= len, "active_len {} > 2^num_vars {}", active_len, len);
        let mut bits = vec![0u8; len.div_ceil(8).max(1)];
        // Set full bytes first, then the tail byte.
        let full_bytes = active_len / 8;
        for byte in bits.iter_mut().take(full_bytes) {
            *byte = 0xff;
        }
        let tail = active_len % 8;
        if tail > 0 && full_bytes < bits.len() {
            bits[full_bytes] = (1u8 << tail) - 1;
        }
        Self {
            storage: MLEStorage::Bit {
                bits,
                inner_num_vars: num_vars,
            },
            nv: None,
        }
    }

    /// Build a `u8`-typed `MLE`. `bytes.len()` must be `<= 1 << num_vars`; if
    /// strictly less, the shorter backing is retained and cyclically repeated
    /// to fit the requested outer size (see [`MLE::from_evaluations_vec`]).
    pub fn from_u8s(bytes: Vec<u8>, num_vars: usize) -> Self {
        assert!(
            bytes.len() <= (1usize << num_vars),
            "u8 backing len {} > 2^num_vars {}",
            bytes.len(),
            1usize << num_vars
        );
        let inner_num_vars = bytes.len().checked_ilog2().unwrap_or_default() as usize;
        Self {
            storage: MLEStorage::U8 {
                bytes,
                inner_num_vars,
            },
            nv: (num_vars > inner_num_vars).then_some(num_vars),
        }
    }

    /// Build a `u32`-typed `MLE`. Same length rules as [`MLE::from_u8s`].
    pub fn from_u32s(words: Vec<u32>, num_vars: usize) -> Self {
        assert!(
            words.len() <= (1usize << num_vars),
            "u32 backing len {} > 2^num_vars {}",
            words.len(),
            1usize << num_vars
        );
        let inner_num_vars = words.len().checked_ilog2().unwrap_or_default() as usize;
        Self {
            storage: MLEStorage::U32 {
                words,
                inner_num_vars,
            },
            nv: (num_vars > inner_num_vars).then_some(num_vars),
        }
    }

    /// Build a `u64`-typed `MLE`. Same length rules as [`MLE::from_u8s`].
    pub fn from_u64s(words: Vec<u64>, num_vars: usize) -> Self {
        assert!(
            words.len() <= (1usize << num_vars),
            "u64 backing len {} > 2^num_vars {}",
            words.len(),
            1usize << num_vars
        );
        let inner_num_vars = words.len().checked_ilog2().unwrap_or_default() as usize;
        Self {
            storage: MLEStorage::U64 {
                words,
                inner_num_vars,
            },
            nv: (num_vars > inner_num_vars).then_some(num_vars),
        }
    }

    /// Read-only access to the storage backing. New code that wants to
    /// dispatch on storage kind should go through this rather than
    /// [`MLE::mat_mle`].
    #[inline]
    pub fn storage(&self) -> &MLEStorage<F> {
        &self.storage
    }

    /// Return an owned `MLE<F>` whose storage is `Field`. If `self` is already
    /// `Field` this is a plain clone; compressed storage is materialized into
    /// a `Vec<F>` and wrapped as a Field MLE. Used at the boundary where a
    /// downstream algorithm (e.g. the sumcheck round loop) requires
    /// `&F` slice access via [`MLE::Index`] or the inner `DenseMultilinearExtension`.
    ///
    /// The at-rest compressed storage on the tracker is unaffected — only the
    /// caller's owned copy is promoted.
    pub fn to_field_owned(&self) -> Self {
        match &self.storage {
            MLEStorage::Field(_) => self.clone(),
            _ => Self {
                storage: MLEStorage::Field(self.storage.to_field().into_owned()),
                nv: self.nv,
            },
        }
    }

    /// Auto-classifies `evals` into the tightest small-scalar
    /// [`MLEStorage`] variant, then constructs the MLE with that backing. Runs
    /// one pass over the vector inspecting each element's `into_bigint()` for
    /// the smallest fitting kind (bit → u8 → u32 → u64 → Field), then builds
    /// the compressed backing and drops `evals`.
    ///
    /// For workloads where the semantic type of a column is known
    /// (bit vectors, ASCII bytes, row indices), this preserves that width all
    /// the way to tracker storage — the resulting MLE occupies 8×-256× less
    /// heap than the same evaluations stored as full field elements.
    ///
    /// Cost: `O(evals.len())` bigint conversions + one small-scalar allocation
    /// of the winning kind. The intermediate `evals` is dropped on return.
    /// Falls back cleanly to [`MLE::from_evaluations_vec`] when nothing smaller
    /// than a full field element fits.
    pub fn from_evaluations_vec_compressed(num_vars: usize, evals: Vec<F>) -> Self
    where
        F: ark_ff::PrimeField,
    {
        // Reuse the same tight-kind classifier used at LIKE-gadget commit
        // sites. Order (tight → loose): Bit, U8, U32, U64, Field. Any element
        // that overflows the current kind bumps to the next looser kind.
        #[derive(Copy, Clone, PartialEq, Eq)]
        enum Kind {
            Bit,
            U8,
            U32,
            U64,
            Field,
        }
        let mut kind = Kind::Bit;
        for x in evals.iter() {
            if kind == Kind::Field {
                break;
            }
            let bigint = x.into_bigint();
            let limbs = bigint.as_ref(); // &[u64]
            let this_kind = if limbs.iter().skip(1).all(|&l| l == 0) {
                let low = limbs.first().copied().unwrap_or(0);
                if low <= 1 {
                    Kind::Bit
                } else if low <= u8::MAX as u64 {
                    Kind::U8
                } else if low <= u32::MAX as u64 {
                    Kind::U32
                } else {
                    Kind::U64
                }
            } else {
                Kind::Field
            };
            kind = match (kind, this_kind) {
                (Kind::Bit, k) => k,
                (Kind::U8, Kind::Bit) => Kind::U8,
                (Kind::U8, k) => k,
                (Kind::U32, Kind::Bit | Kind::U8) => Kind::U32,
                (Kind::U32, k) => k,
                (Kind::U64, Kind::Bit | Kind::U8 | Kind::U32) => Kind::U64,
                (Kind::U64, k) => k,
                (Kind::Field, _) => Kind::Field,
            };
        }
        match kind {
            Kind::Bit => Self::from_bits(
                evals.iter().map(|x| {
                    let low = x.into_bigint().as_ref().first().copied().unwrap_or(0);
                    low == 1
                }),
                num_vars,
            ),
            Kind::U8 => {
                let bytes: Vec<u8> = evals
                    .iter()
                    .map(|x| x.into_bigint().as_ref()[0] as u8)
                    .collect();
                Self::from_u8s(bytes, num_vars)
            }
            Kind::U32 => {
                let words: Vec<u32> = evals
                    .iter()
                    .map(|x| x.into_bigint().as_ref()[0] as u32)
                    .collect();
                Self::from_u32s(words, num_vars)
            }
            Kind::U64 => {
                let words: Vec<u64> = evals
                    .iter()
                    .map(|x| x.into_bigint().as_ref()[0])
                    .collect();
                Self::from_u64s(words, num_vars)
            }
            Kind::Field => Self::from_evaluations_vec(num_vars, evals),
        }
    }

    /// Compress an existing MLE's storage to the tightest small-scalar variant
    /// that fits its evaluations. If the poly is already `Field`-backed and
    /// contains only small-integer values, this rebuilds it as the compressed
    /// variant. For non-Field storage this is a no-op returning `self`.
    ///
    /// Used at the boundary where an upstream stage produced a `Vec<F>`-backed
    /// MLE from small-integer source data (e.g. arithmetization lifting u64
    /// columns into F) and the downstream storage should reflect the true
    /// width.
    pub fn compressed(self) -> Self
    where
        F: ark_ff::PrimeField,
    {
        match self.storage {
            MLEStorage::Field(inner) => {
                let nv = self.nv;
                let mut out =
                    Self::from_evaluations_vec_compressed(inner.num_vars, inner.evaluations);
                // Preserve the outer virtual nv (padding) if present.
                if let Some(target_nv) = nv
                    && target_nv > out.inner_num_vars()
                {
                    out.set_virtual_nv(target_nv);
                }
                out
            }
            _ => self,
        }
    }

    /// Update the virtual `nv` (outer hypercube size) in place, without
    /// touching the storage backing. `target_nv` must be `>= inner_num_vars()`.
    /// If `target_nv == inner_num_vars()`, clears `nv` (the inner hypercube is
    /// the full outer hypercube).
    ///
    /// Used by the bucket-lift path in the tracker so compressed polys can be
    /// promoted to a larger nv without materializing to `Vec<F>` (which would
    /// undo the compression). The virtual repetition semantics of [`MLE`] cover
    /// the "expand by cyclic repeat" step for free.
    pub fn set_virtual_nv(&mut self, target_nv: usize) {
        let inner_nv = self.storage.inner_num_vars();
        assert!(
            target_nv >= inner_nv,
            "set_virtual_nv: target_nv ({}) < inner_num_vars ({})",
            target_nv,
            inner_nv
        );
        self.nv = if target_nv > inner_nv {
            Some(target_nv)
        } else {
            None
        };
    }

    /// Access the poly as a `DenseMultilinearExtension<F>`, materializing on
    /// demand if the backing is compressed. Field variants return a borrow
    /// (zero-cost); compressed variants allocate an owned dense poly, which
    /// dies with the returned `Cow` — so callers should minimise how long the
    /// returned value stays alive.
    ///
    /// Prefer [`MLE::storage`] plus storage-aware operations when possible.
    /// This is here for backward compatibility with callers that unwrap to the
    /// inner arkworks type.
    pub fn mat_mle(&self) -> Cow<'_, DenseMultilinearExtension<F>> {
        self.storage.to_field()
    }

    pub fn num_vars(&self) -> usize {
        match self.nv {
            Some(nv) => nv,
            None => self.storage.inner_num_vars(),
        }
    }

    /// The un-padded (inner) `num_vars`. This is the true count for the
    /// backing evaluation table, ignoring any virtual `nv` repetition.
    #[inline]
    pub fn inner_num_vars(&self) -> usize {
        self.storage.inner_num_vars()
    }

    /// Mutable access to the inner `DenseMultilinearExtension`. Panics if the
    /// storage is not `Field` (compressed variants have no mutable dense
    /// representation to hand out) or if `nv` is set.
    pub fn mat_mle_mut(&mut self) -> &mut DenseMultilinearExtension<F> {
        assert!(
            self.nv.is_none(),
            "You can mutate mat_mle only if nv is None"
        );
        match &mut self.storage {
            MLEStorage::Field(m) => m,
            _ => panic!(
                "mat_mle_mut called on compressed MLE storage; \
                 promote the poly to Field storage first"
            ),
        }
    }

    pub fn evaluations(&self) -> Vec<F> {
        match (self.nv, &self.storage) {
            (Some(_), _) => self.iter().collect::<Vec<F>>(),
            (None, MLEStorage::Field(m)) => m.evaluations.clone(),
            (None, _) => self.storage.to_evaluations_vec(),
        }
    }

    pub fn into_evaluations(self) -> Vec<F> {
        match (self.nv, self.storage) {
            (Some(nv), storage) => {
                // Rebuild an iterator that respects virtual repetition.
                let inner_len = storage.inner_len();
                let outer_len = 1usize << nv;
                (0..outer_len).map(|i| storage.lift(i % inner_len)).collect()
            }
            (None, MLEStorage::Field(m)) => m.evaluations,
            (None, storage) => storage.to_evaluations_vec(),
        }
    }

    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[F]) -> Self {
        Self::from_evaluations_vec(num_vars, evaluations.to_vec())
    }

    pub fn from_evaluations_vec(num_vars: usize, evaluations: Vec<F>) -> Self {
        // assert that the number of variables matches the size of evaluations
        assert!(
            evaluations.len() <= (1 << num_vars),
            "The size of evaluations ({}) should be at most 2^num_vars (= {}).",
            evaluations.len(),
            1 << num_vars,
        );
        let eval_num_vars = evaluations.len().checked_ilog2().unwrap_or_default() as usize;

        Self {
            storage: MLEStorage::Field(DenseMultilinearExtension::from_evaluations_vec(
                eval_num_vars,
                evaluations,
            )),
            nv: (num_vars > eval_num_vars).then_some(num_vars),
        }
    }

    pub fn relabel_in_place(&mut self, mut _a: usize, mut _b: usize, _k: usize) {
        todo!()
    }

    /// Iterate the outer hypercube's evaluations (lifted to `F`). Respects
    /// virtual `nv` padding by cycling the inner backing.
    pub fn iter(&self) -> MLEValueIter<'_, F> {
        let outer_len = 1usize << self.num_vars();
        let inner_len = self.storage.inner_len();
        MLEValueIter {
            storage: &self.storage,
            outer_len,
            inner_len,
            pos: 0,
        }
    }

    /// Mutable iterator over the inner `Field`-storage evaluations. Panics if
    /// `nv` is set (virtual padding is not backed by physical storage) or if
    /// the storage is not `Field` (compressed variants have no mutable slice
    /// of field elements to expose).
    pub fn iter_mut(&mut self) -> IterMut<'_, F> {
        assert!(self.nv.is_none(), "iter_mut is not supported when nv is set");
        match &mut self.storage {
            MLEStorage::Field(m) => m.evaluations.iter_mut(),
            _ => panic!(
                "iter_mut called on compressed MLE storage; promote to Field storage first"
            ),
        }
    }

    pub fn constant(value: F) -> Self {
        Self::from_evaluations_vec(0, vec![value])
    }

    pub fn is_constant(&self) -> bool {
        if self.num_vars() == 0 {
            return true;
        }
        // For any storage variant: fold via lift() to compare all inner points.
        let inner_len = self.storage.inner_len();
        if inner_len == 0 {
            return true;
        }
        let cnst = self.storage.lift(0);
        (1..inner_len).all(|i| self.storage.lift(i) == cnst)
    }

    pub fn concat(_polys: impl IntoIterator<Item = impl AsRef<Self>> + Clone) -> Self {
        todo!("Implement concat for MLE");
    }
}

/// Iterator yielded by [`MLE::iter`]. Owns nothing but a borrow on the
/// underlying storage; each `next()` lifts one evaluation to `F`.
pub struct MLEValueIter<'a, F: Field> {
    storage: &'a MLEStorage<F>,
    outer_len: usize,
    inner_len: usize,
    pos: usize,
}

impl<'a, F: Field> Iterator for MLEValueIter<'a, F> {
    type Item = F;

    #[inline]
    fn next(&mut self) -> Option<F> {
        if self.pos >= self.outer_len {
            return None;
        }
        let i = if self.inner_len == 0 {
            0
        } else {
            self.pos % self.inner_len
        };
        let v = self.storage.lift(i);
        self.pos += 1;
        Some(v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.outer_len.saturating_sub(self.pos);
        (remaining, Some(remaining))
    }
}

impl<'a, F: Field> ExactSizeIterator for MLEValueIter<'a, F> {}

impl<F: Field> AsRef<MLE<F>> for MLE<F> {
    fn as_ref(&self) -> &MLE<F> {
        self
    }
}

impl<F: Field> MultilinearExtension<F> for MLE<F> {
    fn num_vars(&self) -> usize {
        todo!()
    }

    fn rand<R: Rng>(num_vars: usize, rng: &mut R) -> Self {
        MLE {
            storage: MLEStorage::Field(DenseMultilinearExtension::rand(num_vars, rng)),
            nv: None,
        }
    }

    fn relabel(&self, _a: usize, _b: usize, _k: usize) -> Self {
        todo!()
    }

    fn fix_variables(&self, partial_point: &[F]) -> Self {
        assert!(
            partial_point.len() <= self.num_vars(),
            "invalid size of partial point"
        );
        let nv = self.num_vars();
        let dim = partial_point.len();
        // First fold materializes the inner evaluations to `Vec<F>`. For
        // compressed storage this is the necessary lift; the output of a fold
        // step is always `F`-valued so subsequent folds go through Field-only
        // code.
        let mut poly: Vec<F> = self.storage.to_evaluations_vec();
        // evaluate single variable of partial point from left to right
        for point in partial_point {
            if poly.len() == 1 {
                break;
            }
            let p = std::mem::take(&mut poly);
            poly = fix_one_variable_helper(p, point);
        }

        MLE::<F>::from_evaluations_vec(nv - dim, poly)
    }

    fn to_evaluations(&self) -> Vec<F> {
        self.evaluations()
    }
}

impl<F: Field> Index<usize> for MLE<F> {
    type Output = F;

    #[inline]
    fn index(&self, _index: usize) -> &Self::Output {
        // NOTE: This is a legacy accessor kept for callers that read
        // `mle[i]` expecting a `&F`. It only works for `Field` storage
        // (which is the only variant that actually holds `F` elements at
        // rest). Compressed variants must be read through `iter()` /
        // `storage().lift(i)` or promoted first.
        //
        // The signature returning `&F` is not compatible with
        // materialize-on-demand: we have no owned `F` to hand out a reference
        // to. Callers on the hot sumcheck path (see `piop/sum_check/prover.rs`)
        // use `Index<usize>` heavily; those callers get `Field`-backed MLEs
        // because sumcheck's first `fix_variables` transitions into Field
        // storage.
        let index = if self.nv.is_some() {
            _index % (1 << self.storage.inner_num_vars())
        } else {
            _index
        };
        match &self.storage {
            MLEStorage::Field(m) => &m[index],
            _ => panic!(
                "MLE::Index<usize> is only supported for Field storage; \
                 got a compressed variant. Use `storage().lift(i)` or promote \
                 to Field storage first."
            ),
        }
    }
}

impl<F: Field> Add for MLE<F> {
    type Output = MLE<F>;

    fn add(self, other: MLE<F>) -> Self {
        &self + &other
    }
}

impl<'a, F: Field> Add<&'a MLE<F>> for &MLE<F> {
    type Output = MLE<F>;

    fn add(self, rhs: &'a MLE<F>) -> Self::Output {
        if rhs.is_zero() {
            return self.clone();
        }
        if self.is_zero() {
            return rhs.clone();
        }
        // Arithmetic operates on the Field representation. Compressed variants
        // are promoted transiently — callers who add compressed polys pay the
        // materialization cost here.
        let self_field = self.storage.to_field();
        let rhs_field = rhs.storage.to_field();
        match (self.nv, rhs.nv) {
            // TODO: Some cases are not handled
            (Some(nv1), Some(nv2)) if nv1 == nv2 => {
                match self_field.num_vars.cmp(&rhs_field.num_vars) {
                    Ordering::Less => MLE {
                        storage: MLEStorage::Field(
                            &increase_nv(self_field.as_ref(), rhs_field.num_vars) + rhs_field.as_ref(),
                        ),
                        nv: Some(nv1),
                    },
                    Ordering::Greater => MLE {
                        storage: MLEStorage::Field(
                            self_field.as_ref() + &increase_nv(rhs_field.as_ref(), self_field.num_vars),
                        ),
                        nv: Some(nv1),
                    },
                    Ordering::Equal => MLE {
                        storage: MLEStorage::Field(self_field.as_ref() + rhs_field.as_ref()),
                        nv: Some(nv1),
                    },
                }
            }
            (None, None) => MLE {
                storage: MLEStorage::Field(self_field.as_ref() + rhs_field.as_ref()),
                nv: None,
            },
            (Some(nv1), None) if nv1 == rhs_field.num_vars => MLE {
                storage: MLEStorage::Field(
                    &increase_nv(self_field.as_ref(), nv1) + rhs_field.as_ref(),
                ),
                nv: None,
            },
            (None, Some(nv2)) if nv2 == self_field.num_vars => MLE {
                storage: MLEStorage::Field(
                    self_field.as_ref() + &increase_nv(rhs_field.as_ref(), nv2),
                ),
                nv: None,
            },
            _ => {
                panic!("Cannot add MLEs with different number of variables");
            }
        }
    }
}

impl<F: Field> AddAssign for MLE<F> {
    fn add_assign(&mut self, other: Self) {
        *self = &*self + &other;
    }
}

impl<'a, F: Field> AddAssign<&'a MLE<F>> for MLE<F> {
    fn add_assign(&mut self, other: &'a MLE<F>) {
        *self = &*self + other;
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl<'a, F: Field> AddAssign<(F, &'a MLE<F>)> for MLE<F> {
    fn add_assign(&mut self, (f, other): (F, &'a MLE<F>)) {
        // Materialize the RHS to Field, scale, then add. Compressed RHS pays
        // the materialization cost here.
        let other_field = other.storage.to_field();
        let mat_mle = DenseMultilinearExtension::from_evaluations_vec(
            other_field.num_vars,
            cfg_iter!(other_field.evaluations).map(|x| f * x).collect(),
        );
        let other = Self {
            nv: other.nv,
            storage: MLEStorage::Field(mat_mle),
        };
        *self = &*self + &other;
    }
}

impl<F: Field> Neg for MLE<F> {
    type Output = MLE<F>;

    fn neg(self) -> Self::Output {
        // Negation must go through Field storage: `-bit`, `-byte` etc do not
        // fit the small-scalar variants.
        let field = self.storage.to_field().into_owned();
        Self {
            storage: MLEStorage::Field(-field),
            nv: self.nv,
        }
    }
}

impl<F: Field> Sub for MLE<F> {
    type Output = MLE<F>;

    fn sub(self, other: MLE<F>) -> Self {
        &self - &other
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, F: Field> Sub<&'a MLE<F>> for &MLE<F> {
    type Output = MLE<F>;

    fn sub(self, rhs: &'a MLE<F>) -> Self::Output {
        self + &rhs.clone().neg()
    }
}

impl<F: Field> SubAssign for MLE<F> {
    fn sub_assign(&mut self, _other: Self) {
        todo!()
    }
}

impl<'a, F: Field> SubAssign<&'a MLE<F>> for MLE<F> {
    fn sub_assign(&mut self, other: &'a MLE<F>) {
        *self = &*self - other;
    }
}

impl<F: Field> Mul<F> for MLE<F> {
    type Output = MLE<F>;

    fn mul(self, scalar: F) -> Self::Output {
        &self * &scalar
    }
}

impl<'a, F: Field> Mul<&'a F> for &MLE<F> {
    type Output = MLE<F>;

    fn mul(self, scalar: &'a F) -> Self::Output {
        if scalar.is_zero() {
            return MLE::zero();
        } else if scalar.is_one() {
            return self.clone();
        }
        // Multiplication by a scalar promotes compressed storage to Field.
        let field = self.storage.to_field();
        Self::Output {
            storage: MLEStorage::Field(field.as_ref() * scalar),
            nv: self.nv,
        }
    }
}

impl<F: Field> MulAssign<F> for MLE<F> {
    fn mul_assign(&mut self, scalar: F) {
        *self = &*self * &scalar
    }
}

impl<'a, F: Field> MulAssign<&'a F> for MLE<F> {
    fn mul_assign(&mut self, scalar: &'a F) {
        *self = &*self * scalar
    }
}

impl<F: Field> fmt::Debug for MLE<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        // Debug prints go through the materialized Field view for consistency
        // with the pre-refactor behaviour.
        let field = self.storage.to_field();
        match self.nv {
            Some(nv) => write!(f, "real-nv= {}, wrapped-poly= {:?}", nv, field.as_ref())?,
            None => field.as_ref().fmt(f)?,
        }
        Ok(())
    }
}
impl<F: Field> Zero for MLE<F> {
    fn zero() -> Self {
        Self {
            storage: MLEStorage::Field(DenseMultilinearExtension::zero()),
            nv: None,
        }
    }

    fn is_zero(&self) -> bool {
        match (self.nv, &self.storage) {
            (Some(nv), MLEStorage::Field(m)) => m.is_zero() && nv == 0,
            (None, MLEStorage::Field(m)) => m.is_zero(),
            (Some(nv), _) => {
                // Compressed variants: zero iff every inner slot lifts to zero and
                // the virtual nv is zero.
                nv == 0 && (0..self.storage.inner_len()).all(|i| self.storage.lift(i).is_zero())
            }
            (None, _) => (0..self.storage.inner_len()).all(|i| self.storage.lift(i).is_zero()),
        }
    }
}

impl<F: Field> Polynomial<F> for MLE<F> {
    type Point = Vec<F>;

    fn degree(&self) -> usize {
        self.num_vars()
    }

    fn evaluate(&self, point: &Self::Point) -> F {
        assert!(point.len() == self.num_vars());
        // `fix_variables` promotes to Field, so `[0]` on the returned MLE is
        // safe.
        self.fix_variables(point)[0]
    }
}

/// Increase the number of variables of a multilinear polynomial by adding
/// variables at the back Ex for input (P(X, Y), 3) result in P'(X, Y, Z), where
/// P'(X, Y, Z) = P(X, Y)
/// TODO: Parallelize this function
fn increase_nv<F: Field>(
    mle: &DenseMultilinearExtension<F>,
    new_nv: usize,
) -> DenseMultilinearExtension<F> {
    if mle.num_vars() == new_nv {
        return mle.clone();
    }
    if mle.num_vars() > new_nv {
        panic!("dmle_increase_nv Error: old_len > new_len");
    }

    let old_len = 2_usize.pow(mle.num_vars() as u32);
    let new_len = 2_usize.pow(new_nv as u32);
    let mut evals = mle.evaluations.clone();
    evals.resize(new_len, F::default());
    for i in old_len..new_len {
        evals[i] = evals[i % old_len];
    }
    DenseMultilinearExtension::from_evaluations_vec(new_nv, evals)
}

fn fix_one_variable_helper<F: Field>(data: Vec<F>, p: &F) -> Vec<F> {
    cfg_chunks!(&data, 2)
        .map(|c| {
            let diff = c[1] - c[0];
            if diff.is_zero() {
                c[0]
            } else {
                c[0] + diff * p
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};

    fn fr(value: u64) -> Fr {
        Fr::from(value)
    }

    // ── is_constant / constant ──────────────────────────────────────

    #[test]
    fn constant_creates_zero_var_mle() {
        let c = MLE::constant(fr(42));
        assert_eq!(c.num_vars(), 0);
        assert_eq!(c.evaluations(), vec![fr(42)]);
        assert!(c.is_constant());
    }

    #[test]
    fn is_constant_true_for_all_equal_evals() {
        let mle = MLE::from_evaluations_vec(3, vec![fr(7); 8]);
        assert!(mle.is_constant());
    }

    #[test]
    fn is_constant_false_when_one_eval_differs() {
        let mut evals = vec![fr(5); 8];
        evals[3] = fr(6);
        let mle = MLE::from_evaluations_vec(3, evals);
        assert!(!mle.is_constant());
    }

    #[test]
    fn is_constant_true_for_wrapped_constant() {
        // Inner has 2 vars (4 identical evals), virtually expanded to 5 vars.
        let inner =
            DenseMultilinearExtension::from_evaluations_vec(2, vec![fr(9), fr(9), fr(9), fr(9)]);
        let mle = MLE::new(inner, Some(5));
        assert!(mle.is_constant());
    }

    // ── MLE arithmetic ──────────────────────────────────────────────

    #[test]
    fn add_two_mles_same_nv() {
        let a = MLE::from_evaluations_vec(2, vec![fr(1), fr(2), fr(3), fr(4)]);
        let b = MLE::from_evaluations_vec(2, vec![fr(10), fr(20), fr(30), fr(40)]);
        let c = &a + &b;
        assert_eq!(c.evaluations(), vec![fr(11), fr(22), fr(33), fr(44)]);
    }

    #[test]
    fn sub_two_mles() {
        let a = MLE::from_evaluations_vec(2, vec![fr(10), fr(20), fr(30), fr(40)]);
        let b = MLE::from_evaluations_vec(2, vec![fr(1), fr(2), fr(3), fr(4)]);
        let c = &a - &b;
        assert_eq!(c.evaluations(), vec![fr(9), fr(18), fr(27), fr(36)]);
    }

    #[test]
    fn mul_by_scalar_zero_gives_zero() {
        let a = MLE::from_evaluations_vec(2, vec![fr(1), fr(2), fr(3), fr(4)]);
        let z = &a * &Fr::zero();
        assert!(z.evaluations().iter().all(|v| v.is_zero()));
    }

    #[test]
    fn mul_by_scalar_one_is_identity() {
        let a = MLE::from_evaluations_vec(2, vec![fr(1), fr(2), fr(3), fr(4)]);
        let b = &a * &Fr::one();
        assert_eq!(a.evaluations(), b.evaluations());
    }

    #[test]
    fn mul_by_scalar_arbitrary() {
        let a = MLE::from_evaluations_vec(2, vec![fr(1), fr(2), fr(3), fr(4)]);
        let b = &a * &fr(5);
        assert_eq!(b.evaluations(), vec![fr(5), fr(10), fr(15), fr(20)]);
    }

    #[test]
    fn neg_mle() {
        let a = MLE::from_evaluations_vec(1, vec![fr(3), fr(7)]);
        let neg_a = a.clone().neg();
        let sum = &a + &neg_a;
        assert!(sum.evaluations().iter().all(|v| v.is_zero()));
    }

    // ── fix_variables ────────────────────────────────────────────────

    #[test]
    fn fix_variables_matches_materialized_path_while_repetition_remains_virtual() {
        let wrapped = MLE::new(
            DenseMultilinearExtension::from_evaluations_vec(2, vec![fr(1), fr(2), fr(3), fr(4)]),
            Some(3),
        );
        let point = vec![fr(17)];

        let optimized = wrapped.fix_variables(&point);
        let materialized = MLE::from_evaluations_vec(wrapped.num_vars(), wrapped.evaluations())
            .fix_variables(&point);

        assert_eq!(optimized.num_vars(), materialized.num_vars());
        assert_eq!(optimized.evaluations(), materialized.evaluations());
        assert_eq!(optimized.num_vars(), 2);
        assert_eq!(optimized.nv, Some(2));
    }

    #[test]
    fn fix_variables_matches_materialized_path_after_crossing_repeat_boundary() {
        let wrapped = MLE::new(
            DenseMultilinearExtension::from_evaluations_vec(2, vec![fr(1), fr(2), fr(3), fr(4)]),
            Some(4),
        );
        let point = vec![fr(5), fr(6), fr(7)];

        let optimized = wrapped.fix_variables(&point);
        let materialized = MLE::from_evaluations_vec(wrapped.num_vars(), wrapped.evaluations())
            .fix_variables(&point);

        assert_eq!(optimized.num_vars(), materialized.num_vars());
        assert_eq!(optimized.evaluations(), materialized.evaluations());
        assert_eq!(optimized.num_vars(), 1);
        assert_eq!(optimized.nv, Some(1));
    }

    #[test]
    fn fix_variables_matches_materialized_path_after_inner_mle_is_fully_fixed() {
        let wrapped = MLE::new(
            DenseMultilinearExtension::from_evaluations_vec(2, vec![fr(9), fr(10), fr(11), fr(12)]),
            Some(5),
        );
        let point = vec![fr(3), fr(4), fr(5), fr(6)];

        let optimized = wrapped.fix_variables(&point);
        let materialized = MLE::from_evaluations_vec(wrapped.num_vars(), wrapped.evaluations())
            .fix_variables(&point);

        assert_eq!(optimized.num_vars(), materialized.num_vars());
        assert_eq!(optimized.evaluations(), materialized.evaluations());
        assert_eq!(optimized.num_vars(), 1);
        assert_eq!(optimized.nv, Some(1));
    }

    // ── Small-scalar storage ────────────────────────────────────────

    #[test]
    fn from_bits_matches_field_evaluations() {
        // 8 bits: 1 0 1 1 0 1 0 0 -> byte 0b0010_1101 = 0x2d
        let compressed = MLE::<Fr>::from_bits(
            [true, false, true, true, false, true, false, false].into_iter(),
            3,
        );
        let field: MLE<Fr> = MLE::from_evaluations_vec(
            3,
            vec![
                Fr::one(),
                Fr::zero(),
                Fr::one(),
                Fr::one(),
                Fr::zero(),
                Fr::one(),
                Fr::zero(),
                Fr::zero(),
            ],
        );
        assert_eq!(compressed.num_vars(), 3);
        assert_eq!(compressed.inner_num_vars(), 3);
        assert_eq!(compressed.evaluations(), field.evaluations());
    }

    #[test]
    fn from_prefix_activator_matches_manual_prefix() {
        // active_len = 5, num_vars = 3 → bits: 1 1 1 1 1 0 0 0
        let compressed = MLE::<Fr>::from_prefix_activator(5, 3);
        let mut evals = vec![Fr::zero(); 8];
        for slot in evals.iter_mut().take(5) {
            *slot = Fr::one();
        }
        let field: MLE<Fr> = MLE::from_evaluations_vec(3, evals);
        assert_eq!(compressed.evaluations(), field.evaluations());
    }

    #[test]
    fn from_u8s_matches_field_evaluations() {
        let bytes = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let compressed = MLE::<Fr>::from_u8s(bytes.clone(), 3);
        let field: MLE<Fr> =
            MLE::from_evaluations_vec(3, bytes.iter().map(|&b| Fr::from(b as u64)).collect());
        assert_eq!(compressed.evaluations(), field.evaluations());
    }

    #[test]
    fn from_u32s_matches_field_evaluations() {
        let words = vec![0u32, 100, 1_000_000, 4_294_967_295];
        let compressed = MLE::<Fr>::from_u32s(words.clone(), 2);
        let field: MLE<Fr> =
            MLE::from_evaluations_vec(2, words.iter().map(|&v| Fr::from(v as u64)).collect());
        assert_eq!(compressed.evaluations(), field.evaluations());
    }

    #[test]
    fn from_u64s_matches_field_evaluations() {
        let words = vec![0u64, 100, 1_000_000, u64::MAX];
        let compressed = MLE::<Fr>::from_u64s(words.clone(), 2);
        let field: MLE<Fr> =
            MLE::from_evaluations_vec(2, words.iter().map(|&v| Fr::from(v)).collect());
        assert_eq!(compressed.evaluations(), field.evaluations());
    }

    #[test]
    fn compressed_fix_variables_matches_field() {
        let bytes = vec![10u8, 20, 30, 40, 50, 60, 70, 80];
        let compressed = MLE::<Fr>::from_u8s(bytes.clone(), 3);
        let field: MLE<Fr> =
            MLE::from_evaluations_vec(3, bytes.iter().map(|&b| Fr::from(b as u64)).collect());
        let point = vec![fr(3), fr(5)];
        assert_eq!(
            compressed.fix_variables(&point).evaluations(),
            field.fix_variables(&point).evaluations()
        );
    }

    #[test]
    fn compressed_heap_bytes_much_smaller_than_field() {
        // 2^12 = 4096 elements.
        let n = 12;
        let bit_backing = MLE::<Fr>::from_bits((0..(1usize << n)).map(|i| i % 3 == 0), n);
        let byte_backing =
            MLE::<Fr>::from_u8s((0..(1usize << n)).map(|i| (i & 0xff) as u8).collect(), n);
        let field_backing = MLE::<Fr>::from_evaluations_vec(
            n,
            (0..(1usize << n)).map(|i| Fr::from(i as u64)).collect(),
        );

        let bit_bytes = bit_backing.storage().heap_bytes();
        let byte_bytes = byte_backing.storage().heap_bytes();
        let field_bytes = field_backing.storage().heap_bytes();
        // 4096 bits = 512 bytes; 4096 * 32 bytes = 131072 bytes → 256× ratio.
        assert_eq!(bit_bytes, 512);
        // 4096 bytes.
        assert_eq!(byte_bytes, 4096);
        // 4096 * 32 = 131072.
        assert_eq!(field_bytes, 131072);
        assert!(bit_bytes * 200 < field_bytes);
        assert!(byte_bytes * 20 < field_bytes);
    }
}
