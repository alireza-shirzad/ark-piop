use ark_ff::{Field, Zero};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Valid, Validate};
use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_iter, rand::Rng};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::{
    borrow::Cow,
    cmp::Ordering,
    fmt::{self, Formatter},
    ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign},
    slice::IterMut,
    sync::Arc,
};

/// The evaluation-table backing for an [`MLE`]. `Field` holds every hypercube
/// point as a full `F`; the compressed variants keep natively-typed data at
/// its natural width until field-form evaluations are actually needed.
///
/// Contract: the value at inner index `i` (into the hypercube of size
/// `1 << inner_num_vars`) lifts to `F` via [`Self::lift`]; `MLE`'s virtual
/// padding first resolves the inner index as `index % (1 << inner_num_vars)`.
///
/// `Bit` packing is little-endian per byte: bit `i` lives at
/// `bits[i / 8] >> (i % 8) & 1`, and `bits.len() == inner_len().div_ceil(8)`.
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
    /// Every inner slot equals `value`: `1 << inner_num_vars` logical entries
    /// in one `F` plus one `usize` of storage. `lift(i)` is O(1).
    Constant {
        value: F,
        inner_num_vars: usize,
    },
    /// Run-length encoded storage: `(value, count)` runs. Invariants
    /// (enforced by [`Self::new_rle`]): `runs` non-empty and at most
    /// [`Self::RLE_MAX_RUNS`] long, `Σ counts == 1 << inner_num_vars`, no two
    /// adjacent runs share a `value`. `lift(i)` linearly scans the runs.
    Rle {
        runs: Vec<(F, u32)>,
        inner_num_vars: usize,
    },
    /// Sparse storage: a `default` value plus index → value overrides, for
    /// exception sets too scattered for [`Self::Rle`]. Invariants (enforced
    /// by [`Self::new_sparse`]): `exceptions` sorted strictly ascending by
    /// index, every index `< 1 << inner_num_vars`, every value `!= default`.
    /// `lift(i)` is O(log |exceptions|) via binary search.
    Sparse {
        default: F,
        exceptions: Vec<(u32, F)>,
        inner_num_vars: usize,
    },
    /// Native-typed sparse analog of [`Self::Sparse`] for `u8`-shaped
    /// columns; identical invariants, ~7× cheaper per exception.
    SparseU8 {
        default: u8,
        exceptions: Vec<(u32, u8)>,
        inner_num_vars: usize,
    },
    /// Native-typed sparse analog of [`Self::Sparse`] for `u32`-shaped columns.
    SparseU32 {
        default: u32,
        exceptions: Vec<(u32, u32)>,
        inner_num_vars: usize,
    },
    /// Native-typed sparse analog of [`Self::Sparse`] for `u64`-shaped columns.
    SparseU64 {
        default: u64,
        exceptions: Vec<(u32, u64)>,
        inner_num_vars: usize,
    },
    /// Packed unsigned-decimal storage (Arrow `Decimal128` columns): each
    /// row's 128-bit magnitude split across parallel `high`/`low` u64 vectors
    /// (16 B/row vs 32 B as `Field`). `scale` is carried for decoders but NOT
    /// baked into the polynomial value or the commitment.
    ///
    /// Invariants: `high.len() == low.len() == 1 << inner_num_vars`.
    /// `lift(i)` rebuilds `((high[i] as u128) << 64) | low[i]` and lifts via
    /// the same `Field`-generic path the eager encoder used, so results are
    /// bit-identical. Unsigned only: signed decimals must be sign-peeked at
    /// ingest and fall back to the eager `Field` path.
    PackedDecimal {
        high: Vec<u64>,
        low: Vec<u64>,
        scale: u8,
        inner_num_vars: usize,
    },
    /// Lazy inverse-shifted: `1/(source(x) - shift)` at every point, in O(1)
    /// storage. Used for `keyed_sumcheck`'s `phat = 1/(p - γ)` after commit;
    /// sumcheck streams non-`Field` storage via `storage().lift(i)`.
    ///
    /// Contract: `lift(i) = (source.lift(i) - shift).inverse().unwrap_or(0)`.
    /// Callers must ensure `source(x) - shift != 0` where they read — `shift`
    /// is a post-commit transcript challenge, so the zero fallback is only a
    /// safety net over a measure-zero exceptional set.
    LazyInverseShifted {
        source: Arc<MLE<F>>,
        shift: F,
        inner_num_vars: usize,
    },
    /// Lazy `1/(s1(x) - shift) + 1/(s2(x) - shift)`; same rationale as
    /// [`Self::LazyInverseShifted`], for the paired keyed-sumcheck path.
    LazyInverseShiftedSum {
        s1: Arc<MLE<F>>,
        s2: Arc<MLE<F>>,
        shift: F,
        inner_num_vars: usize,
    },
}

impl<F: Field> MLEStorage<F> {
    /// Maximum run count for an `Rle` variant; above this the column is dense
    /// enough that RLE no longer beats native small-int storage and detection
    /// keeps the original form.
    pub const RLE_MAX_RUNS: usize = 256;

    /// Construct an `Rle` variant, enforcing the invariants. Merges
    /// consecutive runs sharing a value; returns `None` if `runs` is empty,
    /// if the counts don't sum to `1 << inner_num_vars`, or if after
    /// merging the run count exceeds [`Self::RLE_MAX_RUNS`].
    pub fn new_rle(runs: Vec<(F, u32)>, inner_num_vars: usize) -> Option<Self> {
        if runs.is_empty() {
            return None;
        }
        // Merge adjacent same-value runs to keep the "shortest RLE" invariant.
        let mut merged: Vec<(F, u32)> = Vec::with_capacity(runs.len());
        for (v, c) in runs {
            if c == 0 {
                continue;
            }
            match merged.last_mut() {
                Some((prev_v, prev_c)) if *prev_v == v => {
                    *prev_c = prev_c.checked_add(c)?;
                }
                _ => merged.push((v, c)),
            }
        }
        if merged.is_empty() || merged.len() > Self::RLE_MAX_RUNS {
            return None;
        }
        let expected: u64 = 1u64 << inner_num_vars;
        let actual: u64 = merged.iter().map(|(_, c)| *c as u64).sum();
        if actual != expected {
            return None;
        }
        Some(Self::Rle {
            runs: merged,
            inner_num_vars,
        })
    }

    /// Construct a `Sparse` variant, enforcing the invariants. Sorts
    /// `exceptions` by index (stable) and drops entries whose value equals
    /// `default`; returns `None` if any index is out of range or any two
    /// entries share the same index.
    pub fn new_sparse(
        default: F,
        mut exceptions: Vec<(u32, F)>,
        inner_num_vars: usize,
    ) -> Option<Self> {
        let inner_len = 1u64 << inner_num_vars;
        exceptions.retain(|(_, v)| *v != default);
        // Stable sort so duplicate indices surface below instead of being
        // resolved arbitrarily.
        exceptions.sort_by_key(|(idx, _)| *idx);
        for w in exceptions.windows(2) {
            if w[0].0 == w[1].0 {
                return None; // duplicate index
            }
        }
        if let Some((last_idx, _)) = exceptions.last() {
            if (*last_idx as u64) >= inner_len {
                return None; // out-of-range index
            }
        }
        Some(Self::Sparse {
            default,
            exceptions,
            inner_num_vars,
        })
    }

    /// `SparseU8` counterpart of [`Self::new_sparse`]; same normalization
    /// and rejection rules on native-typed data.
    pub fn new_sparse_u8(
        default: u8,
        mut exceptions: Vec<(u32, u8)>,
        inner_num_vars: usize,
    ) -> Option<Self> {
        let inner_len = 1u64 << inner_num_vars;
        exceptions.retain(|(_, v)| *v != default);
        exceptions.sort_by_key(|(idx, _)| *idx);
        for w in exceptions.windows(2) {
            if w[0].0 == w[1].0 {
                return None;
            }
        }
        if let Some((last_idx, _)) = exceptions.last() {
            if (*last_idx as u64) >= inner_len {
                return None;
            }
        }
        Some(Self::SparseU8 {
            default,
            exceptions,
            inner_num_vars,
        })
    }

    /// Construct a `SparseU32` variant. See [`Self::new_sparse_u8`].
    pub fn new_sparse_u32(
        default: u32,
        mut exceptions: Vec<(u32, u32)>,
        inner_num_vars: usize,
    ) -> Option<Self> {
        let inner_len = 1u64 << inner_num_vars;
        exceptions.retain(|(_, v)| *v != default);
        exceptions.sort_by_key(|(idx, _)| *idx);
        for w in exceptions.windows(2) {
            if w[0].0 == w[1].0 {
                return None;
            }
        }
        if let Some((last_idx, _)) = exceptions.last() {
            if (*last_idx as u64) >= inner_len {
                return None;
            }
        }
        Some(Self::SparseU32 {
            default,
            exceptions,
            inner_num_vars,
        })
    }

    /// Construct a `SparseU64` variant. See [`Self::new_sparse_u8`].
    pub fn new_sparse_u64(
        default: u64,
        mut exceptions: Vec<(u32, u64)>,
        inner_num_vars: usize,
    ) -> Option<Self> {
        let inner_len = 1u64 << inner_num_vars;
        exceptions.retain(|(_, v)| *v != default);
        exceptions.sort_by_key(|(idx, _)| *idx);
        for w in exceptions.windows(2) {
            if w[0].0 == w[1].0 {
                return None;
            }
        }
        if let Some((last_idx, _)) = exceptions.last() {
            if (*last_idx as u64) >= inner_len {
                return None;
            }
        }
        Some(Self::SparseU64 {
            default,
            exceptions,
            inner_num_vars,
        })
    }

    /// Construct a `PackedDecimal` variant, enforcing the length invariants.
    /// Returns `None` if `high.len() != low.len()` or if the length doesn't
    /// match `1 << inner_num_vars`.
    pub fn new_packed_decimal(
        high: Vec<u64>,
        low: Vec<u64>,
        scale: u8,
        inner_num_vars: usize,
    ) -> Option<Self> {
        if high.len() != low.len() {
            return None;
        }
        if high.len() != (1usize << inner_num_vars) {
            return None;
        }
        Some(Self::PackedDecimal {
            high,
            low,
            scale,
            inner_num_vars,
        })
    }
}

impl<F: Field> Default for MLEStorage<F> {
    fn default() -> Self {
        Self::Field(DenseMultilinearExtension::default())
    }
}

// Hand-written canonical (de)serialization: 1-byte discriminant tag followed
// by the variant payload; inner_num_vars stored as `u64` for platform
// independence (arkworks derives only support structs).
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
            Self::Constant {
                value,
                inner_num_vars,
            } => {
                5u8.serialize_with_mode(&mut writer, compress)?;
                value.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::Rle {
                runs,
                inner_num_vars,
            } => {
                6u8.serialize_with_mode(&mut writer, compress)?;
                // Two parallel vectors: reuses arkworks' `Vec` impl without
                // wrapping `(F, u32)` in a derive-able struct.
                let values: Vec<F> = runs.iter().map(|(v, _)| *v).collect();
                let counts: Vec<u32> = runs.iter().map(|(_, c)| *c).collect();
                values.serialize_with_mode(&mut writer, compress)?;
                counts.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::Sparse {
                default,
                exceptions,
                inner_num_vars,
            } => {
                7u8.serialize_with_mode(&mut writer, compress)?;
                default.serialize_with_mode(&mut writer, compress)?;
                let indices: Vec<u32> = exceptions.iter().map(|(i, _)| *i).collect();
                let values: Vec<F> = exceptions.iter().map(|(_, v)| *v).collect();
                indices.serialize_with_mode(&mut writer, compress)?;
                values.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::SparseU8 {
                default,
                exceptions,
                inner_num_vars,
            } => {
                8u8.serialize_with_mode(&mut writer, compress)?;
                default.serialize_with_mode(&mut writer, compress)?;
                let indices: Vec<u32> = exceptions.iter().map(|(i, _)| *i).collect();
                let values: Vec<u8> = exceptions.iter().map(|(_, v)| *v).collect();
                indices.serialize_with_mode(&mut writer, compress)?;
                values.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::SparseU32 {
                default,
                exceptions,
                inner_num_vars,
            } => {
                9u8.serialize_with_mode(&mut writer, compress)?;
                default.serialize_with_mode(&mut writer, compress)?;
                let indices: Vec<u32> = exceptions.iter().map(|(i, _)| *i).collect();
                let values: Vec<u32> = exceptions.iter().map(|(_, v)| *v).collect();
                indices.serialize_with_mode(&mut writer, compress)?;
                values.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::SparseU64 {
                default,
                exceptions,
                inner_num_vars,
            } => {
                10u8.serialize_with_mode(&mut writer, compress)?;
                default.serialize_with_mode(&mut writer, compress)?;
                let indices: Vec<u32> = exceptions.iter().map(|(i, _)| *i).collect();
                let values: Vec<u64> = exceptions.iter().map(|(_, v)| *v).collect();
                indices.serialize_with_mode(&mut writer, compress)?;
                values.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            Self::PackedDecimal {
                high,
                low,
                scale,
                inner_num_vars,
            } => {
                11u8.serialize_with_mode(&mut writer, compress)?;
                high.serialize_with_mode(&mut writer, compress)?;
                low.serialize_with_mode(&mut writer, compress)?;
                scale.serialize_with_mode(&mut writer, compress)?;
                (*inner_num_vars as u64).serialize_with_mode(&mut writer, compress)?;
            }
            // Lazy variants are internal-only and NEVER part of a serialized
            // artifact (proofs carry the phat commitment, not the MLE);
            // reaching this arm indicates a lazy poly leaked to a boundary.
            Self::LazyInverseShifted { .. } | Self::LazyInverseShiftedSum { .. } => {
                return Err(ark_serialize::SerializationError::NotEnoughSpace);
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
            Self::Constant {
                value,
                inner_num_vars,
            } => {
                value.serialized_size(compress) + (*inner_num_vars as u64).serialized_size(compress)
            }
            Self::Rle {
                runs,
                inner_num_vars,
            } => {
                let values: Vec<F> = runs.iter().map(|(v, _)| *v).collect();
                let counts: Vec<u32> = runs.iter().map(|(_, c)| *c).collect();
                values.serialized_size(compress)
                    + counts.serialized_size(compress)
                    + (*inner_num_vars as u64).serialized_size(compress)
            }
            Self::Sparse {
                default,
                exceptions,
                inner_num_vars,
            } => {
                let indices: Vec<u32> = exceptions.iter().map(|(i, _)| *i).collect();
                let values: Vec<F> = exceptions.iter().map(|(_, v)| *v).collect();
                default.serialized_size(compress)
                    + indices.serialized_size(compress)
                    + values.serialized_size(compress)
                    + (*inner_num_vars as u64).serialized_size(compress)
            }
            Self::SparseU8 {
                default,
                exceptions,
                inner_num_vars,
            } => {
                let indices: Vec<u32> = exceptions.iter().map(|(i, _)| *i).collect();
                let values: Vec<u8> = exceptions.iter().map(|(_, v)| *v).collect();
                default.serialized_size(compress)
                    + indices.serialized_size(compress)
                    + values.serialized_size(compress)
                    + (*inner_num_vars as u64).serialized_size(compress)
            }
            Self::SparseU32 {
                default,
                exceptions,
                inner_num_vars,
            } => {
                let indices: Vec<u32> = exceptions.iter().map(|(i, _)| *i).collect();
                let values: Vec<u32> = exceptions.iter().map(|(_, v)| *v).collect();
                default.serialized_size(compress)
                    + indices.serialized_size(compress)
                    + values.serialized_size(compress)
                    + (*inner_num_vars as u64).serialized_size(compress)
            }
            Self::SparseU64 {
                default,
                exceptions,
                inner_num_vars,
            } => {
                let indices: Vec<u32> = exceptions.iter().map(|(i, _)| *i).collect();
                let values: Vec<u64> = exceptions.iter().map(|(_, v)| *v).collect();
                default.serialized_size(compress)
                    + indices.serialized_size(compress)
                    + values.serialized_size(compress)
                    + (*inner_num_vars as u64).serialized_size(compress)
            }
            Self::PackedDecimal {
                high,
                low,
                scale,
                inner_num_vars,
            } => {
                high.serialized_size(compress)
                    + low.serialized_size(compress)
                    + scale.serialized_size(compress)
                    + (*inner_num_vars as u64).serialized_size(compress)
            }
            // Lazy variants are non-serializable; report 0 so size estimates
            // don't over-allocate (serialize itself errors before writing).
            Self::LazyInverseShifted { .. } | Self::LazyInverseShiftedSum { .. } => 0,
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
            Self::Constant { value, .. } => value.check(),
            Self::Rle { runs, .. } => {
                for (v, _) in runs {
                    v.check()?;
                }
                Ok(())
            }
            Self::Sparse {
                default,
                exceptions,
                ..
            } => {
                default.check()?;
                for (_, v) in exceptions {
                    v.check()?;
                }
                Ok(())
            }
            Self::SparseU8 { .. } | Self::SparseU32 { .. } | Self::SparseU64 { .. } => Ok(()),
            // Re-verify the length invariant so deserialized values that
            // violate it fail loudly.
            Self::PackedDecimal { high, low, .. } => {
                if high.len() != low.len() {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                Ok(())
            }
            // Lazy variants: sources validate themselves via their own `check`.
            Self::LazyInverseShifted { source, shift, .. } => {
                source.storage().check()?;
                shift.check()
            }
            Self::LazyInverseShiftedSum { s1, s2, shift, .. } => {
                s1.storage().check()?;
                s2.storage().check()?;
                shift.check()
            }
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
            5 => {
                let value = F::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                Ok(Self::Constant {
                    value,
                    inner_num_vars: n,
                })
            }
            6 => {
                let values = Vec::<F>::deserialize_with_mode(&mut reader, compress, validate)?;
                let counts = Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                if values.len() != counts.len() {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                let runs: Vec<(F, u32)> = values.into_iter().zip(counts).collect();
                Ok(Self::Rle {
                    runs,
                    inner_num_vars: n,
                })
            }
            7 => {
                let default = F::deserialize_with_mode(&mut reader, compress, validate)?;
                let indices =
                    Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
                let values = Vec::<F>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                if indices.len() != values.len() {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                let exceptions: Vec<(u32, F)> = indices.into_iter().zip(values).collect();
                Ok(Self::Sparse {
                    default,
                    exceptions,
                    inner_num_vars: n,
                })
            }
            8 => {
                let default = u8::deserialize_with_mode(&mut reader, compress, validate)?;
                let indices =
                    Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
                let values = Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                if indices.len() != values.len() {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                let exceptions: Vec<(u32, u8)> = indices.into_iter().zip(values).collect();
                Ok(Self::SparseU8 {
                    default,
                    exceptions,
                    inner_num_vars: n,
                })
            }
            9 => {
                let default = u32::deserialize_with_mode(&mut reader, compress, validate)?;
                let indices =
                    Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
                let values = Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                if indices.len() != values.len() {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                let exceptions: Vec<(u32, u32)> = indices.into_iter().zip(values).collect();
                Ok(Self::SparseU32 {
                    default,
                    exceptions,
                    inner_num_vars: n,
                })
            }
            10 => {
                let default = u64::deserialize_with_mode(&mut reader, compress, validate)?;
                let indices =
                    Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
                let values = Vec::<u64>::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                if indices.len() != values.len() {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                let exceptions: Vec<(u32, u64)> = indices.into_iter().zip(values).collect();
                Ok(Self::SparseU64 {
                    default,
                    exceptions,
                    inner_num_vars: n,
                })
            }
            11 => {
                let high = Vec::<u64>::deserialize_with_mode(&mut reader, compress, validate)?;
                let low = Vec::<u64>::deserialize_with_mode(&mut reader, compress, validate)?;
                let scale = u8::deserialize_with_mode(&mut reader, compress, validate)?;
                let n = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
                if high.len() != low.len() {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                Ok(Self::PackedDecimal {
                    high,
                    low,
                    scale,
                    inner_num_vars: n,
                })
            }
            _ => Err(ark_serialize::SerializationError::InvalidData),
        }
    }
}

impl<F: Field> MLEStorage<F> {
    /// Short label for this storage variant, used in tracker snapshots, logs,
    /// and the bench dashboard. Treat as a wire format: renaming a label is a
    /// dashboard-breaking change that needs coordinated migration.
    #[inline]
    pub const fn kind_tag(&self) -> &'static str {
        match self {
            Self::Field(_) => "field",
            Self::Bit { .. } => "bit",
            Self::U8 { .. } => "u8",
            Self::U32 { .. } => "u32",
            Self::U64 { .. } => "u64",
            Self::Constant { .. } => "const",
            Self::Rle { .. } => "rle",
            Self::Sparse { .. } => "sparse",
            Self::SparseU8 { .. } => "sparseU8",
            Self::SparseU32 { .. } => "sparseU32",
            Self::SparseU64 { .. } => "sparseU64",
            Self::PackedDecimal { .. } => "dec128",
            Self::LazyInverseShifted { .. } => "lazy_inv",
            Self::LazyInverseShiftedSum { .. } => "lazy_inv_sum",
        }
    }

    /// The `num_vars` of the *inner* (unpadded) hypercube.
    #[inline]
    pub fn inner_num_vars(&self) -> usize {
        match self {
            Self::Field(m) => m.num_vars,
            Self::Bit { inner_num_vars, .. }
            | Self::U8 { inner_num_vars, .. }
            | Self::U32 { inner_num_vars, .. }
            | Self::U64 { inner_num_vars, .. }
            | Self::Constant { inner_num_vars, .. }
            | Self::Rle { inner_num_vars, .. }
            | Self::Sparse { inner_num_vars, .. }
            | Self::SparseU8 { inner_num_vars, .. }
            | Self::SparseU32 { inner_num_vars, .. }
            | Self::SparseU64 { inner_num_vars, .. }
            | Self::PackedDecimal { inner_num_vars, .. }
            | Self::LazyInverseShifted { inner_num_vars, .. }
            | Self::LazyInverseShiftedSum { inner_num_vars, .. } => *inner_num_vars,
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
            Self::Constant { value, .. } => *value,
            Self::Rle { runs, .. } => {
                // Linear scan is fastest for ≤ 256 runs (branch-predictable,
                // no prefix-sum table allocation).
                let mut cursor: usize = 0;
                for (val, count) in runs {
                    let end = cursor + *count as usize;
                    if i < end {
                        return *val;
                    }
                    cursor = end;
                }
                // Unreachable when invariants hold (`Σ counts == inner_len`).
                panic!(
                    "Rle::lift out of range: i={} inner_len={}",
                    i,
                    1usize << self.inner_num_vars()
                );
            }
            Self::Sparse {
                default,
                exceptions,
                ..
            } => {
                let idx_u32 = i as u32;
                match exceptions.binary_search_by_key(&idx_u32, |(k, _)| *k) {
                    Ok(pos) => exceptions[pos].1,
                    Err(_) => *default,
                }
            }
            Self::SparseU8 {
                default,
                exceptions,
                ..
            } => {
                let idx_u32 = i as u32;
                let byte = match exceptions.binary_search_by_key(&idx_u32, |(k, _)| *k) {
                    Ok(pos) => exceptions[pos].1,
                    Err(_) => *default,
                };
                F::from(byte as u64)
            }
            Self::SparseU32 {
                default,
                exceptions,
                ..
            } => {
                let idx_u32 = i as u32;
                let word = match exceptions.binary_search_by_key(&idx_u32, |(k, _)| *k) {
                    Ok(pos) => exceptions[pos].1,
                    Err(_) => *default,
                };
                F::from(word as u64)
            }
            Self::SparseU64 {
                default,
                exceptions,
                ..
            } => {
                let idx_u32 = i as u32;
                let word = match exceptions.binary_search_by_key(&idx_u32, |(k, _)| *k) {
                    Ok(pos) => exceptions[pos].1,
                    Err(_) => *default,
                };
                F::from(word)
            }
            // Reassemble the 128-bit magnitude and lift via `F::from(u128)`:
            // same field element as the eager `from_le_bytes_mod_order` path
            // (the encoder rejects negatives at ingest).
            Self::PackedDecimal { high, low, .. } => {
                let value: u128 = ((high[i] as u128) << 64) | (low[i] as u128);
                F::from(value)
            }
            // Lazy inverse, computed on demand. The zero fallback is safety
            // only: `shift` is a post-commit transcript challenge, so a
            // non-invertible value is a soundness event best signalled by a
            // downstream check, not a crash. `i` is cycled modulo the
            // source's inner_len so reads stay consistent with virtual
            // padding after the outer nv is bumped.
            Self::LazyInverseShifted { source, shift, .. } => {
                let src_storage = source.storage();
                let idx = i % src_storage.inner_len();
                let v = src_storage.lift(idx) - *shift;
                v.inverse().unwrap_or_else(F::zero)
            }
            // Same shape, two inversions, same modulo-cycling per source.
            Self::LazyInverseShiftedSum { s1, s2, shift, .. } => {
                let s1_storage = s1.storage();
                let s2_storage = s2.storage();
                let idx1 = i % s1_storage.inner_len();
                let idx2 = i % s2_storage.inner_len();
                let v1 = (s1_storage.lift(idx1) - *shift).inverse().unwrap_or_else(F::zero);
                let v2 = (s2_storage.lift(idx2) - *shift).inverse().unwrap_or_else(F::zero);
                v1 + v2
            }
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
            Self::Constant { .. } => std::mem::size_of::<F>() as u64,
            // Lazy variants report only what the backing itself adds; the
            // source MLE's heap is accounted at its own tracker entry.
            Self::LazyInverseShifted { .. } => {
                (std::mem::size_of::<Arc<MLE<F>>>() as u64)
                    + (std::mem::size_of::<F>() as u64)
                    + (std::mem::size_of::<usize>() as u64)
            }
            Self::LazyInverseShiftedSum { .. } => {
                2 * (std::mem::size_of::<Arc<MLE<F>>>() as u64)
                    + (std::mem::size_of::<F>() as u64)
                    + (std::mem::size_of::<usize>() as u64)
            }
            Self::Rle { runs, .. } => {
                (runs.len() as u64) * ((std::mem::size_of::<F>() as u64) + 4)
            }
            Self::Sparse {
                exceptions, ..
            } => {
                // one F for default + (u32 index + F value) per exception.
                (std::mem::size_of::<F>() as u64)
                    + (exceptions.len() as u64) * (4 + std::mem::size_of::<F>() as u64)
            }
            Self::SparseU8 { exceptions, .. } => 1 + (exceptions.len() as u64) * (4 + 1),
            Self::SparseU32 { exceptions, .. } => 4 + (exceptions.len() as u64) * (4 + 4),
            Self::SparseU64 { exceptions, .. } => 8 + (exceptions.len() as u64) * (4 + 8),
            Self::PackedDecimal { high, low, .. } => {
                (high.len() as u64) * 8 + (low.len() as u64) * 8 + 1
            }
        }
    }

    /// True if this storage is the `Field` variant.
    #[inline]
    pub fn is_field(&self) -> bool {
        matches!(self, Self::Field(_))
    }

    /// Scan the storage for structural redundancy via one O(inner_len) walk
    /// and return the most compact equivalent variant: 0 value transitions →
    /// [`Self::Constant`], up to [`Self::RLE_MAX_RUNS`] runs → [`Self::Rle`],
    /// scattered exceptions → a sparse variant; otherwise `self` unchanged.
    /// Never rewrites variants that are already compact.
    pub fn detect_redundancy(self) -> Self
    where
        F: ark_ff::PrimeField,
    {
        // Already-compact and lazy variants short-circuit: lazy backings are
        // O(1) heap, and a run scan would pay the O(2^inner_nv) lift pass
        // lazy storage exists to avoid.
        if matches!(
            self,
            Self::Constant { .. }
                | Self::Rle { .. }
                | Self::Sparse { .. }
                | Self::SparseU8 { .. }
                | Self::SparseU32 { .. }
                | Self::SparseU64 { .. }
                // PackedDecimal is already tight at 16 B/row.
                | Self::PackedDecimal { .. }
                | Self::LazyInverseShifted { .. }
                | Self::LazyInverseShiftedSum { .. }
        ) {
            return self;
        }
        let inner_len = self.inner_len();
        if inner_len == 0 {
            return self;
        }
        let inner_nv = self.inner_num_vars();
        // Count runs of Copy+Eq scalars; `Some(runs)` when ≤ RLE_MAX_RUNS,
        // `None` to keep dense storage. Comparing in the native scalar type
        // matters a LOT: lifting each element through `F::from` (~100 ns
        // Montgomery conversion on BN254) once caused a ~50% wall-clock
        // regression; this pays one integer eq per element, `F::from` per RUN.
        fn scan_runs_native<S, F>(
            slice: &[S],
            lift: impl Fn(S) -> F,
            max_runs: usize,
        ) -> Option<Vec<(F, u32)>>
        where
            S: Copy + Eq,
        {
            if slice.is_empty() {
                return None;
            }
            let mut prev = slice[0];
            let mut run_count: usize = 1;
            for &v in &slice[1..] {
                if v != prev {
                    run_count += 1;
                    if run_count > max_runs {
                        return None;
                    }
                    prev = v;
                }
            }
            if run_count == 1 {
                return Some(vec![(lift(slice[0]), slice.len() as u32)]);
            }
            let mut runs: Vec<(F, u32)> = Vec::with_capacity(run_count);
            let mut cursor: usize = 0;
            let mut cur = slice[0];
            for (i, &v) in slice.iter().enumerate().skip(1) {
                if v != cur {
                    runs.push((lift(cur), (i - cursor) as u32));
                    cursor = i;
                    cur = v;
                }
            }
            runs.push((lift(cur), (slice.len() - cursor) as u32));
            Some(runs)
        }
        // Bit unpacks its 1-bit elements on the fly; same RLE_MAX_RUNS bail.
        fn scan_bits<F: Field>(
            bits: &[u8],
            len: usize,
            max_runs: usize,
        ) -> Option<Vec<(F, u32)>> {
            if len == 0 {
                return None;
            }
            let get = |i: usize| -> bool { (bits[i >> 3] >> (i & 7)) & 1 == 1 };
            let mut prev = get(0);
            let mut run_count: usize = 1;
            for i in 1..len {
                let v = get(i);
                if v != prev {
                    run_count += 1;
                    if run_count > max_runs {
                        return None;
                    }
                    prev = v;
                }
            }
            let bool_to_f = |b: bool| if b { F::one() } else { F::zero() };
            if run_count == 1 {
                return Some(vec![(bool_to_f(get(0)), len as u32)]);
            }
            let mut runs: Vec<(F, u32)> = Vec::with_capacity(run_count);
            let mut cursor: usize = 0;
            let mut cur = get(0);
            for i in 1..len {
                let v = get(i);
                if v != cur {
                    runs.push((bool_to_f(cur), (i - cursor) as u32));
                    cursor = i;
                    cur = v;
                }
            }
            runs.push((bool_to_f(cur), (len - cursor) as u32));
            Some(runs)
        }
        let max_runs = Self::RLE_MAX_RUNS;
        let runs = match &self {
            Self::Field(m) => scan_runs_native(&m.evaluations, |x: F| x, max_runs),
            Self::Bit { bits, .. } => scan_bits::<F>(bits, inner_len, max_runs),
            Self::U8 { bytes, .. } => {
                scan_runs_native(bytes.as_slice(), |x: u8| F::from(x as u64), max_runs)
            }
            Self::U32 { words, .. } => {
                scan_runs_native(words.as_slice(), |x: u32| F::from(x as u64), max_runs)
            }
            Self::U64 { words, .. } => {
                scan_runs_native(words.as_slice(), |x: u64| F::from(x), max_runs)
            }
            // Compact and lazy variants short-circuited above.
            Self::Constant { .. }
            | Self::Rle { .. }
            | Self::Sparse { .. }
            | Self::SparseU8 { .. }
            | Self::SparseU32 { .. }
            | Self::SparseU64 { .. }
            | Self::PackedDecimal { .. }
            | Self::LazyInverseShifted { .. }
            | Self::LazyInverseShiftedSum { .. } => return self,
        };
        let Some(runs) = runs else {
            // RLE bailed (too many runs): try sparse detection with slot 0 as
            // the mode candidate. Emit only if ≥ 2× smaller than the current
            // dense form, using the matching native-typed sparse variant for
            // native-typed input (F-valued `Sparse` for Field / Bit).
            fn scan_sparse_native<S: Copy + Eq>(
                slice: &[S],
                max_exceptions: usize,
            ) -> Option<(S, Vec<(u32, S)>)> {
                if slice.is_empty() {
                    return None;
                }
                let default = slice[0];
                let mut exceptions: Vec<(u32, S)> = Vec::new();
                for (i, &v) in slice.iter().enumerate() {
                    if v != default {
                        if exceptions.len() >= max_exceptions {
                            return None;
                        }
                        exceptions.push((i as u32, v));
                    }
                }
                Some((default, exceptions))
            }
            let current_bytes = self.heap_bytes();
            let out = match &self {
                Self::Field(m) => {
                    let f_bytes = std::mem::size_of::<F>() as u64;
                    let entry = 4u64 + f_bytes;
                    let max_ex =
                        (current_bytes.saturating_sub(f_bytes) / (2 * entry)) as usize;
                    if max_ex == 0 {
                        return self;
                    }
                    scan_sparse_native(&m.evaluations, max_ex).and_then(|(d, ex)| {
                        Self::new_sparse(d, ex, inner_nv)
                    })
                }
                Self::Bit { bits, .. } => {
                    // Two distinct values with RLE bailed = alternating
                    // pattern; pick the rarer bit value as the exceptions.
                    let f_bytes = std::mem::size_of::<F>() as u64;
                    let entry = 4u64 + f_bytes;
                    let max_ex =
                        (current_bytes.saturating_sub(f_bytes) / (2 * entry)) as usize;
                    if max_ex == 0 {
                        return self;
                    }
                    let mut set_count = 0usize;
                    for i in 0..inner_len {
                        if (bits[i >> 3] >> (i & 7)) & 1 == 1 {
                            set_count += 1;
                        }
                    }
                    let clear_count = inner_len - set_count;
                    let (default, ex_val, ex_count) = if set_count <= clear_count {
                        (F::zero(), F::one(), set_count)
                    } else {
                        (F::one(), F::zero(), clear_count)
                    };
                    if ex_count > max_ex {
                        return self;
                    }
                    let mut exceptions: Vec<(u32, F)> = Vec::with_capacity(ex_count);
                    for i in 0..inner_len {
                        let bit_set = (bits[i >> 3] >> (i & 7)) & 1 == 1;
                        let is_exception = if default.is_zero() { bit_set } else { !bit_set };
                        if is_exception {
                            exceptions.push((i as u32, ex_val));
                        }
                    }
                    Self::new_sparse(default, exceptions, inner_nv)
                }
                Self::U8 { bytes, .. } => {
                    let entry = 4u64 + 1u64;
                    let max_ex = (current_bytes.saturating_sub(1) / (2 * entry)) as usize;
                    if max_ex == 0 {
                        return self;
                    }
                    scan_sparse_native(bytes.as_slice(), max_ex)
                        .and_then(|(d, ex)| Self::new_sparse_u8(d, ex, inner_nv))
                }
                Self::U32 { words, .. } => {
                    let entry = 4u64 + 4u64;
                    let max_ex = (current_bytes.saturating_sub(4) / (2 * entry)) as usize;
                    if max_ex == 0 {
                        return self;
                    }
                    scan_sparse_native(words.as_slice(), max_ex)
                        .and_then(|(d, ex)| Self::new_sparse_u32(d, ex, inner_nv))
                }
                Self::U64 { words, .. } => {
                    let entry = 4u64 + 8u64;
                    let max_ex = (current_bytes.saturating_sub(8) / (2 * entry)) as usize;
                    if max_ex == 0 {
                        return self;
                    }
                    scan_sparse_native(words.as_slice(), max_ex)
                        .and_then(|(d, ex)| Self::new_sparse_u64(d, ex, inner_nv))
                }
                // Compact variants short-circuited above.
                _ => None,
            };
            return out.unwrap_or(self);
        };
        // Single-run → Constant (cheaper storage, O(1) lift).
        if runs.len() == 1 {
            return Self::Constant {
                value: runs.into_iter().next().unwrap().0,
                inner_num_vars: inner_nv,
            };
        }
        Self::new_rle(runs, inner_nv).unwrap_or(self)
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

/// A multilinear extension with (a) an optional virtual `nv`: when set, the
/// hypercube has size `2^nv` and the inner evaluation vector is (virtually)
/// repeated cyclically to fit — more variables without more memory; and (b) an
/// [`MLEStorage`] backing that keeps small-scalar data compressed until
/// field-form evaluations are needed. Supports everything
/// `DenseMultilinearExtension` supports.
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

    /// Wrap `source` in a lazy `1/(source - shift)` backing (O(1) heap),
    /// for the keyed-sumcheck post-commit re-registration flow. Mirrors
    /// `source`'s outer `num_vars` including virtual padding — required so
    /// downstream sumcheck term-nv comparisons match a dense phat — and
    /// cycles `lift(i)` modulo the source's inner_len, like the source does.
    pub fn from_lazy_inverse_shifted(source: Arc<MLE<F>>, shift: F) -> Self {
        let inner_num_vars = source.inner_num_vars();
        let outer_num_vars = source.num_vars();
        Self {
            storage: MLEStorage::LazyInverseShifted {
                source,
                shift,
                inner_num_vars,
            },
            nv: (outer_num_vars > inner_num_vars).then_some(outer_num_vars),
        }
    }

    /// Lazy `1/(s1 - shift) + 1/(s2 - shift)` for the paired keyed-sumcheck
    /// path. Both sources must share `num_vars()` (debug-asserted). See
    /// [`Self::from_lazy_inverse_shifted`].
    pub fn from_lazy_inverse_shifted_sum(s1: Arc<MLE<F>>, s2: Arc<MLE<F>>, shift: F) -> Self {
        let inner_num_vars = s1.inner_num_vars();
        let outer_num_vars = s1.num_vars();
        debug_assert_eq!(
            outer_num_vars,
            s2.num_vars(),
            "lazy_inv_sum: source MLEs must share num_vars"
        );
        Self {
            storage: MLEStorage::LazyInverseShiftedSum {
                s1,
                s2,
                shift,
                inner_num_vars,
            },
            nv: (outer_num_vars > inner_num_vars).then_some(outer_num_vars),
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
        // Bit packs at byte (8-slot) granularity, so a `num_vars < 3` target
        // can't be `Bit` without inflating inner_num_vars to 3 and breaking
        // the `num_vars() == num_vars` contract; fall back to Field (≤ 8
        // elements, negligible).
        if num_vars < 3 {
            let len = 1usize << num_vars;
            let evals: Vec<F> = (0..len)
                .map(|i| {
                    let byte = bits.get(i >> 3).copied().unwrap_or(0);
                    if (byte >> (i & 7)) & 1 == 1 {
                        F::one()
                    } else {
                        F::zero()
                    }
                })
                .collect();
            return Self::from_evaluations_vec(num_vars, evals);
        }
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

    /// Build a bit-packed `MLE` from an iterator of booleans, which must
    /// yield exactly `1 << num_vars` items (checked).
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

    /// Build a `Sparse`-storage `MLE` directly from a `(default, exceptions)`
    /// pair, via [`MLEStorage::new_sparse`] (sorts, drops default-equal
    /// entries). Returns `None` on out-of-range or duplicate indices.
    pub fn from_sparse(
        default: F,
        exceptions: Vec<(u32, F)>,
        num_vars: usize,
    ) -> Option<Self>
    where
        F: ark_ff::PrimeField,
    {
        Some(Self {
            storage: MLEStorage::new_sparse(default, exceptions, num_vars)?,
            nv: None,
        })
    }

    /// Native-typed sparse constructor for `u8`-shaped columns. See
    /// [`Self::from_sparse`].
    pub fn from_sparse_u8(
        default: u8,
        exceptions: Vec<(u32, u8)>,
        num_vars: usize,
    ) -> Option<Self>
    where
        F: ark_ff::PrimeField,
    {
        Some(Self {
            storage: MLEStorage::new_sparse_u8(default, exceptions, num_vars)?,
            nv: None,
        })
    }

    /// Native-typed sparse constructor for `u32`-shaped columns.
    pub fn from_sparse_u32(
        default: u32,
        exceptions: Vec<(u32, u32)>,
        num_vars: usize,
    ) -> Option<Self>
    where
        F: ark_ff::PrimeField,
    {
        Some(Self {
            storage: MLEStorage::new_sparse_u32(default, exceptions, num_vars)?,
            nv: None,
        })
    }

    /// Native-typed sparse constructor for `u64`-shaped columns.
    pub fn from_sparse_u64(
        default: u64,
        exceptions: Vec<(u32, u64)>,
        num_vars: usize,
    ) -> Option<Self>
    where
        F: ark_ff::PrimeField,
    {
        Some(Self {
            storage: MLEStorage::new_sparse_u64(default, exceptions, num_vars)?,
            nv: None,
        })
    }

    /// Prefix activator: first `active_len` slots are `1`, the rest `0`.
    /// Built directly as a compact form — O(1) storage, no bit vector.
    pub fn from_prefix_activator(active_len: usize, num_vars: usize) -> Self {
        Self::from_window_activator(0, active_len, num_vars)
    }

    /// Window activator: `skip` zeros, `active_len` ones, then zeros up to
    /// `1 << num_vars`. Stored as [`MLEStorage::Constant`] or a 2/3-run
    /// [`MLEStorage::Rle`] — O(1) memory regardless of `num_vars`. Panics if
    /// the window exceeds the domain.
    pub fn from_window_activator(skip: usize, active_len: usize, num_vars: usize) -> Self {
        let len = 1usize << num_vars;
        // RLE run counts are u32; guard so segment lengths can't silently
        // truncate on a future large-nv misuse.
        assert!(
            len <= u32::MAX as usize,
            "from_window_activator: 2^num_vars {} exceeds u32::MAX; RLE run counts would truncate",
            len
        );
        let end = skip.checked_add(active_len)
            .expect("from_window_activator: skip + active_len overflows usize");
        assert!(
            end <= len,
            "skip {} + active_len {} > 2^num_vars {}",
            skip, active_len, len
        );
        let storage = if active_len == 0 {
            MLEStorage::Constant {
                value: F::zero(),
                inner_num_vars: num_vars,
            }
        } else if skip == 0 && active_len == len {
            MLEStorage::Constant {
                value: F::one(),
                inner_num_vars: num_vars,
            }
        } else {
            // Compose a 2- or 3-run RLE from the non-empty segments.
            let mut runs: Vec<(F, u32)> = Vec::with_capacity(3);
            if skip > 0 {
                runs.push((F::zero(), skip as u32));
            }
            runs.push((F::one(), active_len as u32));
            let tail = len - end;
            if tail > 0 {
                runs.push((F::zero(), tail as u32));
            }
            MLEStorage::<F>::new_rle(runs, num_vars)
                .expect("window activator runs sum to inner_len by construction")
        };
        Self { storage, nv: None }
    }

    /// Build a `u8`-typed `MLE`. `bytes.len()` must be `<= 1 << num_vars`; a
    /// shorter backing is virtually repeated cyclically to the outer size.
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

    /// Constructor for [`MLEStorage::PackedDecimal`]:
    /// `value[i] = (high[i] << 64) | low[i]`. Panics unless
    /// `high.len() == low.len() <= 2^num_vars` with power-of-two length.
    pub fn from_packed_decimal(
        high: Vec<u64>,
        low: Vec<u64>,
        scale: u8,
        num_vars: usize,
    ) -> Self {
        assert!(
            high.len() == low.len(),
            "packed-decimal backing high/low length mismatch: {} vs {}",
            high.len(),
            low.len()
        );
        assert!(
            high.len() <= (1usize << num_vars),
            "packed-decimal backing len {} > 2^num_vars {}",
            high.len(),
            1usize << num_vars
        );
        let inner_num_vars = high.len().checked_ilog2().unwrap_or_default() as usize;
        Self {
            storage: MLEStorage::PackedDecimal {
                high,
                low,
                scale,
                inner_num_vars,
            },
            nv: (num_vars > inner_num_vars).then_some(num_vars),
        }
    }

    /// Read-only access to the storage backing; prefer this over
    /// [`MLE::mat_mle`] for storage-kind dispatch.
    #[inline]
    pub fn storage(&self) -> &MLEStorage<F> {
        &self.storage
    }

    /// Owned `MLE` with `Field` storage: a clone if already `Field`, else a
    /// materialization. For callers that need `&F` slice access. The at-rest
    /// tracker copy is unaffected — only the returned copy is promoted.
    pub fn to_field_owned(&self) -> Self {
        match &self.storage {
            MLEStorage::Field(_) => self.clone(),
            _ => Self {
                storage: MLEStorage::Field(self.storage.to_field().into_owned()),
                nv: self.nv,
            },
        }
    }

    /// Fold one variable at `p` in place, with zero fresh allocations —
    /// sumcheck's replacement for per-round `fix_variables(&[p])`. Panics on
    /// non-`Field` storage (call [`MLE::to_field_owned`] first).
    ///
    /// Correctness: pass 1 folds disjoint 2-element chunks into their own
    /// `c[0]` (race-free in parallel); pass 2 serially compacts the even-index
    /// fold heads into `[0..len/2]`, safe because read index `2i` is strictly
    /// greater than every previously written index. Folding one *outer*
    /// variable of a virtually padded MLE equals one inner fold plus `nv -= 1`
    /// (`nv` cleared once the outer size no longer exceeds inner storage).
    pub fn fix_one_variable_in_place(&mut self, p: &F) {
        match &mut self.storage {
            MLEStorage::Field(m) => {
                let old_len = m.evaluations.len();
                if old_len > 1 {
                    debug_assert!(old_len.is_power_of_two());
                    let new_len = old_len / 2;
                    let evals = &mut m.evaluations;
                    // Pass 1 (parallel over disjoint pairs): fold into c[0].
                    cfg_chunks_mut!(evals, 2).for_each(|c| {
                        let lo = c[0];
                        let hi = c[1];
                        let diff = hi - lo;
                        c[0] = if diff.is_zero() { lo } else { lo + diff * p };
                    });
                    // Pass 2 (serial): pull even-index fold heads into
                    // `[0..new_len]`; safe because `2·i > i`.
                    for i in 1..new_len {
                        evals[i] = evals[2 * i];
                    }
                    evals.truncate(new_len);
                    m.num_vars = m.num_vars.saturating_sub(1);
                }
            }
            _ => panic!(
                "fix_one_variable_in_place requires Field storage; call \
                 `to_field_owned` first"
            ),
        }
        // Reduce virtual padding to match the outer fold.
        if let Some(nv) = self.nv {
            let new_nv = nv.saturating_sub(1);
            let inner_nv = self.storage.inner_num_vars();
            self.nv = (new_nv > inner_nv).then_some(new_nv);
        }
    }

    /// Classify `evals` into the tightest small-scalar [`MLEStorage`] kind
    /// (bit → u8 → u32 → u64 → Field) via one `into_bigint()` pass, build
    /// that backing, and drop `evals`. Falls back to
    /// [`MLE::from_evaluations_vec`] when nothing smaller fits.
    pub fn from_evaluations_vec_compressed(num_vars: usize, evals: Vec<F>) -> Self
    where
        F: ark_ff::PrimeField,
    {
        // Any element that overflows the current kind bumps to the next
        // looser one (Bit → U8 → U32 → U64 → Field).
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

    /// Rebuild a `Field`-backed MLE holding only small-integer values as the
    /// tightest compressed variant; no-op for non-`Field` storage. Preserves
    /// any outer virtual `nv`.
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

    /// Linear-scan run/sparse detection on top of [`Self::compressed`].
    /// Separated so hot paths can pay for just the cheap classifier; chain
    /// `.compressed().detect_redundancy()` at long-lived-storage boundaries.
    pub fn detect_redundancy(self) -> Self
    where
        F: ark_ff::PrimeField,
    {
        let nv = self.nv;
        let storage = self.storage.detect_redundancy();
        Self { storage, nv }
    }

    /// Update the virtual `nv` in place without touching the backing, so
    /// compressed polys can be promoted to a larger nv without materializing.
    /// `target_nv` must be `>= inner_num_vars()` (asserted); equality clears
    /// `nv`.
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

    /// View as a `DenseMultilinearExtension`, materializing compressed
    /// backings on demand (owned `Cow` — keep it short-lived). Prefer
    /// [`MLE::storage`]; kept for callers that unwrap to the arkworks type.
    pub fn mat_mle(&self) -> Cow<'_, DenseMultilinearExtension<F>> {
        self.storage.to_field()
    }

    pub fn num_vars(&self) -> usize {
        match self.nv {
            Some(nv) => nv,
            None => self.storage.inner_num_vars(),
        }
    }

    /// The un-padded (inner) `num_vars` of the backing evaluation table.
    #[inline]
    pub fn inner_num_vars(&self) -> usize {
        self.storage.inner_num_vars()
    }

    /// Mutable access to the inner `DenseMultilinearExtension`. Panics if the
    /// storage is not `Field` or if `nv` is set.
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
    /// `nv` is set or the storage is compressed.
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
        // Compact variants answer in O(1). Lazy variants conservatively
        // return false: checking would cost the O(2^n) inversions lazy
        // storage exists to avoid, and a wrong `false` only skips an
        // optimisation — never a soundness error.
        match &self.storage {
            MLEStorage::Constant { .. } => return true,
            MLEStorage::Rle { runs, .. } => return runs.len() == 1,
            MLEStorage::LazyInverseShifted { .. } | MLEStorage::LazyInverseShiftedSum { .. } => {
                return false;
            }
            _ => {}
        }
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
        // The first fold materializes to `Vec<F>`; fold outputs are always
        // `F`-valued, so later folds stay in Field-only code.
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
        // NOTE: legacy accessor; only `Field` storage can hand out `&F`
        // (materialize-on-demand has no owned `F` to reference). Hot sumcheck
        // callers are `Field`-backed because the first fold promotes to
        // Field; compressed variants must use `iter()` / `storage().lift(i)`.
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
        // Arithmetic goes through the Field representation; compressed inputs
        // pay a transient materialization here.
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
        // Negated small scalars don't fit their variants; go through Field.
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
        // Debug prints via the materialized Field view (pre-refactor format).
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
        // `fix_variables` promotes to Field, so `[0]` is safe.
        self.fix_variables(point)[0]
    }
}

/// Add variables at the back: (P(X, Y), 3) → P'(X, Y, Z) = P(X, Y).
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

    // ── fix_one_variable_in_place ───────────────────────────────────

    #[test]
    fn fix_one_variable_in_place_matches_fix_variables_single_step() {
        // Small enough to hit every branch. Verify equivalence for a range of
        // sizes, both `nv = None` and `nv = Some(_)`.
        for nv_inner in 1usize..=4 {
            let n = 1usize << nv_inner;
            let evals: Vec<Fr> = (0..n).map(|i| fr(i as u64 * 7 + 3)).collect();
            for &outer_nv in &[None, Some(nv_inner + 1), Some(nv_inner + 2)] {
                let fresh_source = match outer_nv {
                    Some(outer) => MLE::new(
                        DenseMultilinearExtension::from_evaluations_vec(nv_inner, evals.clone()),
                        Some(outer),
                    ),
                    None => MLE::from_evaluations_vec(nv_inner, evals.clone()),
                };
                let baseline = fresh_source.fix_variables(&[fr(11)]);
                let mut fresh = fresh_source;
                fresh.fix_one_variable_in_place(&fr(11));
                assert_eq!(fresh.num_vars(), baseline.num_vars(), "nv_inner={nv_inner} outer={outer_nv:?}");
                assert_eq!(fresh.evaluations(), baseline.evaluations(), "nv_inner={nv_inner} outer={outer_nv:?}");
                assert_eq!(fresh.nv, baseline.nv, "nv_inner={nv_inner} outer={outer_nv:?}");
            }
        }
    }

    #[test]
    fn fix_one_variable_in_place_matches_after_repeated_folds() {
        // Fold the same MLE 4 times in a row via in-place; compare to the
        // batched `fix_variables(&[r1, r2, r3, r4])`. This exercises the
        // Vec::truncate-then-cfg_chunks_mut path across many rounds — the
        // exact shape sumcheck's round loop generates.
        let evals: Vec<Fr> = (0..16u64).map(|i| fr(i * 3 + 1)).collect();
        let points = vec![fr(2), fr(5), fr(11), fr(17)];
        let baseline = MLE::from_evaluations_vec(4, evals.clone()).fix_variables(&points);

        let mut folded = MLE::from_evaluations_vec(4, evals);
        for r in &points {
            folded.fix_one_variable_in_place(r);
        }
        assert_eq!(folded.num_vars(), baseline.num_vars());
        assert_eq!(folded.evaluations(), baseline.evaluations());
    }

    #[test]
    fn fix_one_variable_in_place_matches_when_virtually_padded() {
        // Virtual padding: inner nv=2 but outer nv=4. Sumcheck should fold the
        // outer variable, which we implement as inner fold + nv--.
        let mut wrapped = MLE::new(
            DenseMultilinearExtension::from_evaluations_vec(2, vec![fr(1), fr(2), fr(3), fr(4)]),
            Some(4),
        );
        let baseline = wrapped.fix_variables(&[fr(9)]);
        wrapped.fix_one_variable_in_place(&fr(9));
        assert_eq!(wrapped.num_vars(), baseline.num_vars());
        assert_eq!(wrapped.evaluations(), baseline.evaluations());
        assert_eq!(wrapped.nv, baseline.nv);
    }

    #[test]
    fn fix_one_variable_in_place_on_single_evaluation_is_a_noop_on_inner() {
        // inner_num_vars == 0 (single element): only nv should be decremented,
        // the evaluation itself is unchanged (a constant absorbs any r).
        let mut wrapped = MLE::new(
            DenseMultilinearExtension::from_evaluations_vec(0, vec![fr(42)]),
            Some(3),
        );
        wrapped.fix_one_variable_in_place(&fr(999));
        assert_eq!(wrapped.evaluations(), vec![fr(42); 4]);
        assert_eq!(wrapped.nv, Some(2));
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

    // ── Constant / Rle redundancy compression ──────────────────────────

    #[test]
    fn constant_variant_lifts_uniformly() {
        let inner_nv = 8;
        let s: MLEStorage<Fr> = MLEStorage::Constant {
            value: fr(42),
            inner_num_vars: inner_nv,
        };
        assert_eq!(s.inner_num_vars(), inner_nv);
        assert_eq!(s.inner_len(), 1 << inner_nv);
        for i in 0..s.inner_len() {
            assert_eq!(s.lift(i), fr(42));
        }
        // heap_bytes counts only the F payload (32 for BN254 Fr).
        assert_eq!(s.heap_bytes(), std::mem::size_of::<Fr>() as u64);
    }

    #[test]
    fn rle_variant_lifts_by_run_boundaries() {
        // 8 slots: [7, 7, 7, 0, 0, 5, 5, 5] → 3 runs
        let runs = vec![(fr(7), 3u32), (fr(0), 2u32), (fr(5), 3u32)];
        let s = MLEStorage::<Fr>::new_rle(runs, 3).expect("valid Rle");
        let expected = vec![
            fr(7), fr(7), fr(7),
            fr(0), fr(0),
            fr(5), fr(5), fr(5),
        ];
        for (i, want) in expected.into_iter().enumerate() {
            assert_eq!(s.lift(i), want, "at index {i}");
        }
    }

    #[test]
    fn rle_constructor_merges_adjacent_same_value_runs() {
        // Input has three runs that are actually all the same value; must merge.
        let runs = vec![(fr(1), 3u32), (fr(1), 2u32), (fr(1), 3u32)];
        let s = MLEStorage::<Fr>::new_rle(runs, 3).expect("valid Rle");
        match &s {
            MLEStorage::Rle { runs, .. } => {
                assert_eq!(runs.len(), 1, "adjacent same-value runs should collapse");
                assert_eq!(runs[0].1, 8);
            }
            _ => panic!("expected Rle variant"),
        }
    }

    #[test]
    fn rle_constructor_rejects_wrong_total() {
        // Counts sum to 7 but inner_num_vars=3 → expects 8.
        let runs = vec![(fr(1), 4u32), (fr(0), 3u32)];
        assert!(MLEStorage::<Fr>::new_rle(runs, 3).is_none());
    }

    #[test]
    fn detect_redundancy_finds_constant_from_bit_storage() {
        // 128 zeros packed as Bit → detected as Constant(0).
        let storage = MLEStorage::<Fr>::Bit {
            bits: vec![0u8; 16],
            inner_num_vars: 7,
        };
        let out = storage.detect_redundancy();
        match &out {
            MLEStorage::Constant { value, inner_num_vars } => {
                assert!(value.is_zero());
                assert_eq!(*inner_num_vars, 7);
            }
            _ => panic!("expected Constant"),
        }
    }

    #[test]
    fn detect_redundancy_finds_the_127_zeros_1_one_pattern() {
        // The user's motivating example: 127 zeros, 1 one → 2-run Rle.
        let mut bits = vec![0u8; 16];
        bits[15] = 0b1000_0000; // bit 127
        let storage = MLEStorage::<Fr>::Bit {
            bits,
            inner_num_vars: 7,
        };
        let out = storage.detect_redundancy();
        match &out {
            MLEStorage::Rle { runs, inner_num_vars } => {
                assert_eq!(*inner_num_vars, 7);
                assert_eq!(runs.len(), 2);
                assert_eq!(runs[0], (Fr::zero(), 127));
                assert_eq!(runs[1], (Fr::one(), 1));
            }
            _ => panic!("expected 2-run Rle"),
        }
    }

    #[test]
    fn detect_redundancy_bails_when_too_many_runs() {
        // Alternating 0/1 → inner_len runs → way above RLE_MAX_RUNS. Stays as Bit.
        let inner_nv = 10; // 1024 bits, 1024 alternating runs
        let mut bits = vec![0u8; 1024 / 8];
        for i in (1..1024).step_by(2) {
            bits[i >> 3] |= 1u8 << (i & 7);
        }
        let storage = MLEStorage::<Fr>::Bit {
            bits: bits.clone(),
            inner_num_vars: inner_nv,
        };
        let out = storage.detect_redundancy();
        assert!(matches!(out, MLEStorage::Bit { .. }), "expected Bit fallback");
    }

    #[test]
    fn detect_redundancy_is_noop_on_constant_and_rle() {
        let c: MLEStorage<Fr> = MLEStorage::Constant { value: fr(3), inner_num_vars: 4 };
        assert!(matches!(c.clone().detect_redundancy(), MLEStorage::Constant { .. }));
        let r = MLEStorage::<Fr>::new_rle(vec![(fr(1), 4), (fr(0), 12)], 4).unwrap();
        assert!(matches!(r.clone().detect_redundancy(), MLEStorage::Rle { .. }));
    }

    #[test]
    fn compressed_then_detect_redundancy_collapses_all_zeros() {
        // `.compressed()` alone lands us at Bit (native-int classifier);
        // `.detect_redundancy()` then collapses to Constant. The two are
        // separate so hot registration paths can pay for just the classifier.
        let field_zeros = MLE::<Fr>::from_evaluations_vec(4, vec![Fr::zero(); 16]);
        let out = field_zeros.compressed().detect_redundancy();
        assert!(matches!(out.storage(), MLEStorage::Constant { value, .. } if value.is_zero()));
    }

    #[test]
    fn mle_is_constant_short_circuits_on_constant_variant() {
        let mle = MLE::<Fr> {
            storage: MLEStorage::Constant { value: fr(99), inner_num_vars: 20 },
            nv: None,
        };
        // Should be O(1) — we don't verify timing but we do verify correctness
        // on a large `inner_num_vars` that would otherwise be an expensive scan.
        assert!(mle.is_constant());
    }

    #[test]
    fn constant_and_rle_serialize_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

        for storage in [
            MLEStorage::<Fr>::Constant { value: fr(7), inner_num_vars: 5 },
            MLEStorage::<Fr>::new_rle(vec![(fr(1), 4), (fr(0), 12)], 4).unwrap(),
        ] {
            let mut buf: Vec<u8> = Vec::new();
            storage.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
            let round: MLEStorage<Fr> =
                MLEStorage::deserialize_with_mode(&buf[..], Compress::Yes, Validate::Yes).unwrap();
            assert!(round == storage, "roundtrip mismatch");
        }
    }

    // ── from_prefix_activator emits compact forms directly ─────────────

    // ── from_bit_backing: preserves caller-declared num_vars ───────────

    /// Regression: for `num_vars < 3` (targets smaller than one byte),
    /// the resulting MLE must report `num_vars == the caller-declared value`,
    /// not `log2(bits.len() * 8) = 3`. This was the source of the
    /// `row-domain segment num_vars 3 != table log_vars 2` failure in the
    /// arithmetization pass at TPC-H nation test scale (4-row tables).
    #[test]
    fn from_bit_backing_small_num_vars_reports_correct_num_vars() {
        for nv in 0..=2 {
            let byte_len = (1usize << nv).div_ceil(8).max(1);
            let bits = vec![0u8; byte_len];
            let mle = MLE::<Fr>::from_bit_backing(bits, nv);
            assert_eq!(
                mle.num_vars(),
                nv,
                "from_bit_backing(_, {}) must report num_vars=={}", nv, nv
            );
        }
    }

    /// Same, but with non-zero bits — verifies the fallback Field-storage
    /// path preserves values, not just num_vars.
    #[test]
    fn from_bit_backing_small_num_vars_preserves_values() {
        // nv=2, 4 slots: bits [1, 0, 1, 1] → byte 0b0000_1101 = 13
        let mle = MLE::<Fr>::from_bit_backing(vec![0b0000_1101], 2);
        assert_eq!(mle.num_vars(), 2);
        let evals: Vec<Fr> = mle.evaluations();
        assert_eq!(
            evals,
            vec![Fr::one(), Fr::zero(), Fr::one(), Fr::one()],
            "small-nv bit backing must preserve bit values in the Field fallback"
        );
    }

    /// The `num_vars >= 3` path (one or more full bytes) still uses Bit
    /// storage — the small-nv fallback only kicks in below the byte
    /// granularity boundary.
    #[test]
    fn from_bit_backing_medium_num_vars_uses_bit_storage() {
        // nv=3, 8 slots, one byte: still Bit storage.
        let mle = MLE::<Fr>::from_bit_backing(vec![0b0000_1101], 3);
        assert_eq!(mle.num_vars(), 3);
        assert!(
            matches!(mle.storage(), MLEStorage::Bit { .. }),
            "num_vars >= 3 should retain the compact Bit storage variant"
        );
    }

    #[test]
    fn from_prefix_activator_zero_active_len_is_constant_zero() {
        let mle = MLE::<Fr>::from_prefix_activator(0, 6);
        match mle.storage() {
            MLEStorage::Constant { value, inner_num_vars } => {
                assert!(value.is_zero());
                assert_eq!(*inner_num_vars, 6);
            }
            _ => panic!("expected Constant(0)"),
        }
    }

    #[test]
    fn from_prefix_activator_full_active_len_is_constant_one() {
        let n = 5;
        let mle = MLE::<Fr>::from_prefix_activator(1 << n, n);
        match mle.storage() {
            MLEStorage::Constant { value, inner_num_vars } => {
                assert!(value.is_one());
                assert_eq!(*inner_num_vars, n);
            }
            _ => panic!("expected Constant(1)"),
        }
    }

    #[test]
    fn from_prefix_activator_partial_active_len_is_two_run_rle() {
        // 5 active out of 8 → Rle [(1, 5), (0, 3)].
        let mle = MLE::<Fr>::from_prefix_activator(5, 3);
        match mle.storage() {
            MLEStorage::Rle { runs, inner_num_vars } => {
                assert_eq!(*inner_num_vars, 3);
                assert_eq!(runs.len(), 2);
                assert_eq!(runs[0], (Fr::one(), 5));
                assert_eq!(runs[1], (Fr::zero(), 3));
            }
            _ => panic!("expected 2-run Rle"),
        }
        // Also verify the lifted evaluations match the semantic contract.
        let expected: Vec<Fr> = (0..8).map(|i| if i < 5 { Fr::one() } else { Fr::zero() }).collect();
        assert_eq!(mle.evaluations(), expected);
    }

    #[test]
    fn from_prefix_activator_heap_bytes_dwarfs_prior_bit_backing() {
        // A large-nv prefix activator: the compact form is ~72 bytes vs the
        // prior packed-bit backing which would have been 2^(nv-3) bytes.
        let nv = 24;
        let active_len = 1_000_000;
        let mle = MLE::<Fr>::from_prefix_activator(active_len, nv);
        let bytes = mle.storage().heap_bytes();
        // Rle with 2 runs: 2 × (size_of::<Fr> + 4) = 2 × 36 = 72 bytes on BN254.
        assert!(bytes < 200, "prefix activator storage should be tiny, got {bytes} bytes");
        // A packed-bit alternative would be (1 << 24) / 8 = 2 MiB.
        assert!(bytes * 20_000 < (1u64 << nv) / 8);
    }

    // ── from_window_activator: [0 x skip, 1 x active, 0 x tail] ─────────

    #[test]
    fn from_window_activator_zero_active_is_constant_zero() {
        let mle = MLE::<Fr>::from_window_activator(3, 0, 6);
        match mle.storage() {
            MLEStorage::Constant { value, inner_num_vars } => {
                assert!(value.is_zero());
                assert_eq!(*inner_num_vars, 6);
            }
            _ => panic!("expected Constant(0)"),
        }
    }

    #[test]
    fn from_window_activator_full_active_is_constant_one() {
        let n = 5;
        let mle = MLE::<Fr>::from_window_activator(0, 1 << n, n);
        match mle.storage() {
            MLEStorage::Constant { value, inner_num_vars } => {
                assert!(value.is_one());
                assert_eq!(*inner_num_vars, n);
            }
            _ => panic!("expected Constant(1)"),
        }
    }

    #[test]
    fn from_window_activator_prefix_shape_is_two_run_rle() {
        // skip=0, active=5 in an 8-slot domain → 2-run [(1, 5), (0, 3)].
        let mle = MLE::<Fr>::from_window_activator(0, 5, 3);
        match mle.storage() {
            MLEStorage::Rle { runs, inner_num_vars } => {
                assert_eq!(*inner_num_vars, 3);
                assert_eq!(runs.len(), 2);
                assert_eq!(runs[0], (Fr::one(), 5));
                assert_eq!(runs[1], (Fr::zero(), 3));
            }
            _ => panic!("expected 2-run Rle"),
        }
    }

    #[test]
    fn from_window_activator_suffix_shape_is_two_run_rle() {
        // skip=3, active=5 in an 8-slot domain (window reaches end) →
        // 2-run [(0, 3), (1, 5)].
        let mle = MLE::<Fr>::from_window_activator(3, 5, 3);
        match mle.storage() {
            MLEStorage::Rle { runs, inner_num_vars } => {
                assert_eq!(*inner_num_vars, 3);
                assert_eq!(runs.len(), 2);
                assert_eq!(runs[0], (Fr::zero(), 3));
                assert_eq!(runs[1], (Fr::one(), 5));
            }
            _ => panic!("expected 2-run Rle"),
        }
    }

    #[test]
    fn from_window_activator_middle_is_three_run_rle() {
        // skip=2, active=3 in an 8-slot domain → 3-run
        // [(0, 2), (1, 3), (0, 3)].
        let mle = MLE::<Fr>::from_window_activator(2, 3, 3);
        match mle.storage() {
            MLEStorage::Rle { runs, inner_num_vars } => {
                assert_eq!(*inner_num_vars, 3);
                assert_eq!(runs.len(), 3);
                assert_eq!(runs[0], (Fr::zero(), 2));
                assert_eq!(runs[1], (Fr::one(), 3));
                assert_eq!(runs[2], (Fr::zero(), 3));
            }
            _ => panic!("expected 3-run Rle"),
        }
        // Semantic contract: the lifted evaluations exactly match the window.
        let expected: Vec<Fr> = (0..8)
            .map(|i| if i >= 2 && i < 5 { Fr::one() } else { Fr::zero() })
            .collect();
        assert_eq!(mle.evaluations(), expected);
    }

    #[test]
    fn from_window_activator_large_nv_stays_tiny() {
        // Char-domain-scale window: nv=24 (16.7M slots), a 1M-slot active
        // window in the middle. Storage must remain O(runs) — a full
        // Field `Vec<F>` would be 512 MiB on BN254.
        let nv = 24;
        let skip = 100_000;
        let active_len = 1_000_000;
        let mle = MLE::<Fr>::from_window_activator(skip, active_len, nv);
        let bytes = mle.storage().heap_bytes();
        // 3 runs × (size_of::<Fr> + size_of::<u32>) ≈ 3 × 36 = 108 bytes on BN254.
        assert!(bytes < 300, "window activator storage should be tiny, got {bytes} bytes");
    }

    // ── Sparse variant ────────────────────────────────────────────────

    #[test]
    fn sparse_lift_returns_default_and_exception_values() {
        // 8-slot column: default 0, exceptions at indices 2 and 5 with
        // values 42 and 99 respectively.
        let storage = MLEStorage::<Fr>::new_sparse(
            fr(0),
            vec![(2, fr(42)), (5, fr(99))],
            3,
        )
        .unwrap();
        for i in 0..8 {
            let want = match i {
                2 => fr(42),
                5 => fr(99),
                _ => fr(0),
            };
            assert_eq!(storage.lift(i), want, "slot {i}");
        }
    }

    #[test]
    fn sparse_constructor_sorts_and_drops_default_valued_entries() {
        // Callers may hand us an unsorted vector with a redundant entry
        // (value equals default); the constructor should normalize it.
        let storage = MLEStorage::<Fr>::new_sparse(
            fr(0),
            vec![(5, fr(99)), (2, fr(42)), (4, fr(0))], // (4, 0) is a no-op
            3,
        )
        .unwrap();
        if let MLEStorage::Sparse { exceptions, .. } = &storage {
            assert_eq!(*exceptions, vec![(2, fr(42)), (5, fr(99))]);
        } else {
            panic!("expected Sparse variant");
        }
    }

    #[test]
    fn sparse_constructor_rejects_duplicate_indices() {
        let out = MLEStorage::<Fr>::new_sparse(
            fr(0),
            vec![(2, fr(1)), (2, fr(2))],
            3,
        );
        assert!(out.is_none(), "duplicate indices should be rejected");
    }

    #[test]
    fn sparse_constructor_rejects_out_of_range_index() {
        // inner_len = 8, so index 8 is out of range.
        let out = MLEStorage::<Fr>::new_sparse(
            fr(0),
            vec![(8, fr(1))],
            3,
        );
        assert!(out.is_none(), "out-of-range index should be rejected");
    }

    #[test]
    fn sparse_serialize_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

        let storage = MLEStorage::<Fr>::new_sparse(
            fr(7),
            vec![(1, fr(11)), (4, fr(13)), (9, fr(17))],
            4,
        )
        .unwrap();
        let mut buf: Vec<u8> = Vec::new();
        storage.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        let round: MLEStorage<Fr> =
            MLEStorage::deserialize_with_mode(&buf[..], Compress::Yes, Validate::Yes).unwrap();
        assert!(round == storage, "sparse roundtrip mismatch");
    }

    #[test]
    fn sparse_matches_field_evaluations() {
        // Materializing a Sparse MLE must yield the same evals as building
        // the equivalent dense Field MLE from a Vec<F>.
        let nv = 5;
        let inner_len = 1usize << nv;
        let mut dense = vec![fr(3); inner_len];
        dense[7] = fr(100);
        dense[19] = fr(200);
        dense[31] = fr(300);

        let sparse = MLE::<Fr>::from_sparse(
            fr(3),
            vec![(7, fr(100)), (19, fr(200)), (31, fr(300))],
            nv,
        )
        .unwrap();
        assert_eq!(sparse.evaluations(), dense);
    }

    #[test]
    fn detect_redundancy_finds_sparse_from_field_storage() {
        // Field-storage input (values that don't fit in u64 — anything past
        // the u64 range) should collapse to the F-valued `Sparse` variant.
        // Same "scattered with dominant mode" shape as the native-typed
        // variants' tests: ~300 alternating transitions between two values,
        // enough to blow past RLE_MAX_RUNS = 256.
        let nv = 16;
        let inner_len = 1usize << nv;
        // Pick values that force Field storage (past u64 range) so
        // `compressed()` doesn't reclassify to a smaller variant.
        let a: Fr = fr(7);
        let b: Fr = -fr(1); // MODULUS - 1, a 254-bit scalar
        let mut evals = vec![a; inner_len];
        for i in 0usize..300 {
            if !i.is_multiple_of(2) {
                evals[i] = b;
            }
        }
        let dense = MLEStorage::<Fr>::Field(
            DenseMultilinearExtension::from_evaluations_vec(nv, evals),
        );
        let compressed = dense.detect_redundancy();
        match compressed {
            MLEStorage::Sparse { default, exceptions, .. } => {
                assert_eq!(default, a);
                assert!(
                    !exceptions.is_empty() && exceptions.len() < 200,
                    "sparse exceptions in expected range, got {}",
                    exceptions.len()
                );
            }
            _ => panic!("expected Field → Sparse compression for scattered data"),
        }
    }

    #[test]
    fn detect_redundancy_keeps_dense_when_no_dominant_mode() {
        // Genuinely dense: every slot different. Sparse detection should
        // give up (exceptions to mode > threshold) and return self unchanged.
        let nv = 10;
        let inner_len = 1usize << nv;
        let words: Vec<u32> = (0..inner_len as u32).collect();
        let dense = MLEStorage::<Fr>::U32 {
            words,
            inner_num_vars: nv,
        };
        let compressed = dense.detect_redundancy();
        assert!(
            matches!(compressed, MLEStorage::U32 { .. }),
            "genuinely dense storage must stay dense"
        );
    }

    #[test]
    fn sparse_heap_bytes_beats_dense_for_scattered_columns() {
        // 2^20-slot column with 100 exceptions to a default value.
        let nv = 20;
        let sparse = MLE::<Fr>::from_sparse(
            fr(0),
            (0..100).map(|i| (i * 1000, fr(i as u64 + 1))).collect(),
            nv,
        )
        .unwrap();
        let sparse_bytes = sparse.storage().heap_bytes();
        // 32 (default F) + 100 * (4 + 32) = 3632 bytes.
        assert!(sparse_bytes < 4_000, "sparse should be ~3.6 KB, got {sparse_bytes}");
        // A dense Field alternative would be 2^20 * 32 = 32 MiB.
        assert!(sparse_bytes * 8_000 < (1u64 << nv) * 32);
    }

    // ── Native-typed sparse variants (SparseU8 / SparseU32 / SparseU64) ────

    #[test]
    fn sparse_u8_lift_matches_dense_u8_field_evaluations() {
        // 32-slot U8 column: default 7, exceptions at indices 3, 11, 20.
        let nv = 5;
        let inner_len = 1usize << nv;
        let mut dense = vec![7u8; inner_len];
        dense[3] = 100;
        dense[11] = 200;
        dense[20] = 250;
        let mle = MLE::<Fr>::from_sparse_u8(
            7u8,
            vec![(3, 100), (11, 200), (20, 250)],
            nv,
        )
        .unwrap();
        let want: Vec<Fr> = dense.iter().map(|b| fr(*b as u64)).collect();
        assert_eq!(mle.evaluations(), want);
    }

    #[test]
    fn sparse_u32_lift_matches_dense() {
        let nv = 4;
        let inner_len = 1usize << nv;
        let mut dense = vec![42u32; inner_len];
        dense[5] = 1_000_000;
        let mle = MLE::<Fr>::from_sparse_u32(42u32, vec![(5, 1_000_000)], nv).unwrap();
        let want: Vec<Fr> = dense.iter().map(|w| fr(*w as u64)).collect();
        assert_eq!(mle.evaluations(), want);
    }

    #[test]
    fn sparse_u64_lift_matches_dense() {
        let nv = 3;
        let inner_len = 1usize << nv;
        let mut dense = vec![u64::MAX; inner_len];
        dense[0] = 0;
        dense[7] = u64::MAX - 1;
        let mle = MLE::<Fr>::from_sparse_u64(
            u64::MAX,
            vec![(0, 0), (7, u64::MAX - 1)],
            nv,
        )
        .unwrap();
        let want: Vec<Fr> = dense.iter().map(|w| Fr::from(*w)).collect();
        assert_eq!(mle.evaluations(), want);
    }

    #[test]
    fn sparse_u8_serialize_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

        let storage = MLEStorage::<Fr>::new_sparse_u8(
            5u8,
            vec![(1, 100), (3, 200)],
            3,
        )
        .unwrap();
        let mut buf: Vec<u8> = Vec::new();
        storage.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        let round: MLEStorage<Fr> =
            MLEStorage::deserialize_with_mode(&buf[..], Compress::Yes, Validate::Yes).unwrap();
        assert!(round == storage, "sparse_u8 roundtrip mismatch");
    }

    #[test]
    fn packed_decimal_lift_matches_field() {
        // Every u128 value's `PackedDecimal` lift must equal the value the
        // eager `Field` path would have produced from the same u128 via
        // `F::from(u128)`. Both paths run the same `From<u128>` blanket
        // impl on `Field`, so the fields end up bit-identical for
        // unsigned magnitudes.
        let nv = 3;
        let inner_len = 1usize << nv;
        let values: Vec<u128> = (0..inner_len as u128)
            .map(|i| (i.wrapping_mul(0x1234_5678_9ABC_DEF0_u128)).wrapping_add(u64::MAX as u128))
            .collect();
        let high: Vec<u64> = values.iter().map(|v| (*v >> 64) as u64).collect();
        let low: Vec<u64> = values.iter().map(|v| *v as u64).collect();
        let mle = MLE::<Fr>::from_packed_decimal(high, low, 2, nv);
        let want: Vec<Fr> = values.iter().map(|v| Fr::from(*v)).collect();
        assert_eq!(mle.evaluations(), want);
    }

    #[test]
    fn packed_decimal_serialize_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

        let nv = 2;
        let high = vec![0u64, 1, u64::MAX, 0xDEAD_BEEF_u64];
        let low = vec![u64::MAX, 0, 42, 0xCAFE_BABE_u64];
        let storage = MLEStorage::<Fr>::new_packed_decimal(high, low, 2, nv).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        storage.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        let round: MLEStorage<Fr> =
            MLEStorage::deserialize_with_mode(&buf[..], Compress::Yes, Validate::Yes).unwrap();
        assert!(round == storage, "packed_decimal roundtrip mismatch");
    }

    #[test]
    fn packed_decimal_new_rejects_length_mismatch() {
        // Constructor invariant: `high.len() == low.len() == 1 << nv`.
        assert!(MLEStorage::<Fr>::new_packed_decimal(vec![0u64], vec![0u64, 1], 0, 1).is_none());
        assert!(MLEStorage::<Fr>::new_packed_decimal(vec![0u64], vec![0u64], 0, 2).is_none());
    }

    #[test]
    fn sparse_u32_and_u64_serialize_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

        let s32 = MLEStorage::<Fr>::new_sparse_u32(9u32, vec![(2, 4_000_000_000u32)], 3).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        s32.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        let r32: MLEStorage<Fr> =
            MLEStorage::deserialize_with_mode(&buf[..], Compress::Yes, Validate::Yes).unwrap();
        assert!(r32 == s32);

        let s64 = MLEStorage::<Fr>::new_sparse_u64(1u64, vec![(0, u64::MAX)], 2).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        s64.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        let r64: MLEStorage<Fr> =
            MLEStorage::deserialize_with_mode(&buf[..], Compress::Yes, Validate::Yes).unwrap();
        assert!(r64 == s64);
    }

    #[test]
    fn detect_redundancy_emits_native_typed_sparse_for_u8_input() {
        // Same alternating pattern as the F-valued Sparse test, but U8
        // input — we expect SparseU8 out, not Sparse (F).
        let nv = 16;
        let inner_len = 1usize << nv;
        let mut bytes: Vec<u8> = vec![7u8; inner_len];
        for i in 0usize..300 {
            if !i.is_multiple_of(2) {
                bytes[i] = 42;
            }
        }
        let dense = MLEStorage::<Fr>::U8 {
            bytes,
            inner_num_vars: nv,
        };
        let compressed = dense.detect_redundancy();
        match compressed {
            MLEStorage::SparseU8 { default, exceptions, .. } => {
                assert_eq!(default, 7u8);
                assert!(
                    !exceptions.is_empty() && exceptions.len() < 200,
                    "sparse_u8 exceptions in expected range, got {}",
                    exceptions.len()
                );
            }
            other => panic!(
                "expected SparseU8 for U8 input, got variant with inner_num_vars={}",
                other.inner_num_vars()
            ),
        }
    }

    #[test]
    fn detect_redundancy_emits_sparse_u32_for_u32_input() {
        let nv = 16;
        let inner_len = 1usize << nv;
        let mut words: Vec<u32> = vec![7u32; inner_len];
        for i in 0usize..300 {
            if !i.is_multiple_of(2) {
                words[i] = 42;
            }
        }
        let dense = MLEStorage::<Fr>::U32 {
            words,
            inner_num_vars: nv,
        };
        let compressed = dense.detect_redundancy();
        assert!(
            matches!(compressed, MLEStorage::SparseU32 { .. }),
            "U32 input should emit SparseU32"
        );
    }

    #[test]
    fn native_typed_sparse_beats_f_valued_sparse_on_heap_bytes() {
        // For a u8 column with 100 exceptions, SparseU8 stores
        // 1 + 100 * (4 + 1) = 501 bytes, vs F-valued Sparse at
        // 32 + 100 * (4 + 32) = 3632 bytes — 7× tighter.
        let nv = 20;
        let sparse_u8 = MLE::<Fr>::from_sparse_u8(
            0u8,
            (0..100).map(|i| (i * 1000, (i as u8) + 1)).collect(),
            nv,
        )
        .unwrap();
        let sparse_f = MLE::<Fr>::from_sparse(
            fr(0),
            (0..100).map(|i| (i * 1000, fr(i as u64 + 1))).collect(),
            nv,
        )
        .unwrap();
        let u8_bytes = sparse_u8.storage().heap_bytes();
        let f_bytes = sparse_f.storage().heap_bytes();
        assert!(u8_bytes < 600, "SparseU8 should be ~500 B, got {u8_bytes}");
        assert!(
            u8_bytes * 5 < f_bytes,
            "SparseU8 should be ≥5× smaller than Sparse(F): u8={u8_bytes}, f={f_bytes}"
        );
    }
}
