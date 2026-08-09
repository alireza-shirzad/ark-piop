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
    /// Every inner slot equals `value`. `1 << inner_num_vars` logical entries
    /// but only one `F` and one `usize` of storage — the most extreme form of
    /// per-column compression, catching all-zero / all-one / all-X columns
    /// (null columns, unfiltered activators, `SELECT 1 …` outputs).
    ///
    /// `lift(i)` is O(1) and returns `value` for every `i < inner_len`.
    Constant {
        value: F,
        inner_num_vars: usize,
    },
    /// Run-length encoded storage: a sequence of `(value, count)` runs whose
    /// counts sum to exactly `1 << inner_num_vars`. Catches every kind of
    /// column with structural redundancy — the classic "127 zeros then 1
    /// one" activator (2 runs = ~72 B) and every prefix / suffix pattern.
    /// Constructed only when the run count fits under
    /// [`Self::RLE_MAX_RUNS`], so mixed-value columns still fall back to
    /// their dense native form.
    ///
    /// Invariants (enforced by [`Self::new_rle`]):
    /// - `runs` is non-empty
    /// - `Σ counts == 1 << inner_num_vars`
    /// - No two adjacent runs share the same `value` (would violate
    ///   "shortest RLE" and confuse `lift`'s binary search prefix)
    ///
    /// `lift(i)` walks a prefix-sum table computed lazily on the caller
    /// side (or a linear scan for `runs.len() <= 8`); for the ≤ 256-run
    /// threshold used in [`MLE::detect_compression`] a linear scan wins
    /// on branch predictability.
    Rle {
        runs: Vec<(F, u32)>,
        inner_num_vars: usize,
    },
    /// **Sparse** storage: a single `default` value plus a list of index →
    /// value overrides for slots that differ from the default. Beats the
    /// dense native forms whenever `|exceptions|` is small compared to
    /// `2^inner_num_vars`, and beats [`Self::Rle`] whenever the exceptions
    /// are scattered enough to blow past `RLE_MAX_RUNS` runs (a 1M-slot
    /// column with 1000 scattered non-zero entries → 2000 runs → RLE bails,
    /// but Sparse fits it in `32 + 1000 * 36 ≈ 36 KB` vs the 1 MB (U8) or
    /// 4 MB (U32) dense form).
    ///
    /// Invariants (enforced by [`Self::new_sparse`]):
    /// - `exceptions` is sorted by index in strictly ascending order
    /// - Every `exceptions[k].0 < 1 << inner_num_vars`
    /// - Every `exceptions[k].1 != default` (matching-default entries drop
    ///   into the implicit dense region)
    ///
    /// `lift(i)` is O(log |exceptions|) via binary search on the sorted
    /// index vector.
    Sparse {
        default: F,
        exceptions: Vec<(u32, F)>,
        inner_num_vars: usize,
    },
    /// Native-typed sparse analog of [`Self::Sparse`] for `u8`-shaped
    /// columns. `default` + a sorted list of `(index, value)` overrides;
    /// invariants and semantics identical to [`Self::Sparse`], but the
    /// per-exception cost drops from `4 + sizeof(F) ≈ 36 B` (BN254) to
    /// `4 + 1 = 5 B` and the default drops from `sizeof(F)` to 1 B. Emitted
    /// by [`Self::detect_redundancy`] when the input was `U8` storage.
    SparseU8 {
        default: u8,
        exceptions: Vec<(u32, u8)>,
        inner_num_vars: usize,
    },
    /// Native-typed sparse analog of [`Self::Sparse`] for `u32`-shaped
    /// columns. Per-exception cost `4 + 4 = 8 B` vs `36 B` for the F-valued
    /// form.
    SparseU32 {
        default: u32,
        exceptions: Vec<(u32, u32)>,
        inner_num_vars: usize,
    },
    /// Native-typed sparse analog of [`Self::Sparse`] for `u64`-shaped
    /// columns. Per-exception cost `4 + 8 = 12 B` vs `36 B` for the F-valued
    /// form.
    SparseU64 {
        default: u64,
        exceptions: Vec<(u32, u64)>,
        inner_num_vars: usize,
    },
    /// Packed unsigned-decimal storage for TPC-H `Decimal128` columns
    /// (`l_extendedprice`, `l_discount`, `l_tax`, `o_totalprice`, etc.).
    /// Each row's 128-bit magnitude is split across parallel `high`/`low`
    /// `u64` vectors — 16 B per row versus 32 B for the `Field` form on
    /// BN254 / BLS12-381 — and the commit path can reuse the existing
    /// `msm_u64` small-scalar Pippenger twice (one call on `low`, one on
    /// `high` scaled by `2^64`) with no new MSM port.
    ///
    /// `scale` is the fixed-point exponent from the source Arrow
    /// `Decimal128(precision, scale)` metadata; it is carried alongside
    /// the payload so decoders can reconstruct the original decimal, but
    /// is NOT baked into the polynomial value or the commitment — the
    /// commitment is over the raw 128-bit magnitude only.
    ///
    /// Invariants:
    /// - `high.len() == low.len()`
    /// - `high.len() == 1 << inner_num_vars`
    ///
    /// `lift(i)` reassembles the 128-bit magnitude as
    /// `((high[i] as u128) << 64) | (low[i] as u128)` and lifts to `F`
    /// via `F::from_le_bytes_mod_order(&value.to_le_bytes())` — the same
    /// `Field`-generic path the eager encoder used before this variant
    /// existed, so results are bit-identical.
    ///
    /// Only unsigned 128-bit values fit this variant. Signed decimals
    /// (a rare TPC-H case: negative deltas) must be sign-peeked at
    /// ingest and fall back to the eager `Field` path if any row is
    /// negative — see `tt-arithmetic/src/encoding/primitives.rs`.
    PackedDecimal {
        high: Vec<u64>,
        low: Vec<u64>,
        scale: u8,
        inner_num_vars: usize,
    },
    /// Lazy inverse-shifted: represents `1/(source(x) - shift)` at every
    /// hypercube point. Storage cost is one `Arc<MLE<F>>` pointer + one `F`
    /// + one `usize`, regardless of `inner_num_vars` — the whole point
    /// versus materialising a dense `2^inner_num_vars` `Vec<F>`.
    ///
    /// Used specifically for `keyed_sumcheck`'s `phat = 1/(p - γ)` MLEs
    /// after the PCS commitment has been produced. The commitment is what
    /// the verifier consumes; the dense evaluation vector is only needed
    /// for the commit itself and for sumcheck's round-0 fold. Sumcheck
    /// automatically streams any non-`Field` storage via `storage().lift(i)`
    /// (see `piop/sum_check/prover.rs:135-168`), so once phat is
    /// re-registered with this lazy backing after commit, the ~2 GiB per
    /// side of dense phat storage evaporates.
    ///
    /// Semantic contract: `lift(i) = (source.storage().lift(i) - shift).inverse().unwrap_or(F::zero())`.
    /// Callers are responsible for ensuring `source(x) - shift != 0` at
    /// every point they read — `keyed_sumcheck` picks `shift = γ` as a
    /// transcript-derived challenge, so the exceptional set has measure
    /// zero over a random challenge and the fallback zero is only there
    /// for safety.
    LazyInverseShifted {
        source: Arc<MLE<F>>,
        shift: F,
        inner_num_vars: usize,
    },
    /// Lazy inverse-shifted sum: represents
    /// `1/(s1(x) - shift) + 1/(s2(x) - shift)` at every hypercube point.
    /// Same storage / streaming rationale as [`Self::LazyInverseShifted`],
    /// used for the paired keyed-sumcheck path
    /// (`prove_generate_pair_subclaim`).
    LazyInverseShiftedSum {
        s1: Arc<MLE<F>>,
        s2: Arc<MLE<F>>,
        shift: F,
        inner_num_vars: usize,
    },
}

impl<F: Field> MLEStorage<F> {
    /// Maximum number of runs an `Rle` variant is willing to hold. Above this
    /// the column is dense enough that the RLE form no longer beats the
    /// native small-int storage, and detection returns `None` so the caller
    /// keeps the original form. Chosen so 256 runs × ~36 B ≈ 9 KiB stays
    /// dwarfed by any full-column storage we'd otherwise carry.
    pub const RLE_MAX_RUNS: usize = 256;

    /// Construct an `Rle` variant, enforcing the invariants. Merges
    /// consecutive runs sharing a value; returns `None` if `runs` is empty,
    /// if the counts don't sum to `1 << inner_num_vars`, or if after
    /// merging the run count exceeds [`Self::RLE_MAX_RUNS`].
    pub fn new_rle(runs: Vec<(F, u32)>, inner_num_vars: usize) -> Option<Self> {
        if runs.is_empty() {
            return None;
        }
        // Merge adjacent same-value runs so the storage matches the
        // "shortest RLE" invariant.
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
        // Drop no-op entries (value equals default) up front so callers can
        // hand us a heuristically-collected vector without pre-filtering.
        exceptions.retain(|(_, v)| *v != default);
        // Sort by index; use a stable sort so a mid-caller that happens to
        // hand us duplicates surfaces them below rather than picking the
        // last-inserted arbitrarily.
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

    /// Construct a `SparseU8` variant, enforcing the same invariants as
    /// [`Self::new_sparse`] but on native-typed data. Sorts and drops
    /// default-equal exceptions; returns `None` on duplicate or
    /// out-of-range indices.
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
                // Serialize the runs as two parallel vectors so we can reuse
                // arkworks' `Vec` impl without wrapping `(F, u32)` in a
                // struct/derive.
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
                // Same parallel-vec trick as Rle: reuse arkworks' Vec impl
                // without wrapping the (u32, F) pair.
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
            // Lazy variants are internal-only: they live in the prover's
            // materialized_polys map to make sumcheck stream the phat MLE,
            // but they are NEVER part of any serialized artifact (the
            // proof carries the phat commitment, not the phat MLE, and
            // proving-key files carry base-table MLEs which are never
            // lazy). If a caller ever hits this path, that indicates a
            // bug (e.g. a lazy phat leaked into a serialization boundary).
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
            // Lazy variants are non-serializable (see `serialize_with_mode`).
            // Return 0 so `serialized_size` callers who *estimate* buffer
            // capacity don't over-allocate; the actual serialize call will
            // error before writing anything.
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
            // Native-typed sparse: default and exception values are integer
            // primitives with no Valid state to check.
            Self::SparseU8 { .. } | Self::SparseU32 { .. } | Self::SparseU64 { .. } => Ok(()),
            // Packed decimal: two u64 vectors of equal length; the length
            // invariant is a constructor-only concern, but we still verify
            // it here so deserialized values that violate it fail loudly.
            Self::PackedDecimal { high, low, .. } => {
                if high.len() != low.len() {
                    return Err(ark_serialize::SerializationError::InvalidData);
                }
                Ok(())
            }
            // Lazy variants: nothing to validate beyond what the source
            // MLEs already validate on their own via their own `check`.
            // Construction always goes through the keyed_sumcheck
            // re-registration flow with proven-valid Arc<MLE> sources.
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
                // Linear scan is fastest for `runs.len() <= 256` because
                // branch prediction handles run-boundary crossings well
                // and there's no allocation for a prefix-sum table.
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
                // Binary search on the sorted exception indices; if `i`
                // matches an exception key, return its value, else return
                // the default.
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
            // Packed decimal: reassemble the 128-bit magnitude, then lift
            // via `F::from(u128)` — which the `Field` trait already
            // provides (see the `From<u128>` bound on the trait itself),
            // matching the existing U8 / U32 / U64 lift arms above that
            // rely on `F::from(uN)`. For unsigned 128-bit values this
            // produces the same field element the eager
            // `from_le_bytes_mod_order` path would have — the encoder
            // rejects negatives at ingest so we're guaranteed the u128
            // faithfully represents the source Decimal128 magnitude.
            Self::PackedDecimal { high, low, .. } => {
                let value: u128 = ((high[i] as u128) << 64) | (low[i] as u128);
                F::from(value)
            }
            // Lazy inverse: compute `(source(i) - shift)^{-1}` on demand.
            // Fallback to zero on the measure-zero exceptional set — this
            // preserves the arithmetic identity `phat · (source - shift) = 1`
            // only when the shifted value is invertible; the keyed-sumcheck
            // caller draws `shift = γ` from the transcript AFTER the source
            // is committed, so hitting a zero is a soundness event we'd
            // rather signal via a downstream check than crash here.
            //
            // Cycle `i` modulo the source's inner_len so we handle the
            // virtual-padding case correctly: after `equalize_mat_poly_nv_to`
            // bumps phat's outer nv, sumcheck reads phat at outer indices
            // that exceed the source's inner_len, and the source's outer
            // nv may have been snapshotted at a smaller value. The modulo
            // matches how a bumped source would cyclically repeat its
            // inner backing, so phat's readings stay consistent.
            Self::LazyInverseShifted { source, shift, .. } => {
                let src_storage = source.storage();
                let idx = i % src_storage.inner_len();
                let v = src_storage.lift(idx) - *shift;
                v.inverse().unwrap_or_else(F::zero)
            }
            // Lazy inverse-shifted sum: same on-demand shape, two inversions,
            // same modulo-cycle handling per source.
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
            // Lazy variants own only pointer(s) + scalar + usize; the source
            // MLE's heap is accounted for at its own tracker entry, so we
            // don't double-count it here. The reported size is what the
            // lazy backing itself adds beyond the source Arc pointer word.
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
            // Packed decimal: two parallel `Vec<u64>` at 8 B each per row,
            // plus a 1-B scale byte. This is the point of the variant —
            // 16 B/row on-heap where the `Field` form would carry 32.
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

    /// Scan the storage for structural redundancy and, if found, return the
    /// most compact equivalent variant. Never rewrites `Constant`/`Rle` (they
    /// are already the compact forms) and never allocates when the input
    /// isn't compressible past its current shape.
    ///
    /// Detection is a single O(inner_len) linear walk that counts value
    /// transitions:
    /// - **0 transitions** → [`Self::Constant`] (single value across the whole
    ///   inner hypercube)
    /// - **1 …  [`Self::RLE_MAX_RUNS`]−1 transitions** → [`Self::Rle`] with
    ///   `runs = transitions + 1`
    /// - **more transitions** → returns `self` unchanged; the column is dense
    ///   enough that the compact form no longer beats the native small-int
    ///   storage
    ///
    /// Called from the tracker's auto-compression pass and from ingest-time
    /// detection in `EncodedBacking::into_mle` — see those sites for how
    /// upstream chooses to trigger it.
    pub fn detect_redundancy(self) -> Self
    where
        F: ark_ff::PrimeField,
    {
        // Skip if already in a compact form — no faster representation exists.
        // Lazy variants are inherently symbolic and (a) don't benefit from RLE
        // detection since their heap footprint is already O(1) plus a pointer
        // to the source, and (b) attempting the run scan would trigger a full
        // O(2^inner_nv) lift-per-slot pass which is the very allocation we're
        // trying to avoid — so we bail early with the identity transform.
        if matches!(
            self,
            Self::Constant { .. }
                | Self::Rle { .. }
                | Self::Sparse { .. }
                | Self::SparseU8 { .. }
                | Self::SparseU32 { .. }
                | Self::SparseU64 { .. }
                // Packed decimal short-circuits like the Sparse* variants:
                // an RLE scan over 128-bit values would pay `F::from(u128)`
                // per run (~100 ns/call — see comment below at "Native
                // comparison"), and the storage is already tight at 16 B/row.
                // Same rationale as the SparseU64 skip.
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
        // Per-variant native scan. Comparing in the native form (u8/u32/u64
        // / raw bits) instead of lifting each element through `F::from(...)`
        // matters a LOT: on BN254, `F::from` is a Montgomery-form conversion
        // that costs ~100 ns per call — running it inside this loop for
        // every registered poly turned into ~50% wall-clock regression on
        // small-table benches. Native comparison is one integer eq per
        // element, so we run at memory-bandwidth speed and bail after
        // `RLE_MAX_RUNS` transitions for any dense column.
        let inner_nv = self.inner_num_vars();
        // Generic "count runs of Copy+Eq scalars, then materialize the
        // (value, count) run vector" scan. Returns `Some(runs)` when the
        // collapsed form is worth building (≤ RLE_MAX_RUNS runs), or `None`
        // when the caller should keep dense storage.
        //
        // Comparing in the native scalar type instead of lifting each
        // element through `F::from(...)` first matters a LOT: on BN254 the
        // Montgomery-form conversion is ~100 ns per call, so a lift-based
        // scan turned into ~50% wall-clock regression on small-table
        // benches. This native version does one integer eq per element and
        // pays the field conversion once per RUN (typically ≤ 3).
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
        // Bit needs its own loop: the "elements" are packed 1-bit values, so
        // we unpack on the fly. Same short-circuit at RLE_MAX_RUNS.
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
        // Per-variant dispatch: each call pays a per-element integer eq
        // and a per-RUN `F::from`. The Field variant already has F elements,
        // so its lift is the identity.
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
            // Constant/Rle/Sparse*/PackedDecimal and Lazy* already handled
            // by the early-return above.
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
            // Rle bailed (too many runs). Try scattered-sparse detection
            // before giving up. The mode candidate is the value at slot 0
            // — cheap to read and catches the common "mostly-zero mask
            // with a handful of set slots" case. We emit Sparse only if
            // the compact form is at least 2× smaller than the current
            // dense storage (otherwise compression overhead + slower lift
            // aren't worth it).
            //
            // For native-typed inputs we emit the matching native-typed
            // sparse variant — SparseU8 for U8 input, SparseU32 for U32,
            // etc. — so the per-exception cost stays 5/8/12 B rather
            // than paying the 36 B F-valued entry cost. For Field / Bit
            // inputs we emit the F-valued `Sparse` variant.
            //
            // Generic helper: `default_val` + native scan → returns
            // `Some((default, exceptions))` if under the exception cap,
            // `None` if we should keep dense storage.
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
                    // Bit has only 2 distinct values; if RLE bailed, we're
                    // in an alternating pattern. Encode as F-valued Sparse
                    // with default=F::zero()/one() picked to minimize
                    // exceptions. Scan once to count set bits, pick the
                    // smaller side as exceptions.
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

    /// Wrap a source MLE in a lazy `1/(source - shift)` backing. The
    /// returned MLE reports the same `num_vars` as `source` — including
    /// any virtual padding — and, at every point `i`, evaluates to
    /// `(source(i) - shift)^{-1}`. The heap footprint is one
    /// `Arc<MLE<F>>` pointer + one `F` + one `usize`. Intended for the
    /// keyed-sumcheck post-commit re-registration flow: commit the
    /// dense phat once for the PCS, then swap in this lazy backing so
    /// downstream sumcheck reads phat via the streaming path.
    ///
    /// Padding preservation matters: if `source` reports `num_vars() >
    /// inner_num_vars()` (virtual padding via a set outer nv), the
    /// returned lazy MLE mirrors that outer nv so downstream sumcheck
    /// term-nv comparisons stay consistent with what a dense phat would
    /// have looked like. The lazy `lift(i)` cycles `i` modulo the
    /// source's inner_len — same semantics as the source itself does.
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

    /// Lazy `1/(s1 - shift) + 1/(s2 - shift)` variant for the paired
    /// keyed-sumcheck path. Both sources must share the same
    /// `num_vars()` (including any outer padding); asserts in debug
    /// builds. See [`Self::from_lazy_inverse_shifted`] for the memory
    /// and padding rationale.
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
        // Bit storage packs at 8-bit (2^3-slot) granularity — a single byte
        // already holds 8 slots. For `num_vars < 3` the target hypercube
        // is smaller than one byte, so we can't represent it as `Bit`
        // (the inner_num_vars would be inflated to 3, breaking the
        // encoder contract of `num_vars() == num_vars`). Fall back to
        // Field storage in that regime — the cost is at most 8 field
        // elements, negligible for the tiny-table use case that
        // triggers this path (e.g. TPC-H nation at test scale).
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

    /// Build a "contiguous-one activator" MLE: the first `active_len` inner
    /// slots are `1`, the rest are `0`. `active_len` must satisfy
    /// `active_len <= 1 << num_vars`.
    ///
    /// The shape is exactly known at call time — either a single all-ones or
    /// all-zeros run (Constant), a "1s then 0s" prefix (2-run Rle), or an
    /// empty poly — so we build the compact form directly instead of
    /// allocating and then scanning a full bit vector. On a lineitem
    /// `l_comment`-shaped char-level activator (`num_vars ≈ 31`, `active_len
    /// ≈ 1.3B`) this drops per-poly storage from ~256 MiB of packed bits to
    /// ~72 bytes of `Rle` runs — with no scan and no allocation of the bit
    /// vector to begin with.
    ///
    /// Semantics unchanged: `mle[i]` returns `F::one()` for `i < active_len`
    /// and `F::zero()` for `active_len <= i < 1 << num_vars`, matching the
    /// prior `Bit`-backed construction bit-for-bit.
    /// Build a `Sparse`-storage `MLE` directly from a `(default, exceptions)`
    /// pair. Sorts and de-noises `exceptions` (drops entries equal to
    /// `default`) via [`MLEStorage::new_sparse`]. Returns `None` if any
    /// exception index is out of range or duplicates another.
    ///
    /// Callers that already know their column has structural sparsity —
    /// e.g. an activator mask with a few holes, a computed selector poly
    /// — get the compact form without paying the auto-detection cost.
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
    /// [`Self::from_sparse`] for the semantics.
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

    pub fn from_prefix_activator(active_len: usize, num_vars: usize) -> Self {
        Self::from_window_activator(0, active_len, num_vars)
    }

    /// Build a window activator MLE: `skip` zeros, followed by `active_len`
    /// ones, followed by `total - skip - active_len` zeros, where
    /// `total = 1 << num_vars`. The result is stored as a
    /// [`MLEStorage::Constant`] (edge cases where the window is empty or
    /// the whole domain) or a [`MLEStorage::Rle`] (2-run when `skip == 0`
    /// or the window reaches the end, 3-run otherwise) — never a
    /// full-size `Vec<F>`. Memory is O(1) regardless of `num_vars`.
    pub fn from_window_activator(skip: usize, active_len: usize, num_vars: usize) -> Self {
        let len = 1usize << num_vars;
        // RLE run counts are u32; ensure `len` (and therefore any segment
        // length ≤ `len`) fits without silent truncation. In practice all
        // truth-table nv values are ≤ 24; this guards against future misuse.
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
            // Compose 2- or 3-run RLE from the non-empty segments.
            // `new_rle` merges adjacent same-value runs and validates the
            // counts sum to `len`.
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

    /// Build an MLE from an unsigned 128-bit column, stored as parallel
    /// `high` / `low` `u64` vectors (`value[i] = (high[i] << 64) | low[i]`).
    /// This is the constructor for [`MLEStorage::PackedDecimal`]; see that
    /// variant's docstring for the storage contract and commit-path
    /// treatment.
    ///
    /// Requires `high.len() == low.len() <= 2^num_vars` and both to have
    /// power-of-two length. Panics otherwise (matches the assertion style
    /// of the neighbouring `from_u{8,32,64}s` constructors).
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

    /// Fold one variable at `p`, in place, with zero fresh allocations.
    /// Halves the underlying `Vec<F>` (parallel fold into `c[0]` of each pair
    /// followed by a serial compact of even-index fold heads into `[0..len/2]`),
    /// then decrements `inner_num_vars` and — if the poly is virtually padded —
    /// the outer `nv` by one.
    ///
    /// Requires `Field` storage: compressed variants have no mutable slice of
    /// field elements to fold and must be lifted first via
    /// [`MLE::to_field_owned`]. This is the sumcheck round loop's replacement
    /// for `fix_variables(&[p])`: instead of allocating a fresh half-sized
    /// `Vec<F>` per round, we reuse the same buffer for every round of a
    /// single sumcheck, eliminating the round-loop's dominant allocation
    /// traffic (and the fragmentation that came with it).
    ///
    /// # Correctness of the in-place scheme
    ///
    /// Pass 1 partitions `evals` into disjoint 2-element chunks; each chunk
    /// writes only to its own `c[0]`, so parallel execution is race-free.
    /// After pass 1 the fold heads sit at even indices `0, 2, …, 2·(N/2 − 1)`.
    /// Pass 2 compacts them: for `i in 1..N/2` we set `evals[i] = evals[2·i]`.
    /// The read index `2·i` is strictly greater than every previously written
    /// index (which are `1..i`), so the compaction never reads a value it has
    /// itself already overwritten.
    ///
    /// # Virtual padding
    ///
    /// Folding one *outer* variable of a virtually repeated MLE is equivalent
    /// to folding one *inner* variable plus decrementing `nv` (the outer fold
    /// projects the repetition to the same repetition of half the length).
    /// We update both counters and clear `nv` when the outer size no longer
    /// exceeds inner storage.
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
                    // Pass 2 (serial memcpy-style): pull fold heads at even
                    // indices into `[0..new_len]`. Safe because `2·i > i`
                    // dominates every previously written slot.
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
        // Reduce virtual padding to match the outer-fold ratio; drop it when
        // the outer size no longer exceeds inner storage.
        if let Some(nv) = self.nv {
            let new_nv = nv.saturating_sub(1);
            let inner_nv = self.storage.inner_num_vars();
            self.nv = (new_nv > inner_nv).then_some(new_nv);
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

    /// Additional structural-redundancy compression on top of [`Self::compressed`].
    /// Separated so callers can opt in: [`Self::compressed`] stays a cheap
    /// per-slot classifier that never touches the storage twice, while this
    /// method does the linear-scan run detector that collapses `Constant` and
    /// `Rle` patterns. Chain them (`.compressed().detect_redundancy()`) at
    /// long-lived-storage boundaries where the extra scan pays back in
    /// storage savings; skip it on hot paths where every registered poly is
    /// small and would just pay the scan cost without a meaningful win.
    pub fn detect_redundancy(self) -> Self
    where
        F: ark_ff::PrimeField,
    {
        let nv = self.nv;
        let storage = self.storage.detect_redundancy();
        Self { storage, nv }
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
        // Fast paths for the compact variants — they either KNOW they're
        // constant (Constant variant) or KNOW how many distinct runs they
        // hold (Rle variant), avoiding an O(N) walk. Lazy variants
        // conservatively return false: the underlying source could in
        // principle be constant, but checking would run 2^n inversions
        // — exactly the O(2^n) cost we introduced lazy storage to
        // avoid. A wrong `false` here can at worst prevent a small
        // downstream optimisation; it can never cause a soundness error.
        match &self.storage {
            MLEStorage::Constant { .. } => return true,
            MLEStorage::Rle { runs, .. } => return runs.len() == 1,
            MLEStorage::LazyInverseShifted { .. } | MLEStorage::LazyInverseShiftedSum { .. } => {
                return false;
            }
            _ => {}
        }
        // For any other storage variant: fold via lift() to compare all inner points.
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
