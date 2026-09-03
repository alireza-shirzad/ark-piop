use ark_ff::Field;

use crate::arithmetic::mat_poly::mle::{MLE, MLEStorage};

/// BLAKE3 digest of an MLE's raw storage bytes (no field materialization).
/// Intentionally storage-aware: equal lifted evaluations with different
/// backings hash differently — required for commitment-cache soundness, since
/// different storage variants also produce different MSMs.
pub fn mle_digest<F: Field>(mle: &MLE<F>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    // Per-variant discriminant tag: rules out cross-variant collisions even
    // when payload bytes match (e.g. Constant(0) vs an all-zero Bit).
    let mut constant_bytes: Vec<u8> = Vec::new();
    let mut rle_bytes: Vec<u8> = Vec::new();
    let mut sparse_bytes: Vec<u8> = Vec::new();
    let mut sparse_u8_bytes: Vec<u8> = Vec::new();
    let mut sparse_u32_bytes: Vec<u8> = Vec::new();
    let mut sparse_u64_bytes: Vec<u8> = Vec::new();
    let mut packed_decimal_bytes: Vec<u8> = Vec::new();
    let (tag, byte_slice): (u8, &[u8]) = match mle.storage() {
        MLEStorage::Field(inner) => {
            let evals = &inner.evaluations;
            // Safe: F is Copy + Sized and we only need a deterministic fingerprint.
            let bs = unsafe {
                std::slice::from_raw_parts(
                    evals.as_ptr() as *const u8,
                    std::mem::size_of_val(&**evals),
                )
            };
            (0, bs)
        }
        MLEStorage::Bit { bits, .. } => (1, bits.as_slice()),
        MLEStorage::U8 { bytes, .. } => (2, bytes.as_slice()),
        MLEStorage::U32 { words, .. } => (3, unsafe {
            std::slice::from_raw_parts(words.as_ptr() as *const u8, std::mem::size_of_val(&**words))
        }),
        MLEStorage::U64 { words, .. } => (4, unsafe {
            std::slice::from_raw_parts(words.as_ptr() as *const u8, std::mem::size_of_val(&**words))
        }),
        MLEStorage::Constant { value, .. } => {
            let bs = unsafe {
                std::slice::from_raw_parts(
                    (value as *const F) as *const u8,
                    std::mem::size_of::<F>(),
                )
            };
            constant_bytes.extend_from_slice(bs);
            (5, constant_bytes.as_slice())
        }
        MLEStorage::Rle { runs, .. } => {
            rle_bytes.reserve(runs.len() * (std::mem::size_of::<F>() + 4));
            for (v, c) in runs {
                let vs = unsafe {
                    std::slice::from_raw_parts(
                        (v as *const F) as *const u8,
                        std::mem::size_of::<F>(),
                    )
                };
                rle_bytes.extend_from_slice(vs);
                rle_bytes.extend_from_slice(&c.to_le_bytes());
            }
            (6, rle_bytes.as_slice())
        }
        MLEStorage::Sparse {
            default,
            exceptions,
            ..
        } => {
            sparse_bytes.reserve(
                std::mem::size_of::<F>() + exceptions.len() * (4 + std::mem::size_of::<F>()),
            );
            let def_bs = unsafe {
                std::slice::from_raw_parts(
                    (default as *const F) as *const u8,
                    std::mem::size_of::<F>(),
                )
            };
            sparse_bytes.extend_from_slice(def_bs);
            for (idx, v) in exceptions {
                sparse_bytes.extend_from_slice(&idx.to_le_bytes());
                let vs = unsafe {
                    std::slice::from_raw_parts(
                        (v as *const F) as *const u8,
                        std::mem::size_of::<F>(),
                    )
                };
                sparse_bytes.extend_from_slice(vs);
            }
            (7, sparse_bytes.as_slice())
        }
        MLEStorage::SparseU8 {
            default,
            exceptions,
            ..
        } => {
            sparse_u8_bytes.reserve(1 + exceptions.len() * (4 + 1));
            sparse_u8_bytes.push(*default);
            for (idx, v) in exceptions {
                sparse_u8_bytes.extend_from_slice(&idx.to_le_bytes());
                sparse_u8_bytes.push(*v);
            }
            (8, sparse_u8_bytes.as_slice())
        }
        MLEStorage::SparseU32 {
            default,
            exceptions,
            ..
        } => {
            sparse_u32_bytes.reserve(4 + exceptions.len() * (4 + 4));
            sparse_u32_bytes.extend_from_slice(&default.to_le_bytes());
            for (idx, v) in exceptions {
                sparse_u32_bytes.extend_from_slice(&idx.to_le_bytes());
                sparse_u32_bytes.extend_from_slice(&v.to_le_bytes());
            }
            (9, sparse_u32_bytes.as_slice())
        }
        MLEStorage::SparseU64 {
            default,
            exceptions,
            ..
        } => {
            sparse_u64_bytes.reserve(8 + exceptions.len() * (4 + 8));
            sparse_u64_bytes.extend_from_slice(&default.to_le_bytes());
            for (idx, v) in exceptions {
                sparse_u64_bytes.extend_from_slice(&idx.to_le_bytes());
                sparse_u64_bytes.extend_from_slice(&v.to_le_bytes());
            }
            (10, sparse_u64_bytes.as_slice())
        }
        // Lazy variants only appear on the tracker AFTER commit, so this arm
        // is unreachable in the honest-prover flow. If reached anyway, fold
        // the source digest + shift + tag: slow but still a sound cache key.
        MLEStorage::LazyInverseShifted { source, shift, .. } => {
            let src_digest = mle_digest(source.as_ref());
            rle_bytes.extend_from_slice(&src_digest);
            let shift_bs = unsafe {
                std::slice::from_raw_parts(
                    (shift as *const F) as *const u8,
                    std::mem::size_of::<F>(),
                )
            };
            rle_bytes.extend_from_slice(shift_bs);
            (11, rle_bytes.as_slice())
        }
        MLEStorage::PackedDecimal {
            high, low, scale, ..
        } => {
            // Hash both u64 vectors as raw LE bytes (same fingerprinting as
            // U32/U64 above) plus the scale byte.
            packed_decimal_bytes.reserve(high.len() * 8 + low.len() * 8 + 1);
            let hi_bs = unsafe {
                std::slice::from_raw_parts(
                    high.as_ptr() as *const u8,
                    std::mem::size_of_val(&**high),
                )
            };
            let lo_bs = unsafe {
                std::slice::from_raw_parts(low.as_ptr() as *const u8, std::mem::size_of_val(&**low))
            };
            packed_decimal_bytes.extend_from_slice(hi_bs);
            packed_decimal_bytes.extend_from_slice(lo_bs);
            packed_decimal_bytes.push(*scale);
            (13, packed_decimal_bytes.as_slice())
        }
        MLEStorage::LazyInverseShiftedSum { s1, s2, shift, .. } => {
            let s1_digest = mle_digest(s1.as_ref());
            let s2_digest = mle_digest(s2.as_ref());
            rle_bytes.extend_from_slice(&s1_digest);
            rle_bytes.extend_from_slice(&s2_digest);
            let shift_bs = unsafe {
                std::slice::from_raw_parts(
                    (shift as *const F) as *const u8,
                    std::mem::size_of::<F>(),
                )
            };
            rle_bytes.extend_from_slice(shift_bs);
            (12, rle_bytes.as_slice())
        }
    };
    hasher.update(&[tag]);
    hasher.update_rayon(byte_slice);
    // Mix in the shape so equal evals with different nv/inner_num_vars differ.
    hasher.update(&mle.num_vars().to_le_bytes());
    hasher.update(&mle.inner_num_vars().to_le_bytes());
    hasher.finalize().into()
}
