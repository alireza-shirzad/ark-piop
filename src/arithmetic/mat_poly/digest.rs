use ark_ff::Field;

use crate::arithmetic::mat_poly::mle::{MLE, MLEStorage};

/// Compute a BLAKE3 digest of an MLE by hashing the raw bytes of its storage
/// backing directly — no field-form materialization needed. The digest is
/// storage-aware: two MLEs whose lifted evaluations are equal but whose
/// backings differ (e.g. `Bit`-packed vs `Field(vec![0/1])`) hash to
/// *different* digests. That is intentional and correct for the commitment
/// cache — different storage variants also produce different MSMs (small-scalar
/// vs full-width Pippenger), so cross-variant cache hits would be unsound.
pub fn mle_digest<F: Field>(mle: &MLE<F>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    // Discriminant byte so the (Field, [0,1,0,1,...]) collision-with-Bit case
    // can't happen even if the byte payloads were identical.
    // For the compact `Constant` and `Rle` variants we hash a lifted byte
    // slice built on the fly (Constant → one F payload; Rle → parallel
    // value/count arrays). Discriminant tags are unique per variant so
    // cross-variant collisions remain impossible even when the lifted bytes
    // happen to match (e.g. Constant(0) vs an all-zero Bit).
    let mut constant_bytes: Vec<u8> = Vec::new();
    let mut rle_bytes: Vec<u8> = Vec::new();
    let mut sparse_bytes: Vec<u8> = Vec::new();
    let mut sparse_u8_bytes: Vec<u8> = Vec::new();
    let mut sparse_u32_bytes: Vec<u8> = Vec::new();
    let mut sparse_u64_bytes: Vec<u8> = Vec::new();
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
            std::slice::from_raw_parts(
                words.as_ptr() as *const u8,
                std::mem::size_of_val(&**words),
            )
        }),
        MLEStorage::U64 { words, .. } => (4, unsafe {
            std::slice::from_raw_parts(
                words.as_ptr() as *const u8,
                std::mem::size_of_val(&**words),
            )
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
            sparse_bytes
                .reserve(std::mem::size_of::<F>() + exceptions.len() * (4 + std::mem::size_of::<F>()));
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
        // Lazy variants: `mle_digest` feeds the commitment cache lookup
        // which fires *before* commit. Lazy backings only ever appear on
        // the tracker AFTER commit (via `register_mat_mv_poly`), so this
        // arm should never be reached in the honest-prover flow. If it
        // is (unexpected caller), fold the source's digest with the
        // shift and a per-variant tag so the cache key still discriminates
        // — degrades to a slow but correct path rather than a panic.
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
    // Also mix in the shape so MLEs with the same evals but different nv (or
    // different inner_num_vars for compressed variants) are distinguished.
    hasher.update(&mle.num_vars().to_le_bytes());
    hasher.update(&mle.inner_num_vars().to_le_bytes());
    hasher.finalize().into()
}
