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
    };
    hasher.update(&[tag]);
    hasher.update_rayon(byte_slice);
    // Also mix in the shape so MLEs with the same evals but different nv (or
    // different inner_num_vars for compressed variants) are distinguished.
    hasher.update(&mle.num_vars().to_le_bytes());
    hasher.update(&mle.inner_num_vars().to_le_bytes());
    hasher.finalize().into()
}
