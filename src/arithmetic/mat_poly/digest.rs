use ark_ff::Field;

use crate::arithmetic::mat_poly::mle::MLE;

/// Compute a BLAKE3 digest of an MLE by hashing the raw memory of its
/// evaluation vector directly — no serialization or allocation.
///
/// Uses `blake3::Hasher::update_rayon` which automatically parallelises
/// when the input exceeds ~128 KiB.
pub fn mle_digest<F: Field>(mle: &MLE<F>) -> [u8; 32] {
    let evals = &mle.mat_mle().evaluations;
    // Reinterpret the &[F] as &[u8] — safe because F is Copy + Sized and we
    // only need a deterministic fingerprint for cache deduplication.
    let byte_slice = unsafe {
        std::slice::from_raw_parts(evals.as_ptr() as *const u8, std::mem::size_of_val(&**evals))
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update_rayon(byte_slice);
    // Also mix in the shape so MLEs with the same evals but different nv are
    // distinguished.
    hasher.update(&mle.num_vars().to_le_bytes());
    hasher.finalize().into()
}
