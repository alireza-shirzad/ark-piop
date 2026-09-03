//! Small-scalar MSM entry points (`msm_u1`..`msm_u64`) vendored from arkworks master,
//! letting the pst13 commit path consume compressed MLE backings directly instead of
//! materializing 32-byte field elements. Kept next to their only caller since the
//! arkworks-0.5 `VariableBaseMSM` trait doesn't expose them.
//!
//! Adaptation: ark-ec 0.5.0 has no `V::Bucket`, so `V` itself is the bucket type,
//! matching 0.5.0's own `msm_bigint`; semantics are preserved.
//!
//! Correctness anchor: each entry point must match `msm_unchecked` on the same
//! scalars lifted through `F::from` — tested end-to-end below.

use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_std::{cfg_chunks, vec::Vec};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Approximate `ln(a)` for Pippenger window sizing; verbatim from ark-ec 0.5.0's
/// private `ln_without_floats`.
#[inline]
fn ln_without_floats(a: usize) -> usize {
    // log2(a) * ln(2)  ≈  log2(a) * 0.69
    (ark_std::log2(a) as usize) * 69 / 100
}

/// Returns the per-thread chunk length (`None` if no work) and truncates both slices
/// to their shortest common length, matching `msm_unchecked`'s convention.
fn preamble<A, B>(bases: &mut &[A], scalars: &mut &[B]) -> Option<usize> {
    let size = bases.len().min(scalars.len());
    if size == 0 {
        return None;
    }
    #[cfg(feature = "parallel")]
    let chunk_size = {
        let cs = size / rayon::current_num_threads().max(1);
        if cs == 0 { size } else { cs }
    };
    #[cfg(not(feature = "parallel"))]
    let chunk_size = size;

    *bases = &bases[..size];
    *scalars = &scalars[..size];
    Some(chunk_size)
}

/// MSM with boolean scalars: add each base whose scalar is `true`. No bucketing —
/// `O(set bits)` curve additions, far cheaper than a full Pippenger over field scalars.
pub(crate) fn msm_u1<V: VariableBaseMSM>(mut bases: &[V::MulBase], mut scalars: &[bool]) -> V {
    let chunk_size = match preamble(&mut bases, &mut scalars) {
        Some(cs) => cs,
        None => return V::zero(),
    };
    cfg_chunks!(bases, chunk_size)
        .zip(cfg_chunks!(scalars, chunk_size))
        .map(|(bases, scalars)| {
            let mut res = V::zero();
            for (base, _) in bases.iter().zip(scalars).filter(|&(_, &s)| s) {
                res += base;
            }
            res
        })
        .sum()
}

/// Multi-scalar multiplication with `u8` scalars.
pub(crate) fn msm_u8<V: VariableBaseMSM>(mut bases: &[V::MulBase], mut scalars: &[u8]) -> V {
    let chunk_size = match preamble(&mut bases, &mut scalars) {
        Some(cs) => cs,
        None => return V::zero(),
    };
    cfg_chunks!(bases, chunk_size)
        .zip(cfg_chunks!(scalars, chunk_size))
        .map(|(bases, scalars)| msm_serial_small::<V, u8>(bases, scalars))
        .sum()
}

/// Multi-scalar multiplication with `u16` scalars.
#[allow(dead_code)] // MLEStorage has no U16 variant today; kept for API completeness.
pub(crate) fn msm_u16<V: VariableBaseMSM>(mut bases: &[V::MulBase], mut scalars: &[u16]) -> V {
    let chunk_size = match preamble(&mut bases, &mut scalars) {
        Some(cs) => cs,
        None => return V::zero(),
    };
    cfg_chunks!(bases, chunk_size)
        .zip(cfg_chunks!(scalars, chunk_size))
        .map(|(bases, scalars)| msm_serial_small::<V, u16>(bases, scalars))
        .sum()
}

/// Multi-scalar multiplication with `u32` scalars.
pub(crate) fn msm_u32<V: VariableBaseMSM>(mut bases: &[V::MulBase], mut scalars: &[u32]) -> V {
    let chunk_size = match preamble(&mut bases, &mut scalars) {
        Some(cs) => cs,
        None => return V::zero(),
    };
    cfg_chunks!(bases, chunk_size)
        .zip(cfg_chunks!(scalars, chunk_size))
        .map(|(bases, scalars)| msm_serial_small::<V, u32>(bases, scalars))
        .sum()
}

/// Multi-scalar multiplication with `u64` scalars.
pub(crate) fn msm_u64<V: VariableBaseMSM>(mut bases: &[V::MulBase], mut scalars: &[u64]) -> V {
    let chunk_size = match preamble(&mut bases, &mut scalars) {
        Some(cs) => cs,
        None => return V::zero(),
    };
    cfg_chunks!(bases, chunk_size)
        .zip(cfg_chunks!(scalars, chunk_size))
        .map(|(bases, scalars)| msm_serial_small::<V, u64>(bases, scalars))
        .sum()
}

/// Serial Pippenger over small (≤ 64 bit) scalars: arkworks master's `msm_serial`
/// with `V` as the bucket type (ark-ec 0.5.0 has no `V::Bucket`) and `num_bits`
/// restricted to 64, so high windows are skipped for free. Window width follows
/// arkworks' own `ln_without_floats` tuning.
fn msm_serial_small<V, S>(bases: &[V::MulBase], scalars: &[S]) -> V
where
    V: VariableBaseMSM,
    S: Into<u64> + Copy + Send + Sync,
{
    let c = if bases.len() < 32 {
        3
    } else {
        ln_without_floats(bases.len()) + 2
    };

    let zero = V::zero();
    let two_to_c = 1u64 << c;
    let num_bits = core::mem::size_of::<u64>() * 8;

    // Each window is of size `c`.
    let window_sums: Vec<_> = (0..num_bits)
        .step_by(c)
        .map(|w_start| {
            let mut res = zero;
            // `V` as the bucket type — see the fn doc.
            let mut buckets = vec![zero; (two_to_c as usize) - 1];
            scalars
                .iter()
                .zip(bases)
                .filter_map(|(&s, b)| {
                    let s = s.into();
                    (s != 0).then_some((s, b))
                })
                .for_each(|(scalar, base)| {
                    if scalar == 1 {
                        // Unit scalars are processed once in the first window.
                        if w_start == 0 {
                            res += base;
                        }
                    } else {
                        let mut scalar = scalar;
                        scalar >>= w_start as u32;
                        scalar %= two_to_c;
                        if scalar != 0 {
                            buckets[(scalar - 1) as usize] += base;
                        }
                    }
                });

            // Compute Σ_i (Σ_{j ≥ i} bucket[j]) by walking buckets right to left.
            let mut running_sum = V::zero();
            buckets.into_iter().rev().for_each(|b| {
                running_sum += &b;
                res += &running_sum;
            });
            res
        })
        .collect();

    // Combine windows: doubling `c` times between each.
    let lowest = *window_sums.first().unwrap();
    lowest
        + window_sums[1..]
            .iter()
            .rev()
            .fold(V::zero(), |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective as G1};
    use ark_ec::PrimeGroup;
    use ark_ff::{UniformRand, Zero};
    use ark_std::{rand::SeedableRng, test_rng};

    /// Random G1 bases — cheap, fine for correctness tests.
    fn rand_bases(count: usize) -> Vec<<G1 as ark_ec::scalar_mul::ScalarMul>::MulBase> {
        use ark_ec::CurveGroup;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xB007);
        let g = G1::generator();
        (0..count)
            .map(|_| (g * Fr::rand(&mut rng)).into_affine())
            .collect()
    }

    fn as_field<T: Into<u64> + Copy>(scalars: &[T]) -> Vec<Fr> {
        scalars.iter().map(|&s| Fr::from(s.into())).collect()
    }

    #[test]
    fn msm_u1_matches_field_msm() {
        let bases = rand_bases(128);
        let mut rng = test_rng();
        let scalars: Vec<bool> = (0..128).map(|_| bool::rand(&mut rng)).collect();
        let field_scalars: Vec<Fr> = scalars.iter().map(|&b| Fr::from(b as u64)).collect();

        let ours: G1 = msm_u1(&bases, &scalars);
        let baseline = <G1 as VariableBaseMSM>::msm_unchecked(&bases, &field_scalars);
        assert_eq!(ours, baseline);
    }

    #[test]
    fn msm_u1_all_zero_returns_identity() {
        let bases = rand_bases(64);
        let scalars = vec![false; 64];
        let out: G1 = msm_u1(&bases, &scalars);
        assert!(out.is_zero());
    }

    #[test]
    fn msm_u1_all_one_matches_sum_of_bases() {
        let bases = rand_bases(64);
        let scalars = vec![true; 64];
        let out: G1 = msm_u1(&bases, &scalars);
        let mut expected = G1::zero();
        for b in &bases {
            expected += b;
        }
        assert_eq!(out, expected);
    }

    #[test]
    fn msm_u8_matches_field_msm() {
        // Cover the branchy scalar values (0, 1, near-max).
        let bases = rand_bases(300);
        let mut rng = test_rng();
        let scalars: Vec<u8> = (0..300).map(|_| u8::rand(&mut rng)).collect();
        let ours: G1 = msm_u8(&bases, &scalars);
        let baseline = <G1 as VariableBaseMSM>::msm_unchecked(&bases, &as_field(&scalars));
        assert_eq!(ours, baseline);
    }

    #[test]
    fn msm_u32_matches_field_msm() {
        let bases = rand_bases(200);
        let mut rng = test_rng();
        let scalars: Vec<u32> = (0..200).map(|_| u32::rand(&mut rng)).collect();
        let ours: G1 = msm_u32(&bases, &scalars);
        let baseline = <G1 as VariableBaseMSM>::msm_unchecked(&bases, &as_field(&scalars));
        assert_eq!(ours, baseline);
    }

    #[test]
    fn msm_u64_matches_field_msm() {
        let bases = rand_bases(200);
        let mut rng = test_rng();
        let scalars: Vec<u64> = (0..200).map(|_| u64::rand(&mut rng)).collect();
        let ours: G1 = msm_u64(&bases, &scalars);
        let baseline = <G1 as VariableBaseMSM>::msm_unchecked(&bases, &as_field(&scalars));
        assert_eq!(ours, baseline);
    }

    #[test]
    fn msm_u16_matches_field_msm() {
        let bases = rand_bases(200);
        let mut rng = test_rng();
        let scalars: Vec<u16> = (0..200).map(|_| u16::rand(&mut rng)).collect();
        let ours: G1 = msm_u16(&bases, &scalars);
        let baseline = <G1 as VariableBaseMSM>::msm_unchecked(&bases, &as_field(&scalars));
        assert_eq!(ours, baseline);
    }

    #[test]
    fn msm_u8_empty_returns_identity() {
        let bases: Vec<<G1 as ark_ec::scalar_mul::ScalarMul>::MulBase> = vec![];
        let scalars: Vec<u8> = vec![];
        let out: G1 = msm_u8(&bases, &scalars);
        assert!(out.is_zero());
    }

    #[test]
    fn msm_u8_mismatched_lengths_truncates_to_min() {
        // Longer scalars slice must be truncated to bases.len().
        let bases = rand_bases(50);
        let mut rng = test_rng();
        let long_scalars: Vec<u8> = (0..100).map(|_| u8::rand(&mut rng)).collect();
        let ours: G1 = msm_u8(&bases, &long_scalars);
        let baseline =
            <G1 as VariableBaseMSM>::msm_unchecked(&bases, &as_field(&long_scalars[..50]));
        assert_eq!(ours, baseline);
    }
}
