//! MSM wrapper that picks a strategy based on the input size and hardware.
//!
//! Workflow:
//! * When `bases.len() < NAIVE_THRESHOLD`, we run a plain scalar-mul + sum —
//!   cheap to set up and faster than Pippenger for tiny inputs.
//! * Otherwise we call `VariableBaseMSM::msm_unchecked` (arkworks Pippenger)
//!   inside a rayon thread pool whose width is looked up from `THREAD_TABLE`.
//!
//! Tune `NAIVE_THRESHOLD` and `THREAD_TABLE` for your hardware by running
//! `calibrate::calibrate::<G>()` and pasting the recommended values into
//! this file.

use ark_ec::scalar_mul::variable_base::VariableBaseMSM;

/// Input size strictly below this threshold runs through `naive_msm`.
/// Override by running [`calibrate::calibrate`] and replacing this constant.
pub const NAIVE_THRESHOLD: usize = 4;

/// Size-range → rayon thread-count table used when `bases.len() >= NAIVE_THRESHOLD`.
///
/// Format: `(min_size_inclusive, max_size_exclusive, threads)`. Ranges must
/// cover `[NAIVE_THRESHOLD, usize::MAX)` without gaps or overlap; the last
/// entry should extend to `usize::MAX`.
pub const THREAD_TABLE: &[(usize, usize, usize)] = &[
    (0, 5, 5),
    (8, 17, 9),
    (24, 25, 4),
    (32, 33, 8),
    (48, 49, 6),
    (64, 65, 8),
    (96, 97, 4),
    (128, 129, 9),
    (192, 193, 6),
    (256, 257, 5),
    (384, 385, 7),
    (512, 513, 9),
    (768, 769, 6),
    (1024, 1025, 11),
    (1536, 1537, 13),
    (2048, 2049, 7),
    (3072, 3073, 14),
    (4096, 4097, 16),
    (6144, 6145, 14),
    (8192, 8193, 11),
    (12288, 12289, 14),
    (16384, 16385, 15),
    (24576, 24577, 13),
    (32768, 32769, 15),
    (49152, 49153, 12),
    (65536, 65537, 16),
    (131072, usize::MAX, 15),
];

/// Look up the preferred thread count for an MSM of size `n`.
#[inline]
pub fn threads_for_size(n: usize) -> usize {
    for &(lo, hi, t) in THREAD_TABLE {
        if n >= lo && n < hi {
            return t.max(1);
        }
    }
    1
}

/// Naive MSM: `sum_i bases[i] * scalars[i]`. Used below `NAIVE_THRESHOLD`.
pub fn naive_msm<G: VariableBaseMSM>(bases: &[G::MulBase], scalars: &[G::ScalarField]) -> G {
    debug_assert_eq!(
        bases.len(),
        scalars.len(),
        "msm: bases/scalars length mismatch"
    );
    bases
        .iter()
        .zip(scalars.iter())
        .map(|(b, s)| *b * *s)
        .fold(G::zero(), |acc, term| acc + term)
}

/// Entry point: switches between naive and Pippenger based on size and pins
/// the Pippenger call to a rayon pool sized from `THREAD_TABLE`.
///
/// The preferred thread count from `THREAD_TABLE` is clamped against
/// `rayon::current_num_threads()` so we never escape a caller-imposed budget
/// (e.g. `RAYON_NUM_THREADS=1` benches stay single-threaded).
pub fn msm<G: VariableBaseMSM>(bases: &[G::MulBase], scalars: &[G::ScalarField]) -> G {
    debug_assert_eq!(
        bases.len(),
        scalars.len(),
        "msm: bases/scalars length mismatch"
    );
    let n = bases.len();
    if n < NAIVE_THRESHOLD {
        return naive_msm::<G>(bases, scalars);
    }
    #[cfg(feature = "parallel")]
    {
        let preferred = threads_for_size(n);
        let budget = rayon::current_num_threads().max(1);
        let threads = preferred.min(budget);
        if threads <= 1 {
            // Caller only allows one worker — skip the pool dance entirely so we
            // don't pay install overhead on every call.
            G::msm_unchecked(bases, scalars)
        } else {
            pool::install(threads, || G::msm_unchecked(bases, scalars))
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        G::msm_unchecked(bases, scalars)
    }
}

#[cfg(feature = "parallel")]
mod pool {
    //! Cache rayon thread pools per distinct thread count so we don't rebuild
    //! one on every MSM call.

    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, OnceLock};

    type PoolMap = Mutex<BTreeMap<usize, Arc<rayon::ThreadPool>>>;
    static POOLS: OnceLock<PoolMap> = OnceLock::new();

    fn get_or_build(threads: usize) -> Arc<rayon::ThreadPool> {
        let pools = POOLS.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut guard = pools.lock().expect("MSM pool mutex poisoned");
        Arc::clone(guard.entry(threads).or_insert_with(|| {
            Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .thread_name(move |i| format!("msm-t{threads}-{i}"))
                    .build()
                    .expect("failed to build MSM rayon pool"),
            )
        }))
    }

    pub fn install<OP, R>(threads: usize, op: OP) -> R
    where
        OP: FnOnce() -> R + Send,
        R: Send,
    {
        get_or_build(threads).install(op)
    }
}

/// Hardware calibration: sweep sizes + thread counts, measure `msm_unchecked`
/// timings, and print a recommended `NAIVE_THRESHOLD` / `THREAD_TABLE`.
pub mod calibrate {
    use super::*;
    use ark_std::{UniformRand, rand::Rng};
    use std::time::{Duration, Instant};

    /// Result of a calibration sweep.
    #[derive(Debug, Clone)]
    pub struct Calibration {
        /// Smallest size at which Pippenger (via arkworks) beats the naive loop.
        pub naive_threshold: usize,
        /// Per-range best thread count: `(min_inclusive, max_exclusive, threads)`.
        pub thread_table: Vec<(usize, usize, usize)>,
    }

    impl Calibration {
        /// Print the calibration as copy-pasteable constants for this file.
        pub fn print_as_constants(&self) {
            println!(
                "pub const NAIVE_THRESHOLD: usize = {};",
                self.naive_threshold
            );
            println!("pub const THREAD_TABLE: &[(usize, usize, usize)] = &[");
            for (lo, hi, t) in &self.thread_table {
                let hi_str = if *hi == usize::MAX {
                    "usize::MAX".to_string()
                } else {
                    hi.to_string()
                };
                println!("    ({}, {}, {}),", lo, hi_str, t);
            }
            println!("];");
        }
    }

    /// Calibrate on the current hardware.
    ///
    /// * `sizes` — sizes to benchmark (should span the range you care about).
    /// * `max_threads` — upper bound for thread counts to try.
    /// * `iters` — timing iterations per measurement (more = steadier, slower).
    ///
    /// The resulting `Calibration` picks the fastest Pippenger thread count per
    /// size, then collapses adjacent sizes with the same winner into a single
    /// table row.
    pub fn calibrate<G: VariableBaseMSM>(
        sizes: &[usize],
        max_threads: usize,
        iters: usize,
    ) -> Calibration {
        assert!(!sizes.is_empty(), "calibrate: sizes is empty");
        assert!(max_threads >= 1, "calibrate: max_threads must be >= 1");
        assert!(iters >= 1, "calibrate: iters must be >= 1");
        let mut rng = ark_std::test_rng();

        let mut naive_threshold = usize::MAX;
        let mut per_size: Vec<(usize, usize)> = Vec::with_capacity(sizes.len());

        for &n in sizes {
            let (bases, scalars) = random_inputs::<G, _>(n, &mut rng);

            let naive_time = time_it(iters, || {
                let _ = naive_msm::<G>(&bases, &scalars);
            });

            // Best thread count for Pippenger at this size.
            let mut best_threads = 1usize;
            let mut best_pip_time = Duration::MAX;
            for t in 1..=max_threads {
                let elapsed = bench_pippenger::<G>(t, iters, &bases, &scalars);
                if elapsed < best_pip_time {
                    best_pip_time = elapsed;
                    best_threads = t;
                }
            }

            // Smallest size where Pippenger wins → becomes the naive threshold.
            if naive_threshold == usize::MAX && best_pip_time < naive_time {
                naive_threshold = n;
            }

            println!(
                "  n={n:>7}  naive={naive_time:?}  pippenger(best t={best_threads})={best_pip_time:?}"
            );
            per_size.push((n, best_threads));
        }

        if naive_threshold == usize::MAX {
            // Pippenger never won in the swept range — keep naive for everything.
            naive_threshold = *sizes.last().unwrap();
        }

        // Collapse adjacent sizes with the same winning thread count into ranges.
        let mut thread_table: Vec<(usize, usize, usize)> = Vec::new();
        for (n, t) in &per_size {
            match thread_table.last_mut() {
                Some(last) if last.2 == *t => last.1 = *n + 1,
                _ => thread_table.push((*n, *n + 1, *t)),
            }
        }
        // Extend the first row down to 0 and the last row to usize::MAX so the
        // table covers the full input space.
        if let Some(first) = thread_table.first_mut() {
            first.0 = 0;
        }
        if let Some(last) = thread_table.last_mut() {
            last.1 = usize::MAX;
        }

        Calibration {
            naive_threshold,
            thread_table,
        }
    }

    fn bench_pippenger<G: VariableBaseMSM>(
        threads: usize,
        iters: usize,
        bases: &[G::MulBase],
        scalars: &[G::ScalarField],
    ) -> Duration {
        #[cfg(feature = "parallel")]
        {
            pool::install(threads, || {
                time_it(iters, || {
                    let _ = G::msm_unchecked(bases, scalars);
                })
            })
        }
        #[cfg(not(feature = "parallel"))]
        {
            let _ = threads;
            time_it(iters, || {
                let _ = G::msm_unchecked(bases, scalars);
            })
        }
    }

    fn time_it<F: FnMut()>(iters: usize, mut f: F) -> Duration {
        // Warm-up so caches, thread pools, and JIT-like state are primed.
        f();
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        start.elapsed() / iters as u32
    }

    fn random_inputs<G: VariableBaseMSM, R: Rng>(
        n: usize,
        rng: &mut R,
    ) -> (Vec<G::MulBase>, Vec<G::ScalarField>) {
        let bases_proj: Vec<G> = (0..n).map(|_| G::rand(rng)).collect();
        let bases = G::batch_convert_to_mul_base(&bases_proj);
        let scalars: Vec<G::ScalarField> = (0..n).map(|_| G::ScalarField::rand(rng)).collect();
        (bases, scalars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-utils")]
    #[test]
    fn msm_matches_naive_on_bn254_g1() {
        use ark_bn254::{Fr, G1Projective};
        use ark_ec::ScalarMul;
        use ark_std::{UniformRand, test_rng};

        let mut rng = test_rng();

        // Span both sides of the naive threshold so both code paths get hit.
        for n in [
            1usize,
            5,
            NAIVE_THRESHOLD.saturating_sub(1),
            NAIVE_THRESHOLD,
            NAIVE_THRESHOLD + 17,
            256,
            1024,
        ] {
            if n == 0 {
                continue;
            }
            let bases_proj: Vec<G1Projective> =
                (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
            let bases = G1Projective::batch_convert_to_mul_base(&bases_proj);
            let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

            let fast: G1Projective = msm(&bases, &scalars);
            let naive: G1Projective = naive_msm(&bases, &scalars);
            assert_eq!(fast, naive, "msm mismatch at n={n}");
        }
    }
}
