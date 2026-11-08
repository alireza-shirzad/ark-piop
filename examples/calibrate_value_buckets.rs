//! Times the bucketed commitment of `ark_piop::pcs::pst13::value_buckets`
//! against the MSM over the table it commits, and prints what the guard
//! decides for each case, to check `MARGIN`, `SCAN_COST` and `THREAD_COST` on this
//! machine.
//!
//!     cargo run --release --example calibrate_value_buckets --features test-utils -- 1,16
//!
//! The argument lists the thread counts. Prints one CSV row per case: rows,
//! columns, how the values are drawn, the bound on them, threads, both
//! times, the guard's choice, and the entries and distinct values it saw
//! besides the most frequent one. A row with `guard = bucket` and a speedup
//! below 1 is a case the guard gets wrong.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, UniformRand};
use ark_piop::pcs::pst13::value_buckets::{Histogram, bucketing_pays, commit};
use ark_std::rand::{Rng, seq::SliceRandom};
use rayon::prelude::*;
use std::time::Instant;

fn best_of<T>(runs: usize, mut f: impl FnMut() -> T) -> f64 {
    (0..runs)
        .map(|_| {
            let start = Instant::now();
            std::hint::black_box(f());
            start.elapsed().as_secs_f64()
        })
        .fold(f64::MAX, f64::min)
}

/// The values of a column of `n` rows below `bound`.
fn draw(shape: &str, n: usize, bound: usize, rng: &mut impl Rng) -> Vec<u32> {
    let uniform = |rng: &mut dyn ark_std::rand::RngCore| rng.gen_range(0..bound as u32);
    match shape {
        "uniform" => (0..n).map(|_| uniform(rng)).collect(),
        "mode50" | "mode90" => {
            let share = if shape == "mode50" { 0.5 } else { 0.9 };
            (0..n)
                .map(|_| if rng.gen_bool(share) { 0 } else { uniform(rng) })
                .collect()
        }
        // Two values with 45% of the entries each.
        "heavy" => (0..n)
            .map(|_| match rng.gen_range(0..20) {
                0..9 => 0,
                9..18 => 1,
                _ => uniform(rng),
            })
            .collect(),
        // Small values far more often than large ones.
        "zipf" => (0..n)
            .map(|_| ((bound as f64) * rng.gen_range(0.0f64..1.0).powi(3)) as u32)
            .collect(),
        // Every value once: the most distinct values a column can have.
        "distinct" => {
            let mut values: Vec<u32> = (0..n as u32).collect();
            values.shuffle(rng);
            values
        }
        _ => unreachable!(),
    }
}

fn main() {
    let mut rng = ark_std::test_rng();
    let max_log = 22;
    let g = G1Projective::rand(&mut rng);
    let mut acc = g;
    let bases: Vec<G1Affine> = G1Projective::normalize_batch(
        &(0..1usize << max_log)
            .map(|_| {
                acc += g;
                acc
            })
            .collect::<Vec<_>>(),
    );
    let threads: Vec<usize> = std::env::args()
        .nth(1)
        .map(|arg| arg.split(',').map(|t| t.parse().unwrap()).collect())
        .unwrap_or(vec![1, 16]);
    let bits = Fr::MODULUS_BIT_SIZE as usize;
    println!("rows_log,cols,shape,bound,threads,dense_s,bucketed_s,speedup,guard,entries,distinct");
    for &t in &threads {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(t)
            .build()
            .unwrap();
        pool.install(|| {
            for rows_log in [10usize, 12, 14, 16, 18, 20, 22] {
                if t < 4 && rows_log == 22 {
                    continue;
                }
                let n = 1usize << rows_log;
                let bases = &bases[..n];
                let total: G1Projective =
                    G1Projective::msm_unchecked(bases, &vec![Fr::from(1u64); n]);
                for cols in [1usize, 2] {
                    for shape in ["uniform", "mode50", "mode90", "heavy", "zipf", "distinct"] {
                        // Values from 2^20 up are never bucketed.
                        let ratios: &[f64] = match shape {
                            "distinct" if n > 1 << 20 => &[],
                            "distinct" => &[1.0],
                            _ => &[1.0 / 256.0, 1.0 / 16.0, 0.25, 0.5, 0.75, 1.0, 2.0],
                        };
                        for ratio in ratios {
                            let bound = ((n as f64 * ratio) as usize).clamp(2, 1 << 20);
                            let values: Vec<Vec<u32>> =
                                (0..cols).map(|_| draw(shape, n, bound, &mut rng)).collect();
                            let columns: Vec<Vec<Fr>> = values
                                .iter()
                                .map(|col| col.iter().map(|v| Fr::from(*v as u64)).collect())
                                .collect();
                            let gamma = Fr::rand(&mut rng);
                            let mut table: Vec<Fr> =
                                (0..bound).map(|v| Fr::from(v as u64) - gamma).collect();
                            ark_ff::batch_inversion(&mut table);
                            let dense: Vec<Fr> = (0..n)
                                .map(|row| values.iter().map(|col| table[col[row] as usize]).sum())
                                .collect();
                            let runs = if rows_log >= 20 { 1 } else { 3 };
                            let dense_s =
                                best_of(runs, || G1Projective::msm_unchecked(bases, &dense));
                            let (mut decided, mut entries, mut distinct) = (false, 0, 0);
                            let bucketed_s = best_of(runs, || {
                                let small: Vec<Vec<u32>> = columns
                                    .iter()
                                    .map(|col| {
                                        col.par_iter()
                                            .map(|value| value.into_bigint().as_ref()[0] as u32)
                                            .collect()
                                    })
                                    .collect();
                                let views: Vec<&[u32]> = small.iter().map(Vec::as_slice).collect();
                                let histogram = Histogram::of(&views, bound).unwrap();
                                (entries, distinct) = (histogram.entries(), histogram.distinct());
                                decided = bucketing_pays(n, cols * n, entries, distinct, bits, t);
                                commit(bases, total, &views, &table, &histogram)
                            });
                            println!(
                                "{rows_log},{cols},{shape},{bound},{t},{dense_s:.5},{bucketed_s:.5},{:.2},{},{entries},{distinct}",
                                dense_s / bucketed_s,
                                if decided { "bucket" } else { "msm" }
                            );
                        }
                    }
                }
            }
        });
    }
}
