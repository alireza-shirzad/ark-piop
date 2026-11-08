//! Commitment to `x ↦ Σ_j s[c_j(x)]` for `k` columns `c_j` of small integers,
//! one MSM base `G_x` per row, through one bucket per value.
//!
//! With `B_v = Σ_{(x, j): c_j(x) = v} G_x` the commitment is `Σ_v s[v]·B_v`:
//! a point addition per entry and an MSM over the values present, where
//! committing the table would be an MSM over all `2^nv` rows with
//! full-width scalars. The most frequent value `m` is never added, since
//! `Σ_v s[v]·B_v = Σ_{v≠m} (s[v] − s[m])·B_v + k·s[m]·Σ_x G_x`.
//!
//! Whether it pays is decided on the columns alone, before any point is
//! added ([`bucketing_pays`]): too many distinct values make the MSM over
//! the buckets about as large as the one it replaces.

use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ff::Zero;
use ark_std::{cfg_chunks, cfg_chunks_mut, cfg_into_iter, cfg_iter, cfg_iter_mut, vec::Vec};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Values past this are not bucketed: the histogram and the slot table are
/// indexed by value.
pub const MAX_VALUE_BOUND: usize = 1 << 20;

/// The share of the table's MSM the bucketed commitment may cost, so that
/// columns near the break-even stay on the MSM despite the model's error.
/// Checked with `examples/calibrate_value_buckets.rs`, as are [`SCAN_COST`]
/// and [`THREAD_COST`].
pub const MARGIN: f64 = 0.9;

/// Cost of reading one entry (histogram, value range scans), in point
/// additions.
pub const SCAN_COST: f64 = 0.05;

/// Fixed cost of each thread beyond the first, in point additions: the
/// tables and tasks a commitment of a few thousand rows does not earn back
/// when it is split across many threads.
pub const THREAD_COST: f64 = 600.0;

/// Point additions of `msm_unchecked` over `n` full-width scalars of
/// `bits` bits, as ark-ec 0.5's windowed NAF runs it: a window of `c` bits
/// adds every row into a bucket and sums `2^(c−1)` buckets twice.
pub fn msm_additions(n: usize, bits: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let c = if n < 32 {
        3
    } else {
        (ark_std::log2(n) as usize) * 69 / 100 + 2
    };
    let windows = bits.div_ceil(c) + 1;
    (windows * (n + (1usize << c))) as f64
}

/// Whether bucketing `entries` additions into `distinct` buckets, besides
/// the most frequent value, costs less than an MSM over `rows` full-width
/// scalars on `threads` threads: `entries` additions, an MSM over the
/// buckets, a scan of all `scanned` entries and [`THREAD_COST`], against
/// [`msm_additions`] of the table.
pub fn bucketing_pays(
    rows: usize,
    scanned: usize,
    entries: usize,
    distinct: usize,
    bits: usize,
    threads: usize,
) -> bool {
    let bucketed = entries as f64
        + msm_additions(distinct, bits)
        + SCAN_COST * scanned as f64
        + THREAD_COST * threads.saturating_sub(1) as f64;
    bucketed < MARGIN * msm_additions(rows, bits)
}

/// How the entries of the columns fall on values.
pub struct Histogram {
    counts: Vec<u32>,
    /// The most frequent value.
    mode: u32,
    /// Distinct values other than the mode.
    distinct: usize,
    /// Entries not equal to the mode.
    entries: usize,
}

impl Histogram {
    /// `None` if a value is `bound` or more.
    pub fn of(cols: &[&[u32]], bound: usize) -> Option<Self> {
        let total: usize = cols.iter().map(|col| col.len()).sum();
        // Each chunk counts into a table of its own, and a chunk has at least
        // `bound` entries, so that the tables never outweigh the entries.
        let chunk = (total / threads()).max(bound).max(1);
        let chunks: Vec<&[u32]> = cols.iter().flat_map(|col| col.chunks(chunk)).collect();
        let mut tables: Vec<Vec<u32>> = cfg_iter!(chunks)
            .map(|chunk| {
                let mut counts = vec![0u32; bound];
                for &value in *chunk {
                    *counts.get_mut(value as usize)? += 1;
                }
                Some(counts)
            })
            .collect::<Option<_>>()?;
        let counts = match tables.len() {
            0 => vec![0; bound],
            1 => tables.pop().expect("one table"),
            _ => cfg_into_iter!(0..bound)
                .map(|value| tables.iter().map(|counts| counts[value]).sum())
                .collect(),
        };
        let (mode, mode_count) = cfg_iter!(counts)
            .enumerate()
            .max_by_key(|(value, count)| (**count, core::cmp::Reverse(*value)))
            .map(|(value, count)| (value as u32, *count as usize))?;
        let present = cfg_iter!(counts).filter(|count| **count != 0).count();
        Some(Self {
            counts,
            mode,
            distinct: present - usize::from(mode_count != 0),
            entries: total - mode_count,
        })
    }

    pub fn distinct(&self) -> usize {
        self.distinct
    }

    pub fn entries(&self) -> usize {
        self.entries
    }
}

#[cfg(feature = "parallel")]
pub fn threads() -> usize {
    rayon::current_num_threads().max(1)
}

#[cfg(not(feature = "parallel"))]
pub fn threads() -> usize {
    1
}

/// `Σ_x Σ_j s[c_j(x)]·bases[x]` for `table[v] = s[v]`, given `total = Σ_x
/// bases[x]`. Every column has one entry per base, and every value in the
/// histogram indexes `table`.
///
/// Buckets are numbered in value order, the mode skipped, and cut into runs
/// of about `entries / threads` entries each. A run adds only its own
/// values as it scans the columns, so runs share no bucket; a value with
/// more entries than a run is split by rows instead, and its partial sums
/// are added at the end.
pub fn commit<G: VariableBaseMSM>(
    bases: &[G::MulBase],
    total: G,
    cols: &[&[u32]],
    table: &[G::ScalarField],
    histogram: &Histogram,
) -> G {
    let Histogram {
        counts,
        mode,
        entries,
        ..
    } = histogram;
    let kept = |value: usize| counts[value] != 0 && value as u32 != *mode;
    const BLOCK: usize = 1 << 12;
    let block_starts: Vec<u32> = {
        let sizes: Vec<u32> = cfg_into_iter!(0..counts.len().div_ceil(BLOCK))
            .map(|block| {
                let values = block * BLOCK..((block + 1) * BLOCK).min(counts.len());
                values.filter(|value| kept(*value)).count() as u32
            })
            .collect();
        sizes
            .iter()
            .scan(0, |start, size| {
                let this = *start;
                *start += size;
                Some(this)
            })
            .collect()
    };
    let mut slot = vec![u32::MAX; counts.len()];
    cfg_chunks_mut!(slot, BLOCK)
        .zip(cfg_iter!(block_starts))
        .enumerate()
        .for_each(|(block, (slots, start))| {
            let mut next = *start;
            for (at, slot) in slots.iter_mut().enumerate() {
                if kept(block * BLOCK + at) {
                    *slot = next;
                    next += 1;
                }
            }
        });
    let values: Vec<u32> = cfg_into_iter!(0..counts.len())
        .filter(|value| kept(*value))
        .map(|value| value as u32)
        .collect();

    // Runs of buckets: a cut wherever the running count of entries passes a
    // multiple of `share`, and around every value of more than `share`.
    let share = entries.div_ceil(threads()).max(1);
    let mut running: Vec<usize> = cfg_iter!(values)
        .map(|value| counts[*value as usize] as usize)
        .collect();
    let block_totals: Vec<usize> = cfg_chunks!(running, BLOCK)
        .map(|block| block.iter().sum())
        .collect();
    let block_offsets: Vec<usize> = block_totals
        .iter()
        .scan(0, |seen, total| {
            let before = *seen;
            *seen += total;
            Some(before)
        })
        .collect();
    cfg_chunks_mut!(running, BLOCK)
        .zip(cfg_iter!(block_offsets))
        .for_each(|(block, offset)| {
            let mut seen = *offset;
            for count in block {
                seen += *count;
                *count = seen;
            }
        });
    let heavy: Vec<usize> = cfg_into_iter!(0..values.len())
        .filter(|at| counts[values[*at] as usize] as usize > share)
        .collect();
    let mut cuts: Vec<usize> = (1..threads())
        .map(|part| running.partition_point(|seen| *seen <= part * share))
        .chain(heavy.iter().flat_map(|at| [*at, at + 1]))
        .chain([0, values.len()])
        .collect();
    cuts.sort_unstable();
    cuts.dedup();

    let mut buckets = vec![G::zero(); values.len()];
    let mut runs = Vec::with_capacity(cuts.len());
    let mut rest = buckets.as_mut_slice();
    for pair in cuts.windows(2) {
        let (run, tail) = rest.split_at_mut(pair[1] - pair[0]);
        runs.push((pair[0] as u32, run));
        rest = tail;
    }
    let rows = bases.len();
    cfg_iter_mut!(runs).for_each(|(first, run)| {
        let first = *first;
        let count = counts[values[first as usize] as usize] as usize;
        if run.len() == 1 && count > share {
            let pieces = count.div_ceil(share);
            let piece = rows.div_ceil(pieces);
            let partial: Vec<G> = cfg_into_iter!(0..pieces)
                .map(|at| {
                    let mut sum = G::zero();
                    for col in cols {
                        let end = ((at + 1) * piece).min(rows);
                        for row in (at * piece).min(end)..end {
                            if slot[col[row] as usize] == first {
                                sum += &bases[row];
                            }
                        }
                    }
                    sum
                })
                .collect();
            run[0] = partial.into_iter().fold(G::zero(), |sum, part| sum + part);
        } else {
            let len = run.len() as u32;
            for col in cols {
                for (row, &value) in col.iter().enumerate() {
                    let at = slot[value as usize].wrapping_sub(first);
                    if at < len {
                        run[at as usize] += &bases[row];
                    }
                }
            }
        }
    });

    let skipped = table[*mode as usize];
    let scalars: Vec<G::ScalarField> = cfg_iter!(values)
        .map(|value| table[*value as usize] - skipped)
        .collect();
    let mut acc = G::msm_unchecked(&G::batch_convert_to_mul_base(&buckets), &scalars);
    if !skipped.is_zero() {
        acc += total * (skipped * G::ScalarField::from(cols.len() as u64));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_std::rand::Rng;

    fn check(cols: Vec<Vec<u32>>, bound: usize) {
        let mut rng = ark_std::test_rng();
        let n = cols[0].len();
        let bases: Vec<_> = (0..n)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();
        let table: Vec<Fr> = (0..bound).map(|_| Fr::rand(&mut rng)).collect();
        let dense: Vec<Fr> = (0..n)
            .map(|row| cols.iter().map(|col| table[col[row] as usize]).sum())
            .collect();
        let expected = G1Projective::msm_unchecked(&bases, &dense);
        let total: G1Projective = bases.iter().copied().map(G1Projective::from).sum();
        let views: Vec<&[u32]> = cols.iter().map(Vec::as_slice).collect();
        let histogram = Histogram::of(&views, bound).unwrap();
        assert_eq!(commit(&bases, total, &views, &table, &histogram), expected);
    }

    #[test]
    fn matches_the_table_msm() {
        let mut rng = ark_std::test_rng();
        for (n, bound, cols) in [
            (1, 4, 1),
            (64, 8, 1),
            (1 << 10, 1 << 6, 2),
            (1 << 10, 1 << 12, 2),
            (777, 3, 3),
        ] {
            let cols = (0..cols)
                .map(|_| (0..n).map(|_| rng.gen_range(0..bound as u32)).collect())
                .collect();
            check(cols, bound);
        }
    }

    #[test]
    fn matches_on_skewed_and_constant_columns() {
        let mut rng = ark_std::test_rng();
        let skewed: Vec<u32> = (0..1024)
            .map(|_| {
                if rng.gen_bool(0.9) {
                    5
                } else {
                    rng.gen_range(0..64)
                }
            })
            .collect();
        let other: Vec<u32> = (0..1024).map(|_| rng.gen_range(0..64)).collect();
        check(vec![skewed.clone(), other], 64);
        check(vec![vec![7; 256]], 8);
        check(vec![vec![0; 256], vec![3; 256]], 4);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn matches_with_heavy_values_on_any_thread_count() {
        let mut rng = ark_std::test_rng();
        let mut draw = || -> Vec<u32> {
            (0..4096)
                .map(|_| match rng.gen_range(0..20) {
                    0..9 => 3,
                    9..18 => 7,
                    _ => rng.gen_range(0..64),
                })
                .collect()
        };
        let cols = vec![draw(), draw()];
        for threads in [1, 3, 8] {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| check(cols.clone(), 64));
        }
    }

    #[test]
    fn values_past_the_bound_are_refused() {
        assert!(Histogram::of(&[&[0, 1, 9]], 8).is_none());
    }

    #[test]
    fn guard_follows_the_value_count() {
        let rows = 1 << 19;
        assert!(bucketing_pays(rows, 2 * rows, 2 * rows, 1 << 16, 254, 16));
        assert!(!bucketing_pays(rows, 2 * rows, 2 * rows, rows, 254, 1));
        assert!(!bucketing_pays(1 << 10, 1 << 10, 1 << 10, 800, 254, 16));
    }
}
