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
use ark_std::{cfg_into_iter, vec::Vec};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Values past this are not bucketed: the histogram and the slot table are
/// indexed by value.
pub const MAX_VALUE_BOUND: usize = 1 << 20;

/// The share of the table's MSM the bucketed commitment may cost, so that
/// columns near the break-even stay on the MSM despite the model's error.
/// Checked with `examples/calibrate_value_buckets.rs`, as is [`SCAN_COST`].
pub const MARGIN: f64 = 0.9;

/// Cost of reading one entry (histogram, value range scans), in point
/// additions.
pub const SCAN_COST: f64 = 0.05;

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
/// scalars: `entries` additions, an MSM over the buckets and a scan of all
/// `scanned` entries, against [`msm_additions`] of the table.
pub fn bucketing_pays(
    rows: usize,
    scanned: usize,
    entries: usize,
    distinct: usize,
    bits: usize,
) -> bool {
    let bucketed = entries as f64 + msm_additions(distinct, bits) + SCAN_COST * scanned as f64;
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
        let mut counts = vec![0u32; bound];
        for col in cols {
            for &value in *col {
                *counts.get_mut(value as usize)? += 1;
            }
        }
        let (mode, mode_count) = counts
            .iter()
            .enumerate()
            .max_by_key(|(value, count)| (**count, core::cmp::Reverse(*value)))
            .map(|(value, count)| (value as u32, *count as usize))?;
        let present = counts.iter().filter(|count| **count != 0).count();
        let total: usize = cols.iter().map(|col| col.len()).sum();
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

/// `Σ_x Σ_j s[c_j(x)]·bases[x]` for `table[v] = s[v]`, given `total = Σ_x
/// bases[x]`. Every column has one entry per base, and every value in the
/// histogram indexes `table`.
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
        distinct,
        entries,
    } = histogram;
    // Buckets are numbered in value order, the mode skipped. A part owns a
    // run of values with about its share of the entries, and adds only those
    // as it scans the columns, so that no bucket is shared between parts.
    let mut slot = vec![u32::MAX; counts.len()];
    let mut values = Vec::with_capacity(*distinct);
    for (value, count) in counts.iter().enumerate() {
        if *count != 0 && value as u32 != *mode {
            slot[value] = values.len() as u32;
            values.push(value as u32);
        }
    }
    #[cfg(feature = "parallel")]
    let parts = rayon::current_num_threads().clamp(1, values.len().max(1));
    #[cfg(not(feature = "parallel"))]
    let parts = 1;
    let mut cuts = vec![0usize];
    let mut seen = 0usize;
    for (at, value) in values.iter().enumerate() {
        seen += counts[*value as usize] as usize;
        if seen * parts >= entries * cuts.len() && cuts.len() < parts {
            cuts.push(at + 1);
        }
    }
    if *cuts.last().expect("starts with 0") != values.len() {
        cuts.push(values.len());
    }
    let buckets: Vec<Vec<G>> = cfg_into_iter!(0..cuts.len() - 1)
        .map(|part| {
            let (first, end) = (cuts[part] as u32, cuts[part + 1] as u32);
            let mut buckets = vec![G::zero(); (end - first) as usize];
            for col in cols {
                for (row, &value) in col.iter().enumerate() {
                    let at = slot[value as usize].wrapping_sub(first);
                    if at < end - first {
                        buckets[at as usize] += &bases[row];
                    }
                }
            }
            buckets
        })
        .collect();
    let buckets = buckets.concat();
    let skipped = table[*mode as usize];
    let scalars: Vec<G::ScalarField> = values
        .iter()
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

    #[test]
    fn values_past_the_bound_are_refused() {
        assert!(Histogram::of(&[&[0, 1, 9]], 8).is_none());
    }

    #[test]
    fn guard_follows_the_value_count() {
        let rows = 1 << 19;
        assert!(bucketing_pays(rows, 2 * rows, 2 * rows, 1 << 16, 254));
        assert!(!bucketing_pays(rows, 2 * rows, 2 * rows, rows, 254));
    }
}
