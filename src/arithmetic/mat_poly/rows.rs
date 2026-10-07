//! Row-wise sums of products of MLEs, read from each factor's own storage.
//!
//! Expanding a compressed column to field elements costs a conversion per
//! row, and a product of such columns a multiplication per factor on top.
//! Most products a prover materializes are much simpler than that: a column
//! of small integers switched on and off by 0/1 columns and scaled by a
//! constant. Those are read here as what they are.

use std::borrow::Cow;

use ark_ff::PrimeField;
use ark_std::{cfg_chunks_mut, cfg_iter};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::mle::{MLE, MLEStorage};

/// Rows handed to one job of a parallel pass.
const ROWS_PER_JOB: usize = 1 << 12;

/// A column whose values all lie below this is scaled through a table of
/// the multiples of the scalar instead of a multiplication per row.
const TABLE_VALUES: u64 = 1 << 16;

/// A column of unsigned integers, whatever their width.
#[derive(Clone, Copy)]
enum Ints<'a> {
    U8(&'a [u8]),
    U32(&'a [u32]),
    U64(&'a [u64]),
}

impl Ints<'_> {
    #[inline]
    fn get(&self, row: usize) -> u64 {
        match self {
            Ints::U8(values) => u64::from(values[row]),
            Ints::U32(values) => u64::from(values[row]),
            Ints::U64(values) => values[row],
        }
    }

    fn max(&self) -> u64 {
        match self {
            Ints::U8(values) => cfg_iter!(values).copied().max().map(u64::from),
            Ints::U32(values) => cfg_iter!(values).copied().max().map(u64::from),
            Ints::U64(values) => cfg_iter!(values).copied().max(),
        }
        .unwrap_or(0)
    }

    /// `scalar·v` for every `v` up to the largest in the column, if those
    /// are few enough for the table to be cheaper than the `rows`
    /// multiplications it saves.
    fn multiples_of<F: PrimeField>(&self, scalar: F, rows: usize) -> Option<Vec<F>> {
        let max = self.max();
        if max >= TABLE_VALUES || max > rows as u64 {
            return None;
        }
        let mut multiple = F::zero();
        Some(
            (0..=max)
                .map(|_| {
                    let current = multiple;
                    multiple += scalar;
                    current
                })
                .collect(),
        )
    }
}

fn for_each_row<F: Send>(acc: &mut [F], row: impl Fn(usize, &mut F) + Sync) {
    cfg_chunks_mut!(acc, ROWS_PER_JOB)
        .enumerate()
        .for_each(|(job, slots)| {
            let first = job * ROWS_PER_JOB;
            for (offset, slot) in slots.iter_mut().enumerate() {
                row(first + offset, slot);
            }
        });
}

/// Adds `coeff · prod_f factors[f]` to `acc`, row by row. A factor with
/// fewer rows than `acc` repeats along the others, as it does in a sumcheck.
pub(crate) fn add_scaled_product<F: PrimeField>(acc: &mut [F], coeff: F, factors: &[&MLE<F>]) {
    let mut coeff = coeff;
    // Each factor comes with the mask that takes a row of `acc` to its own.
    let mut gates: Vec<(&[u8], usize)> = Vec::new();
    let mut ints: Vec<(Ints, usize)> = Vec::new();
    let mut fields: Vec<(Cow<[F]>, usize)> = Vec::new();
    for factor in factors {
        let storage = factor.storage();
        let mask = storage.inner_len().min(1 << factor.num_vars()) - 1;
        match storage {
            MLEStorage::Constant { value, .. } => coeff *= value,
            MLEStorage::Bit { bits, .. } => gates.push((bits, mask)),
            MLEStorage::U8 { bytes, .. } => ints.push((Ints::U8(bytes), mask)),
            MLEStorage::U32 { words, .. } => ints.push((Ints::U32(words), mask)),
            MLEStorage::U64 { words, .. } => ints.push((Ints::U64(words), mask)),
            MLEStorage::Field(dense) => fields.push((Cow::Borrowed(&dense.evaluations), mask)),
            // The remaining kinds are slow to read row by row, a lazy
            // inverse most of all: expand them once.
            _ => fields.push((Cow::Owned(storage.to_evaluations_vec()), mask)),
        }
    }
    if coeff.is_zero() {
        return;
    }

    // A 0/1 factor decides whether a row gets anything at all.
    let open = |row: usize| {
        gates.iter().all(|(bits, mask)| {
            let row = row & mask;
            (bits[row >> 3] >> (row & 7)) & 1 == 1
        })
    };
    match (&ints[..], &fields[..]) {
        ([], []) => for_each_row(acc, |row, slot| {
            if open(row) {
                *slot += coeff;
            }
        }),
        ([(column, mask)], []) => match column.multiples_of(coeff, acc.len()) {
            Some(multiples) => for_each_row(acc, |row, slot| {
                if open(row) {
                    *slot += multiples[column.get(row & mask) as usize];
                }
            }),
            None => for_each_row(acc, |row, slot| {
                if open(row) {
                    *slot += coeff * F::from(column.get(row & mask));
                }
            }),
        },
        ([], [(column, mask)]) if coeff.is_one() => for_each_row(acc, |row, slot| {
            if open(row) {
                *slot += column[row & mask];
            }
        }),
        _ => for_each_row(acc, |row, slot| {
            if open(row) {
                let mut product = coeff;
                for (column, mask) in &ints {
                    product *= F::from(column.get(row & mask));
                }
                for (column, mask) in &fields {
                    product *= column[row & mask];
                }
                *slot += product;
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ark_bn254::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};
    use proptest::prelude::*;

    use super::*;

    const NV: usize = 7;

    /// The product the slow way: every factor expanded to field elements.
    fn expanded(acc: &mut [Fr], coeff: Fr, factors: &[&MLE<Fr>]) {
        let columns: Vec<Vec<Fr>> = factors.iter().map(|factor| factor.evaluations()).collect();
        for (row, slot) in acc.iter_mut().enumerate() {
            let mut product = coeff;
            for column in &columns {
                product *= column[row % column.len()];
            }
            *slot += product;
        }
    }

    fn assert_same_rows(rows: usize, coeff: Fr, factors: &[&MLE<Fr>]) {
        // Something to add to, so that a row left alone is told from a row
        // overwritten.
        let start: Vec<Fr> = (0..rows as u64)
            .map(|row| Fr::from(row * row + 3))
            .collect();
        let mut fast = start.clone();
        add_scaled_product(&mut fast, coeff, factors);
        let mut slow = start;
        expanded(&mut slow, coeff, factors);
        assert_eq!(fast, slow);
    }

    fn from_values(nv: usize, value: impl Fn(u64) -> Fr) -> MLE<Fr> {
        MLE::from_evaluations_vec(nv, (0..1u64 << nv).map(value).collect())
    }

    /// One column per storage kind over `nv` variables, with the kind's tag.
    fn every_kind(nv: usize, rng: &mut StdRng) -> Vec<MLE<Fr>> {
        let rows = 1usize << nv;
        // Random values below `modulus`, the largest of them among them so
        // that the column is stored as wide as intended.
        let mut scatter = |modulus: u64| -> Vec<u64> {
            let mut values: Vec<u64> = (0..rows).map(|_| rng.gen_range(0..modulus)).collect();
            values[0] = modulus - 1;
            values
        };
        let bits = scatter(2);
        let bytes = scatter(256);
        let words = scatter(1 << 16);
        let wide_words = scatter(1 << 31);
        let long_words = scatter(1 << 60);
        let source = Arc::new(from_values(nv, |row| Fr::from(row + 1)));
        // A few exceptions to a default, at scattered rows.
        let exceptions = |value: u64| -> Vec<(u32, u64)> {
            (0..rows as u32)
                .filter(|row| row % 5 == 3)
                .map(|row| (row, value + u64::from(row)))
                .collect()
        };
        let columns = vec![
            (
                "bit",
                from_values(nv, |row| Fr::from(bits[row as usize])).compressed(),
            ),
            (
                "u8",
                from_values(nv, |row| Fr::from(bytes[row as usize])).compressed(),
            ),
            (
                "u32",
                from_values(nv, |row| Fr::from(words[row as usize])).compressed(),
            ),
            (
                "u32",
                from_values(nv, |row| Fr::from(wide_words[row as usize])).compressed(),
            ),
            (
                "u64",
                from_values(nv, |row| Fr::from(long_words[row as usize])).compressed(),
            ),
            ("field", from_values(nv, |row| -Fr::from(row * 7 + 1))),
            (
                "const",
                from_values(nv, |_| Fr::from(41u64))
                    .compressed()
                    .detect_redundancy(),
            ),
            (
                "rle",
                from_values(nv, |row| Fr::from(row >> (nv - 2)))
                    .compressed()
                    .detect_redundancy(),
            ),
            (
                "sparse",
                MLE::from_sparse(
                    -Fr::one(),
                    exceptions(9)
                        .into_iter()
                        .map(|(row, v)| (row, Fr::from(v)))
                        .collect(),
                    nv,
                )
                .unwrap(),
            ),
            (
                "sparseU8",
                MLE::from_sparse_u8(
                    200,
                    exceptions(0)
                        .into_iter()
                        .map(|(row, v)| (row, (v % 199) as u8))
                        .collect(),
                    nv,
                )
                .unwrap(),
            ),
            (
                "sparseU32",
                MLE::from_sparse_u32(
                    70_000,
                    exceptions(1)
                        .into_iter()
                        .map(|(row, v)| (row, v as u32))
                        .collect(),
                    nv,
                )
                .unwrap(),
            ),
            (
                "sparseU64",
                MLE::from_sparse_u64(1 << 50, exceptions(2), nv).unwrap(),
            ),
            (
                "dec128",
                MLE::from_packed_decimal(scatter(1 << 30), scatter(u64::MAX), 2, nv),
            ),
            (
                "lazy_inv",
                MLE::from_lazy_inverse_shifted(source.clone(), -Fr::from(3u64)),
            ),
            (
                "lazy_inv_sum",
                MLE::from_lazy_inverse_shifted_sum(source.clone(), source, -Fr::from(5u64)),
            ),
        ];
        columns
            .into_iter()
            .map(|(tag, column)| {
                assert_eq!(column.storage().kind_tag(), tag);
                column
            })
            .collect()
    }

    /// Every storage kind alone, scaled by one and by something else, and
    /// every pair of kinds.
    #[test]
    fn products_read_from_storage_match_expanded_products() {
        let mut rng = StdRng::seed_from_u64(1);
        let columns = every_kind(NV, &mut rng);
        let scalar = Fr::rand(&mut rng);
        for first in &columns {
            assert_same_rows(1 << NV, Fr::one(), &[first]);
            assert_same_rows(1 << NV, scalar, &[first]);
            assert_same_rows(1 << NV, Fr::zero(), &[first]);
            for second in &columns {
                assert_same_rows(1 << NV, scalar, &[first, second]);
            }
        }
        // No factors at all: the constant itself.
        assert_same_rows(1 << NV, scalar, &[]);
    }

    /// A column of fewer variables repeats, whether it says so itself or is
    /// simply shorter than the rows asked for.
    #[test]
    fn narrower_factors_repeat() {
        let mut rng = StdRng::seed_from_u64(2);
        let scalar = Fr::rand(&mut rng);
        let wide = every_kind(NV, &mut rng);
        for narrow_nv in [2, NV - 3] {
            for mut narrow in every_kind(narrow_nv, &mut rng) {
                assert_same_rows(1 << NV, scalar, &[&narrow]);
                assert_same_rows(1 << NV, scalar, &[&narrow, &wide[2], &wide[0]]);
                narrow.set_virtual_nv(NV);
                assert_same_rows(1 << NV, Fr::one(), &[&narrow]);
                assert_same_rows(1 << NV, scalar, &[&wide[0], &narrow]);
            }
        }
        for narrow_nv in [0, 1] {
            let narrow = from_values(narrow_nv, |row| Fr::from(row + 2)).compressed();
            assert_same_rows(1 << NV, scalar, &[&narrow, &wide[1]]);
        }
        // More rows than are asked for: the first ones are read.
        assert_same_rows(1 << (NV - 2), scalar, &[&wide[2], &wide[0]]);
    }

    /// Small integers go through a table of multiples, up to a largest
    /// value and only when there are rows enough to make it worthwhile.
    #[test]
    fn table_of_multiples_has_the_values_of_the_column() {
        let scalar = Fr::from(123_456_789u64);
        for (nv, max, tabled) in [
            (4, 15, true),
            (4, 16, true),
            (4, 17, false),
            (17, TABLE_VALUES - 1, true),
            (17, TABLE_VALUES, false),
        ] {
            let mut words: Vec<u32> = (0..1u64 << nv)
                .map(|row| ((row * 31) % (max + 1)) as u32)
                .collect();
            words[0] = max as u32;
            let column = MLE::from_u32s(words.clone(), nv);
            let multiples = Ints::U32(&words).multiples_of(scalar, 1 << nv);
            assert_eq!(multiples.is_some(), tabled);
            if let Some(multiples) = multiples {
                assert_eq!(multiples.len() as u64, max + 1);
                for (value, multiple) in multiples.iter().enumerate() {
                    assert_eq!(*multiple, scalar * Fr::from(value as u64));
                }
            }
            assert_same_rows(1 << nv, scalar, &[&column]);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Random products of random kinds and widths.
        #[test]
        fn random_products_match_expanded_products(
            picks in proptest::collection::vec((0usize..15, 0usize..3), 0..5),
            scalar in 0u64..3,
            seed in any::<u64>(),
        ) {
            let mut rng = StdRng::seed_from_u64(seed);
            let by_width = [every_kind(NV, &mut rng), every_kind(NV - 2, &mut rng), every_kind(2, &mut rng)];
            let factors: Vec<&MLE<Fr>> = picks.iter().map(|(kind, width)| &by_width[*width][*kind]).collect();
            let coeff = match scalar {
                0 => Fr::one(),
                1 => -Fr::one(),
                _ => Fr::rand(&mut rng),
            };
            assert_same_rows(1 << NV, coeff, &factors);
        }
    }
}
