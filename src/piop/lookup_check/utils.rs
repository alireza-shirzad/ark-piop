use crate::prover::structs::polynomial::TrackedPoly;
use crate::{SnarkBackend, arithmetic::mat_poly::mle::MLE};
use ark_ff::PrimeField;
use ark_std::{cfg_into_iter, cfg_iter};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// TODO: check for optimization; put in the paper
/// Output an MLE of the multiplicities with which super-column elements appear across
/// the included columns. The output length matches the super column.
pub fn calc_inclusion_multiplicity<B>(
    included_col: &[TrackedPoly<B>],
    super_col: &TrackedPoly<B>,
) -> MLE<B::F>
where
    B: SnarkBackend,
{
    let included_col_evals = included_col
        .iter()
        .map(|col| col.evaluations())
        .collect::<Vec<_>>();
    let super_col_evals = super_col.evaluations();

    calc_inclusion_multiplicity_from_evals::<B>(
        &included_col_evals,
        &super_col_evals,
        super_col.log_size(),
    )
}

/// Same as [`calc_inclusion_multiplicity`], but on pre-extracted evaluation vectors.
///
/// A repeated super-column value gets its full multiplicity at the first position
/// only (later duplicates get zero), keeping the LogUp identity
/// `sum_x m(x)/(g(x)-γ) = sum_v N_sub(v)/(v-γ)` balanced.
pub fn calc_inclusion_multiplicity_from_evals<B>(
    included_col_evals: &[Vec<B::F>],
    super_col_evals: &[B::F],
    super_col_nv: usize,
) -> MLE<B::F>
where
    B: SnarkBackend,
{
    let included: Vec<&[B::F]> = included_col_evals.iter().map(Vec::as_slice).collect();
    MLE::from_evaluations_vec(
        super_col_nv,
        inclusion_multiplicities(&included, super_col_evals),
    )
}

/// The evaluations behind [`calc_inclusion_multiplicity_from_evals`], from
/// borrowed columns: one multiplicity per super-column row.
pub(crate) fn inclusion_multiplicities<F: PrimeField>(
    included_col_evals: &[&[F]],
    super_col_evals: &[F],
) -> Vec<F> {
    multiplicities_by_counting(included_col_evals, super_col_evals)
        .unwrap_or_else(|| multiplicities_by_sorting(included_col_evals, super_col_evals))
}

/// The integer `value` is, if it is below `bound`.
#[inline]
fn small_key<F: PrimeField>(value: &F, bound: usize) -> Option<usize> {
    let repr = value.into_bigint();
    let limbs = repr.as_ref();
    let low = usize::try_from(limbs[0]).ok()?;
    (low < bound && limbs[1..].iter().all(|limb| *limb == 0)).then_some(low)
}

/// [`multiplicities_by_sorting`] for a super column of small integers, such
/// as a range table: the included values are counted in an array indexed by
/// value, which takes one reduction per value where sorting takes several
/// field comparisons. `None` when the super column is not of that kind.
fn multiplicities_by_counting<F: PrimeField>(
    included_col_evals: &[&[F]],
    super_col_evals: &[F],
) -> Option<Vec<F>> {
    // The array may be this much longer than the super column. Beyond that
    // the column is too sparse in its range for an array to pay off.
    let bound = super_col_evals.len().checked_mul(8)?.max(1 << 16);
    let super_keys = cfg_iter!(super_col_evals)
        .map(|value| small_key(value, bound))
        .collect::<Option<Vec<usize>>>()?;
    let slots = super_keys.iter().max()? + 1;

    // A chunk of rows is counted on its own and the counts are added up, so
    // a chunk has to be worth the array it clears.
    let chunk_rows = slots.max(1 << 16);
    let chunks: Vec<&[F]> = included_col_evals
        .iter()
        .flat_map(|evals| evals.chunks(chunk_rows))
        .collect();
    let count = |chunk: &[F]| {
        let mut counts = vec![0u64; slots];
        // Equal neighbours are common (the zeros of inactive rows), and
        // comparing two values is much cheaper than reducing one.
        let mut previous = None;
        for value in chunk {
            let key = match previous {
                Some((seen, key)) if seen == value => key,
                _ => small_key(value, slots),
            };
            previous = Some((value, key));
            // A value outside the array is not in the super column.
            if let Some(key) = key {
                counts[key] += 1;
            }
        }
        counts
    };
    let add = |mut total: Vec<u64>, counts: Vec<u64>| {
        total.iter_mut().zip(counts).for_each(|(t, c)| *t += c);
        total
    };
    #[cfg(feature = "parallel")]
    let counts = chunks.into_par_iter().map(count).reduce_with(add);
    #[cfg(not(feature = "parallel"))]
    let counts = chunks.into_iter().map(count).reduce(add);
    let counts = counts.unwrap_or_else(|| vec![0; slots]);

    // The first occurrence of a value carries its count; later duplicates
    // get 0 so the super-column total equals the sub-union total.
    let mut seen = vec![false; slots];
    let credited: Vec<u64> = super_keys
        .into_iter()
        .map(|key| match std::mem::replace(&mut seen[key], true) {
            false => counts[key],
            true => 0,
        })
        .collect();
    Some(cfg_into_iter!(credited).map(F::from).collect())
}

/// Multiplicities for any super column, by sorting both sides.
pub(crate) fn multiplicities_by_sorting<F: PrimeField>(
    included_col_evals: &[&[F]],
    super_col_evals: &[F],
) -> Vec<F> {
    // Sort-based rather than a hash map: on a 2^23-entry super column the
    // map version was several seconds of one core per lookup, and this
    // runs inside a parallel job per super column.
    let mut included: Vec<F> = included_col_evals
        .iter()
        .flat_map(|evals| evals.iter().copied())
        .collect();
    sort_unstable(&mut included);
    // (value, count) runs, in value order.
    let mut runs: Vec<(F, u64)> = Vec::new();
    for val in included {
        match runs.last_mut() {
            Some((last, n)) if *last == val => *n += 1,
            _ => runs.push((val, 1)),
        }
    }

    // Super positions by value, ties by position: the first of each run is
    // the value's first occurrence, which carries the count; later
    // duplicates get 0 so the super-column total equals the sub-union total.
    let mut sup: Vec<(F, usize)> = cfg_iter!(super_col_evals)
        .enumerate()
        .map(|(i, &v)| (v, i))
        .collect();
    sort_unstable(&mut sup);

    let mut super_col_mult_evals = vec![F::zero(); super_col_evals.len()];
    let mut runs = runs.iter().peekable();
    let mut previous: Option<&F> = None;
    for (val, pos) in &sup {
        if previous == Some(val) {
            continue;
        }
        previous = Some(val);
        while runs.peek().is_some_and(|(v, _)| v < val) {
            runs.next();
        }
        if let Some((v, n)) = runs.peek()
            && v == val
        {
            super_col_mult_evals[*pos] = F::from(*n);
        }
    }

    super_col_mult_evals
}

fn sort_unstable<T: Ord + Send>(v: &mut [T]) {
    #[cfg(feature = "parallel")]
    {
        use rayon::slice::ParallelSliceMut;
        v.par_sort_unstable();
    }
    #[cfg(not(feature = "parallel"))]
    v.sort_unstable();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultSnarkBackend;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};
    use proptest::prelude::*;

    type F = <DefaultSnarkBackend as SnarkBackend>::F;

    fn fr(v: u64) -> F {
        F::from(v)
    }

    /// Both ways of computing the multiplicities, checked to agree wherever
    /// counting applies. Returns them and whether it applied.
    fn both_ways(included: &[Vec<F>], super_col: &[F]) -> (Vec<F>, bool) {
        let borrowed: Vec<&[F]> = included.iter().map(Vec::as_slice).collect();
        let sorted = multiplicities_by_sorting(&borrowed, super_col);
        let counted = multiplicities_by_counting(&borrowed, super_col);
        if let Some(counted) = &counted {
            assert_eq!(counted, &sorted);
        }
        assert_eq!(inclusion_multiplicities(&borrowed, super_col), sorted);
        (sorted, counted.is_some())
    }

    /// The count goes to the first of several equal super rows, and included
    /// values the super column lacks count nowhere.
    #[test]
    fn counting_credits_first_occurrence_and_ignores_missing_values() {
        let super_col: Vec<F> = [5u64, 3, 5, 0, 3, 9, 0, 5].map(fr).to_vec();
        let included = vec![
            [3u64, 3, 7, 5, 0, 0, 0, 1 << 40].map(fr).to_vec(),
            // A different length, a value above every array bound, and the
            // negative of a value that is there.
            vec![fr(9), -fr(3), fr(4), F::from(u128::MAX)],
        ];
        let (m, counted) = both_ways(&included, &super_col);
        assert!(counted);
        assert_eq!(m, [1u64, 2, 0, 3, 0, 1, 0, 0].map(fr).to_vec());
    }

    #[test]
    fn counting_handles_empty_inputs() {
        let super_col: Vec<F> = (0..4).map(fr).collect();
        assert_eq!(both_ways(&[], &super_col), (vec![F::zero(); 4], true));
        assert_eq!(
            both_ways(&[vec![], vec![]], &super_col),
            (vec![F::zero(); 4], true)
        );
        assert_eq!(both_ways(&[vec![fr(1)]], &[]), (vec![], false));
    }

    /// A super column that is not small integers in a dense enough range is
    /// left to sorting.
    #[test]
    fn counting_declines_large_or_sparse_super_columns() {
        let included = vec![vec![fr(1), -fr(1), fr(1 << 20), fr(1)]];

        let (m, counted) = both_ways(&included, &[fr(1), fr(2), -fr(1), fr(1)]);
        assert!(!counted);
        assert_eq!(m, [2u64, 0, 1, 0].map(fr).to_vec());

        let (m, counted) = both_ways(&included, &[fr(1), fr(1 << 20)]);
        assert!(!counted);
        assert_eq!(m, [2u64, 1].map(fr).to_vec());

        // The largest value an array is still used for, and the first one
        // it is not.
        let (_, counted) = both_ways(&included, &[fr(1), fr((1 << 16) - 1)]);
        assert!(counted);
        let (_, counted) = both_ways(&included, &[fr(1), fr(1 << 16)]);
        assert!(!counted);
    }

    /// A value that is a small integer in its lowest limb only is not that
    /// integer: it is no key of the array, in the super column or in an
    /// included one, and it is not the value of the row before it.
    #[test]
    fn counting_tells_a_small_integer_from_a_value_that_ends_in_it() {
        let high = F::from(1u128 << 64);

        // In the super column, beside the integer it ends in: such a column
        // is not small integers, and each of the two rows has its own count.
        let super_col = vec![fr(3) + high, fr(3), fr(5)];
        let included = vec![vec![fr(3), fr(3), fr(5), fr(3) + high]];
        let (m, counted) = both_ways(&included, &super_col);
        assert!(!counted);
        assert_eq!(m, [1u64, 2, 1].map(fr).to_vec());

        // In an included column, right after the integer it ends in and
        // right before it: it is in no row of the super column.
        let super_col: Vec<F> = (0..8).map(fr).collect();
        let included = vec![vec![fr(3), fr(3) + high, fr(3) + high, fr(3), high]];
        let (m, counted) = both_ways(&included, &super_col);
        assert!(counted);
        assert_eq!(m, [0u64, 0, 0, 2, 0, 0, 0, 0].map(fr).to_vec());
    }

    /// Columns longer than one counting chunk, with long runs of one value
    /// across the chunk boundary.
    #[test]
    fn counting_adds_up_across_chunks() {
        let mut rng = StdRng::seed_from_u64(7);
        let super_col: Vec<F> = (0..1u64 << 8).map(|i| fr(i % 200)).collect();
        let included: Vec<Vec<F>> = [(1usize << 17) + 13, 1 << 16, 5]
            .into_iter()
            .map(|len| {
                (0..len)
                    .map(|i| match (i >> 12) % 3 {
                        0 => F::zero(),
                        1 => fr(rng.gen_range(0..260)),
                        _ => fr(199),
                    })
                    .collect()
            })
            .collect();
        let (m, counted) = both_ways(&included, &super_col);
        assert!(counted);
        let total: F = m.iter().sum();
        let in_range = included
            .iter()
            .flatten()
            .filter(|value| **value < fr(200))
            .count();
        assert_eq!(total, fr(in_range as u64));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Random columns of every kind: a dense range, small values with
        /// gaps and repeats, field elements at large, and values that are
        /// small in their lowest limb only.
        #[test]
        fn counting_matches_sorting(
            super_log in 0usize..7,
            range in 1u64..300,
            large_supers in 0usize..2,
            sub_lens in proptest::collection::vec(0usize..200, 0..4),
            seed in any::<u64>(),
        ) {
            let mut rng = StdRng::seed_from_u64(seed);
            let above = |rng: &mut StdRng, low: u64| {
                fr(low) + F::from(1u128 << 64) * fr(rng.gen_range(1..4))
            };
            let mut super_col: Vec<F> = (0..1usize << super_log)
                .map(|_| fr(rng.gen_range(0..range)))
                .collect();
            for _ in 0..large_supers {
                let row = rng.gen_range(0..super_col.len());
                super_col[row] = match rng.gen_range(0..2) {
                    0 => F::rand(&mut rng),
                    _ => {
                        let low = rng.gen_range(0..range);
                        above(&mut rng, low)
                    }
                };
            }
            let included: Vec<Vec<F>> = sub_lens
                .iter()
                .map(|len| {
                    (0..*len)
                        .map(|_| match rng.gen_range(0..10) {
                            0 => F::rand(&mut rng),
                            1 => super_col[rng.gen_range(0..super_col.len())],
                            2 => {
                                let low = rng.gen_range(0..range + 20);
                                above(&mut rng, low)
                            }
                            _ => fr(rng.gen_range(0..range + 20)),
                        })
                        .collect()
                })
                .collect();
            let (_, counted) = both_ways(&included, &super_col);
            prop_assert_eq!(counted, large_supers == 0);
        }
    }

    /// Regression test for the multiplicity double-count bug that appeared
    /// when the super column has repeated values.  The total multiplicity
    /// must equal the total count in the sub-column union.
    #[test]
    fn multiplicity_sums_to_total_sub_count_when_super_has_duplicates() {
        // super repeats each of 0..4 twice → 8 entries, N_super(v) = 2.
        let super_evals: Vec<F> = (0..8).map(|i| fr((i % 4) as u64)).collect();
        // sub repeats each of 0..4 twice as well → 8 entries, N_sub(v) = 2.
        let sub_evals: Vec<F> = (0..8).map(|i| fr(((i * 3) % 4) as u64)).collect();

        let m = calc_inclusion_multiplicity_from_evals::<DefaultSnarkBackend>(
            std::slice::from_ref(&sub_evals),
            &super_evals,
            3,
        );

        let total_m: F = m
            .evaluations()
            .iter()
            .copied()
            .fold(F::zero(), |a, b| a + b);
        let total_sub: F = fr(sub_evals.len() as u64);
        assert_eq!(
            total_m, total_sub,
            "total multiplicity must equal total sub count"
        );
    }

    /// Two sub columns sharing a super column: total multiplicity must equal
    /// the sum of the sub column sizes.  This is the exact case exercised by
    /// the `end_to_end_pipeline` integration test.
    #[test]
    fn multiplicity_with_two_sub_columns_and_duplicated_super() {
        // super has values 0..7 each appearing twice (16 entries).
        let super_evals: Vec<F> = (0..16).map(|i| fr((i % 8) as u64)).collect();
        let sub_a: Vec<F> = (0..16).map(|i| fr(((i * 3) % 8) as u64)).collect();
        let sub_b: Vec<F> = (0..16).map(|i| fr((15 - i) % 8_u64)).collect();

        let m = calc_inclusion_multiplicity_from_evals::<DefaultSnarkBackend>(
            &[sub_a.clone(), sub_b.clone()],
            &super_evals,
            4,
        );

        let total_m: F = m
            .evaluations()
            .iter()
            .copied()
            .fold(F::zero(), |a, b| a + b);
        let expected: F = fr((sub_a.len() + sub_b.len()) as u64);
        assert_eq!(total_m, expected);
    }

    /// Sanity check: with a distinct-valued super column, multiplicities are
    /// unchanged from the natural per-position count.
    #[test]
    fn multiplicity_unchanged_when_super_has_distinct_values() {
        // super has values 0..7 exactly once.
        let super_evals: Vec<F> = (0..8).map(|i| fr(i as u64)).collect();
        // sub contains each value 0..7 exactly once.
        let sub_evals: Vec<F> = (0..8).map(|i| fr(i as u64)).collect();

        let m = calc_inclusion_multiplicity_from_evals::<DefaultSnarkBackend>(
            &[sub_evals],
            &super_evals,
            3,
        );

        for eval in m.evaluations() {
            assert_eq!(eval, F::one(), "each super position should have m = 1");
        }
    }
}
