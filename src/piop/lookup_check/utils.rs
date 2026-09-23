use crate::prover::structs::polynomial::TrackedPoly;
use crate::{SnarkBackend, arithmetic::mat_poly::mle::MLE};
use ark_ff::Zero;
use ark_std::cfg_iter;
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
    // Sort-based rather than a hash map: on a 2^23-entry super column the
    // map version was several seconds of one core per lookup, and this
    // runs inside a parallel job per super column.
    let mut included: Vec<B::F> = included_col_evals
        .iter()
        .flat_map(|evals| evals.iter().copied())
        .collect();
    sort_unstable(&mut included);
    // (value, count) runs, in value order.
    let mut runs: Vec<(B::F, u64)> = Vec::new();
    for val in included {
        match runs.last_mut() {
            Some((last, n)) if *last == val => *n += 1,
            _ => runs.push((val, 1)),
        }
    }

    // Super positions by value, ties by position: the first of each run is
    // the value's first occurrence, which carries the count; later
    // duplicates get 0 so the super-column total equals the sub-union total.
    let mut sup: Vec<(B::F, usize)> = cfg_iter!(super_col_evals)
        .enumerate()
        .map(|(i, &v)| (v, i))
        .collect();
    sort_unstable(&mut sup);

    let mut super_col_mult_evals = vec![B::F::zero(); super_col_evals.len()];
    let mut runs = runs.iter().peekable();
    let mut previous: Option<&B::F> = None;
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
            super_col_mult_evals[*pos] = B::F::from(*n);
        }
    }

    MLE::from_evaluations_vec(super_col_nv, super_col_mult_evals)
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
    use ark_ff::{One, Zero};

    type F = <DefaultSnarkBackend as SnarkBackend>::F;

    fn fr(v: u64) -> F {
        F::from(v)
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
