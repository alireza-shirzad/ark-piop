use crate::prover::structs::polynomial::TrackedPoly;
use crate::{SnarkBackend, arithmetic::mat_poly::mle::MLE};
use ark_ff::PrimeField;
use indexmap::IndexMap;

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
    let super_col_len = super_col_evals.len();

    let mut included_col_mults_map = included_col_evals
        .iter()
        .map(|evals| vec_multiplicity_count::<B::F>(evals, None))
        .fold(IndexMap::<B::F, u64>::new(), |mut acc, map| {
            for (val, count) in map {
                *acc.entry(val).or_insert(0) += count;
            }
            acc
        });

    let mut super_col_mult_evals = Vec::with_capacity(super_col_len);

    // Consume each value's count at its first super position; later duplicates get 0
    // so the super-column total equals the sub-union total.
    for &val in super_col_evals.iter() {
        let count = included_col_mults_map.get(&val).copied().unwrap_or(0);
        super_col_mult_evals.push(B::F::from(count));
        if count > 0 {
            included_col_mults_map.insert(val, 0);
        }
    }

    MLE::from_evaluations_vec(super_col_nv, super_col_mult_evals)
}

// Map from unique evaluations to multiplicities, skipping zero-selector positions.
fn vec_multiplicity_count<F>(poly: &[F], sel: Option<&[F]>) -> IndexMap<F, u64>
where
    F: PrimeField,
{
    let mut mults_map = IndexMap::<F, u64>::new();

    if let Some(sel) = sel {
        for (i, &val) in poly.iter().enumerate() {
            if sel[i] == F::zero() {
                continue;
            }
            *mults_map.entry(val).or_insert(0) += 1;
        }
    } else {
        for &val in poly {
            *mults_map.entry(val).or_insert(0) += 1;
        }
    }

    mults_map
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
