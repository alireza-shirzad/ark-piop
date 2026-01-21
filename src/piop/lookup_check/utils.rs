use crate::prover::structs::polynomial::TrackedPoly;
use crate::{SnarkBackend, arithmetic::mat_poly::mle::MLE};
use ark_ff::Zero;

// TODO: Check if it can be optimized. Also, put in the paper
/// Given a super column and a set of included columns, output an MLE
/// representing the multiplicity of super column elements that appear
/// in all included columns. The output length matches the super column.
pub fn calc_inclusion_multiplicity<B>(
    included_col: &Vec<TrackedPoly<B>>,
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

    let super_col_nv = super_col.log_size();
    let super_col_len = super_col_evals.len();

    let included_col_mults_map = included_col_evals
        .iter()
        .map(|evals| vec_multiplicity_count::<B::F>(evals, None))
        .fold(HashMap::<B::F, u64>::new(), |mut acc, map| {
            for (val, count) in map {
                *acc.entry(val).or_insert(0) += count;
            }
            acc
        });

    let mut super_col_mult_evals = Vec::with_capacity(super_col_len);

    for &val in super_col_evals.iter() {
        let count = included_col_mults_map.get(&val).copied().unwrap_or(0);
        super_col_mult_evals.push(B::F::from(count));
    }

    MLE::from_evaluations_vec(super_col_nv, super_col_mult_evals)
}

use ark_ff::PrimeField;
use std::collections::HashMap;

// Returns a map from the unique evaluations of col to their multiplicities
// does not include values where the selector is zero
fn vec_multiplicity_count<F>(poly: &[F], sel: Option<&[F]>) -> HashMap<F, u64>
where
    F: PrimeField,
{
    let mut mults_map = HashMap::<F, u64>::new();

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
