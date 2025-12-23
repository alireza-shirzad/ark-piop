use crate::prover::structs::polynomial::TrackedPoly;
use crate::{SnarkBackend, arithmetic::mat_poly::mle::MLE};
use ark_ff::Zero;

// TODO: Check if it can be optimized. Also, put in the paper
/// Given a super column and a claimed included column, It outputs an MLE
/// representing the multiplicity of the super polynomial elements in the
/// claimed included column. This MLE will be used in the Multiplicity check
pub fn calc_inclusion_multiplicity<B>(
    included_col: &TrackedPoly<B>,
    super_col: &TrackedPoly<B>,
) -> MLE<B::F>
where
    B: SnarkBackend,
{
    let included_col_evals = included_col.evaluations();
    let super_col_evals = super_col.evaluations();

    let super_col_nv = super_col.log_size();
    let super_col_len = super_col_evals.len();

    let mut included_col_mults_map = vec_multiplicity_count::<B::F>(&included_col_evals, None);

    let mut super_col_mult_evals = Vec::with_capacity(super_col_len);

    for (_i, &val) in super_col_evals.iter().enumerate() {
        if let Some(&included_col_mult) = included_col_mults_map.get(&val) {
            super_col_mult_evals.push(B::F::from(included_col_mult));
            included_col_mults_map.insert(val, 0);
        } else {
            super_col_mult_evals.push(B::F::zero());
        }
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
