use ark_ff::{Field, PrimeField};
use ark_poly::{
    DenseMVPolynomial, DenseMultilinearExtension, MultilinearExtension,
    multivariate::{SparsePolynomial, SparseTerm, Term},
};
use ark_std::cfg_iter_mut;
use std::collections::BTreeMap;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{arithmetic::errors::ArithErrors, errors::SnarkResult};

use super::mle::MLE;

pub(crate) fn evaluate_opt<F: PrimeField>(poly: &MLE<F>, point: &[F]) -> F {
    assert_eq!(poly.num_vars(), point.len());
    fix_variables(poly, point).evaluations()[0]
}

pub(crate) fn evaluate_with_eq<F: PrimeField>(poly: &MLE<F>, eq: &MLE<F>) -> F {
    assert_eq!(poly.mat_mle().num_vars, eq.num_vars());
    ark_std::cfg_iter!(eq.mat_mle().evaluations)
        .zip(&poly.mat_mle().evaluations)
        .filter_map(|(e, p)| (!p.is_zero()).then(|| if p.is_one() { *e } else { *e * p }))
        .sum::<F>()
}

//TODO: Why do we need this when we have a fix-variables method for MLE? is it because of the way MLE fixes variables?
pub(crate) fn fix_variables<F: Field>(poly: &MLE<F>, partial_point: &[F]) -> MLE<F> {
    poly.fix_variables(partial_point)
}

/// Evaluate eq polynomial.
pub(crate) fn eq_eval<F: PrimeField>(x: &[F], y: &[F]) -> SnarkResult<F> {
    if x.len() != y.len() {
        return Err(
            ArithErrors::InvalidParameters("x and y have different length".to_string()).into(),
        );
    }
    let mut res = F::one();
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::one();
    }
    Ok(res)
}

/// This function build the eq(x, r) polynomial for any given r.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r<F: PrimeField>(r: &[F]) -> SnarkResult<MLE<F>> {
    // we build eq(x,r) from its evaluations
    // we want to evaluate eq(x,r) over x \in {0, 1}^num_vars
    // for example, with num_vars = 4, x is a binary vector of 4, then
    //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
    //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
    //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
    //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
    //  ....
    //  1 1 1 1 -> r0       * r1        * r2        * r3
    // we will need 2^num_var evaluations

    if r.is_empty() {
        return Err(ArithErrors::InvalidParameters("r length is 0".to_string()).into());
    }
    let n = r.len();
    let mut buf = vec![F::zero(); 1 << n];
    buf[0] = F::one();

    for (k, ri) in r.iter().enumerate() {
        let active = 1 << k;
        let one_minus_ri = F::one() - *ri;
        // split into disjoint halves — no borrow conflict
        let (lo, hi) = buf[..active * 2].split_at_mut(active);
        hi.copy_from_slice(lo); // copy source
        cfg_iter_mut!(lo).for_each(|x| *x *= one_minus_ri); // lower half: x_k = 0
        cfg_iter_mut!(hi).for_each(|x| *x *= *ri); // upper half: x_k = 1
    }

    let mle = MLE::from_evaluations_vec(r.len(), buf);

    Ok(mle)
}

/// Build the multivariate sparse representation of eq(x, r).
pub fn build_sparse_eq_x_r<F: PrimeField>(r: &[F]) -> SnarkResult<SparsePolynomial<F, SparseTerm>> {
    if r.is_empty() {
        return Err(ArithErrors::InvalidParameters("r length is 0".to_string()).into());
    }

    let mut terms: BTreeMap<Vec<usize>, F> = BTreeMap::new();
    terms.insert(Vec::new(), F::one());

    for (idx, &ri) in r.iter().enumerate() {
        let mut next_terms: BTreeMap<Vec<usize>, F> = BTreeMap::new();
        let const_factor = F::one() - ri;
        let linear_factor = ri + ri - F::one();

        for (mon, coeff) in terms.iter() {
            let const_coeff = *coeff * const_factor;
            if !const_coeff.is_zero() {
                next_terms
                    .entry(mon.clone())
                    .and_modify(|c| *c += const_coeff)
                    .or_insert(const_coeff);
            }

            let mut mon_with_var = mon.clone();
            mon_with_var.push(idx);
            let linear_coeff = *coeff * linear_factor;
            if !linear_coeff.is_zero() {
                next_terms
                    .entry(mon_with_var)
                    .and_modify(|c| *c += linear_coeff)
                    .or_insert(linear_coeff);
            }
        }

        terms = next_terms;
    }

    let coeffs = terms
        .into_iter()
        .map(|(mon, coeff)| {
            let sparse_term = SparseTerm::new(mon.into_iter().map(|i| (i, 1)).collect());
            (coeff, sparse_term)
        })
        .collect();

    Ok(SparsePolynomial::from_coefficients_vec(r.len(), coeffs))
}

/// Generate eq(t,x), a product of multilinear polynomials with fixed t.
/// eq(a,b) is takes extensions of a,b in {0,1}^num_vars such that if a and b in
/// {0,1}^num_vars are equal then this polynomial evaluates to 1.
pub(crate) fn eq_extension<F: PrimeField>(t: &[F]) -> Vec<DenseMultilinearExtension<F>> {
    let dim = t.len();
    let mut result = Vec::new();
    for (i, &ti) in t.iter().enumerate().take(dim) {
        let mut poly = Vec::with_capacity(1 << dim);
        for x in 0..(1 << dim) {
            let xi = if x >> i & 1 == 1 { F::one() } else { F::zero() };
            let ti_xi = ti * xi;
            poly.push(ti_xi + ti_xi - xi - ti + F::one());
        }
        result.push(DenseMultilinearExtension::from_evaluations_vec(dim, poly));
    }

    result
}
