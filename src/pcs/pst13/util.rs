use crate::{
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
};
use ark_ff::PrimeField;
use ark_std::vec::Vec;

use crate::pcs::errors::PCSError;

/// Generate eq(t,x), a product of multilinear polynomials with fixed t.
/// eq(a,b) is takes extensions of a,b in {0,1}^num_vars such that if a and b in
/// {0,1}^num_vars are equal then this polynomial evaluates to 1.
pub(crate) fn eq_extension<F: PrimeField>(t: &[F]) -> Vec<MLE<F>> {
    let dim = t.len();
    let mut result = Vec::new();
    for (i, &ti) in t.iter().enumerate().take(dim) {
        let mut poly = Vec::with_capacity(1 << dim);
        for x in 0..(1 << dim) {
            let xi = if x >> i & 1 == 1 { F::one() } else { F::zero() };
            let ti_xi = ti * xi;
            poly.push(ti_xi + ti_xi - xi - ti + F::one());
        }
        result.push(MLE::from_evaluations_vec(dim, poly));
    }
    result
}

/// Evaluate eq polynomial. use the public one later
pub(crate) fn eq_eval<F: PrimeField>(x: &[F], y: &[F]) -> SnarkResult<F> {
    if x.len() != y.len() {
        return Err(SnarkError::PCSErrors(PCSError::InvalidParameters(
            "x and y have different length".to_string(),
        )));
    }
    let mut res = F::one();
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::one();
    }
    Ok(res)
}
