use ark_ff::{Field, PrimeField};
use ark_poly::MultilinearExtension;
use ark_std::{cfg_iter_mut, rand::RngCore};
use std::sync::Arc;

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

use crate::arithmetic::errors::ArithErrors;

use super::mle::MLE;

/// Sample a random list of multilinear polynomials.
/// Returns
/// - the list of polynomials,
/// - its sum of polynomial evaluations over the boolean hypercube.
pub fn random_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> (Vec<Arc<MLE<F>>>, F) {
    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    let mut sum = F::zero();

    for _ in 0..(1 << nv) {
        let mut product = F::one();

        for e in multiplicands.iter_mut() {
            let val = F::rand(rng);
            e.push(val);
            product *= val;
        }
        sum += product;
    }

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(MLE::from_evaluations_vec(nv, x)))
        .collect();

    (list, sum)
}

// Build a randomize list of mle-s whose sum is zero.
pub fn random_zero_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> Vec<Arc<MLE<F>>> {
    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    for _ in 0..(1 << nv) {
        multiplicands[0].push(F::zero());
        for e in multiplicands.iter_mut().skip(1) {
            e.push(F::rand(rng));
        }
    }

    multiplicands
        .into_iter()
        .map(|x| Arc::new(MLE::from_evaluations_vec(nv, x)))
        .collect()
}

pub fn random_permutation<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    let mut s_id_vec: Vec<F> = (0..len).map(F::from).collect();
    let mut s_perm_vec = vec![];
    for _ in 0..len {
        let index = rng.next_u64() as usize % s_id_vec.len();
        s_perm_vec.push(s_id_vec.remove(index));
    }
    s_perm_vec
}

/// A list of MLEs that represent a random permutation
pub fn random_permutation_mles<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<MLE<F>> {
    let s_perm_vec = random_permutation(num_vars, num_chunks, rng);
    let mut res = vec![];
    let n = 1 << num_vars;
    for i in 0..num_chunks {
        res.push(MLE::from_evaluations_vec(
            num_vars,
            s_perm_vec[i * n..i * n + n].to_vec(),
        ));
    }
    res
}

pub fn evaluate_opt<F: PrimeField>(poly: &MLE<F>, point: &[F]) -> F {
    assert_eq!(poly.num_vars(), point.len());
    fix_variables(poly, point).evaluations()[0]
}

pub fn fix_variables<F: Field>(poly: &MLE<F>, partial_point: &[F]) -> MLE<F> {
    assert!(
        partial_point.len() <= poly.num_vars(),
        "invalid size of partial point"
    );
    let nv = poly.num_vars();
    let mut poly = poly.evaluations().to_vec();
    let dim = partial_point.len();
    // evaluate single variable of partial point from left to right
    for (i, point) in partial_point.iter().enumerate().take(dim) {
        poly = fix_one_variable_helper(&poly, nv - i, point);
    }

    MLE::<F>::from_evaluations_slice(nv - dim, &poly[..(1 << (nv - dim))])
}

fn fix_one_variable_helper<F: Field>(data: &[F], nv: usize, point: &F) -> Vec<F> {
    let mut res = vec![F::zero(); 1 << (nv - 1)];

    // evaluate single variable of partial point from left to right
    #[cfg(not(feature = "parallel"))]
    for i in 0..(1 << (nv - 1)) {
        res[i] = data[i] + (data[(i << 1) + 1] - data[i << 1]) * point;
    }

    #[cfg(feature = "parallel")]
    res.par_iter_mut().enumerate().for_each(|(i, x)| {
        *x = data[i << 1] + (data[(i << 1) + 1] - data[i << 1]) * point;
    });

    res
}

/// Evaluate eq polynomial.
pub(crate) fn eq_eval<F: PrimeField>(x: &[F], y: &[F]) -> Result<F, ArithErrors> {
    if x.len() != y.len() {
        return Err(ArithErrors::InvalidParameters(
            "x and y have different length".to_string(),
        ));
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
pub fn build_eq_x_r<F: PrimeField>(r: &[F]) -> Result<Arc<MLE<F>>, ArithErrors> {
    let evals = build_eq_x_r_vec(r)?;
    let mle = MLE::from_evaluations_vec(r.len(), evals);

    Ok(Arc::new(mle))
}
/// This function build the eq(x, r) polynomial for any given r, and output the
/// evaluation of eq(x, r) in its vector form.
///
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r_vec<F: PrimeField>(r: &[F]) -> Result<Vec<F>, ArithErrors> {
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

    let mut eval = Vec::new();
    build_eq_x_r_helper(r, &mut eval)?;

    Ok(eval)
}

/// A helper function to build eq(x, r) recursively.
/// This function takes `r.len()` steps, and for each step it requires a maximum
/// `r.len()-1` multiplications.
fn build_eq_x_r_helper<F: PrimeField>(r: &[F], buf: &mut Vec<F>) -> Result<(), ArithErrors> {
    if r.is_empty() {
        return Err(ArithErrors::InvalidParameters("r length is 0".to_string()));
    } else if r.len() == 1 {
        // initializing the buffer with [1-r_0, r_0]
        buf.push(F::one() - r[0]);
        buf.push(r[0]);
    } else {
        build_eq_x_r_helper(&r[1..], buf)?;

        // suppose at the previous step we received [b_1, ..., b_k]
        // for the current step we will need
        // if x_0 = 0:   (1-r0) * [b_1, ..., b_k]
        // if x_0 = 1:   r0 * [b_1, ..., b_k]
        // let mut res = vec![];
        // for &b_i in buf.iter() {
        //     let tmp = r[0] * b_i;
        //     res.push(b_i - tmp);
        //     res.push(tmp);
        // }
        // *buf = res;

        let mut res = vec![F::zero(); buf.len() << 1];
        cfg_iter_mut!(res).enumerate().for_each(|(i, val)| {
            let bi = buf[i >> 1];
            let tmp = r[0] * bi;
            if i & 1 == 0 {
                *val = bi - tmp;
            } else {
                *val = tmp;
            }
        });
        *buf = res;
    }

    Ok(())
}
