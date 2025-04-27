use ark_ff::PrimeField;
use ark_std::rand::RngCore;
use std::sync::Arc;

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

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

pub fn fix_variables<F: PrimeField>(poly: &MLE<F>, partial_point: &[F]) -> MLE<F> {
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

fn fix_one_variable_helper<F: PrimeField>(data: &[F], nv: usize, point: &F) -> Vec<F> {
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
