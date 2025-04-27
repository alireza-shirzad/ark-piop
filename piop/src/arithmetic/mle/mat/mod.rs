use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{DenseMVPolynomial, DenseMultilinearExtension, MultilinearExtension, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_iter, end_timer,
    rand::{Rng, RngCore},
    start_timer,
};
use itertools::Either;
use macros::timed;
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::{
    fmt::{self, Formatter},
    ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign},
    slice::{Iter, IterMut},
    sync::Arc,
};
/// A wrapper around `DenseMultilinearExtension` that allows for a modifiede
/// hypercube size If the nv is not set, it will have the same size as the
/// `DenseMultilinearExtension`. If the nv is set, it will be the size of the
/// `DenseMultilinearExtension` multiplied by 2^(nv - num_vars)
/// Every functionality supported by `DenseMultilinearExtension` is also
/// supported by `MLE`. This is for easier usage in the codebase and less memory
/// usage.

#[derive(Clone, PartialEq, Eq, Hash, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct MLE<F: Field> {
    pub(crate) mat_mle: DenseMultilinearExtension<F>,
    pub(crate) nv: Option<usize>,
}

impl<F: Field> MLE<F> {
    pub fn num_vars(&self) -> usize {
        match self.nv {
            Some(nv) => nv,
            None => self.mat_mle.num_vars,
        }
    }

    pub fn evaluations(&self) -> Vec<F> {
        match self.nv {
            Some(_) => self.iter().cloned().collect::<Vec<F>>(),
            None => self.mat_mle.evaluations.clone(),
        }
    }

    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[F]) -> Self {
        Self::from_evaluations_vec(num_vars, evaluations.to_vec())
    }

    pub fn from_evaluations_vec(num_vars: usize, evaluations: Vec<F>) -> Self {
        // assert that the number of variables matches the size of evaluations
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "The size of evaluations should be 2^num_vars."
        );

        Self {
            mat_mle: DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations),
            nv: None,
        }
    }

    pub fn relabel_in_place(&mut self, mut a: usize, mut b: usize, k: usize) {
        todo!()
    }

    pub fn iter(&self) -> impl Iterator<Item = &F> + '_ {
        match self.nv {
            Some(nv) => Either::Left(self.mat_mle.iter().cycle().take(1 << nv)),
            None => Either::Right(self.mat_mle.iter()),
        }
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, F> {
        match self.nv {
            Some(_) => panic!("iter_mut is not supported when nv is set"),
            None => self.mat_mle.evaluations.iter_mut(),
        }
    }

    pub fn concat(polys: impl IntoIterator<Item = impl AsRef<Self>> + Clone) -> Self {
        todo!("Implement concat for MLE");
    }
}

impl<F: Field> AsRef<MLE<F>> for MLE<F> {
    fn as_ref(&self) -> &MLE<F> {
        self
    }
}

impl<F: Field> MultilinearExtension<F> for MLE<F> {
    fn num_vars(&self) -> usize {
        dbg!(19);
        todo!()
    }

    fn rand<R: Rng>(num_vars: usize, rng: &mut R) -> Self {
        MLE {
            mat_mle: DenseMultilinearExtension::rand(num_vars, rng),
            nv: None,
        }
    }

    fn relabel(&self, a: usize, b: usize, k: usize) -> Self {
        dbg!(17);
        todo!()
    }
    fn fix_variables(&self, partial_point: &[F]) -> Self {
        // TODO: Should not clone here
        match self.nv {
            Some(max_nv) => {
                let num_free_fixable_vars = max_nv - self.mat_mle.num_vars;
                let num_vars_to_be_fixed = partial_point.len();
                if num_vars_to_be_fixed < num_free_fixable_vars {
                    Self {
                        mat_mle: self.mat_mle.clone(),
                        nv: Some(max_nv - num_vars_to_be_fixed),
                    }
                } else if num_vars_to_be_fixed == num_free_fixable_vars {
                    Self {
                        mat_mle: self.mat_mle.clone(),
                        nv: None,
                    }
                } else {
                    let diff = num_vars_to_be_fixed - num_free_fixable_vars;
                    let (_, partial_truncated_point) =
                        partial_point.split_at(partial_point.len() - diff);
                    Self {
                        mat_mle: self.mat_mle.fix_variables(partial_truncated_point),
                        nv: None,
                    }
                }
            },
            None => Self {
                mat_mle: self.mat_mle.fix_variables(partial_point),
                nv: None,
            },
        }
    }

    fn to_evaluations(&self) -> Vec<F> {
        match self.nv {
            Some(nv) => self
                .mat_mle
                .to_evaluations()
                .repeat(nv - self.mat_mle.num_vars),
            None => self.mat_mle.to_evaluations(),
        }
    }
}

impl<F: Field> Index<usize> for MLE<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        match self.nv {
            Some(_) => &self.mat_mle[index % (1 << self.mat_mle.num_vars)],
            None => &self.mat_mle[index],
        }
    }
}

impl<F: Field> Add for MLE<F> {
    type Output = MLE<F>;

    fn add(self, other: MLE<F>) -> Self {
        &self + &other
    }
}

impl<'a, 'b, F: Field> Add<&'a MLE<F>> for &'b MLE<F> {
    type Output = MLE<F>;

    fn add(self, rhs: &'a MLE<F>) -> Self::Output {
        match (self.nv, rhs.nv) {
            // TODO: Some cases are not handled
            (Some(nv1), Some(nv2)) if nv1 == nv2 => MLE {
                mat_mle: &self.mat_mle + &rhs.mat_mle,
                nv: Some(nv1),
            },
            (None, None) => MLE {
                mat_mle: &self.mat_mle + &rhs.mat_mle,
                nv: None,
            },
            _ => panic!("Cannot add MLEs with different number of variables"),
        }
    }
}

impl<F: Field> AddAssign for MLE<F> {
    fn add_assign(&mut self, other: Self) {
        *self = &*self + &other;
    }
}

impl<'a, F: Field> AddAssign<&'a MLE<F>> for MLE<F> {
    fn add_assign(&mut self, other: &'a MLE<F>) {
        *self = &*self + other;
    }
}

impl<'a, F: Field> AddAssign<(F, &'a MLE<F>)> for MLE<F> {
    fn add_assign(&mut self, (f, other): (F, &'a MLE<F>)) {
        let mat_mle = DenseMultilinearExtension::from_evaluations_vec(
            other.mat_mle.num_vars,
            cfg_iter!(other.mat_mle.evaluations)
                .map(|x| f * x)
                .collect(),
        );
        let other = Self {
            nv: other.nv,
            mat_mle,
        };
        *self = &*self + &other;
    }
}

impl<F: Field> Neg for MLE<F> {
    type Output = MLE<F>;

    fn neg(self) -> Self::Output {
        dbg!(2);
        todo!()
    }
}

impl<F: Field> Sub for MLE<F> {
    type Output = MLE<F>;

    fn sub(self, other: MLE<F>) -> Self {
        &self - &other
    }
}

impl<'a, 'b, F: Field> Sub<&'a MLE<F>> for &'b MLE<F> {
    type Output = MLE<F>;

    fn sub(self, rhs: &'a MLE<F>) -> Self::Output {
        dbg!(3);
        todo!()
    }
}

impl<F: Field> SubAssign for MLE<F> {
    fn sub_assign(&mut self, other: Self) {
        dbg!(4);
        todo!()
    }
}

impl<'a, F: Field> SubAssign<&'a MLE<F>> for MLE<F> {
    fn sub_assign(&mut self, other: &'a MLE<F>) {
        dbg!(5);
        todo!()
    }
}

impl<F: Field> Mul<F> for MLE<F> {
    type Output = MLE<F>;

    fn mul(self, scalar: F) -> Self::Output {
        dbg!(6);
        todo!()
    }
}

impl<'a, 'b, F: Field> Mul<&'a F> for &'b MLE<F> {
    type Output = MLE<F>;

    fn mul(self, scalar: &'a F) -> Self::Output {
        dbg!(7);
        todo!()
    }
}

impl<F: Field> MulAssign<F> for MLE<F> {
    fn mul_assign(&mut self, scalar: F) {
        dbg!(8);
        todo!()
    }
}

impl<'a, F: Field> MulAssign<&'a F> for MLE<F> {
    fn mul_assign(&mut self, scalar: &'a F) {
        dbg!(9);
        todo!()
    }
}

impl<F: Field> fmt::Debug for MLE<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self.nv {
            Some(nv) => write!(f, "real-nv= {}, wrapped-poly= {:?}", nv, self.mat_mle)?,
            None => self.mat_mle.fmt(f)?,
        }
        Ok(())
    }
}
impl<F: Field> Zero for MLE<F> {
    fn zero() -> Self {
        Self {
            mat_mle: DenseMultilinearExtension::zero(),
            nv: None,
        }
    }

    fn is_zero(&self) -> bool {
        match self.nv {
            Some(nv) => self.mat_mle.is_zero() && nv == 0,
            None => self.mat_mle.is_zero(),
        }
    }
}

impl<F: Field> Polynomial<F> for MLE<F> {
    type Point = Vec<F>;

    fn degree(&self) -> usize {
        self.num_vars()
    }

    fn evaluate(&self, point: &Self::Point) -> F {
        assert!(point.len() == self.num_vars());
        self.fix_variables(&point)[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use ark_test_curves::bls12_381::Fr;

    // TODO: Add tests for MLE
}

/// Sample a random list of multilinear polynomials.
/// Returns
/// - the list of polynomials,
/// - its sum of polynomial evaluations over the boolean hypercube.
#[timed]
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
#[timed]
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

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(MLE::from_evaluations_vec(nv, x)))
        .collect();

    list
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
    res.par_iter_mut().enumerate().for_each(|(i, mut x)| {
        *x = data[i << 1] + (data[(i << 1) + 1] - data[i << 1]) * point;
    });

    res
}

