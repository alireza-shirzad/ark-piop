use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, rand::Rng};
use itertools::Either;
#[cfg(feature = "parallel")]
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use std::{
    cmp::Ordering,
    fmt::{self, Formatter},
    ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign},
    slice::IterMut,
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
    mat_mle: DenseMultilinearExtension<F>,
    nv: Option<usize>,
}

impl<F: Field> MLE<F> {
    pub fn new(mat_mle: DenseMultilinearExtension<F>, nv: Option<usize>) -> Self {
        Self { mat_mle, nv }
    }

    pub fn mat_mle(&self) -> &DenseMultilinearExtension<F> {
        &self.mat_mle
    }

    pub fn num_vars(&self) -> usize {
        match self.nv {
            Some(nv) => nv,
            None => self.mat_mle.num_vars,
        }
    }

    pub fn mat_mle_mut(&mut self) -> &mut DenseMultilinearExtension<F> {
        assert!(
            self.nv.is_none(),
            "You can mutate mat_mle only if nv is None"
        );
        &mut self.mat_mle
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
        todo!()
    }

    fn rand<R: Rng>(num_vars: usize, rng: &mut R) -> Self {
        MLE {
            mat_mle: DenseMultilinearExtension::rand(num_vars, rng),
            nv: None,
        }
    }

    fn relabel(&self, a: usize, b: usize, k: usize) -> Self {
        todo!()
    }
    fn fix_variables(&self, partial_point: &[F]) -> Self {
        assert!(
            partial_point.len() <= self.num_vars(),
            "invalid size of partial point"
        );
        let nv = self.num_vars();
        let mut poly = self.evaluations().to_vec();
        let dim = partial_point.len();
        // evaluate single variable of partial point from left to right
        for (i, point) in partial_point.iter().enumerate().take(dim) {
            poly = fix_one_variable_helper(&poly, nv - i, point);
        }

        MLE::<F>::from_evaluations_slice(nv - dim, &poly[..(1 << (nv - dim))])
    }

    fn to_evaluations(&self) -> Vec<F> {
        match self.nv {
            Some(nv) => self.iter().cloned().collect::<Vec<F>>(),
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
        if rhs.is_zero() {
            return self.clone();
        }
        if self.is_zero() {
            return rhs.clone();
        }
        match (self.nv, rhs.nv) {
            // TODO: Some cases are not handled
            (Some(nv1), Some(nv2)) if nv1 == nv2 => {
                match self.mat_mle.num_vars.cmp(&rhs.mat_mle.num_vars) {
                    Ordering::Less => MLE {
                        mat_mle: &dmle_increase_nv_back(&self.mat_mle, rhs.mat_mle.num_vars)
                            + &rhs.mat_mle,
                        nv: Some(nv1),
                    },
                    Ordering::Greater => MLE {
                        mat_mle: &self.mat_mle
                            + &dmle_increase_nv_back(&rhs.mat_mle, self.mat_mle.num_vars),
                        nv: Some(nv1),
                    },
                    Ordering::Equal => MLE {
                        mat_mle: &self.mat_mle + &rhs.mat_mle,
                        nv: Some(nv1),
                    },
                }
            }
            (None, None) => MLE {
                mat_mle: &self.mat_mle + &rhs.mat_mle,
                nv: None,
            },
            (Some(nv1), None) if nv1 == rhs.mat_mle.num_vars => MLE {
                mat_mle: &dmle_increase_nv_back(&self.mat_mle, nv1) + &rhs.mat_mle,
                nv: None,
            },
            (None, Some(nv2)) if nv2 == self.mat_mle.num_vars => MLE {
                mat_mle: &self.mat_mle + &dmle_increase_nv_back(&rhs.mat_mle, nv2),
                nv: None,
            },
            _ => {
                panic!("Cannot add MLEs with different number of variables");
            }
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
        Self {
            mat_mle: -self.mat_mle,
            nv: self.nv,
        }
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
        self + &rhs.clone().neg()
    }
}

impl<F: Field> SubAssign for MLE<F> {
    fn sub_assign(&mut self, other: Self) {
        todo!()
    }
}

impl<'a, F: Field> SubAssign<&'a MLE<F>> for MLE<F> {
    fn sub_assign(&mut self, other: &'a MLE<F>) {
        *self = &*self - &other;
    }
}

impl<F: Field> Mul<F> for MLE<F> {
    type Output = MLE<F>;

    fn mul(self, scalar: F) -> Self::Output {
        &self * &scalar
    }
}

impl<'a, 'b, F: Field> Mul<&'a F> for &'b MLE<F> {
    type Output = MLE<F>;

    fn mul(self, scalar: &'a F) -> Self::Output {
        if scalar.is_zero() {
            return MLE::zero();
        } else if scalar.is_one() {
            return self.clone();
        }
        Self::Output {
            mat_mle: &self.mat_mle * scalar,
            nv: self.nv,
        }
    }
}

impl<F: Field> MulAssign<F> for MLE<F> {
    fn mul_assign(&mut self, scalar: F) {
        *self = &*self * &scalar
    }
}

impl<'a, F: Field> MulAssign<&'a F> for MLE<F> {
    fn mul_assign(&mut self, scalar: &'a F) {
        *self = &*self * scalar
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
        self.fix_variables(point)[0]
    }
}

/// Increase the number of variables of a multilinear polynomial by adding
/// variables at the back Ex for input (P(X, Y), 3) result in P'(X, Y, Z), where
/// P'(X, Y, Z) = P(X, Y)
/// TODO: Parallelize this function
pub fn dmle_increase_nv_back<F: Field>(
    mle: &DenseMultilinearExtension<F>,
    new_nv: usize,
) -> DenseMultilinearExtension<F> {
    if mle.num_vars() == new_nv {
        return mle.clone();
    }
    if mle.num_vars() > new_nv {
        panic!("dmle_increase_nv Error: old_len > new_len");
    }

    let old_len = 2_usize.pow(mle.num_vars() as u32);
    let new_len = 2_usize.pow(new_nv as u32);
    let mut evals = mle.evaluations.clone();
    evals.resize(new_len, F::default());
    for i in old_len..new_len {
        evals[i] = evals[i % old_len];
    }
    DenseMultilinearExtension::from_evaluations_vec(new_nv, evals)
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

#[cfg(test)]
mod tests {
    use crate::arithmetic::mat_poly::utils::evaluate_opt;

    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use ark_test_curves::bls12_381::Fr;
}
