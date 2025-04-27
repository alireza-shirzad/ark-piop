use ark_ff::{Field, Zero};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, rand::Rng};
use itertools::Either;
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::prelude::ParallelIterator;
use std::{
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
            }
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
        todo!()
    }
}

impl<F: Field> SubAssign for MLE<F> {
    fn sub_assign(&mut self, other: Self) {
        todo!()
    }
}

impl<'a, F: Field> SubAssign<&'a MLE<F>> for MLE<F> {
    fn sub_assign(&mut self, other: &'a MLE<F>) {
        todo!()
    }
}

impl<F: Field> Mul<F> for MLE<F> {
    type Output = MLE<F>;

    fn mul(self, scalar: F) -> Self::Output {
        todo!()
    }
}

impl<'a, 'b, F: Field> Mul<&'a F> for &'b MLE<F> {
    type Output = MLE<F>;

    fn mul(self, scalar: &'a F) -> Self::Output {
        todo!()
    }
}

impl<F: Field> MulAssign<F> for MLE<F> {
    fn mul_assign(&mut self, scalar: F) {
        todo!()
    }
}

impl<'a, F: Field> MulAssign<&'a F> for MLE<F> {
    fn mul_assign(&mut self, scalar: &'a F) {
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
