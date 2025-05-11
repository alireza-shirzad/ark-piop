//! This module is copied from the [hyperplonk](https://github.com/EspressoSystems/hyperplonk/tree/main) library.

use ark_ff::PrimeField;
use ark_poly::{MultilinearExtension, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use std::{cmp::max, collections::HashMap, marker::PhantomData, ops::Add, sync::Arc};

use crate::arithmetic::{errors::ArithErrors, mat_poly::mle::MLE};

#[rustfmt::skip]
/// A virtual polynomial is a sum of products of multilinear polynomials;
/// where the multilinear polynomials are stored via their multilinear
/// extensions:  `(coefficient, MLE)`
/// 
/// TODO: The only reason we have the hyperplonk virtual polynomial is to be compatible with the sumcheck. we need to merge this virtual polynomial to our virtual polynomial.
///
/// * Number of products n = `polynomial.products.len()`,
/// * Number of multiplicands of ith product m_i =
///   `polynomial.products[i].1.len()`,
/// * Coefficient of ith product c_i = `polynomial.products[i].0`
///
/// The resulting polynomial is
///
/// $$ \sum_{i=0}^{n} c_i \cdot \prod_{j=0}^{m_i} P_{ij} $$
///
/// Example:
///  f = c0 * f0 * f1 * f2 + c1 * f3 * f4
/// where f0 ... f4 are multilinear polynomials
///
/// - flattened_ml_extensions stores the multilinear extension representation of
///   f0, f1, f2, f3 and f4
/// - products is 
///   \[ 
///   (c0, \[0, 1, 2\]), 
///   (c1, \[3, 4\]) 
///   \]
/// - raw_pointers_lookup_table maps fi to i
///
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct HPVirtualPolynomial<F: PrimeField> {
    /// Aux information about the multilinear polynomial
    pub aux_info: VPAuxInfo<F>,
    /// list of reference to products (as usize) of multilinear extension
    pub products: Vec<(F, Vec<usize>)>,
    /// Stores multilinear extensions in which product multiplicand can refer
    /// to.
    pub flattened_ml_extensions: Vec<Arc<MLE<F>>>,
    /// Pointers to the above poly extensions
    raw_pointers_lookup_table: HashMap<*const MLE<F>, usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
/// Auxiliary information about the multilinear polynomial
pub(crate) struct VPAuxInfo<F: PrimeField> {
    /// max number of multiplicands in each product
    pub max_degree: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// Associated field
    #[doc(hidden)]
    pub phantom: PhantomData<F>,
}

impl<F: PrimeField> Add for &HPVirtualPolynomial<F> {
    type Output = HPVirtualPolynomial<F>;
    fn add(self, other: &HPVirtualPolynomial<F>) -> Self::Output {
        let mut res = self.clone();
        for products in other.products.iter() {
            let cur: Vec<Arc<MLE<F>>> = products
                .1
                .iter()
                .map(|&x| other.flattened_ml_extensions[x].clone())
                .collect();

            res.add_mle_list(cur, products.0)
                .expect("add product failed");
        }
        res
    }
}

// TODO: convert this into a trait
impl<F: PrimeField> HPVirtualPolynomial<F> {
    /// Creates an empty virtual polynomial with `num_variables`.
    pub(crate) fn new(num_variables: usize) -> Self {
        HPVirtualPolynomial {
            aux_info: VPAuxInfo {
                max_degree: 0,
                num_variables,
                phantom: PhantomData,
            },
            products: Vec::new(),
            flattened_ml_extensions: Vec::new(),
            raw_pointers_lookup_table: HashMap::new(),
        }
    }

    /// Creates an new virtual polynomial from a MLE and its coefficient.
    pub(crate) fn new_from_mle(mle: &Arc<MLE<F>>, coefficient: F) -> Self {
        let mle_ptr: *const MLE<F> = Arc::as_ptr(mle);
        let mut hm = HashMap::new();
        hm.insert(mle_ptr, 0);

        HPVirtualPolynomial {
            aux_info: VPAuxInfo {
                // The max degree is the max degree of any individual variable
                max_degree: 1,
                num_variables: mle.num_vars(),
                phantom: PhantomData,
            },
            // here `0` points to the first polynomial of `flattened_ml_extensions`
            products: vec![(coefficient, vec![0])],
            flattened_ml_extensions: vec![mle.clone()],
            raw_pointers_lookup_table: hm,
        }
    }

    /// Add a product of list of multilinear extensions to self
    /// Returns an error if the list is empty, or the MLE has a different
    /// `num_vars` from self.
    ///
    /// The MLEs will be multiplied together, and then multiplied by the scalar
    /// `coefficient`.
    pub(crate) fn add_mle_list(
        &mut self,
        mle_list: impl IntoIterator<Item = Arc<MLE<F>>>,
        coefficient: F,
    ) -> Result<(), ArithErrors> {
        let mle_list: Vec<Arc<MLE<F>>> = mle_list.into_iter().collect();
        let mut indexed_product = Vec::with_capacity(mle_list.len());

        if mle_list.is_empty() {
            return Err(ArithErrors::InvalidParameters(
                "input mle_list is empty".to_string(),
            ));
        }

        self.aux_info.max_degree = max(self.aux_info.max_degree, mle_list.len());

        for mle in mle_list {
            if mle.num_vars() != self.aux_info.num_variables {
                return Err(ArithErrors::InvalidParameters(format!(
                    "product has a multiplicand with wrong number of variables {} vs {}",
                    mle.num_vars(),
                    self.aux_info.num_variables
                )));
            }

            let mle_ptr: *const MLE<F> = Arc::as_ptr(&mle);
            if let Some(index) = self.raw_pointers_lookup_table.get(&mle_ptr) {
                indexed_product.push(*index)
            } else {
                let curr_index = self.flattened_ml_extensions.len();
                self.flattened_ml_extensions.push(mle.clone());
                self.raw_pointers_lookup_table.insert(mle_ptr, curr_index);
                indexed_product.push(curr_index);
            }
        }
        self.products.push((coefficient, indexed_product));
        Ok(())
    }

    /// Evaluate the virtual polynomial at point `point`.
    /// Returns an error is point.len() does not match `num_variables`.
    pub(crate) fn evaluate(&self, point: &[F]) -> Result<F, ArithErrors> {
        if self.aux_info.num_variables != point.len() {
            return Err(ArithErrors::InvalidParameters(format!(
                "wrong number of variables {} vs {}",
                self.aux_info.num_variables,
                point.len()
            )));
        }

        // TODO: Fix to_vec
        let evals: Vec<F> = self
            .flattened_ml_extensions
            .iter()
            .map(|x| {
                x.evaluate(&point.to_vec()) // safe unwrap here since we have
                // already checked that num_var
                // matches
            })
            .collect();

        let res = self
            .products
            .iter()
            .map(|(c, p)| *c * p.iter().map(|&i| evals[i]).product::<F>())
            .sum();

        Ok(res)
    }

    /// Print out the evaluation map for testing. Panic if the num_vars > 5.
    pub(crate) fn print_evals(&self) {
        if self.aux_info.num_variables > 5 {
            panic!("this function is used for testing only. cannot print more than 5 num_vars")
        }
        for i in 0..1 << self.aux_info.num_variables {
            let point = bit_decompose(i, self.aux_info.num_variables);
            let point_fr: Vec<F> = point.iter().map(|&x| F::from(x)).collect();
            println!("{} {}", i, self.evaluate(point_fr.as_ref()).unwrap())
        }
        println!()
    }

    pub(crate) fn materialize(&self) -> MLE<F> {
        let nv = self.aux_info.num_variables;
        let mut eval_vec = Vec::<F>::new();
        for pt in 0..2_usize.pow(nv as u32) {
            let pt_eval = self
                .products
                .iter()
                .map(|(coeff, prod)| {
                    *coeff
                        * prod
                            .iter()
                            .map(|&i| self.flattened_ml_extensions[i].evaluations()[pt])
                            .product::<F>()
                })
                .sum();

            eval_vec.push(pt_eval);
        }
        MLE::from_evaluations_vec(nv, eval_vec)
    }
}

/// Decompose an integer into a binary vector in little endian.
pub(crate) fn bit_decompose(input: u64, num_var: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(num_var);
    let mut i = input;
    for _ in 0..num_var {
        res.push(i & 1 == 1);
        i >>= 1;
    }
    res
}
