//! This module is copied from the [hyperplonk](https://github.com/EspressoSystems/hyperplonk/tree/main) library.

use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::CanonicalSerialize;

use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
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
pub struct HPVirtualPolynomial<F: PrimeField> {
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

#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize)]
/// Auxiliary information about the multilinear polynomial
pub struct VPAuxInfo<F: PrimeField> {
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
    pub fn new(num_variables: usize) -> Self {
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
    pub fn new_from_mle(mle: &Arc<MLE<F>>, coefficient: F) -> Self {
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
    pub fn print_evals(&self) {
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

    pub fn materialize(&self) -> MLE<F> {
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
pub(crate) fn build_eq_x_r<F: PrimeField>(r: &[F]) -> Result<Arc<MLE<F>>, ArithErrors> {
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
pub(crate) fn build_eq_x_r_vec<F: PrimeField>(r: &[F]) -> Result<Vec<F>, ArithErrors> {
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
        res.par_iter_mut().enumerate().for_each(|(i, val)| {
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

/// Decompose an integer into a binary vector in little endian.
pub fn bit_decompose(input: u64, num_var: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(num_var);
    let mut i = input;
    for _ in 0..num_var {
        res.push(i & 1 == 1);
        i >>= 1;
    }
    res
}
