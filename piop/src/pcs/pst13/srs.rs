// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Implementing Structured Reference Strings for multilinear polynomial KZG
use crate::{
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    pcs::{
        StructuredReferenceString,
        errors::PCSError,
        pst13::util::{eq_eval, eq_extension},
    },
};
use ark_ec::{AffineRepr, CurveGroup, ScalarMul, pairing::Pairing};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;
use ark_std::{end_timer, rand::Rng, start_timer};
use core::iter::FromIterator;
use macros::timed;
use std::collections::LinkedList;
/// Evaluations over {0,1}^n for G1 or G2
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Evaluations<C: AffineRepr> {
    /// The evaluations.
    pub evals: Vec<C>,
}

/// Universal Parameter
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MultilinearUniversalParams<E: Pairing> {
    /// prover parameters
    pub prover_param: MultilinearProverParam<E>,
    /// h^randomness: h^t1, h^t2, ..., **h^{t_nv}**
    pub h_mask: Vec<E::G2Affine>,
}

/// Prover Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MultilinearProverParam<E: Pairing> {
    /// number of variables
    pub num_vars: usize,
    /// `pp_{0}`, `pp_{1}`, ...,pp_{nu_vars} defined
    /// by XZZPD19 where pp_{nv-0}=g and
    /// pp_{nv-i}=g^{eq((t_1,..t_i),(X_1,..X_i))}
    pub powers_of_g: Vec<Evaluations<E::G1Affine>>,
    /// generator for G1
    pub g: E::G1Affine,
    /// generator for G2
    pub h: E::G2Affine,
}

/// Verifier Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MultilinearVerifierParam<E: Pairing> {
    /// number of variables
    pub num_vars: usize,
    /// generator of G1
    pub g: E::G1Affine,
    /// generator of G2
    pub h: E::G2Affine,
    /// h^randomness: h^t1, h^t2, ..., **h^{t_nv}**
    pub h_mask: Vec<E::G2Affine>,
}

impl<E: Pairing> StructuredReferenceString<E> for MultilinearUniversalParams<E> {
    type ProverParam = MultilinearProverParam<E>;
    type VerifierParam = MultilinearVerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_num_vars: usize) -> Self::ProverParam {
        let to_reduce = self.prover_param.num_vars - supported_num_vars;

        Self::ProverParam {
            powers_of_g: self.prover_param.powers_of_g[to_reduce..].to_vec(),
            g: self.prover_param.g,
            h: self.prover_param.h,
            num_vars: supported_num_vars,
        }
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_num_vars: usize) -> Self::VerifierParam {
        let to_reduce = self.prover_param.num_vars - supported_num_vars;
        Self::VerifierParam {
            num_vars: supported_num_vars,
            g: self.prover_param.g,
            h: self.prover_param.h,
            h_mask: self.h_mask[to_reduce..].to_vec(),
        }
    }

    /// Trim the universal parameters to specialize the public parameters
    /// for multilinear polynomials to the given `supported_num_vars`, and
    /// returns committer key and verifier key. `supported_num_vars` should
    /// be in range `1..=params.num_vars`
    #[timed]
    fn trim(
        &self,
        supported_num_vars: usize,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)> {
        if supported_num_vars > self.prover_param.num_vars {
            return Err(SnarkError::PCSErrors(PCSError::InvalidParameters(format!(
                "SRS does not support target number of vars {}",
                supported_num_vars
            ))));
        }

        let to_reduce = self.prover_param.num_vars - supported_num_vars;
        let ck = Self::ProverParam {
            powers_of_g: self.prover_param.powers_of_g[to_reduce..].to_vec(),
            g: self.prover_param.g,
            h: self.prover_param.h,
            num_vars: supported_num_vars,
        };
        let vk = Self::VerifierParam {
            num_vars: supported_num_vars,
            g: self.prover_param.g,
            h: self.prover_param.h,
            h_mask: self.h_mask[to_reduce..].to_vec(),
        };
        Ok((ck, vk))
    }

    /// Build SRS for testing.
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    #[timed]
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, num_vars: usize) -> SnarkResult<Self> {
        if num_vars == 0 {
            return Err(SnarkError::PCSErrors(PCSError::InvalidParameters(
                "constant polynomial not supported".to_string(),
            )));
        }

        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);

        let mut powers_of_g = Vec::new();

        let t: Vec<_> = (0..num_vars).map(|_| E::ScalarField::rand(rng)).collect();

        let mut eq: LinkedList<MLE<E::ScalarField>> = LinkedList::from_iter(eq_extension(&t));
        let mut eq_arr = LinkedList::new();
        // TODO: See if you can get rid of the clone next line
        let mut base = eq.pop_back().unwrap().evaluations().clone();

        for i in (0..num_vars).rev() {
            eq_arr.push_front(remove_dummy_variable(&base, i)?);
            if i != 0 {
                let mul = eq.pop_back().unwrap();
                base = base
                    .into_iter()
                    .zip(mul.iter())
                    .map(|(a, b)| a * b)
                    .collect();
            }
        }

        let mut pp_powers = Vec::new();
        let mut _total_scalars = 0;
        for i in 0..num_vars {
            let eq = eq_arr.pop_front().unwrap();
            let pp_k_powers = (0..(1 << (num_vars - i))).map(|x| eq[x]);
            pp_powers.extend(pp_k_powers);
            _total_scalars += 1 << (num_vars - i);
        }
        let pp_g = g.batch_mul(&pp_powers);

        let mut start = 0;
        for i in 0..num_vars {
            let size = 1 << (num_vars - i);
            let pp_k_g = Evaluations {
                evals: pp_g[start..(start + size)].to_vec(),
            };
            // check correctness of pp_k_g
            let t_eval_0 = eq_eval(&vec![E::ScalarField::zero(); num_vars - i], &t[i..num_vars])?;
            assert_eq!((g * t_eval_0).into(), pp_k_g.evals[0]);
            powers_of_g.push(pp_k_g);
            start += size;
        }
        let gg = Evaluations {
            evals: [g.into_affine()].to_vec(),
        };
        powers_of_g.push(gg);

        let pp = Self::ProverParam {
            num_vars,
            g: g.into_affine(),
            h: h.into_affine(),
            powers_of_g,
        };

        let h_mask = { h.batch_mul(&t) };
        Ok(Self {
            prover_param: pp,
            h_mask,
        })
    }
}

/// fix first `pad` variables of `poly` represented in evaluation form to zero
fn remove_dummy_variable<F: PrimeField>(poly: &[F], pad: usize) -> SnarkResult<Vec<F>> {
    if pad == 0 {
        return Ok(poly.to_vec());
    }
    if !poly.len().is_power_of_two() {
        return Err(SnarkError::PCSErrors(PCSError::InvalidParameters(
            "Size of polynomial should be power of two.".to_string(),
        )));
    }
    let nv = ark_std::log2(poly.len()) as usize - pad;
    Ok((0..(1 << nv)).map(|x| poly[x << pad]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    type E = ark_test_curves::bls12_381::Bls12_381;

    #[test]
    fn test_srs_gen() -> SnarkResult<()> {
        let mut rng = test_rng();
        for nv in 4..10 {
            let _ = MultilinearUniversalParams::<E>::gen_srs_for_testing(&mut rng, nv)?;
        }

        Ok(())
    }
}
