//! Verifier subroutines for a SumCheck protocol.

use crate::{
    arithmetic::virt_poly::hp_interface::VPAuxInfo,
    errors::{SnarkError, SnarkResult},
    piop::{
        errors::PolyIOPErrors,
        structs::{SumcheckProverMessage, SumcheckVerifierState},
    },
    transcript::Tr,
};
use ark_ff::PrimeField;

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use super::SumCheckSubClaim;

impl<F: PrimeField> SumcheckVerifierState<F> {
    /// Initialize the verifier's state.
    pub(crate) fn verifier_init(index_info: &VPAuxInfo<F>) -> Self {
        Self {
            round: 1,
            num_vars: index_info.num_variables,
            max_degree: index_info.max_degree,
            finished: false,
            polynomials_received: Vec::with_capacity(index_info.num_variables),
            challenges: Vec::with_capacity(index_info.num_variables),
        }
    }

    /// Run one verifier round: sample and store the challenge only. The actual
    /// checks are deferred in batch to `check_and_generate_subclaim`.
    pub(crate) fn verify_round_and_update_state(
        &mut self,
        prover_msg: &SumcheckProverMessage<F>,
        transcript: &mut Tr<F>,
    ) -> Result<F, PolyIOPErrors> {
        if self.finished {
            return Err(PolyIOPErrors::InvalidVerifier(
                "Incorrect verifier state: Verifier is already finished.".to_string(),
            ));
        }

        // The interactive checks (P(0) + P(1) == expected; expected := P(r)) are safely
        // deferred to `check_and_generate_subclaim` in the non-interactive setting.
        let challenge = transcript.get_and_append_challenge(b"Internal round")?;
        self.challenges.push(challenge);
        self.polynomials_received
            .push(prover_msg.evaluations.to_vec());

        if self.round == self.num_vars {
            self.finished = true;
        } else {
            self.round += 1;
        }
        Ok(challenge)
    }

    /// Run the deferred per-round checks and produce the subclaim, erroring if the
    /// proof fails. If the asserted sum is correct, the polynomial evaluated at
    /// `subclaim.point` equals `subclaim.expected_evaluation` (soundness error
    /// shrinks with field size).
    pub fn check_and_generate_subclaim(
        &self,
        asserted_sum: &F,
    ) -> SnarkResult<SumCheckSubClaim<F>> {
        if !self.finished {
            return Err(SnarkError::from(PolyIOPErrors::InvalidVerifier(
                "Incorrect verifier state: Verifier has not finished.".to_string(),
            )));
        }

        if self.polynomials_received.len() != self.num_vars {
            return Err(SnarkError::from(PolyIOPErrors::InvalidVerifier(
                "insufficient rounds".to_string(),
            )));
        }

        // Deferred check 2: expected := P(r).
        #[cfg(feature = "parallel")]
        let mut expected_vec = self
            .polynomials_received
            .clone()
            .into_par_iter()
            .zip(self.challenges.clone().into_par_iter())
            .map(|(evaluations, challenge)| {
                if evaluations.len() != self.max_degree + 1 {
                    return Err(PolyIOPErrors::InvalidVerifier(format!(
                        "incorrect number of evaluations: {} vs {}",
                        evaluations.len(),
                        self.max_degree + 1
                    )));
                }
                interpolate_uni_poly::<F>(&evaluations, challenge)
            })
            .collect::<Result<Vec<_>, PolyIOPErrors>>()?;

        #[cfg(not(feature = "parallel"))]
        let mut expected_vec = self
            .polynomials_received
            .clone()
            .into_iter()
            .zip(self.challenges.clone().into_iter())
            .map(|(evaluations, challenge)| {
                if evaluations.len() != self.max_degree + 1 {
                    return Err(PolyIOPErrors::InvalidVerifier(format!(
                        "incorrect number of evaluations: {} vs {}",
                        evaluations.len(),
                        self.max_degree + 1
                    )));
                }
                interpolate_uni_poly::<F>(&evaluations, challenge)
            })
            .collect::<Result<Vec<_>, PolyIOPErrors>>()?;

        expected_vec.insert(0, *asserted_sum);

        for (i, (evaluations, &expected)) in self
            .polynomials_received
            .iter()
            .zip(expected_vec.iter())
            .enumerate()
            .take(self.num_vars)
        {
            // Deferred check 1: P(0) + P(1) == expected.
            if evaluations[0] + evaluations[1] != expected {
                return Err(SnarkError::VerifierError(
                    crate::verifier::errors::VerifierError::VerifierCheckFailed(format!(
                        "Sumcheck's deferred checks failed in round {i}. Prover message is not consistent with the claim."
                    )),
                ));
            }
        }
        Ok(SumCheckSubClaim {
            point: self.challenges.clone(),
            // The last expected value is not checked here; it goes into the subclaim.
            expected_evaluation: expected_vec[self.num_vars],
        })
    }
}

/// Interpolate the degree-`p_i.len()-1` univariate polynomial through `p_i` (at
/// points 0..len) and evaluate it at `eval_at`. Linear in field operations.
/// TODO: precompute Lagrange coefficients to drop the quadratic primitive-op term.
fn interpolate_uni_poly<F: PrimeField>(p_i: &[F], eval_at: F) -> Result<F, PolyIOPErrors> {
    let len = p_i.len();
    let mut evals = vec![];
    let mut prod = eval_at;
    evals.push(eval_at);

    // `prod = \prod_{j} (eval_at - j)`
    for e in 1..len {
        let tmp = eval_at - F::from(e as u64);
        evals.push(tmp);
        prod *= tmp;
    }
    let mut res = F::zero();
    // Compute denom[i] = \prod_{j!=i} (i-j) iteratively from i = len-1 downward via
    // denom[i-1] = denom[i] * (len-i) / i, keeping the running ratio as a fraction to
    // avoid field divisions. Since 2^61 < 20! < 2^62 and 2^122 < 33! < 2^123, the
    // ratio fits in i64 for len <= 20, i128 for len <= 33, else field arithmetic.
    if p_i.len() <= 20 {
        let last_denominator = F::from(u64_factorial(len - 1));
        let mut ratio_numerator = 1i64;
        let mut ratio_denominator = 1u64;

        for i in (0..len).rev() {
            let ratio_numerator_f = if ratio_numerator < 0 {
                -F::from((-ratio_numerator) as u64)
            } else {
                F::from(ratio_numerator as u64)
            };

            res += p_i[i] * prod * F::from(ratio_denominator)
                / (last_denominator * ratio_numerator_f * evals[i]);

            // compute denom for the next step is current_denom * (len-i)/i
            if i != 0 {
                ratio_numerator *= -(len as i64 - i as i64);
                ratio_denominator *= i as u64;
            }
        }
    } else if p_i.len() <= 33 {
        let last_denominator = F::from(u128_factorial(len - 1));
        let mut ratio_numerator = 1i128;
        let mut ratio_denominator = 1u128;

        for i in (0..len).rev() {
            let ratio_numerator_f = if ratio_numerator < 0 {
                -F::from((-ratio_numerator) as u128)
            } else {
                F::from(ratio_numerator as u128)
            };

            res += p_i[i] * prod * F::from(ratio_denominator)
                / (last_denominator * ratio_numerator_f * evals[i]);

            // compute denom for the next step is current_denom * (len-i)/i
            if i != 0 {
                ratio_numerator *= -(len as i128 - i as i128);
                ratio_denominator *= i as u128;
            }
        }
    } else {
        let mut denom_up = field_factorial::<F>(len - 1);
        let mut denom_down = F::one();

        for i in (0..len).rev() {
            res += p_i[i] * prod * denom_down / (denom_up * evals[i]);

            // compute denom for the next step is current_denom * (len-i)/i
            if i != 0 {
                denom_up *= -F::from((len - i) as u64);
                denom_down *= F::from(i as u64);
            }
        }
    }
    Ok(res)
}

/// compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn field_factorial<F: PrimeField>(a: usize) -> F {
    let mut res = F::one();
    for i in 2..=a {
        res *= F::from(i as u64);
    }
    res
}

/// compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn u128_factorial(a: usize) -> u128 {
    let mut res = 1u128;
    for i in 2..=a {
        res *= i as u128;
    }
    res
}

/// compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn u64_factorial(a: usize) -> u64 {
    let mut res = 1u64;
    for i in 2..=a {
        res *= i as u64;
    }
    res
}

#[cfg(test)]
mod test {
    use super::interpolate_uni_poly;
    use crate::{arithmetic::mat_poly::lde::LDE, piop::errors::PolyIOPErrors};
    use ark_bn254::Fr;
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use ark_std::{self, UniformRand, vec::Vec};
    #[test]
    fn test_interpolation() -> Result<(), PolyIOPErrors> {
        let mut prng = ark_std::test_rng();

        // test a polynomial with 20 known points, i.e., with degree 19
        let poly = LDE::<Fr>::rand(20 - 1, &mut prng);
        let evals = (0..20)
            .map(|i| poly.evaluate(&Fr::from(i)))
            .collect::<Vec<Fr>>();
        let query = Fr::rand(&mut prng);

        assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query)?);

        // test a polynomial with 33 known points, i.e., with degree 32
        let poly = LDE::<Fr>::rand(33 - 1, &mut prng);
        let evals = (0..33)
            .map(|i| poly.evaluate(&Fr::from(i)))
            .collect::<Vec<Fr>>();
        let query = Fr::rand(&mut prng);

        assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query)?);

        // test a polynomial with 64 known points, i.e., with degree 63
        let poly = LDE::<Fr>::rand(64 - 1, &mut prng);
        let evals = (0..64)
            .map(|i| poly.evaluate(&Fr::from(i)))
            .collect::<Vec<Fr>>();
        let query = Fr::rand(&mut prng);

        assert_eq!(poly.evaluate(&query), interpolate_uni_poly(&evals, query)?);

        Ok(())
    }
}
