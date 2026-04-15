use crate::{
    arithmetic::{
        mat_poly::{mle::MLE, utils::fix_variables},
        virt_poly::hp_interface::HPVirtualPolynomial,
    },
    piop::errors::PolyIOPErrors,
};
use ark_ff::{PrimeField, batch_inversion};
use ark_poly::MultilinearExtension;
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut};
#[cfg(feature = "parallel")]
use rayon::prelude::{
    IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use std::sync::Arc;
use tracing::instrument;

use crate::piop::structs::{SumcheckProverMessage, SumcheckProverState};

impl<F: PrimeField> SumcheckProverState<F> {
    // type HPVirtualPolynomial = HPVirtualPolynomial<F>;
    // type ProverMessage = IOPProverMessage<F>;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn prover_init(polynomial: &HPVirtualPolynomial<F>) -> Result<Self, PolyIOPErrors> {
        if polynomial.aux_info.num_variables == 0 {
            return Err(PolyIOPErrors::InvalidParameters(
                "Attempt to prove a constant.".to_string(),
            ));
        }

        Ok(Self {
            challenges: Vec::with_capacity(polynomial.aux_info.num_variables),
            round: 0,
            poly: polynomial.clone(),
            extrapolation_aux: (1..polynomial.aux_info.max_degree)
                .map(|degree| {
                    let points = (0..1 + degree as u64).map(F::from).collect::<Vec<_>>();
                    let weights = barycentric_weights(&points);
                    (points, weights)
                })
                .collect(),
        })
    }

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<F>,
    ) -> Result<SumcheckProverMessage<F>, PolyIOPErrors> {
        if self.round >= self.poly.aux_info.num_variables {
            return Err(PolyIOPErrors::Prover("Prover is not active".to_string()));
        }

        // Step 1:
        // fix argument and evaluate f(x) over x_m = r; where r is the challenge
        // for the current round, and m is the round number, indexed from 1
        //
        // i.e.:
        // at round m <= n, for each mle g(x_1, ... x_n) within the flattened_mle
        // which has already been evaluated to
        //
        //    g(r_1, ..., r_{m-1}, x_m ... x_n)
        //
        // eval g over r_m, and mutate g to g(r_1, ... r_m,, x_{m+1}... x_n)
        let mut flattened_mles: Vec<MLE<F>> = cfg_iter!(self.poly.flattened_ml_extensions)
            .map(|x| x.as_ref().clone())
            .collect();
        if let Some(chal) = challenge {
            if self.round == 0 {
                return Err(PolyIOPErrors::Prover(
                    "first round should be prover first.".to_string(),
                ));
            }
            self.challenges.push(*chal);

            let r = self.challenges[self.round - 1];
            cfg_iter_mut!(flattened_mles).for_each(|mle| *mle = fix_variables(mle, &[r]));
        } else if self.round > 0 {
            return Err(PolyIOPErrors::Prover(
                "verifier message is empty".to_string(),
            ));
        }
        // end_timer!(fix_argument);

        self.round += 1;

        let products_list = self.poly.products.clone();
        let mut products_sum = vec![F::zero(); self.poly.aux_info.max_degree + 1];

        // let mles = cfg_iter!(flattened_mles)
        //     .map(|f| {
        //         if f.mat_mle().num_vars() == 0 {
        //             vec![(f.mat_mle()[0], F::zero())]
        //         } else {
        //             f.mat_mle()
        //                 .evaluations
        //                 .chunks(2)
        //                 .map(|c| (c[0], c[1] - c[0]))
        //                 .collect::<Vec<_>>()
        //         }
        //     })
        //     .collect::<Vec<_>>();

        let max_nv = flattened_mles[0].num_vars();

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)

        let zero = F::zero();
        let sums = cfg_iter!(products_list)
            .map(|(coefficient, products)| {
                let mut coefficient = *coefficient;

                // Domain size from ALL factors (including scalars) — must be
                // preserved so the summation covers the correct hypercube.
                let term_nv = products
                    .iter()
                    .map(|i| flattened_mles[*i].mat_mle().num_vars())
                    .max()
                    .unwrap();

                // Fold true scalar MLEs (mat_mle().num_vars == 0) into the
                // coefficient. These have a single evaluation element that
                // never changes with fix_variables, so they contribute a
                // constant multiplicative factor at every summation position.
                // Crucially, removing them does NOT change term_nv because
                // max(0, other_nvs) == max(other_nvs).
                let mut non_scalar_products: Vec<usize> = Vec::with_capacity(products.len());
                for &f in products.iter() {
                    if flattened_mles[f].mat_mle().num_vars == 0 {
                        coefficient *= flattened_mles[f][0];
                    } else {
                        non_scalar_products.push(f);
                    }
                }

                let term_size = non_scalar_products.len();

                // All factors were scalar — the product is just a constant.
                if term_size == 0 {
                    let scale = F::from(1u64 << (max_nv - term_nv.max(1)));
                    // Sum over half-hypercube: each position contributes
                    // `coefficient`, and the round polynomial is constant
                    // (step = 0), so p(k) = same value for all k.
                    let summation_size = 1u64 << term_nv.saturating_sub(1);
                    let val = coefficient * scale * F::from(summation_size);
                    return vec![val; self.poly.aux_info.max_degree + 1];
                }

                let summation_size = 1 << (term_nv.saturating_sub(1));
                let mut sum = cfg_into_iter!(0..summation_size)
                    .fold(
                        || (vec![(zero, zero); term_size], vec![zero; term_size + 1]),
                        |(mut buf, mut acc), b| {
                            let mut any_eval_is_zero = false;
                            let mut any_step_and_eval_simultaneously_zero = false;
                            buf.iter_mut().zip(non_scalar_products.iter()).for_each(
                                |((eval, step), f)| {
                                    let table = &flattened_mles[*f];
                                    *eval = table[b << 1];
                                    let cur_eval_is_zero = eval.is_zero();
                                    any_eval_is_zero |= cur_eval_is_zero;
                                    *step = table[(b << 1) + 1] - *eval;
                                    any_step_and_eval_simultaneously_zero |=
                                        cur_eval_is_zero & step.is_zero();
                                },
                            );

                            if !any_eval_is_zero {
                                acc[0] += buf.iter().map(|(eval, _)| eval).product::<F>();
                            }

                            if !any_step_and_eval_simultaneously_zero {
                                acc[1..].iter_mut().for_each(|acc| {
                                    buf.iter_mut().for_each(|(eval, step)| *eval += step);
                                    *acc += buf.iter().map(|(eval, _)| eval).product::<F>();
                                });
                            }

                            (buf, acc)
                        },
                    )
                    .map(|(_, partial)| partial)
                    .reduce(
                        || vec![F::zero(); term_size + 1],
                        |mut sum, partial| {
                            sum.iter_mut()
                                .zip(partial)
                                .for_each(|(sum, partial)| *sum += partial);
                            sum
                        },
                    );
                coefficient *= F::from(1 << (max_nv - term_nv.max(1)));
                sum.iter_mut().for_each(|sum| *sum *= coefficient);

                let extrapolation = cfg_into_iter!(0..self.poly.aux_info.max_degree - term_size)
                    .map(|i| {
                        let (points, weights) = &self.extrapolation_aux[term_size - 1];
                        let at = F::from((term_size + 1 + i) as u64);
                        extrapolate(points, weights, &sum, &at)
                    })
                    .collect::<Vec<_>>();

                [sum, extrapolation].concat()
            })
            .collect::<Vec<_>>();

        sums.iter().for_each(|v| {
            v.iter()
                .zip(products_sum.iter_mut())
                .for_each(|(val, acc)| *acc += val)
        });

        // products_sum.iter_mut().enumerate().for_each(|(i, acc)| {
        //     *acc += cfg_iter!(sums).map(|v| v[i]).sum::<F>();
        // });
        // update prover's state to the partial evaluated polynomial
        self.poly.flattened_ml_extensions = cfg_into_iter!(flattened_mles).map(Arc::new).collect();

        Ok(SumcheckProverMessage {
            evaluations: products_sum,
        })
    }
}

fn barycentric_weights<F: PrimeField>(points: &[F]) -> Vec<F> {
    let mut weights = points
        .iter()
        .enumerate()
        .map(|(j, point_j)| {
            points
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != j)
                .map(|(_, point_i)| *point_j - point_i)
                .reduce(|acc, value| acc * value)
                .unwrap_or_else(F::one)
        })
        .collect::<Vec<_>>();
    batch_inversion(&mut weights);
    weights
}

fn extrapolate<F: PrimeField>(points: &[F], weights: &[F], evals: &[F], at: &F) -> F {
    let (coeffs, sum_inv) = {
        let mut coeffs = points.iter().map(|point| *at - point).collect::<Vec<_>>();
        batch_inversion(&mut coeffs);
        coeffs.iter_mut().zip(weights).for_each(|(coeff, weight)| {
            *coeff *= weight;
        });
        let sum_inv = coeffs.iter().sum::<F>().inverse().unwrap_or_default();
        (coeffs, sum_inv)
    };
    coeffs
        .iter()
        .zip(evals)
        .map(|(coeff, eval)| *coeff * eval)
        .sum::<F>()
        * sum_inv
}
