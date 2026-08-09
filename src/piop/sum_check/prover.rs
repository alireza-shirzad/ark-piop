use crate::{
    arithmetic::{mat_poly::mle::MLE, virt_poly::hp_interface::HPVirtualPolynomial},
    piop::errors::PolyIOPErrors,
};
use ark_ff::{PrimeField, batch_inversion};
use ark_poly::MultilinearExtension;
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut};
#[cfg(feature = "parallel")]
use rayon::prelude::{
    IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use std::sync::{Arc, OnceLock};
use tracing::instrument;

use crate::piop::structs::{MleSlot, SumcheckProverMessage, SumcheckProverState};

/// Read the configured number of streaming rounds from the environment,
/// with a permanent per-process cache. `0` = fully eager fold (current
/// default, no memory optimization); `num_variables` = fully streaming
/// (never materialize, minimum peak memory, `n×` compute cost); values in
/// between give partial streaming — the first `k` rounds are streamed,
/// then the poly is materialized at its shrunk `2^(n-k)` size and eager
/// folding resumes.
///
/// The cap-at-`num_variables` clamp is applied by the caller, not here;
/// this reader returns the raw env value.
pub(crate) fn stream_first_k_rounds() -> usize {
    static CACHED: OnceLock<usize> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("TT_SUMCHECK_STREAM_K")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0)
    })
}

impl<F: PrimeField> SumcheckProverState<F> {
    // type HPVirtualPolynomial = HPVirtualPolynomial<F>;
    // type ProverMessage = IOPProverMessage<F>;

    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`. Reads the streaming-window size from the
    /// `TT_SUMCHECK_STREAM_K` env var; tests that need deterministic
    /// control should call [`Self::prover_init_with_stream_k`] instead.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn prover_init(polynomial: &HPVirtualPolynomial<F>) -> Result<Self, PolyIOPErrors> {
        Self::prover_init_with_stream_k(polynomial, stream_first_k_rounds())
    }

    /// Same as [`Self::prover_init`] but takes an explicit `stream_k`
    /// window, bypassing the env-var read. Used by the streaming-parity
    /// tests so a single process can exercise multiple `k` values (the
    /// env-var reader caches its answer per-process via `OnceLock`).
    ///
    /// Streaming policy: the (capped) `stream_k` picks how many rounds to
    /// defer materialization for. This picker just stores the value; the
    /// actual routing of individual MLEs into `Materialized` vs
    /// `Streaming` slots happens lazily on the first call to
    /// `prove_round_and_update_state`.
    pub(crate) fn prover_init_with_stream_k(
        polynomial: &HPVirtualPolynomial<F>,
        stream_k_raw: usize,
    ) -> Result<Self, PolyIOPErrors> {
        if polynomial.aux_info.num_variables == 0 {
            return Err(PolyIOPErrors::InvalidParameters(
                "Attempt to prove a constant.".to_string(),
            ));
        }
        let stream_k = stream_k_raw.min(polynomial.aux_info.num_variables);

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
            mle_slots: Vec::new(),
            mles_initialized: false,
            stream_k,
            // Seed with the empty-product identity so round 1's compute path
            // (which reads `stream_eq_table[0] * lift(idx)`) is naturally
            // an identity read before any challenge has arrived.
            stream_eq_table: vec![F::one()],
        })
    }

    /// Receive message from verifier, generate prover message, and proceed to
    /// next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    ///
    /// # Streaming behavior
    ///
    /// When `stream_k > 0`, the first `stream_k` rounds defer materialization:
    /// compressed-storage MLEs stay in their native form and the fold is
    /// applied *virtually* via a growing `stream_eq_table` (see the
    /// `read_slot` helper below). Field-storage MLEs cannot benefit from
    /// streaming and are always materialized eagerly. At the transition
    /// (once `round == stream_k`), any remaining `Streaming` slots are
    /// materialized to the residual `2^(n-k)` size and the `eq_table` is
    /// dropped; from that point on, all slots fold in place as before.
    ///
    /// When `stream_k == 0` (the default), this reduces to the previous
    /// eager path: every MLE is materialized on the first call and folded
    /// in place thereafter.
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
        // At round m <= n, for each mle g(x_1, ... x_n) within `mle_slots`
        // which is already logically evaluated to
        //
        //    g(r_1, ..., r_{m-1}, x_m ... x_n)
        //
        // we eval g over r_m, updating it to g(r_1, ... r_m, x_{m+1}... x_n).
        // Materialized slots do this via `fix_one_variable_in_place` on
        // their owned `Vec<F>` buffer (single lift+in-place-truncate for
        // the whole sumcheck — no per-round allocations). Streaming slots
        // do nothing here except let `stream_eq_table` be extended by one
        // variable — the fold is applied virtually at read time.
        if !self.mles_initialized {
            let drained = std::mem::take(&mut self.poly.flattened_ml_extensions);
            let stream_k = self.stream_k;
            self.mle_slots = cfg_into_iter!(drained)
                .map(|arc| {
                    // Field storage gets nothing from streaming (it's already
                    // materialized), so route it straight to Materialized and
                    // pay the eager fold cost. Compressed storage only routes
                    // to Streaming when `stream_k > 0` — with `k == 0` we
                    // keep the exact prior eager behavior (materialize now,
                    // fold in place).
                    let can_stream = stream_k > 0
                        && !matches!(
                            arc.storage(),
                            crate::arithmetic::mat_poly::mle::MLEStorage::Field(_)
                        );
                    if can_stream {
                        MleSlot::Streaming(arc)
                    } else {
                        // Sole-owner fast path: promote to Field without
                        // cloning the underlying Vec if it's already Field.
                        let mle = match Arc::try_unwrap(arc) {
                            Ok(mle) => match mle.storage() {
                                crate::arithmetic::mat_poly::mle::MLEStorage::Field(_) => mle,
                                _ => mle.to_field_owned(),
                            },
                            Err(arc) => arc.to_field_owned(),
                        };
                        MleSlot::Materialized(mle)
                    }
                })
                .collect();
            self.mles_initialized = true;
        }
        if let Some(chal) = challenge {
            if self.round == 0 {
                return Err(PolyIOPErrors::Prover(
                    "first round should be prover first.".to_string(),
                ));
            }
            self.challenges.push(*chal);

            let r = self.challenges[self.round - 1];
            // Streaming-phase bookkeeping: if this challenge lands inside the
            // streaming window (round-1 < stream_k), extend the eq_table by
            // one variable. Note that `stream_k == 0` short-circuits this
            // whole block (self.round - 1 < 0 is false for usize round >= 1)
            // — the eager path never touches stream_eq_table after init.
            let is_stream_round = self.round <= self.stream_k;
            if is_stream_round {
                let old_len = self.stream_eq_table.len();
                let mut new_table: Vec<F> = Vec::with_capacity(old_len * 2);
                let one_minus_r = F::one() - r;
                for i in 0..old_len {
                    new_table.push(self.stream_eq_table[i] * one_minus_r);
                }
                for i in 0..old_len {
                    new_table.push(self.stream_eq_table[i] * r);
                }
                self.stream_eq_table = new_table;
            }
            // Fold Materialized slots in place. Streaming slots are untouched
            // — the fold for them is captured in `stream_eq_table`.
            cfg_iter_mut!(self.mle_slots).for_each(|slot| {
                if let MleSlot::Materialized(mle) = slot {
                    mle.fix_one_variable_in_place(&r);
                }
            });
            // Transition: when we've consumed `stream_k` challenges, all
            // remaining Streaming slots must be materialized to their
            // residual `2^(n - stream_k)` size so downstream rounds can
            // fold in place. Peak-memory-wise this is the smallest
            // realisation of the streamed polys we'll ever hold: at
            // `k == 6, n == 26` this materialization is `1M × 32 B = 32 MiB`
            // per streamed poly vs `2^26 × 32 B = 2 GiB` under eager.
            if self.round == self.stream_k {
                let residual_nv = self.poly.aux_info.num_variables - self.stream_k;
                let eq_table = std::mem::take(&mut self.stream_eq_table);
                for slot in self.mle_slots.iter_mut() {
                    if let MleSlot::Streaming(arc) = slot {
                        let materialized =
                            materialize_streamed(arc, &eq_table, residual_nv);
                        // Replace: the Arc drops here — its underlying
                        // original storage frees IFF we were the sole
                        // strong ref (typically true; the tracker Arc is
                        // dropped before sumcheck enters).
                        *slot = MleSlot::Materialized(materialized);
                    }
                }
                // eq_table gets dropped when this scope ends.
                let _ = eq_table;
            }
        } else if self.round > 0 {
            return Err(PolyIOPErrors::Prover(
                "verifier message is empty".to_string(),
            ));
        }
        // end_timer!(fix_argument);

        let mle_slots = &self.mle_slots;
        let stream_eq_table = &self.stream_eq_table;

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

        // How many streaming challenges have been applied by the time this
        // round's message is computed. During the streaming window this
        // equals `self.round` at entry (self.round hasn't been incremented
        // yet); after transition it stays at `stream_k` because we no
        // longer extend the table. The compute path uses this only for
        // the Streaming-slot read shift (`idx << stream_m`).
        let stream_m = stream_eq_table.len().trailing_zeros() as usize;

        // Slot "current" num_vars — respects both in-place folds
        // (Materialized) and virtual folds via eq_table (Streaming).
        let slot_num_vars = |slot: &MleSlot<F>| -> usize {
            match slot {
                MleSlot::Materialized(mle) => mle.num_vars(),
                MleSlot::Streaming(arc) => arc.num_vars().saturating_sub(stream_m),
            }
        };

        // Slot inner num_vars — matches `mat_mle().num_vars` semantics for
        // Materialized (Field storage after in-place folds: inner drops
        // by one per fold). For Streaming we've folded virtually via
        // `stream_eq_table` (not in-place), so we subtract `stream_m` to
        // report the same virtual size a hypothetical in-place fold
        // would give. Assumes non-padded input MLEs
        // (`inner_num_vars == outer num_vars`) — the sumcheck flow in
        // this crate never enters with padded storage.
        let slot_inner_num_vars = |slot: &MleSlot<F>| -> usize {
            match slot {
                MleSlot::Materialized(mle) => mle.mat_mle().num_vars(),
                MleSlot::Streaming(arc) => {
                    arc.storage().inner_num_vars().saturating_sub(stream_m)
                }
            }
        };

        // Read the slot's current virtual value at logical index `idx` in
        // this round's residual hypercube. Materialized: direct index
        // (`mle[idx]`) into the in-place-folded buffer. Streaming: dot
        // product of the accumulated eq_table against the original
        // storage, with cyclic-index masking to respect virtual padding
        // (`nv > inner_num_vars`) — otherwise a scalar-storage poly
        // (inner_num_vars == 0) would panic on lift(nonzero).
        let read_slot = |slot: &MleSlot<F>, idx: usize| -> F {
            match slot {
                MleSlot::Materialized(mle) => mle[idx],
                MleSlot::Streaming(arc) => {
                    let inner_nv = arc.storage().inner_num_vars();
                    let inner_mask = (1usize << inner_nv).wrapping_sub(1);
                    let base = idx << stream_m;
                    let mut acc = F::zero();
                    for (i, eq_val) in stream_eq_table.iter().enumerate() {
                        let raw_idx = i | base;
                        let masked = raw_idx & inner_mask;
                        acc += *eq_val * arc.storage().lift(masked);
                    }
                    acc
                }
            }
        };

        let max_nv = slot_num_vars(&mle_slots[0]);

        // Step 2: generate sum for the partial evaluated polynomial:
        // f(r_1, ... r_m,, x_{m+1}... x_n)
        //
        // NOTE: the inner cfg_iter closure MUST NOT capture the parent-scope
        // `slot_num_vars` / `read_slot` / `slot_inner_num_vars` closures
        // because rayon needs the closure body to be `Sync`. Instead we
        // re-implement the small ops inline (via `mle_slots`, `stream_m`,
        // and `stream_eq_table`, which are all `Sync`).

        let zero = F::zero();
        let sums = cfg_iter!(products_list)
            .map(|(coefficient, products)| {
                let mut coefficient = *coefficient;

                // Domain size from ALL factors (including scalars) — must be
                // preserved so the summation covers the correct hypercube.
                // We use inner_num_vars here (matching the existing
                // `mat_mle().num_vars()` semantics) so the summation-size
                // arithmetic below stays bit-identical to the eager path.
                let term_nv = products
                    .iter()
                    .map(|i| slot_inner_num_vars(&mle_slots[*i]))
                    .max()
                    .unwrap();

                // Fold true scalar MLEs (inner num_vars == 0) into the
                // coefficient. These have a single evaluation element that
                // never changes with fix_variables, so they contribute a
                // constant multiplicative factor at every summation position.
                // Crucially, removing them does NOT change term_nv because
                // max(0, other_nvs) == max(other_nvs).
                let mut non_scalar_products: Vec<usize> = Vec::with_capacity(products.len());
                for &f in products.iter() {
                    if slot_inner_num_vars(&mle_slots[f]) == 0 {
                        coefficient *= read_slot(&mle_slots[f], 0);
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
                                    // Slot-aware read: Materialized takes
                                    // the direct-index fast path; Streaming
                                    // does the eq_table dot product with
                                    // inner-length cyclic masking. See the
                                    // `read_slot` closure comment above.
                                    let slot = &mle_slots[*f];
                                    let (v0, v1) = match slot {
                                        MleSlot::Materialized(mle) => {
                                            (mle[b << 1], mle[(b << 1) + 1])
                                        }
                                        MleSlot::Streaming(arc) => {
                                            let inner_nv = arc.storage().inner_num_vars();
                                            let inner_mask =
                                                (1usize << inner_nv).wrapping_sub(1);
                                            let base0 = (b << 1) << stream_m;
                                            let base1 = ((b << 1) + 1) << stream_m;
                                            let mut a0 = F::zero();
                                            let mut a1 = F::zero();
                                            for (i, eq_val) in
                                                stream_eq_table.iter().enumerate()
                                            {
                                                let m0 = (i | base0) & inner_mask;
                                                let m1 = (i | base1) & inner_mask;
                                                a0 += *eq_val * arc.storage().lift(m0);
                                                a1 += *eq_val * arc.storage().lift(m1);
                                            }
                                            (a0, a1)
                                        }
                                    };
                                    *eval = v0;
                                    let cur_eval_is_zero = eval.is_zero();
                                    any_eval_is_zero |= cur_eval_is_zero;
                                    *step = v1 - *eval;
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
        // No write-back to `self.poly.flattened_ml_extensions`: the round-fold
        // result lives in `self.flattened_mles` and is consumed by the next
        // round via `fix_one_variable_in_place`. Nothing outside the prover
        // state ever reads `self.poly.flattened_ml_extensions` after the
        // sumcheck loop, so skipping the re-wrap into `Vec<Arc<MLE<F>>>` also
        // drops per-round Arc allocation traffic.

        Ok(SumcheckProverMessage {
            evaluations: products_sum,
        })
    }
}

/// Materialize a streaming MLE at the transition boundary. Given the
/// original storage plus the `eq_table` accumulated over `stream_k`
/// streaming challenges, compute the folded evaluations at their
/// residual `2^(n - stream_k)` size:
///
/// ```text
///   materialized[j] = Σ_{i ∈ [0, 2^k)} eq_table[i] * original.lift((i | (j << k)) & inner_mask)
/// ```
///
/// The `inner_mask` handles virtually-padded inputs (nv > inner_num_vars)
/// by cycling through the physical storage — matches the same
/// convention used in the round-message read path.
///
/// Peak memory during this call is `residual_len × sizeof(F)` per poly —
/// at `k=6, n=26` that's 32 MiB per poly vs 2 GiB under eager. The
/// original `Arc<MLE>` is dropped once the caller replaces the slot.
fn materialize_streamed<F: PrimeField>(
    original: &Arc<MLE<F>>,
    eq_table: &[F],
    residual_nv: usize,
) -> MLE<F> {
    let k = eq_table.len().trailing_zeros() as usize;
    let residual_len = 1usize << residual_nv;
    let inner_nv = original.storage().inner_num_vars();
    let inner_mask = (1usize << inner_nv).wrapping_sub(1);
    let evals: Vec<F> = cfg_into_iter!(0..residual_len)
        .map(|j| {
            let base = j << k;
            let mut acc = F::zero();
            for (i, eq_val) in eq_table.iter().enumerate() {
                let raw = i | base;
                let masked = raw & inner_mask;
                acc += *eq_val * original.storage().lift(masked);
            }
            acc
        })
        .collect();
    MLE::from_evaluations_vec(residual_nv, evals)
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
