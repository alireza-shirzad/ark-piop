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
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use tracing::{info, instrument};

use crate::piop::structs::{MleSlot, SumcheckProverMessage, SumcheckProverState};

/// User-configurable streaming policy, cached per-process; see [`stream_policy`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum StreamPolicy {
    /// Materialize everything on round 1, fold in place. Fastest, highest peak memory.
    Eager,
    /// Stream the first `k` rounds (fold applied virtually via `stream_eq_table`),
    /// then materialize at the shrunk `2^(n-k)` size.
    Explicit(usize),
    /// Decide at init time from the factor mix — see [`decide_auto_stream_k`].
    Auto,
}

/// Read `TT_SUMCHECK_STREAM_K` (cached per-process): unset/`0`/unrecognized → Eager,
/// `auto` → Auto, positive `N` → Explicit(N) (capped at `num_variables` later).
///
/// Streaming is OFF by default: the auto heuristic counts compressed factors
/// but not bytes, so it engaged on ordinary nv-20 TPC-H sumchecks — where it
/// saves tens of MiB but costs ~30-45% prover time. Until the decision is
/// byte-budgeted, streaming is opt-in via `TT_SUMCHECK_STREAM_K=auto` (or an
/// explicit window) for the char-domain workloads it was built for.
pub(crate) fn stream_policy() -> StreamPolicy {
    static CACHED: OnceLock<StreamPolicy> = OnceLock::new();
    *CACHED.get_or_init(|| match std::env::var("TT_SUMCHECK_STREAM_K") {
        Err(_) => StreamPolicy::Eager,
        Ok(s) => {
            let trimmed = s.trim();
            if trimmed.eq_ignore_ascii_case("auto") {
                StreamPolicy::Auto
            } else if let Ok(n) = trimmed.parse::<usize>() {
                if n == 0 {
                    StreamPolicy::Eager
                } else {
                    StreamPolicy::Explicit(n)
                }
            } else {
                StreamPolicy::Eager
            }
        }
    })
}

/// Wall-clock ms since the UNIX epoch (kept local to avoid a tracker dependency).
fn wall_clock_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Emit one `sumcheck_stream_decision` JSON event (target `bench_stats`) describing how
/// `prover_init` picked `stream_k`; also echoes to stderr when `TT_MEMSNAP=1`.
fn emit_sumcheck_stream_decision<F: PrimeField>(
    polynomial: &HPVirtualPolynomial<F>,
    breakdown: &BTreeMap<&'static str, usize>,
    policy_source: &'static str,
    policy_raw_k: Option<usize>,
    auto_would_pick_k: usize,
    stream_k_effective: usize,
) {
    let n = polynomial.aux_info.num_variables;
    let factors_total: usize = breakdown.values().sum();
    let compressed_factor_count: usize = breakdown
        .iter()
        .filter(|(k, _)| **k != "field")
        .map(|(_, v)| *v)
        .sum();
    let decision = if stream_k_effective == 0 {
        "eager"
    } else if stream_k_effective >= n {
        "streaming"
    } else {
        "partial"
    };
    let by_kind_json: serde_json::Map<String, serde_json::Value> = breakdown
        .iter()
        .map(|(k, v)| ((*k).to_string(), serde_json::json!(*v)))
        .collect();
    let payload = serde_json::json!({
        "wall_ms": wall_clock_ms(),
        "num_variables": n,
        "max_degree": polynomial.aux_info.max_degree,
        "factors_total": factors_total,
        "factors_by_kind": by_kind_json,
        "compressed_factor_count": compressed_factor_count,
        "policy_source": policy_source,
        "policy_raw_k": policy_raw_k,
        "auto_would_pick_k": auto_would_pick_k,
        "stream_k_effective": stream_k_effective,
        "decision": decision,
    });
    info!(
        target: "bench_stats",
        sumcheck_stream_decision_json = %payload.to_string(),
        "sumcheck_stream_decision"
    );
    if std::env::var("TT_MEMSNAP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        eprintln!("[TT_SUMCHECK] {}", payload);
    }
}

/// Bucket the poly's unique MLEs (deduped by Arc pointer, matching the lift-cost
/// accounting in `decide_auto_stream_k`) by `MLEStorage::kind_tag()`.
/// `BTreeMap` keeps the emitted JSON stable across runs.
pub(crate) fn factor_breakdown_by_kind<F: PrimeField>(
    polynomial: &HPVirtualPolynomial<F>,
) -> BTreeMap<&'static str, usize> {
    use std::collections::HashSet;

    let mut seen: HashSet<*const MLE<F>> = HashSet::new();
    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    for arc in &polynomial.flattened_ml_extensions {
        let ptr = Arc::as_ptr(arc);
        if !seen.insert(ptr) {
            continue;
        }
        *by_kind.entry(arc.storage().kind_tag()).or_insert(0) += 1;
    }
    by_kind
}

/// Decide full streaming (`k = num_variables`) vs eager (`k = 0`) from the factor mix:
/// streaming avoids materializing compressed factors to `2^n` field storage but pays for
/// one growing `stream_eq_table`, so it's enabled only when enough compressed factors each
/// save an eq_table's worth. Field-storage factors never benefit; duplicate Arcs count once.
// Only reached from tests today; `prover_init` uses `decide_auto_stream_k_from_breakdown`
// to share one breakdown walk with the emitted event.
#[allow(dead_code)]
pub(crate) fn decide_auto_stream_k<F: PrimeField>(
    polynomial: &HPVirtualPolynomial<F>,
) -> usize {
    let breakdown = factor_breakdown_by_kind(polynomial);
    decide_auto_stream_k_from_breakdown(polynomial.aux_info.num_variables, &breakdown)
}

/// Threshold-application half of the auto-decision, taking a prebuilt breakdown.
pub(crate) fn decide_auto_stream_k_from_breakdown(
    num_variables: usize,
    breakdown: &BTreeMap<&'static str, usize>,
) -> usize {
    // Small polys never benefit — eq_table + streaming compute dominates.
    if num_variables < 20 {
        return 0;
    }
    let compressed_factor_count: usize = breakdown
        .iter()
        .filter(|(k, _)| **k != "field")
        .map(|(_, v)| *v)
        .sum();
    // Deliberately conservative: one compressed poly isn't worth the wall-time
    // overhead of streaming, a handful is.
    const THRESHOLD_FACTORS: usize = 4;
    if compressed_factor_count >= THRESHOLD_FACTORS {
        num_variables
    } else {
        0
    }
}

impl<F: PrimeField> SumcheckProverState<F> {
    /// Initialize the prover state to argue for the sum of the input polynomial
    /// over {0,1}^`num_vars`. Streaming policy comes from `TT_SUMCHECK_STREAM_K`
    /// (see [`stream_policy`]); tests needing deterministic control should call
    /// [`Self::prover_init_with_stream_k`] instead.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn prover_init(polynomial: &HPVirtualPolynomial<F>) -> Result<Self, PolyIOPErrors> {
        // One factor walk shared between the auto decision and the diagnostic event.
        let breakdown = factor_breakdown_by_kind(polynomial);
        let policy = stream_policy();
        let n = polynomial.aux_info.num_variables;
        let auto_would_pick_k = decide_auto_stream_k_from_breakdown(n, &breakdown);
        let (policy_source, policy_raw_k, k_raw) = match policy {
            StreamPolicy::Eager => ("eager", None, 0usize),
            StreamPolicy::Explicit(n_raw) => ("explicit", Some(n_raw), n_raw),
            StreamPolicy::Auto => ("auto", None, auto_would_pick_k),
        };
        // Mirror the `num_variables` cap applied by `prover_init_with_stream_k`.
        let k_effective = k_raw.min(n);
        emit_sumcheck_stream_decision(
            polynomial,
            &breakdown,
            policy_source,
            policy_raw_k,
            auto_would_pick_k,
            k_effective,
        );
        Self::prover_init_with_stream_k(polynomial, k_raw)
    }

    /// Same as [`Self::prover_init`] but with an explicit `stream_k` window,
    /// bypassing the (per-process-cached) env-var read. The value is only stored
    /// here; MLE routing into Materialized/Streaming slots happens lazily on the
    /// first `prove_round_and_update_state` call.
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
            // Empty-product identity: round 1 reads `stream_eq_table[0] * lift(idx)`
            // before any challenge has arrived.
            stream_eq_table: vec![F::one()],
        })
    }

    /// Receive the verifier's challenge, generate the prover message, and advance a
    /// round. Algorithm from section 3.2 of
    /// [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    ///
    /// Streaming: with `stream_k > 0`, the first `stream_k` rounds keep compressed MLEs
    /// in native form and fold virtually via a growing `stream_eq_table`; at
    /// `round == stream_k` remaining Streaming slots materialize at `2^(n-k)` and eager
    /// in-place folding resumes. `stream_k == 0` is the fully eager path.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn prove_round_and_update_state(
        &mut self,
        challenge: &Option<F>,
    ) -> Result<SumcheckProverMessage<F>, PolyIOPErrors> {
        if self.round >= self.poly.aux_info.num_variables {
            return Err(PolyIOPErrors::Prover("Prover is not active".to_string()));
        }

        // Step 1: fix x_m = r for round m. Materialized slots fold via
        // `fix_one_variable_in_place` (no per-round allocations); Streaming slots
        // just let `stream_eq_table` grow — their fold is applied at read time.
        if !self.mles_initialized {
            let drained = std::mem::take(&mut self.poly.flattened_ml_extensions);
            let stream_k = self.stream_k;
            self.mle_slots = cfg_into_iter!(drained)
                .map(|arc| {
                    // Field storage never benefits from streaming; compressed storage
                    // streams only when `stream_k > 0` (k == 0 keeps exact eager behavior).
                    let can_stream = stream_k > 0
                        && !matches!(
                            arc.storage(),
                            crate::arithmetic::mat_poly::mle::MLEStorage::Field(_)
                        );
                    if can_stream {
                        MleSlot::Streaming(arc)
                    } else {
                        // Sole-owner fast path: avoid cloning the Vec if already Field.
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
            // Challenges inside the streaming window extend the eq_table by one
            // variable; the eager path (stream_k == 0) never touches it after init.
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
            // Fold Materialized slots in place; Streaming folds live in stream_eq_table.
            cfg_iter_mut!(self.mle_slots).for_each(|slot| {
                if let MleSlot::Materialized(mle) = slot {
                    mle.fix_one_variable_in_place(&r);
                }
            });
            // Transition: after `stream_k` challenges, materialize remaining Streaming
            // slots at their residual `2^(n - stream_k)` size — the smallest realization
            // of the streamed polys we ever hold — so later rounds fold in place.
            if self.round == self.stream_k {
                let residual_nv = self.poly.aux_info.num_variables - self.stream_k;
                let eq_table = std::mem::take(&mut self.stream_eq_table);
                for slot in self.mle_slots.iter_mut() {
                    if let MleSlot::Streaming(arc) = slot {
                        let materialized =
                            materialize_streamed(arc, &eq_table, residual_nv);
                        // The Arc drops here; original storage frees iff we were the
                        // sole strong ref (typically true).
                        *slot = MleSlot::Materialized(materialized);
                    }
                }
                let _ = eq_table;
            }
        } else if self.round > 0 {
            return Err(PolyIOPErrors::Prover(
                "verifier message is empty".to_string(),
            ));
        }

        let mle_slots = &self.mle_slots;
        let stream_eq_table = &self.stream_eq_table;

        self.round += 1;

        let products_list = self.poly.products.clone();
        let mut products_sum = vec![F::zero(); self.poly.aux_info.max_degree + 1];

        // Streaming challenges applied so far (stays at `stream_k` after transition);
        // used only for the Streaming-slot read shift (`idx << stream_m`).
        let stream_m = stream_eq_table.len().trailing_zeros() as usize;

        // Slot "current" num_vars, respecting in-place and virtual folds alike.
        let slot_num_vars = |slot: &MleSlot<F>| -> usize {
            match slot {
                MleSlot::Materialized(mle) => mle.num_vars(),
                MleSlot::Streaming(arc) => arc.num_vars().saturating_sub(stream_m),
            }
        };

        // Slot inner num_vars, matching `mat_mle().num_vars` semantics; Streaming
        // subtracts `stream_m` to report what an in-place fold would give. Assumes
        // non-padded inputs (`inner_num_vars == outer num_vars`).
        let slot_inner_num_vars = |slot: &MleSlot<F>| -> usize {
            match slot {
                MleSlot::Materialized(mle) => mle.mat_mle().num_vars(),
                MleSlot::Streaming(arc) => {
                    arc.storage().inner_num_vars().saturating_sub(stream_m)
                }
            }
        };

        // Read the slot's current virtual value at `idx`. Materialized: direct index.
        // Streaming: eq_table dot product against original storage, with cyclic-index
        // masking for virtual padding — otherwise a scalar-storage poly
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

        // Step 2: sum the partially evaluated polynomial f(r_1..r_m, x_{m+1}..x_n).
        // NOTE: the inner cfg_iter closure MUST NOT capture the parent-scope helper
        // closures — rayon needs its body `Sync` — so the small ops are re-implemented
        // inline via `mle_slots`, `stream_m`, and `stream_eq_table`.

        let zero = F::zero();
        let sums = cfg_iter!(products_list)
            .map(|(coefficient, products)| {
                let mut coefficient = *coefficient;

                // Domain size from ALL factors (including scalars) so the summation
                // covers the correct hypercube; inner_num_vars keeps the arithmetic
                // bit-identical to the eager path.
                let term_nv = products
                    .iter()
                    .map(|i| slot_inner_num_vars(&mle_slots[*i]))
                    .max()
                    .unwrap();

                // Fold scalar MLEs (inner num_vars == 0) into the coefficient: they're
                // a constant factor at every position, and removing them cannot change
                // term_nv since max(0, other_nvs) == max(other_nvs).
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
                    // Half-hypercube sum of a constant round polynomial (step = 0).
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
                                    // Slot-aware read; see the `read_slot` comment above.
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

        // Deliberately no write-back to `self.poly.flattened_ml_extensions`: nothing
        // reads it after the sumcheck loop, and skipping the re-wrap avoids per-round
        // Arc allocation traffic.

        Ok(SumcheckProverMessage {
            evaluations: products_sum,
        })
    }
}

/// Materialize a streaming MLE at the transition boundary: fold the original storage
/// against the accumulated `eq_table` into the residual `2^(n - stream_k)` evaluations.
///
/// ```text
///   materialized[j] = Σ_{i ∈ [0, 2^k)} eq_table[i] * original.lift((i | (j << k)) & inner_mask)
/// ```
///
/// `inner_mask` cycles physical storage for virtually-padded inputs, matching the
/// round-message read path.
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
