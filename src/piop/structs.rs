//! This module defines structs that are shared by all sub protocols.

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::sync::Arc;

use crate::arithmetic::{mat_poly::mle::MLE, virt_poly::hp_interface::HPVirtualPolynomial};
/// An IOP proof: per-round prover messages plus the transcript-generated
/// evaluation point.
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumcheckProof<F: PrimeField> {
    pub point: Vec<F>,
    pub proofs: Vec<SumcheckProverMessage<F>>,
}

/// A per-round prover message: a list of evaluations.
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SumcheckProverMessage<F: PrimeField> {
    pub(crate) evaluations: Vec<F>,
}

/// Per-factor storage slot inside the sumcheck prover.
///
/// `Materialized` folds in place each round (buffer halves and is reused).
/// `Streaming` reads through compressed storage without materializing: value at `j`
/// is `Σ_k stream_eq_table[k] * original.lift(k | (j << m))` for `m` accumulated
/// challenges, until the transition round materializes it. Streaming defers the
/// Field-materialization blowup that dominates sumcheck peak memory.
pub(crate) enum MleSlot<F: PrimeField> {
    Materialized(MLE<F>),
    Streaming(Arc<MLE<F>>),
}

/// Prover State of a PolyIOP.
pub struct SumcheckProverState<F: PrimeField> {
    /// sampled randomness given by the verifier
    pub challenges: Vec<F>,
    /// the current round number
    pub(crate) round: usize,
    /// pointer to the virtual polynomial
    pub(crate) poly: HPVirtualPolynomial<F>,
    /// Points with precomputed barycentric weights for extrapolating smaller
    /// degree uni-polys to `max_degree + 1` evaluations.
    pub(crate) extrapolation_aux: Vec<(Vec<F>, Vec<F>)>,
    /// One [`MleSlot`] per factor, populated on the first
    /// `prove_round_and_update_state` call from `poly.flattened_ml_extensions`.
    pub(crate) mle_slots: Vec<MleSlot<F>>,
    /// True once `mle_slots` is populated and `poly.flattened_ml_extensions` cleared.
    pub(crate) mles_initialized: bool,
    /// Streaming rounds before the eager transition (0 = fully eager). Resolved at
    /// `prover_init` from `TT_SUMCHECK_STREAM_K` (see `stream_policy`), capped at
    /// `poly.aux_info.num_variables`.
    pub(crate) stream_k: usize,
    /// Equality table `eq[b] = Π_j (b_j == 1 ? r_j : 1 - r_j)` over the accumulated
    /// streaming challenges, first challenge at the low bit. Grows from length 1
    /// (empty product) to `2^stream_k`, then dropped at the transition.
    pub(crate) stream_eq_table: Vec<F>,
}

/// Verifier state of a PolyIOP.
pub struct SumcheckVerifierState<F: PrimeField> {
    pub(crate) round: usize,
    pub(crate) num_vars: usize,
    pub(crate) max_degree: usize,
    pub(crate) finished: bool,
    /// Per-round univariate polynomials from the prover, in evaluation form.
    pub(crate) polynomials_received: Vec<Vec<F>>,
    /// Per-round verifier randomness.
    pub(crate) challenges: Vec<F>,
}
