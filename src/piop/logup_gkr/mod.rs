//! Batched LogUp-GKR (Papini-Haböck, eprint 2023/1284): a sumcheck-only
//! argument that reduces sums of fractions to evaluation claims on their
//! numerators and denominators, with no helper commitment.
//!
//! An instance is `2^n` fractions `p(x)/q(x)`. They are added pairwise in a
//! binary tree: layer `k` holds `2^k` fractions, layer `n` is the input and
//! layer 0 the root, with
//! `p_k[j] = p_{k+1}[2j]·q_{k+1}[2j+1] + p_{k+1}[2j+1]·q_{k+1}[2j]` and
//! `q_k[j] = q_{k+1}[2j]·q_{k+1}[2j+1]`. The prover sends layer 1 of every
//! tree, which gives the root, and then walks all trees down together, one
//! layer per iteration: a sumcheck turns the claims `(p_k(r), q_k(r))` into
//! four evaluations of layer `k+1` (the mask), and a line challenge `mu`
//! folds the mask into the next claims.
//!
//! Conventions, as everywhere in the crate: variable 0 is the index LSB, the
//! first sumcheck round and `point[0]`. The pairing variable of a layer is
//! its variable 0, so the point of layer `k+1` is `(mu, rho_0..rho_{k-1})`.
//!
//! Instances of different sizes share the iterations. With `N = max n_i`,
//! instance `i` joins at iteration `N - n_i`, so all of them reach their
//! input layer in the last one, and instance `i`'s point is always a PREFIX
//! of the shared point. `GkrClaims::inputs` are therefore the input-layer
//! MLEs at `point[..n_i]`.
//!
//! # Protocol
//!
//! Every prover message is absorbed before the next challenge is drawn, and
//! the proof is the messages in that order. The mask of a layer at `y` is
//! `(p0, p1, q0, q1) = (p(0,y), p(1,y), q(0,y), q(1,y))`, sent in full or,
//! on the input layer of a unit-numerator instance, as `(q0, q1)` with
//! `p0 = p1 = 1` understood. Its gate value under `lambda` is
//! `gate = p0·q1 + p1·q0 + lambda·q0·q1`.
//!
//! 1. The statement is absorbed: the number of instances and each one's
//!    size and kind.
//! 2. First layers, in instance order: the mask of layer 1, or for an
//!    instance of one fraction that fraction `(p, q)`. The root is
//!    `(p0·q1 + p1·q0, q0·q1)`, or `(p, q)`.
//! 3. For `t` in `0..N`, with `r` the point of the previous iteration
//!    (length `t`), `k_i = t - (N - n_i)` the variables of the layer
//!    instance `i` has a claim `(P_i, Q_i)` on, and `idx` its position in
//!    the batch:
//!    - an instance with `k_i = 0` joins: its mask is its first layer and it
//!      has no part in the sumcheck, since the claim it would bring is the
//!      root, which was derived from that very mask;
//!    - if `t > 0`, challenges `lambda`, then `alpha`, and a sumcheck over
//!      `t` variables of
//!      `sum_i alpha^idx · eq(r[..k_i], y[..k_i]) · gate_i(y[..k_i])`
//!      against `C_0 = sum_i alpha^idx · 2^(t-k_i) · (P_i + lambda·Q_i)`,
//!      both over the instances with `k_i > 0`. In round `j`, with
//!      `z = r[j]` and `E_j = eq(r[..j], rho[..j])`, the round polynomial is
//!
//!      `s_j(X) = 2^(t-1-j)·D_j + ((1-z)(1-X) + z·X)·(a + b·X + c·X^2)`
//!
//!      where `D_j = sum_{0 < k_i <= j} alpha^idx · E_{k_i} · gate_i` is
//!      what the instances that have bound all their variables contribute
//!      at every point still summed over, and the quadratic is what the
//!      others contribute once the factor of `eq` in `X` is taken out. The
//!      prover sends `(b, c)`. The verifier takes
//!      `a = C_j - 2^(t-j)·D_j - z·(b + c)`, which is `s_j(0) + s_j(1) = C_j`
//!      solved for `a`, draws `rho_j` and sets `C_{j+1} = s_j(rho_j)`. Then
//!      the instances with `k_i = j + 1`, in instance order, send their mask
//!      of layer `k_i + 1` at `rho[..k_i]`: this is what makes `D_{j+1}`
//!      known to the verifier before `rho_{j+1}` is drawn;
//!    - the layer check `C_t = D_t`;
//!    - challenge `mu`: every instance in the iteration, joining or not,
//!      gets `(P_i, Q_i) = ((1-mu)·p0 + mu·p1, (1-mu)·q0 + mu·q1)` from its
//!      last mask, and the next point is `(mu, rho_0..rho_{t-1})`.
//!
//! `verify_batch` checks the layer reductions only. Its caller still has
//! to (1) check the relation it wants on `GkrClaims::roots` (every root
//! denominator is already known to be non-zero, so `P/Q` is the sum of the
//! instance's fractions) and (2) discharge `GkrClaims::inputs` against the
//! polynomials the statement is about. For an instance declared with unit
//! numerators the numerator claim is exactly 1 and needs no opening. A
//! first layer that is not the tree's gives claims that are not the tree's
//! either, whatever root it was chosen to yield, so (2) is also what makes
//! the roots the sums they stand for.

mod layer;
mod prover;
#[cfg(test)]
pub(crate) mod tests;
mod verifier;

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{errors::SnarkResult, transcript::Tr};

pub(crate) use {prover::prove_batch, verifier::verify_batch};

/// Largest instance (in variables) the verifier accepts. Shapes come from
/// proof-supplied sizes in places, and the bound keeps every loop and every
/// power of two of the verifier small whatever they claim.
pub(crate) const MAX_GKR_VARS: usize = 48;

const DOMAIN_LABEL: &[u8] = b"logup-gkr";
const COUNT_LABEL: &[u8] = b"logup-gkr instances";
const SHAPE_LABEL: &[u8] = b"logup-gkr shape";
const FIRST_LAYERS_LABEL: &[u8] = b"logup-gkr first layers";
const LAMBDA_LABEL: &[u8] = b"logup-gkr lambda";
const ALPHA_LABEL: &[u8] = b"logup-gkr alpha";
const ROUND_LABEL: &[u8] = b"logup-gkr round";
const RHO_LABEL: &[u8] = b"logup-gkr rho";
const MASKS_LABEL: &[u8] = b"logup-gkr masks";
const MU_LABEL: &[u8] = b"logup-gkr mu";

/// Numerators of an instance.
#[derive(Clone, Debug)]
pub(crate) enum Numerator<F> {
    /// Every numerator is exactly 1; nothing is stored or sent for them.
    One,
    /// One numerator per denominator.
    Values(Vec<F>),
}

/// `2^n` fractions `num[x] / den[x]`, `n >= 0`.
#[derive(Clone, Debug)]
pub(crate) struct FractionInstance<F> {
    pub num: Numerator<F>,
    pub den: Vec<F>,
}

/// Proof of one batch of instances.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct LogupGkrProof<F: PrimeField> {
    /// Every message of the prover, in the order it enters the transcript
    /// (see the module docs). How many there are and what each one is
    /// follows from the statement alone, so nothing here says where one
    /// message ends and the next begins.
    pub messages: Vec<F>,
}

/// What the verifier knows about an instance: its size and whether its
/// numerators are all one. Both must come from the statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GkrShape {
    pub n_vars: usize,
    pub numerator_is_one: bool,
}

impl GkrShape {
    /// Variables of the layer the instance has a claim on in iteration `t` of
    /// a batch whose largest instance has `n_max` variables, `None` before
    /// the instance joins. Instances join late so that all of them end on
    /// their input layer.
    fn claimed_vars(&self, t: usize, n_max: usize) -> Option<usize> {
        (self.n_vars + t).checked_sub(n_max)
    }

    /// Values sent for the instance's layer of `vars` variables: the root
    /// fraction, a mask, or a mask without its numerators where the
    /// statement says they are one.
    fn layer_len(&self, vars: usize) -> usize {
        if vars == 0 || (self.numerator_is_one && vars == self.n_vars) {
            2
        } else {
            4
        }
    }

    /// Values of the instance's first message: layer 1, or the root when
    /// that is the only layer.
    fn first_layer_len(&self) -> usize {
        self.layer_len(self.n_vars.min(1))
    }
}

/// Number of field elements in the proof of a batch of this shape: two per
/// sumcheck round, iteration `t` having `t` of them, and one message per
/// instance and layer from the first on. `None` for the empty batch and for
/// sizes no count fits.
pub(crate) fn proof_len(shape: &[GkrShape]) -> Option<usize> {
    let n_max = shape.iter().map(|s| s.n_vars).max()?;
    let mut len = n_max.checked_mul(n_max.saturating_sub(1))?;
    for s in shape {
        let masks = s.n_vars.checked_mul(4)?;
        let layers = match (s.n_vars, s.numerator_is_one) {
            (0, _) => 2,
            (_, true) => masks - 2,
            (_, false) => masks,
        };
        len = len.checked_add(layers)?;
    }
    Some(len)
}

/// Outcome of a batch, identical on both sides for an honest proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GkrClaims<F> {
    /// Shared evaluation point, of length `max n_i`.
    pub point: Vec<F>,
    /// Per instance, `(P, Q)` of the root fraction, as the first layers give
    /// it.
    pub roots: Vec<[F; 2]>,
    /// Per instance, the input numerator and denominator MLEs at
    /// `point[..n_i]`. The numerator of a unit-numerator instance is 1.
    pub inputs: Vec<[F; 2]>,
}

/// Binds the statement before any challenge is drawn, so that a proof for
/// one batch layout cannot be replayed against another.
fn absorb_shape<F: PrimeField>(shape: &[GkrShape], tr: &mut Tr<F>) -> SnarkResult<()> {
    tr.append_message(DOMAIN_LABEL, b"v2")?;
    tr.append_serializable_element(COUNT_LABEL, &(shape.len() as u64))?;
    for s in shape {
        let kind = u8::from(s.numerator_is_one);
        tr.append_serializable_element(SHAPE_LABEL, &(s.n_vars as u64, kind))?;
    }
    Ok(())
}

/// `[2^0, .., 2^max_exp]`, by doubling in the field: the exponents are
/// differences of instance sizes, which a proof can influence, so they never
/// go through an integer shift.
fn powers_of_two<F: PrimeField>(max_exp: usize) -> Vec<F> {
    let mut powers = Vec::with_capacity(max_exp + 1);
    let mut power = F::one();
    for _ in 0..=max_exp {
        powers.push(power);
        power.double_in_place();
    }
    powers
}
