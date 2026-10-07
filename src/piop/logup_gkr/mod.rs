//! Batched LogUp-GKR (Papini-Haböck, eprint 2023/1284): a sumcheck-only
//! argument that reduces sums of fractions to evaluation claims on their
//! numerators and denominators, with no helper commitment.
//!
//! An instance is `2^n` fractions `p(x)/q(x)`. They are added pairwise in a
//! binary tree: layer `k` holds `2^k` fractions, layer `n` is the input and
//! layer 0 the root, with
//! `p_k[j] = p_{k+1}[2j]·q_{k+1}[2j+1] + p_{k+1}[2j+1]·q_{k+1}[2j]` and
//! `q_k[j] = q_{k+1}[2j]·q_{k+1}[2j+1]`. The prover sends every root and
//! then walks all trees down together, one layer per iteration: a sumcheck
//! turns the claims `(p_k(r), q_k(r))` into four evaluations of layer `k+1`
//! (the mask), and a line challenge `mu` folds the mask into the next claims.
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
//! `verify_batch` checks the layer reductions only. Its caller still has
//! to (1) check the relation it wants on `GkrClaims::roots` (every root
//! denominator is already known to be non-zero, so `P/Q` is the sum of the
//! instance's fractions) and (2) discharge `GkrClaims::inputs` against the
//! polynomials the statement is about. For an instance declared with unit
//! numerators the numerator claim is exactly 1 and needs no opening.

// Nothing calls into the module until the tracker integration lands.
#![cfg_attr(not(test), expect(dead_code))]

mod layer;
mod prover;
#[cfg(test)]
mod tests;
mod verifier;

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{errors::SnarkResult, transcript::Tr};

#[cfg_attr(not(test), expect(unused_imports))]
pub(crate) use {prover::prove_batch, verifier::verify_batch};

/// Largest instance (in variables) the verifier accepts. Shapes come from
/// proof-supplied sizes in places, and the bound keeps every loop and every
/// power of two of the verifier small whatever they claim.
pub(crate) const MAX_GKR_VARS: usize = 48;

const DOMAIN_LABEL: &[u8] = b"logup-gkr";
const COUNT_LABEL: &[u8] = b"logup-gkr instances";
const SHAPE_LABEL: &[u8] = b"logup-gkr shape";
const ROOTS_LABEL: &[u8] = b"logup-gkr roots";
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
    /// Per instance, `(P, Q)` of the root fraction.
    pub roots: Vec<[F; 2]>,
    /// `[iteration][round]`: the round polynomial at 0, 2 and 3. Its value at
    /// 1 is implied by the running claim.
    pub round_polys: Vec<Vec<[F; 3]>>,
    /// `[iteration][active instance, in instance order]`: `[p0, p1, q0, q1]`,
    /// or `[q0, q1]` on the input layer of a unit-numerator instance.
    pub masks: Vec<Vec<Vec<F>>>,
}

/// What the verifier knows about an instance: its size and whether its
/// numerators are all one. Both must come from the statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GkrShape {
    pub n_vars: usize,
    pub numerator_is_one: bool,
}

/// Outcome of a batch, identical on both sides for an honest proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GkrClaims<F> {
    /// Shared evaluation point, of length `max n_i`.
    pub point: Vec<F>,
    /// Per instance, `(P, Q)` of the root fraction.
    pub roots: Vec<[F; 2]>,
    /// Per instance, the input numerator and denominator MLEs at
    /// `point[..n_i]`. The numerator of a unit-numerator instance is 1.
    pub inputs: Vec<[F; 2]>,
}

/// Binds the statement before any challenge is drawn, so that a proof for
/// one batch layout cannot be replayed against another.
fn absorb_shape<F: PrimeField>(shape: &[GkrShape], tr: &mut Tr<F>) -> SnarkResult<()> {
    tr.append_message(DOMAIN_LABEL, b"v1")?;
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

/// Evaluates cubics given by their values at 0, 1, 2 and 3.
struct CubicInterpolator<F> {
    inv2: F,
    inv6: F,
}

impl<F: PrimeField> CubicInterpolator<F> {
    /// `None` in characteristic 2 or 3, where the four nodes are not
    /// distinct.
    fn new() -> Option<Self> {
        let inv6 = F::from(6u64).inverse()?;
        Some(Self {
            inv2: inv6 * F::from(3u64),
            inv6,
        })
    }

    fn evaluate(&self, evals: [F; 4], x: F) -> F {
        let [s0, s1, s2, s3] = evals;
        let x1 = x - F::one();
        let x2 = x1 - F::one();
        let x3 = x2 - F::one();
        // Lagrange basis on {0, 1, 2, 3}, sharing the products x(x-1) and
        // (x-2)(x-3).
        let lo = x * x1;
        let hi = x2 * x3;
        self.inv6 * (s3 * lo * x2 - s0 * x1 * hi) + self.inv2 * (s1 * x * hi - s2 * lo * x3)
    }
}
