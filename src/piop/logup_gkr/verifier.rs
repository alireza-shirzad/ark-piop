//! Verifier side of batched LogUp-GKR.

use ark_ff::PrimeField;

use super::{
    ALPHA_LABEL, FIRST_LAYERS_LABEL, GkrClaims, GkrShape, LAMBDA_LABEL, LogupGkrProof, MASKS_LABEL,
    MAX_GKR_VARS, MU_LABEL, RHO_LABEL, ROUND_LABEL, absorb_shape, powers_of_two, proof_len,
};
use crate::{
    errors::{SnarkError, SnarkResult},
    transcript::Tr,
    verifier::errors::VerifierError,
};

fn reject<T>(reason: impl Into<String>) -> SnarkResult<T> {
    Err(SnarkError::VerifierError(
        VerifierError::VerifierCheckFailed(reason.into()),
    ))
}

/// Compares the statement with the bounds and the proof with the length the
/// statement dictates. Returns `max n_i`.
fn check_lengths<F: PrimeField>(
    shape: &[GkrShape],
    proof: &LogupGkrProof<F>,
) -> SnarkResult<usize> {
    if shape.is_empty() {
        return reject("LogUp-GKR batch without instances");
    }
    if shape.iter().any(|s| s.n_vars > MAX_GKR_VARS) {
        return reject(format!("LogUp-GKR instance above {MAX_GKR_VARS} variables"));
    }
    if proof_len(shape) != Some(proof.messages.len()) {
        return reject("LogUp-GKR proof has the wrong number of messages");
    }
    Ok(shape.iter().map(|s| s.n_vars).max().unwrap_or(0))
}

/// The messages of a proof that are still to be read.
struct Messages<'a, F>(&'a [F]);

impl<'a, F: PrimeField> Messages<'a, F> {
    /// The next `len` values. The total was compared with the statement up
    /// front, so running out is not something a proof can cause; it is
    /// reported like every other refusal all the same.
    fn take(&mut self, len: usize) -> SnarkResult<&'a [F]> {
        let Some((values, rest)) = self.0.split_at_checked(len) else {
            return reject("LogUp-GKR proof ends early");
        };
        self.0 = rest;
        Ok(values)
    }

    /// The next mask as `[p0, p1, q0, q1]`. It was sent in `len` values:
    /// all four, or the denominators alone where the numerators are one by
    /// the statement.
    fn take_mask(&mut self, len: usize) -> SnarkResult<[F; 4]> {
        match *self.take(len)? {
            [p0, p1, q0, q1] => Ok([p0, p1, q0, q1]),
            [q0, q1] => Ok([F::one(), F::one(), q0, q1]),
            _ => reject("LogUp-GKR mask of unexpected length"),
        }
    }
}

/// Verifies a batch against the statement `shape` and returns the claims the
/// caller has to finish: the relation on the roots and the openings of the
/// input layers at `point[..n_i]`.
///
/// Every rejection is a [`VerifierError::VerifierCheckFailed`]; no proof
/// value makes it panic.
pub(crate) fn verify_batch<F: PrimeField>(
    shape: &[GkrShape],
    proof: &LogupGkrProof<F>,
    tr: &mut Tr<F>,
) -> SnarkResult<GkrClaims<F>> {
    let n_max = check_lengths(shape, proof)?;
    let mut messages = Messages(&proof.messages);

    let first_layers = messages.take(shape.iter().map(GkrShape::first_layer_len).sum())?;
    let mut first_layers_left = Messages(first_layers);
    // Per instance, the mask it sent last.
    let mut gates = Vec::with_capacity(shape.len());
    let mut roots = Vec::with_capacity(shape.len());
    for s in shape {
        if s.n_vars == 0 {
            let [p, q] = *first_layers_left.take(2)? else {
                return reject("LogUp-GKR root of unexpected length");
            };
            roots.push([p, q]);
            // Never read: the instance is in no iteration.
            gates.push([F::zero(); 4]);
        } else {
            let gate = first_layers_left.take_mask(s.first_layer_len())?;
            let [p0, p1, q0, q1] = gate;
            roots.push([p0 * q1 + p1 * q0, q0 * q1]);
            gates.push(gate);
        }
    }
    // The root denominator is the product of the input denominators, so this
    // is what makes P/Q the sum of the fractions: with a zero among them the
    // root would be 0/0 whatever the other fractions are.
    if roots.iter().any(|root| root[1].is_zero()) {
        return reject("LogUp-GKR root with a zero denominator");
    }

    absorb_shape(shape, tr)?;
    tr.append_serializable_element(FIRST_LAYERS_LABEL, &first_layers)?;

    let pow2 = powers_of_two::<F>(n_max);
    // A root is the claim on layer 0, and for an instance of one fraction
    // the claim on its input.
    let mut claims = roots.clone();
    let mut point: Vec<F> = Vec::with_capacity(n_max);
    let mut alpha_pows = vec![F::zero(); shape.len()];

    for t in 0..n_max {
        let mut rho = Vec::with_capacity(t);
        // In the first iteration the largest instances join and no instance
        // has a claim to reduce.
        if t > 0 {
            let lambda = tr.get_and_append_challenge(LAMBDA_LABEL)?;
            let alpha = tr.get_and_append_challenge(ALPHA_LABEL)?;

            let mut claim = F::zero();
            let mut alpha_pow = F::one();
            for ((s, instance_claim), slot) in shape.iter().zip(&claims).zip(&mut alpha_pows) {
                // An instance that joins in this iteration brings its root,
                // which is the gate value of its first layer by
                // definition: there is nothing to check. The others are on
                // k <= t variables and constant in the remaining t - k.
                if let Some(k) = s.claimed_vars(t, n_max).filter(|k| *k > 0) {
                    let [p, q] = *instance_claim;
                    claim += alpha_pow * pow2[t - k] * (p + lambda * q);
                }
                *slot = alpha_pow;
                alpha_pow *= alpha;
            }

            // Sum of alpha^idx · eq(point[..k], rho[..k]) · gate value over
            // the instances that have bound all their k variables.
            let mut done = F::zero();
            // eq(point[..j], rho[..j]) after j rounds.
            let mut bound = F::one();
            for round in 0..t {
                let [b, c] = *messages.take(2)? else {
                    return reject("LogUp-GKR round of unexpected length");
                };
                tr.append_serializable_element(ROUND_LABEL, &[b, c])?;
                let r = tr.get_and_append_challenge(RHO_LABEL)?;

                // The round polynomial is
                // 2^(t-1-round)·done + eq(z, X)·(a + b·X + c·X^2): each
                // variable still summed over doubles what the finished
                // instances contribute. Its values at 0 and 1 have to add
                // up to the claim, which leaves one choice for `a`.
                let z = point[round];
                let a = claim - pow2[t - round] * done - z * (b + c);
                let zr = z * r;
                let eq = zr.double() - z - r + F::one();
                claim = pow2[t - 1 - round] * done + eq * (a + r * (b + r * c));
                bound *= eq;

                // The masks of the instances that just bound their last
                // variable come before the next round.
                let unread = messages.0;
                for ((s, gate), alpha_pow) in shape.iter().zip(&mut gates).zip(&alpha_pows) {
                    let k = round + 1;
                    if s.claimed_vars(t, n_max) == Some(k) {
                        *gate = messages.take_mask(s.layer_len(k + 1))?;
                        let [p0, p1, q0, q1] = *gate;
                        done += *alpha_pow * bound * (p0 * q1 + p1 * q0 + lambda * q0 * q1);
                    }
                }
                let sent = &unread[..unread.len() - messages.0.len()];
                if !sent.is_empty() {
                    tr.append_serializable_element(MASKS_LABEL, &sent)?;
                }
                rho.push(r);
            }
            // Every instance is finished, so nothing is left to sum over.
            if claim != done {
                return reject(format!("LogUp-GKR layer check failed in iteration {t}"));
            }
        }

        let mu = tr.get_and_append_challenge(MU_LABEL)?;
        for ((s, claim), [p0, p1, q0, q1]) in shape.iter().zip(&mut claims).zip(&gates) {
            if s.claimed_vars(t, n_max).is_some() {
                *claim = [*p0 + mu * (*p1 - p0), *q0 + mu * (*q1 - q0)];
            }
        }
        point.clear();
        point.push(mu);
        point.extend(rho);
    }

    // Holds by construction once an instance went through a layer, since the
    // verifier filled in p0 = p1 = 1 itself. For a zero-variable instance the
    // claim is still the root the prover sent, and nothing else pins it.
    let numerators_ok = shape
        .iter()
        .zip(&claims)
        .all(|(s, claim)| !s.numerator_is_one || claim[0].is_one());
    if !numerators_ok {
        return reject("LogUp-GKR unit numerator claim is not one");
    }

    Ok(GkrClaims {
        point,
        roots,
        inputs: claims,
    })
}
