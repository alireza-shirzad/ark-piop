//! Verifier side of batched LogUp-GKR.

use ark_ff::PrimeField;

use super::{
    ALPHA_LABEL, CubicInterpolator, GkrClaims, GkrShape, LAMBDA_LABEL, LogupGkrProof, MASKS_LABEL,
    MAX_GKR_VARS, MU_LABEL, RHO_LABEL, ROOTS_LABEL, ROUND_LABEL, absorb_shape, powers_of_two,
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

/// Whether an instance of `n_vars` variables takes part in iteration `t` of a
/// batch whose largest instance has `n_max` variables. Instances join late
/// so that all of them end on their input layer.
fn is_active(n_vars: usize, t: usize, n_max: usize) -> bool {
    n_vars + t >= n_max
}

/// Mask length the statement dictates: numerators of a unit-numerator
/// instance are sent on every layer but its input layer, which all
/// instances reach in the last iteration.
fn mask_len(shape: &GkrShape, t: usize, n_max: usize) -> usize {
    if shape.numerator_is_one && t + 1 == n_max {
        2
    } else {
        4
    }
}

/// Compares every length in the proof with the statement, so that the main
/// loop can index without further checks. Returns `max n_i`.
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
    let n_max = shape.iter().map(|s| s.n_vars).max().unwrap_or(0);
    if proof.roots.len() != shape.len() {
        return reject("LogUp-GKR proof has the wrong number of roots");
    }
    if proof.round_polys.len() != n_max || proof.masks.len() != n_max {
        return reject("LogUp-GKR proof has the wrong number of iterations");
    }
    for (t, (rounds, masks)) in proof.round_polys.iter().zip(&proof.masks).enumerate() {
        if rounds.len() != t {
            return reject(format!(
                "LogUp-GKR iteration {t} has the wrong number of rounds"
            ));
        }
        let mut expected = shape.iter().filter(|s| is_active(s.n_vars, t, n_max));
        let masks_match = masks.len() == expected.clone().count()
            && masks
                .iter()
                .all(|mask| expected.next().map(|s| mask_len(s, t, n_max)) == Some(mask.len()));
        if !masks_match {
            return reject(format!("LogUp-GKR iteration {t} has malformed masks"));
        }
    }
    Ok(n_max)
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
    // The root denominator is the product of the input denominators, so this
    // is what makes P/Q the sum of the fractions: with a zero among them the
    // root would be 0/0 whatever the other fractions are.
    if proof.roots.iter().any(|root| root[1].is_zero()) {
        return reject("LogUp-GKR root with a zero denominator");
    }

    // Not something a proof can cause, but reported like every other
    // refusal, and before the transcript is touched.
    let Some(cubic) = CubicInterpolator::new() else {
        return reject("LogUp-GKR needs a field of characteristic above 3");
    };

    absorb_shape(shape, tr)?;
    tr.append_serializable_element(ROOTS_LABEL, &proof.roots)?;

    let pow2 = powers_of_two::<F>(n_max);
    let mut claims = proof.roots.clone();
    let mut point: Vec<F> = Vec::with_capacity(n_max);
    // (instance, alpha^instance, [p0, p1, q0, q1]) of the active instances.
    let mut gates: Vec<(usize, F, [F; 4])> = Vec::with_capacity(shape.len());

    for t in 0..n_max {
        let lambda = tr.get_and_append_challenge(LAMBDA_LABEL)?;
        let alpha = tr.get_and_append_challenge(ALPHA_LABEL)?;

        gates.clear();
        let mut masks = proof.masks[t].iter();
        let mut alpha_pow = F::one();
        let mut claim = F::zero();
        for (i, s) in shape.iter().enumerate() {
            if is_active(s.n_vars, t, n_max) {
                // An instance on k < t variables is constant in the other
                // t - k = n_max - n_i sumcheck variables.
                let weight = alpha_pow * pow2[n_max - s.n_vars];
                claim += weight * (claims[i][0] + lambda * claims[i][1]);
                let gate = match masks.next().map(Vec::as_slice) {
                    Some(&[p0, p1, q0, q1]) => [p0, p1, q0, q1],
                    Some(&[q0, q1]) => [F::one(), F::one(), q0, q1],
                    _ => return reject("LogUp-GKR mask of unexpected length"),
                };
                gates.push((i, alpha_pow, gate));
            }
            alpha_pow *= alpha;
        }

        let mut rho = Vec::with_capacity(t);
        for evals in &proof.round_polys[t] {
            tr.append_serializable_element(ROUND_LABEL, evals)?;
            let r = tr.get_and_append_challenge(RHO_LABEL)?;
            // s(1) is not sent: defining it as claim - s(0) is the round check.
            claim = cubic.evaluate([evals[0], claim - evals[0], evals[1], evals[2]], r);
            rho.push(r);
        }
        tr.append_serializable_element(MASKS_LABEL, &proof.masks[t])?;

        // eq(point[..k], rho[..k]) for every prefix length k.
        let mut eq_prefix = Vec::with_capacity(t + 1);
        let mut eq = F::one();
        eq_prefix.push(eq);
        for (a, b) in point.iter().zip(&rho) {
            let ab = *a * b;
            eq *= ab + ab - a - b + F::one();
            eq_prefix.push(eq);
        }

        let mut expected = F::zero();
        for (i, alpha_pow, [p0, p1, q0, q1]) in &gates {
            let k = shape[*i].n_vars + t - n_max;
            expected += *alpha_pow * eq_prefix[k] * (*p0 * q1 + *p1 * q0 + lambda * q0 * q1);
        }
        if expected != claim {
            return reject(format!("LogUp-GKR layer check failed in iteration {t}"));
        }

        let mu = tr.get_and_append_challenge(MU_LABEL)?;
        for (i, _, [p0, p1, q0, q1]) in &gates {
            claims[*i] = [*p0 + mu * (*p1 - p0), *q0 + mu * (*q1 - q0)];
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
        roots: proof.roots.clone(),
        inputs: claims,
    })
}
