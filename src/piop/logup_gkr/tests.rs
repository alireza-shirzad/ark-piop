//! Tests of the LogUp-GKR core. The reference prover below is written from
//! the protocol definition alone (dense evaluation of every layer MLE,
//! brute-force round polynomials) and shares no code with `prover.rs`.

use std::{collections::BTreeMap, ops::Range, time::Instant};

use ark_bn254::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};
use proptest::prelude::*;

use super::*;
use crate::{errors::SnarkError, verifier::errors::VerifierError};

fn transcript() -> Tr<Fr> {
    Tr::new(b"logup-gkr-test")
}

fn random_instance(n_vars: usize, one: bool, rng: &mut StdRng) -> FractionInstance<Fr> {
    let len = 1usize << n_vars;
    let den = (0..len).map(|_| Fr::rand(rng)).collect();
    let num = if one {
        Numerator::One
    } else {
        Numerator::Values((0..len).map(|_| Fr::rand(rng)).collect())
    };
    FractionInstance { num, den }
}

/// One random instance per `(n_vars, numerators are one)` entry.
fn random_batch(batch: &[(usize, bool)], seed: u64) -> Vec<FractionInstance<Fr>> {
    let mut rng = StdRng::seed_from_u64(seed);
    batch
        .iter()
        .map(|&(n_vars, one)| random_instance(n_vars, one, &mut rng))
        .collect()
}

fn n_vars(instance: &FractionInstance<Fr>) -> usize {
    instance.den.len().ilog2() as usize
}

fn shape_of(instances: &[FractionInstance<Fr>]) -> Vec<GkrShape> {
    instances
        .iter()
        .map(|instance| GkrShape {
            n_vars: n_vars(instance),
            numerator_is_one: matches!(instance.num, Numerator::One),
        })
        .collect()
}

/// The multilinear extension of `table` at `point`, straight from the
/// definition: `point[k]` goes with bit `k` of the index.
fn mle_eval(table: &[Fr], point: &[Fr]) -> Fr {
    assert_eq!(table.len(), 1 << point.len());
    table
        .iter()
        .enumerate()
        .map(|(x, value)| {
            let weight: Fr = point
                .iter()
                .enumerate()
                .map(|(k, r)| if (x >> k) & 1 == 1 { *r } else { Fr::one() - r })
                .product();
            *value * weight
        })
        .sum()
}

fn eq_coordinate(a: Fr, b: Fr) -> Fr {
    a * b + (Fr::one() - a) * (Fr::one() - b)
}

fn eq_points(a: &[Fr], b: &[Fr]) -> Fr {
    assert_eq!(a.len(), b.len());
    let coordinates = a.iter().zip(b);
    coordinates.map(|(a, b)| eq_coordinate(*a, *b)).product()
}

/// The input claims the statement `shape` over `instances` implies at
/// `point`: what the caller of `verify_batch` compares `inputs` with when it
/// opens the input layers. A unit-numerator instance has nothing to open on
/// the numerator side.
fn direct_inputs(
    instances: &[FractionInstance<Fr>],
    shape: &[GkrShape],
    point: &[Fr],
) -> Vec<[Fr; 2]> {
    instances
        .iter()
        .zip(shape)
        .map(|(instance, s)| {
            let point = &point[..s.n_vars];
            let numerator = match &instance.num {
                Numerator::Values(values) if !s.numerator_is_one => mle_eval(values, point),
                _ => Fr::one(),
            };
            [numerator, mle_eval(&instance.den, point)]
        })
        .collect()
}

fn root_sum(roots: &[[Fr; 2]]) -> Fr {
    roots.iter().map(|[p, q]| *p / q).sum()
}

// ─── Layout of a proof ───────────────────────────────────────────────────

/// Where each message sits in the proof of a batch, worked out from the
/// protocol description in the module docs and not by the code under test.
struct Layout {
    /// Per instance, its first layer.
    first: Vec<Range<usize>>,
    /// `[iteration][round]`: where the two coefficients of the round start.
    rounds: Vec<Vec<usize>>,
    /// `(iteration, instance)`: the mask the instance sends in the
    /// iteration's sumcheck.
    masks: BTreeMap<(usize, usize), Range<usize>>,
    len: usize,
}

fn layout(shape: &[GkrShape]) -> Layout {
    let n_max = shape.iter().map(|s| s.n_vars).max().unwrap();
    let mut len = 0;
    let mut next = |values: usize| {
        len += values;
        len - values..len
    };
    let first = shape
        .iter()
        .map(|s| match (s.n_vars, s.numerator_is_one) {
            // The root, and the input layer of two unit-numerator fractions.
            (0, _) | (1, true) => next(2),
            _ => next(4),
        })
        .collect();
    let mut rounds = vec![Vec::new()];
    let mut masks = BTreeMap::new();
    for t in 1..n_max {
        let mut starts = Vec::new();
        for round in 0..t {
            starts.push(next(2).start);
            for (i, s) in shape.iter().enumerate() {
                // The instance is on a layer of `round + 1` variables and
                // sends the mask of the layer below.
                if s.n_vars + t == n_max + round + 1 {
                    let input = round + 2 == s.n_vars;
                    masks.insert(
                        (t, i),
                        next(if input && s.numerator_is_one { 2 } else { 4 }),
                    );
                }
            }
        }
        rounds.push(starts);
    }
    Layout {
        first,
        rounds,
        masks,
        len,
    }
}

/// The roots a proof gives, read off its first layers.
fn roots_in(shape: &[GkrShape], proof: &LogupGkrProof<Fr>) -> Vec<[Fr; 2]> {
    let layout = layout(shape);
    shape
        .iter()
        .zip(&layout.first)
        .map(|(s, range)| match proof.messages[range.clone()] {
            [p, q] if s.n_vars == 0 => [p, q],
            [q0, q1] => [q0 + q1, q0 * q1],
            [p0, p1, q0, q1] => [p0 * q1 + p1 * q0, q0 * q1],
            _ => unreachable!(),
        })
        .collect()
}

// ─── Reference prover ────────────────────────────────────────────────────

/// Where a cheating reference prover leaves the protocol.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Deviation {
    /// The first layer of `instance` is sent with one fraction written as
    /// `(scale·p)/(scale·q)`, so that its root is the equal fraction
    /// `(scale·P, scale·Q)`.
    ScaleRoot { instance: usize, scale: Fr },
    /// The first layers of two instances are exchanged, and with them the
    /// roots, which keeps their sum.
    SwapRoots { a: usize, b: usize },
    /// `delta` is added to the two coefficients of one round message. The
    /// constant coefficient is the verifier's to derive, so the polynomial
    /// still sums to the running claim and is wrong everywhere else.
    RoundPoly {
        iteration: usize,
        round: usize,
        delta: [Fr; 2],
    },
    /// A round message is bent as by `RoundPoly`, and the mask `instance`
    /// sends in the same iteration makes up for it: its gate value is
    /// chosen so that the claim the false message left is the one the true
    /// messages of the remaining rounds go on from. A mask sent before that
    /// round is the true one, and nothing is made up for.
    RoundPolyMadeUpByMask {
        iteration: usize,
        round: usize,
        delta: [Fr; 2],
        instance: usize,
    },
    /// The mask `instance` sends in `iteration` is moved by `delta` along a
    /// direction that keeps its gate value. In the iteration the instance
    /// joins in, that mask is its first layer and the move keeps the root.
    Mask {
        iteration: usize,
        instance: usize,
        delta: Fr,
    },
    /// `delta` is added to one entry of the first fraction of the mask
    /// `instance` sends in `iteration`, which changes its gate value (and,
    /// for a first layer, the root).
    MaskValue {
        iteration: usize,
        instance: usize,
        delta: Fr,
    },
    /// `instance` has arbitrary numerators but is run as a unit-numerator
    /// instance: declared so in the transcript and with its input-layer
    /// mask sent without numerators (on zero variables its root is sent as
    /// it is).
    DeclareOne { instance: usize },
}

/// A deviation plus how long the cheater keeps the lie alive. Everything it
/// sends is absorbed before the challenges that follow, as in a real attack;
/// nothing is edited after the fact.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fault {
    pub(crate) deviation: Deviation,
    /// In every iteration before this one the cheater bends the first mask
    /// sent after the last round so that the layer check passes, carrying
    /// its false claim one layer down. From this iteration on it sends true
    /// masks again.
    pub(crate) patch_until: usize,
}

/// Layers `0..=n` of an instance, numerators always materialised.
fn naive_layers(instance: &FractionInstance<Fr>) -> Vec<(Vec<Fr>, Vec<Fr>)> {
    let den = instance.den.clone();
    let num = match &instance.num {
        Numerator::One => vec![Fr::one(); den.len()],
        Numerator::Values(values) => values.clone(),
    };
    let mut layers = vec![(num, den)];
    while layers[layers.len() - 1].1.len() > 1 {
        let (p, q) = &layers[layers.len() - 1];
        let pairs = 0..q.len() / 2;
        let parent_p = pairs
            .clone()
            .map(|j| p[2 * j] * q[2 * j + 1] + p[2 * j + 1] * q[2 * j])
            .collect();
        let parent_q = pairs.map(|j| q[2 * j] * q[2 * j + 1]).collect();
        layers.push((parent_p, parent_q));
    }
    layers.reverse();
    layers
}

/// `[p(0,y), p(1,y), q(0,y), q(1,y)]` for the layer MLEs `p`, `q`.
fn children(layer: &(Vec<Fr>, Vec<Fr>), y: &[Fr]) -> [Fr; 4] {
    let at = |table: &[Fr], bit: u64| {
        let mut point = vec![Fr::from(bit)];
        point.extend_from_slice(y);
        mle_eval(table, &point)
    };
    [
        at(&layer.0, 0),
        at(&layer.0, 1),
        at(&layer.1, 0),
        at(&layer.1, 1),
    ]
}

fn gate([p0, p1, q0, q1]: [Fr; 4], lambda: Fr) -> Fr {
    p0 * q1 + p1 * q0 + lambda * q0 * q1
}

/// A mask as it is sent: without its numerators when the statement says
/// they are one.
fn sent(mask: [Fr; 4], short: bool) -> Vec<Fr> {
    mask[if short { 2 } else { 0 }..].to_vec()
}

/// The verifier's claim after a round whose message is `[b, c]`: the round
/// polynomial is `2^free·done + eq(z, X)·(a + b·X + c·X^2)` with `free`
/// variables still summed over, `a` is what makes its values at 0 and 1 add
/// up to `claim`, and the new claim is its value at `r`.
fn claim_after_round(claim: Fr, done: Fr, free: usize, z: Fr, [b, c]: [Fr; 2], r: Fr) -> Fr {
    let constant = Fr::from(2u64).pow([free as u64]) * done;
    let a = claim - constant - constant - z * (b + c);
    constant + eq_coordinate(z, r) * (a + b * r + c * r * r)
}

/// Adds `need` to the gate value of `mask` by changing one entry of its
/// second fraction, the denominator when the numerators are not sent
/// (`short`).
fn bend_mask(mask: [Fr; 4], short: bool, need: Fr, lambda: Fr) -> [Fr; 4] {
    let [p0, p1, q0, q1] = mask;
    if short {
        let target = gate(mask, lambda) + need;
        [p0, p1, q0, (target - q0) / (Fr::one() + lambda * q0)]
    } else {
        [p0, p1 + need / q0, q0, q1]
    }
}

/// Reference prover. With `fault = None` it is the honest prover and also
/// asserts, by brute force, the identities the protocol rests on (the shape
/// of every round polynomial and its sum, every layer check).
pub(crate) fn naive_prove_batch(
    instances: &[FractionInstance<Fr>],
    tr: &mut Tr<Fr>,
    fault: Option<Fault>,
) -> (LogupGkrProof<Fr>, GkrClaims<Fr>) {
    let deviation = fault.map(|fault| fault.deviation);
    let patch_until = fault.map_or(0, |fault| fault.patch_until);
    let sizes: Vec<usize> = instances.iter().map(n_vars).collect();
    let n_max = sizes.iter().copied().max().unwrap();
    let declared_one: Vec<bool> = instances
        .iter()
        .enumerate()
        .map(|(i, instance)| {
            matches!(instance.num, Numerator::One)
                || matches!(deviation, Some(Deviation::DeclareOne { instance }) if instance == i)
        })
        .collect();
    // Whether instance `i` sends its layer of `vars` variables without
    // numerators.
    let short = |i: usize, vars: usize| declared_one[i] && vars == sizes[i];
    // The iteration an instance joins in.
    let joins = |i: usize| n_max - sizes[i];

    tr.append_message(DOMAIN_LABEL, b"v2").unwrap();
    tr.append_serializable_element(COUNT_LABEL, &(instances.len() as u64))
        .unwrap();
    for (n, one) in sizes.iter().zip(&declared_one) {
        tr.append_serializable_element(SHAPE_LABEL, &(*n as u64, *one as u8))
            .unwrap();
    }

    let layers: Vec<_> = instances.iter().map(naive_layers).collect();
    // The first layers as they are sent: the root alone on zero variables.
    let mut first: Vec<Vec<Fr>> = (0..instances.len())
        .map(|i| {
            if sizes[i] == 0 {
                vec![layers[i][0].0[0], layers[i][0].1[0]]
            } else {
                sent(children(&layers[i][1], &[]), short(i, 1))
            }
        })
        .collect();
    match deviation {
        Some(Deviation::ScaleRoot { instance, scale }) => match first[instance][..] {
            [p, q] if sizes[instance] == 0 => first[instance] = vec![scale * p, scale * q],
            [p0, p1, q0, q1] => first[instance] = vec![scale * p0, p1, scale * q0, q1],
            _ => panic!("a first layer without numerators has none to scale"),
        },
        Some(Deviation::SwapRoots { a, b }) => {
            assert_eq!(first[a].len(), first[b].len());
            assert_eq!(sizes[a].min(1), sizes[b].min(1));
            first.swap(a, b);
        }
        Some(Deviation::Mask {
            iteration,
            instance,
            delta,
        }) if sizes[instance] > 0 && iteration == joins(instance) => {
            first[instance] = match first[instance][..] {
                // Keeps p0·q1 + p1·q0, and the denominators.
                [p0, p1, q0, q1] => vec![p0 + delta * q0, p1 - delta * q1, q0, q1],
                // The only other pair with this sum and this product.
                [q0, q1] if !delta.is_zero() => vec![q1, q0],
                _ => first[instance].clone(),
            };
        }
        Some(Deviation::MaskValue {
            iteration,
            instance,
            delta,
        }) if sizes[instance] > 0 && iteration == joins(instance) => first[instance][0] += delta,
        _ => {}
    }
    let mut messages = first.concat();
    tr.append_serializable_element(FIRST_LAYERS_LABEL, &messages)
        .unwrap();

    // Per instance, the mask it sent last as the verifier reads it, and the
    // claim the verifier holds: both stop being true once the prover has
    // deviated.
    let mut gates: Vec<[Fr; 4]> = first
        .iter()
        .map(|message| match message[..] {
            [p0, p1, q0, q1] => [p0, p1, q0, q1],
            [q0, q1] => [Fr::one(), Fr::one(), q0, q1],
            _ => unreachable!(),
        })
        .collect();
    let roots: Vec<[Fr; 2]> = (0..instances.len())
        .map(|i| {
            let [p0, p1, q0, q1] = gates[i];
            if sizes[i] == 0 {
                [first[i][0], first[i][1]]
            } else {
                [p0 * q1 + p1 * q0, q0 * q1]
            }
        })
        .collect();
    let mut claims = roots.clone();
    let mut point: Vec<Fr> = Vec::new();
    for t in 0..n_max {
        let mut rho: Vec<Fr> = Vec::new();
        if t > 0 {
            let lambda = tr.get_and_append_challenge(LAMBDA_LABEL).unwrap();
            let alpha = tr.get_and_append_challenge(ALPHA_LABEL).unwrap();
            // (instance, variables of its claimed layer, alpha^instance) of
            // the instances that joined before this iteration.
            let running: Vec<(usize, usize, Fr)> = (0..instances.len())
                .filter(|i| joins(*i) < t)
                .map(|i| (i, t - joins(i), alpha.pow([i as u64])))
                .collect();
            // One instance's term of the batched polynomial at a point of
            // F^t, with the eq factor of variable `without` left out.
            let term = |&(i, k, weight): &(usize, usize, Fr), y: &[Fr], without: Option<usize>| {
                let eq: Fr = (0..k)
                    .filter(|l| Some(*l) != without)
                    .map(|l| eq_coordinate(point[l], y[l]))
                    .product();
                weight * eq * gate(children(&layers[i][k + 1], &y[..k]), lambda)
            };

            let mut claim: Fr = running
                .iter()
                .map(|&(i, k, weight)| {
                    weight * Fr::from(1u64 << (t - k)) * (claims[i][0] + lambda * claims[i][1])
                })
                .sum();
            // What the masks sent so far in this iteration come to, as the
            // verifier computes it.
            let mut done = Fr::zero();
            let mut made_up = false;
            for j in 0..t {
                let free = t - 1 - j;
                // `f` at `(rho, x, b)`, summed over the boolean `b`.
                let sum_at = |f: &dyn Fn(&[Fr]) -> Fr, x: u64| -> Fr {
                    (0..1u64 << free)
                        .map(|bits| {
                            let mut y = rho.clone();
                            y.push(Fr::from(x));
                            y.extend((0..free).map(|bit| Fr::from((bits >> bit) & 1)));
                            f(&y)
                        })
                        .sum()
                };
                // The quadratic of the round: the instances that still
                // have a variable, without the eq factor of this one.
                let live = |y: &[Fr]| -> Fr {
                    let live = running.iter().filter(|(_, k, _)| *k > j);
                    live.map(|instance| term(instance, y, Some(j))).sum()
                };
                let quadratic = [0, 1, 2].map(|x| sum_at(&live, x));
                let c =
                    (quadratic[2] - quadratic[1] - quadratic[1] + quadratic[0]) / Fr::from(2u64);
                let mut message = [quadratic[1] - quadratic[0] - c, c];
                if fault.is_none() {
                    let all = |y: &[Fr]| -> Fr {
                        running.iter().map(|instance| term(instance, y, None)).sum()
                    };
                    let constant = Fr::from(1u64 << free) * done;
                    for x in 0..4 {
                        let at = Fr::from(x);
                        let inner = quadratic[0] + message[0] * at + c * at * at;
                        assert_eq!(
                            sum_at(&all, x),
                            constant + eq_coordinate(point[j], at) * inner,
                            "round {j} of iteration {t} at {x}"
                        );
                    }
                    assert_eq!(
                        sum_at(&all, 0) + sum_at(&all, 1),
                        claim,
                        "round {j} of iteration {t}"
                    );
                }
                if let Some(
                    Deviation::RoundPoly {
                        iteration,
                        round,
                        delta,
                    }
                    | Deviation::RoundPolyMadeUpByMask {
                        iteration,
                        round,
                        delta,
                        ..
                    },
                ) = deviation
                    && (iteration, round) == (t, j)
                {
                    message[0] += delta[0];
                    message[1] += delta[1];
                }
                tr.append_serializable_element(ROUND_LABEL, &message)
                    .unwrap();
                let r = tr.get_and_append_challenge(RHO_LABEL).unwrap();
                claim = claim_after_round(claim, done, free, point[j], message, r);
                rho.push(r);
                messages.extend(message);

                // The instances whose last variable this was send the mask
                // of the layer below.
                let finished: Vec<&(usize, usize, Fr)> =
                    running.iter().filter(|(_, k, _)| *k == j + 1).collect();
                let bound = eq_points(&point[..j + 1], &rho);
                for &&(i, k, _) in &finished {
                    let short = short(i, k + 1);
                    let [p0, p1, q0, q1] = children(&layers[i][k + 1], &rho[..k]);
                    // On the input layer of a declared unit-numerator
                    // instance the verifier supplies p0 = p1 = 1 itself.
                    gates[i] = if short {
                        [Fr::one(), Fr::one(), q0, q1]
                    } else {
                        [p0, p1, q0, q1]
                    };
                    match deviation {
                        Some(Deviation::Mask {
                            iteration,
                            instance,
                            delta,
                        }) if (iteration, instance) == (t, i) => {
                            gates[i] = if short {
                                // Keeps q0 + q1 + lambda·q0·q1.
                                let moved = q0 + delta;
                                let other =
                                    (gate(gates[i], lambda) - moved) / (Fr::one() + lambda * moved);
                                [Fr::one(), Fr::one(), moved, other]
                            } else {
                                // Keeps p0·q1 + p1·q0, and the denominators.
                                [p0 + delta * q0, p1 - delta * q1, q0, q1]
                            };
                        }
                        Some(Deviation::MaskValue {
                            iteration,
                            instance,
                            delta,
                        }) if (iteration, instance) == (t, i) => {
                            gates[i][if short { 2 } else { 0 }] += delta;
                        }
                        _ => {}
                    }
                }
                let total = |gates: &[[Fr; 4]]| -> Fr {
                    let finished = finished.iter();
                    done + finished
                        .map(|&&(i, _, weight)| weight * bound * gate(gates[i], lambda))
                        .sum::<Fr>()
                };
                if let Some(Deviation::RoundPolyMadeUpByMask {
                    iteration,
                    round,
                    instance,
                    ..
                }) = deviation
                    && iteration == t
                    && round <= j
                    && let Some(&&(i, k, weight)) = finished.iter().find(|(i, _, _)| *i == instance)
                {
                    // What the instances that still have variables sum to
                    // from here. The claim is that plus the masks sent so
                    // far, doubled per variable still summed over; with a
                    // false message behind it, the masks have to come to
                    // something else than the tables give.
                    let rest: Fr = (0..1u64 << free)
                        .map(|bits| {
                            let mut y = rho.clone();
                            y.extend((0..free).map(|bit| Fr::from((bits >> bit) & 1)));
                            let live = running.iter().filter(|(_, k, _)| *k > j + 1);
                            live.map(|other| term(other, &y, None)).sum::<Fr>()
                        })
                        .sum();
                    let masks = (claim - rest) / Fr::from(1u64 << free);
                    let need = (masks - total(&gates)) / (weight * bound);
                    gates[i] = bend_mask(gates[i], short(i, k + 1), need, lambda);
                    made_up = true;
                }
                // After the last round every instance is finished and the
                // gate values of the masks have to add up to the claim.
                if free == 0 {
                    // A lie made up for by a mask is one the verifier does
                    // not see in this iteration either.
                    if fault.is_none() || made_up {
                        assert_eq!(total(&gates), claim, "layer check of iteration {t}");
                    }
                    if t < patch_until && total(&gates) != claim {
                        // The largest instance is in every iteration, so
                        // there is always a mask to bend here.
                        let &&(i, k, weight) = &finished[0];
                        let need = (claim - total(&gates)) / (weight * bound);
                        gates[i] = bend_mask(gates[i], short(i, k + 1), need, lambda);
                        assert_eq!(total(&gates), claim);
                    }
                }
                done = total(&gates);
                let group: Vec<Fr> = finished
                    .iter()
                    .flat_map(|&&(i, k, _)| sent(gates[i], short(i, k + 1)))
                    .collect();
                if !group.is_empty() {
                    tr.append_serializable_element(MASKS_LABEL, &group).unwrap();
                    messages.extend(group);
                }
            }
        }

        let mu = tr.get_and_append_challenge(MU_LABEL).unwrap();
        for i in (0..instances.len()).filter(|i| joins(*i) <= t) {
            let [p0, p1, q0, q1] = gates[i];
            claims[i] = [
                (Fr::one() - mu) * p0 + mu * p1,
                (Fr::one() - mu) * q0 + mu * q1,
            ];
        }
        point = std::iter::once(mu).chain(rho).collect();
    }

    let proof = LogupGkrProof { messages };
    let claims = GkrClaims {
        point,
        roots,
        inputs: claims,
    };
    (proof, claims)
}

// ─── Honest runs ─────────────────────────────────────────────────────────

#[test]
fn prove_batch_matches_reference_prover() {
    let mut batches: Vec<Vec<(usize, bool)>> = Vec::new();
    for n in 0..=6 {
        batches.push(vec![(n, true)]);
        batches.push(vec![(n, false)]);
    }
    batches.extend([
        vec![
            (6, false),
            (6, true),
            (3, true),
            (3, false),
            (1, true),
            (1, false),
            (0, true),
            (0, false),
        ],
        vec![(0, true), (5, true), (2, false), (5, false)],
        vec![(0, false), (0, true)],
        vec![(4, true); 3],
        vec![(1, true), (2, true), (3, true), (4, false)],
        vec![(2, false), (6, true)],
    ]);
    for (seed, batch) in batches.iter().enumerate() {
        let instances = random_batch(batch, seed as u64);

        let mut reference_tr = transcript();
        let (reference_proof, reference_claims) =
            naive_prove_batch(&instances, &mut reference_tr, None);
        let mut prover_tr = transcript();
        let (proof, claims) = prove_batch(instances.clone(), &mut prover_tr).unwrap();
        assert_eq!(proof, reference_proof, "batch {batch:?}");
        assert_eq!(claims, reference_claims, "batch {batch:?}");

        let mut verifier_tr = transcript();
        let verified = verify_batch(&shape_of(&instances), &proof, &mut verifier_tr).unwrap();
        assert_eq!(verified, claims, "batch {batch:?}");

        // All three leave the transcript in the same state for whatever
        // protocol runs next.
        let next = |tr: &mut Tr<Fr>| tr.get_and_append_challenge(b"next").unwrap();
        let expected = next(&mut reference_tr);
        assert_eq!(next(&mut prover_tr), expected);
        assert_eq!(next(&mut verifier_tr), expected);
    }
}

fn batch_strategy() -> impl Strategy<Value = Vec<(usize, bool)>> {
    prop::collection::vec((0usize..=7, any::<bool>()), 1..=6)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn gkr_claims_equal_direct_mle_evaluations(batch in batch_strategy(), seed in any::<u64>()) {
        let instances = random_batch(&batch, seed);
        let shape = shape_of(&instances);
        let (proof, claims) = prove_batch(instances.clone(), &mut transcript()).unwrap();
        let verified = verify_batch(&shape, &proof, &mut transcript()).unwrap();
        prop_assert_eq!(&verified, &claims);

        let n_max = batch.iter().map(|(n, _)| *n).max().unwrap();
        prop_assert_eq!(claims.point.len(), n_max);
        prop_assert_eq!(&claims.inputs, &direct_inputs(&instances, &shape, &claims.point));

        // The root is the sum of the instance's fractions, over the product
        // of its denominators.
        for (instance, [p, q]) in instances.iter().zip(&claims.roots) {
            let sum: Fr = match &instance.num {
                Numerator::One => instance.den.iter().map(|d| Fr::one() / d).sum(),
                Numerator::Values(values) => {
                    values.iter().zip(&instance.den).map(|(n, d)| *n / d).sum()
                }
            };
            prop_assert_eq!(*q, instance.den.iter().product::<Fr>());
            prop_assert_eq!(*p, sum * q);
        }
    }
}

/// Instances of different sizes share one point, and each one's claims are
/// its input MLEs at the PREFIX of that point.
#[test]
fn mixed_size_claims_are_prefix_evaluations() {
    let sizes = [0, 1, 3, 6];
    for one in [false, true] {
        let batch: Vec<(usize, bool)> = sizes.iter().map(|n| (*n, one)).collect();
        let instances = random_batch(&batch, 40 + one as u64);
        let shape = shape_of(&instances);
        let (proof, claims) = prove_batch(instances.clone(), &mut transcript()).unwrap();
        let verified = verify_batch(&shape, &proof, &mut transcript()).unwrap();
        assert_eq!(verified, claims);
        assert_eq!(claims.point.len(), 6);

        for (i, (instance, n)) in instances.iter().zip(sizes).enumerate() {
            let den_at = |point: &[Fr]| mle_eval(&instance.den, point);
            assert_eq!(claims.inputs[i][1], den_at(&claims.point[..n]));
            match &instance.num {
                Numerator::One => assert_eq!(claims.inputs[i][0], Fr::one()),
                Numerator::Values(values) => {
                    assert_eq!(claims.inputs[i][0], mle_eval(values, &claims.point[..n]));
                }
            }
            // Not the suffix, which is what a last-variable-first batching
            // would give.
            if 0 < n && n < 6 {
                assert_ne!(claims.inputs[i][1], den_at(&claims.point[6 - n..]));
            }
        }
        // A zero-variable instance never runs: its root is its input.
        assert_eq!(claims.inputs[0], claims.roots[0]);
    }
}

/// Sizes above the serial thresholds, so that rounds are split into several
/// work items and run on the pool.
#[test]
fn large_batch_crosses_parallel_and_chunk_thresholds() {
    let batch = [(15, true), (15, false), (13, true), (12, false), (5, true)];
    let instances = random_batch(&batch, 50);
    let shape = shape_of(&instances);
    let (proof, claims) = prove_batch(instances.clone(), &mut transcript()).unwrap();
    let verified = verify_batch(&shape, &proof, &mut transcript()).unwrap();
    assert_eq!(verified, claims);
    assert_eq!(
        claims.inputs,
        direct_inputs(&instances, &shape, &claims.point)
    );
}

/// Instances below the serial threshold are built after the larger ones,
/// whatever their place in the batch: each must come back in its own place.
#[test]
fn small_instances_listed_before_large_ones_keep_their_position() {
    let batch = [(3, false), (12, true), (0, true), (13, false), (5, true)];
    let instances = random_batch(&batch, 51);
    let shape = shape_of(&instances);
    let (proof, claims) = prove_batch(instances.clone(), &mut transcript()).unwrap();
    for (instance, [_, q]) in instances.iter().zip(&claims.roots) {
        assert_eq!(*q, instance.den.iter().product::<Fr>());
    }
    let verified = verify_batch(&shape, &proof, &mut transcript()).unwrap();
    assert_eq!(verified, claims);
    assert_eq!(
        claims.inputs,
        direct_inputs(&instances, &shape, &claims.point)
    );
}

/// A work item never holds more than 2^11 gate pairs, and on a small pool it
/// holds exactly that. At 2^15 fractions a table is then split into at most
/// four of them, so a fault in a later one would not show.
#[test]
fn rounds_split_into_more_than_four_work_items() {
    let batch = [(16, false), (16, true)];
    let instances = random_batch(&batch, 52);
    let shape = shape_of(&instances);
    let (proof, claims) = prove_batch(instances.clone(), &mut transcript()).unwrap();
    let verified = verify_batch(&shape, &proof, &mut transcript()).unwrap();
    assert_eq!(verified, claims);
    assert_eq!(
        claims.inputs,
        direct_inputs(&instances, &shape, &claims.point)
    );
}

/// The pairwise path, its one-element remainder, and both together.
#[test]
fn weighted_sums_match_the_plain_sum() {
    let mut rng = StdRng::seed_from_u64(53);
    for len in 0..=9 {
        let weights: Vec<Fr> = (0..len).map(|_| Fr::rand(&mut rng)).collect();
        let terms: Vec<[Fr; 3]> = (0..len)
            .map(|_| [Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)])
            .collect();
        let mut expected = [Fr::zero(); 3];
        for (weight, term) in weights.iter().zip(&terms) {
            for (sum, value) in expected.iter_mut().zip(term) {
                *sum += *weight * value;
            }
        }
        assert_eq!(
            prover::weighted_sums(&weights, |i| terms[i]),
            expected,
            "length {len}"
        );
    }
}

#[test]
fn prove_batch_rejects_malformed_instances() {
    let one = Fr::one();
    let bad = [
        vec![],
        vec![FractionInstance {
            num: Numerator::One,
            den: vec![],
        }],
        vec![FractionInstance {
            num: Numerator::One,
            den: vec![one; 3],
        }],
        vec![FractionInstance {
            num: Numerator::Values(vec![one; 2]),
            den: vec![one; 4],
        }],
    ];
    for instances in bad {
        assert!(prove_batch(instances, &mut transcript()).is_err());
    }
}

#[test]
fn logup_gkr_proof_roundtrip() {
    let instances = random_batch(&[(4, false), (4, true), (2, true), (0, false)], 60);
    let (proof, _) = prove_batch(instances, &mut transcript()).unwrap();
    for proof in [proof, LogupGkrProof::default()] {
        let mut compressed = Vec::new();
        proof.serialize_compressed(&mut compressed).unwrap();
        assert_eq!(compressed.len(), proof.compressed_size());
        let decoded = LogupGkrProof::<Fr>::deserialize_compressed(&compressed[..]).unwrap();
        assert_eq!(decoded, proof);

        let mut uncompressed = Vec::new();
        proof.serialize_uncompressed(&mut uncompressed).unwrap();
        assert_eq!(uncompressed.len(), proof.uncompressed_size());
        let decoded = LogupGkrProof::<Fr>::deserialize_uncompressed(&uncompressed[..]).unwrap();
        assert_eq!(decoded, proof);

        if !compressed.is_empty() {
            let truncated = &compressed[..compressed.len() - 1];
            assert!(LogupGkrProof::<Fr>::deserialize_compressed(truncated).is_err());
        }
    }
}

// ─── Proof size ──────────────────────────────────────────────────────────

/// A proof is `N(N-1)` round coefficients, four values per instance and
/// layer from the first on, two less where the input numerators are one,
/// and two for an instance of one fraction. Nothing else is serialized but
/// one length.
#[test]
fn proof_length_follows_the_statement() {
    let batches: [&[(usize, bool)]; 8] = [
        &[(0, true)],
        &[(0, false), (0, true)],
        &[(1, true)],
        &[(1, false), (1, true), (0, false)],
        &[(5, true)],
        &[(5, false)],
        &[
            (6, false),
            (6, true),
            (3, true),
            (3, false),
            (1, true),
            (0, true),
        ],
        &[(2, true), (4, false), (4, true), (1, false)],
    ];
    for (seed, batch) in batches.into_iter().enumerate() {
        let n_max = batch.iter().map(|(n, _)| *n).max().unwrap();
        let expected: usize = n_max * n_max.saturating_sub(1)
            + batch
                .iter()
                .map(|&(n, one)| match (n, one) {
                    (0, _) => 2,
                    (n, true) => 4 * n - 2,
                    (n, false) => 4 * n,
                })
                .sum::<usize>();
        let shape = shapes(batch);
        assert_eq!(proof_len(&shape), Some(expected), "{batch:?}");
        assert_eq!(layout(&shape).len, expected, "{batch:?}");

        let instances = random_batch(batch, seed as u64);
        let (proof, _) = prove_batch(instances.clone(), &mut transcript()).unwrap();
        let (reference, _) = naive_prove_batch(&instances, &mut transcript(), None);
        assert_eq!(proof.messages.len(), expected, "{batch:?}");
        assert_eq!(reference.messages.len(), expected, "{batch:?}");
        assert_eq!(proof.compressed_size(), 8 + 32 * expected, "{batch:?}");
    }

    // The batch the timing test proves: 4 unit-numerator instances and a
    // general one of 2^18 fractions.
    let timing = shapes(&[(18, true), (18, true), (18, true), (18, true), (18, false)]);
    assert_eq!(proof_len(&timing), Some(18 * 17 + 4 * 70 + 72));

    // No count for the empty batch, nor for sizes that have none.
    assert_eq!(proof_len(&[]), None);
    for n_vars in [usize::MAX, usize::MAX / 2, 1 << 40] {
        assert_eq!(proof_len(&shapes(&[(n_vars, false), (3, true)])), None);
        assert_eq!(proof_len(&shapes(&[(3, true), (n_vars, true)])), None);
    }
}

// ─── Cheating provers ────────────────────────────────────────────────────

/// How a transcript produced by the reference prover fares.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `verify_batch` returned a check failure.
    Rejected,
    /// `verify_batch` accepted, but some input claim is not the evaluation
    /// of the statement's input layer: the caller rejects when it opens it.
    FalseInputs,
    /// `verify_batch` accepted and every input claim is true.
    Accepted,
}

fn is_check_failure<T>(result: &SnarkResult<T>) -> bool {
    matches!(
        result,
        Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(_)
        ))
    )
}

fn outcome_of(
    instances: &[FractionInstance<Fr>],
    shape: &[GkrShape],
    proof: &LogupGkrProof<Fr>,
) -> Outcome {
    let result = verify_batch(shape, proof, &mut transcript());
    match result {
        Ok(claims) if claims.inputs == direct_inputs(instances, shape, &claims.point) => {
            Outcome::Accepted
        }
        Ok(_) => Outcome::FalseInputs,
        Err(_) => {
            assert!(is_check_failure(&result), "unexpected error kind");
            Outcome::Rejected
        }
    }
}

fn outcome(instances: &[FractionInstance<Fr>], shape: &[GkrShape], fault: Fault) -> Outcome {
    let (proof, _) = naive_prove_batch(instances, &mut transcript(), Some(fault));
    outcome_of(instances, shape, &proof)
}

/// What every fault below comes to, by how long the cheater keeps patching,
/// provided the lie is told at least one layer above the input:
/// - it stops before the last iteration: the first iteration that gets true
///   masks while a claim is false fails its LAYER CHECK (the claim left by
///   the last round against the masks sent);
/// - it never stops: `verify_batch` accepts, since each layer check was made
///   to pass, and the lie ends in an input claim. Only the CALLER'S OPENING
///   of the input layers catches that.
fn expected_outcome(patch_until: usize, n_max: usize) -> Outcome {
    if patch_until < n_max {
        Outcome::Rejected
    } else {
        Outcome::FalseInputs
    }
}

#[test]
fn cheating_prover_is_rejected_at_root() {
    let instances = random_batch(
        &[(3, false), (3, true), (2, false), (2, true), (0, false)],
        70,
    );
    let shape = shape_of(&instances);
    let n_max = 3;
    let (honest, honest_claims) = naive_prove_batch(&instances, &mut transcript(), None);
    assert_eq!(roots_in(&shape, &honest), honest_claims.roots);

    // The identity deviation is the honest prover: the fault plumbing
    // itself does not cause the rejections below.
    let identity = Fault {
        deviation: Deviation::ScaleRoot {
            instance: 0,
            scale: Fr::one(),
        },
        patch_until: n_max,
    };
    assert_eq!(
        naive_prove_batch(&instances, &mut transcript(), Some(identity)).0,
        honest
    );
    assert_eq!(outcome(&instances, &shape, identity), Outcome::Accepted);

    // An equal fraction, and two roots swapped: neither changes the sum of
    // the roots, so the caller's relation on the roots cannot see them. A
    // root is only ever what a first layer gives, so the lie is in a first
    // layer, and it becomes a false claim when `mu` folds that layer in the
    // iteration the instance joins in (0 for the size-3 instances, 1 for
    // the size-2 ones). The layer check of the next iteration, or of the
    // first later one the cheater does not patch, rejects.
    let mut deviations: Vec<Deviation> = (0..4)
        .map(|instance| Deviation::ScaleRoot {
            instance,
            scale: Fr::from(5u64),
        })
        .collect();
    deviations.extend([(0, 1), (0, 2), (2, 3), (1, 3)].map(|(a, b)| Deviation::SwapRoots { a, b }));
    for deviation in deviations {
        for patch_until in 0..=n_max {
            let fault = Fault {
                deviation,
                patch_until,
            };
            let (proof, claims) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
            assert_eq!(roots_in(&shape, &proof), claims.roots);
            assert_ne!(claims.roots, honest_claims.roots);
            assert_eq!(root_sum(&claims.roots), root_sum(&honest_claims.roots));
            assert_eq!(
                outcome_of(&instances, &shape, &proof),
                expected_outcome(patch_until, n_max),
                "{fault:?}"
            );
        }
    }

    // A root off by more than its representation, which the caller's
    // relation may or may not see: inside the batch it fares the same.
    for instance in 0..4 {
        for patch_until in 0..=n_max {
            let fault = Fault {
                deviation: Deviation::MaskValue {
                    iteration: n_max - shape[instance].n_vars,
                    instance,
                    delta: Fr::from(5u64),
                },
                patch_until,
            };
            let (proof, claims) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
            assert_ne!(
                root_sum(&claims.roots[instance..=instance]),
                root_sum(&honest_claims.roots[instance..=instance])
            );
            assert_eq!(
                outcome_of(&instances, &shape, &proof),
                expected_outcome(patch_until, n_max),
                "{fault:?}"
            );
        }
    }

    // A zero-variable instance has no layer: its root IS its input claim, so
    // `verify_batch` has nothing to check and the caller's opening is the
    // only defence.
    let fault = Fault {
        deviation: Deviation::ScaleRoot {
            instance: 4,
            scale: Fr::from(5u64),
        },
        patch_until: 0,
    };
    assert_eq!(outcome(&instances, &shape, fault), Outcome::FalseInputs);
}

/// The root is not sent, so a prover can choose a first layer that is not
/// the tree's and still gives the tree's root: the relation the caller
/// checks on the roots holds, and nothing is wrong at the top. What is wrong
/// is every claim folded from that layer.
#[test]
fn forged_first_layer_with_the_true_root_is_caught_below_it() {
    let batch = [
        (3, false),
        (3, true),
        (2, false),
        (2, true),
        (1, false),
        (1, true),
    ];
    let instances = random_batch(&batch, 77);
    let shape = shape_of(&instances);
    let n_max = 3;
    let (honest, honest_claims) = naive_prove_batch(&instances, &mut transcript(), None);
    let layout = layout(&shape);

    for (instance, &(n, _)) in batch.iter().enumerate() {
        for patch_until in 0..=n_max {
            let fault = Fault {
                deviation: Deviation::Mask {
                    iteration: n_max - n,
                    instance,
                    delta: Fr::from(9u64),
                },
                patch_until,
            };
            let (proof, claims) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
            let first = layout.first[instance].clone();
            assert_ne!(proof.messages[first.clone()], honest.messages[first]);
            // Not an equal fraction: the very same root.
            assert_eq!(claims.roots, honest_claims.roots);
            assert_eq!(roots_in(&shape, &proof), honest_claims.roots);

            let expected = if n == 1 {
                // The first layer is the input layer. No layer check is
                // left to fail: `verify_batch` ACCEPTS whatever the cheater
                // does next, and the forged values are the instance's input
                // claim, which the CALLER'S OPENING refutes.
                Outcome::FalseInputs
            } else {
                // The LAYER CHECK of the iteration after the instance
                // joined fails, or of the first later one that is not
                // patched; patched to the end, the lie is an input claim.
                expected_outcome(patch_until, n_max)
            };
            assert_eq!(
                outcome_of(&instances, &shape, &proof),
                expected,
                "{fault:?}"
            );
        }
    }
}

#[test]
fn cheating_prover_is_rejected_at_round_poly() {
    let instances = random_batch(&[(4, false), (4, true), (2, true), (1, false)], 71);
    let shape = shape_of(&instances);
    let n_max = 4;
    let (honest, _) = naive_prove_batch(&instances, &mut transcript(), None);
    let layout = layout(&shape);

    for iteration in 1..n_max {
        for round in 0..iteration {
            let fault = |delta: [u64; 2], patch_until: usize| Fault {
                deviation: Deviation::RoundPoly {
                    iteration,
                    round,
                    delta: delta.map(Fr::from),
                },
                patch_until,
            };
            assert_eq!(
                outcome(&instances, &shape, fault([0, 0], n_max)),
                Outcome::Accepted
            );

            // Whatever two coefficients are sent, the round polynomial the
            // verifier builds from them sums to its claim: the constant
            // coefficient is derived for that. But its value at the
            // challenge is not the true partial sum. The remaining rounds
            // cannot repair that, so the LAYER CHECK at the end of the same
            // iteration fails; a cheater that patches a mask there is
            // caught one iteration later, and so on.
            for delta in [[7, 0], [0, 7], [3, 5]] {
                for patch_until in 0..=n_max {
                    let fault = fault(delta, patch_until);
                    let (proof, _) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
                    let at = layout.rounds[iteration][round];
                    assert_eq!(proof.messages[..at], honest.messages[..at]);
                    for (coefficient, delta) in delta.into_iter().enumerate() {
                        assert_eq!(
                            proof.messages[at + coefficient],
                            honest.messages[at + coefficient] + Fr::from(delta)
                        );
                    }
                    assert_eq!(
                        outcome_of(&instances, &shape, &proof),
                        expected_outcome(patch_until, n_max),
                        "{fault:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn cheating_prover_is_rejected_at_mask() {
    let instances = random_batch(&[(4, false), (4, true), (3, true), (2, false)], 72);
    let shape = shape_of(&instances);
    let n_max = 4;

    // Every iteration but the last (see the next test for that one).
    for iteration in 0..n_max - 1 {
        for (instance, s) in shape.iter().enumerate() {
            if s.n_vars + iteration < n_max {
                continue;
            }
            let fault = |delta: u64, patch_until: usize| Fault {
                deviation: Deviation::Mask {
                    iteration,
                    instance,
                    delta: Fr::from(delta),
                },
                patch_until,
            };
            assert_eq!(
                outcome(&instances, &shape, fault(0, n_max)),
                Outcome::Accepted
            );

            // The altered mask has the same gate value, so the layer check
            // of its own iteration passes: nothing is wrong yet from the
            // verifier's side. But the mask is absorbed before `mu`, so the
            // claims folded from it are false, and the LAYER CHECK of the
            // NEXT iteration fails (or of the first one the cheater stops
            // patching in).
            for patch_until in 0..=n_max {
                assert_eq!(
                    outcome(&instances, &shape, fault(9, patch_until)),
                    expected_outcome(patch_until, n_max),
                    "iteration {iteration}, instance {instance}, patch_until {patch_until}"
                );
            }
        }
    }
}

/// An instance smaller than the largest runs out of variables before the
/// iteration's sumcheck ends and sends its mask at that point. From then on
/// the verifier subtracts the mask's gate value, doubled per variable still
/// summed over, from its claim. A mask that is not what the tables fold to
/// therefore bends every later round of the iteration, although the cheater
/// goes on sending the round messages of the true tables.
#[test]
fn cheating_prover_is_rejected_at_early_mask() {
    let batch = [(4, false), (4, true), (3, true), (3, false), (2, false)];
    let instances = random_batch(&batch, 78);
    let shape = shape_of(&instances);
    let n_max = 4;
    let (honest, _) = naive_prove_batch(&instances, &mut transcript(), None);
    let layout = layout(&shape);

    let mut early = 0;
    for iteration in 1..n_max {
        for (instance, &(n, one)) in batch.iter().enumerate() {
            // Out of variables after round `k - 1` of `iteration` rounds.
            let Some(k) = (n + iteration).checked_sub(n_max).filter(|k| *k > 0) else {
                continue;
            };
            let fault = |delta: u64, patch_until: usize| Fault {
                deviation: Deviation::MaskValue {
                    iteration,
                    instance,
                    delta: Fr::from(delta),
                },
                patch_until,
            };
            assert_eq!(
                outcome(&instances, &shape, fault(0, n_max)),
                Outcome::Accepted
            );
            let mask = layout.masks[&(iteration, instance)].clone();
            let input = iteration + 1 == n_max;
            assert_eq!(mask.len(), if input && one { 2 } else { 4 });
            if k < iteration {
                // Rounds of the iteration come after this mask.
                assert!(mask.end <= layout.rounds[iteration][k]);
                early += 1;
            }

            // Not patched in its own iteration, the mask fails that
            // iteration's LAYER CHECK: the masks sent no longer come to
            // the claim the rounds arrive at. Patched there, by a mask of
            // a largest instance sent after the last round, both masks
            // fold into false claims and the next iteration's check fails;
            // patched to the end, the lie is an input claim.
            for patch_until in 0..=n_max {
                let fault = fault(9, patch_until);
                let (proof, _) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
                // The mask bent to patch the iteration is sent with the
                // last ones, and may come before this one among them.
                if k < iteration || patch_until <= iteration {
                    assert_eq!(proof.messages[..mask.start], honest.messages[..mask.start]);
                }
                assert_ne!(proof.messages[mask.clone()], honest.messages[mask.clone()]);
                assert_eq!(
                    outcome_of(&instances, &shape, &proof),
                    expected_outcome(patch_until, n_max),
                    "{fault:?}"
                );
            }
        }
    }
    // The two instances of size 3 in iterations 2 and 3, the one of size 2
    // in iteration 3.
    assert_eq!(early, 5);
}

/// A false round message can be made up for inside its iteration by an
/// instance that runs out of variables after it. The gate value of that
/// instance's mask is a constant of every later round, so the cheater picks
/// the one under which the false claim is where the true messages go on
/// from, and the iteration's layer check passes with every other mask true.
/// What it has to give for that is the mask itself, which is absorbed
/// before the next challenge and is not what the tables fold to.
#[test]
fn cheating_prover_making_up_for_a_round_by_an_early_mask_is_rejected() {
    let batch = [(4, false), (4, true), (3, true), (3, false), (2, false)];
    let instances = random_batch(&batch, 79);
    let shape = shape_of(&instances);
    let n_max = 4;
    let (honest, _) = naive_prove_batch(&instances, &mut transcript(), None);
    let layout = layout(&shape);
    let delta = [3u64, 5].map(Fr::from);

    let mut early = 0;
    for iteration in 1..n_max {
        for (instance, &(n, _)) in batch.iter().enumerate() {
            // Out of variables after round `k - 1` of `iteration` rounds.
            let Some(k) = (n + iteration).checked_sub(n_max).filter(|k| *k > 0) else {
                continue;
            };
            for round in 0..iteration {
                let fault = |delta: [Fr; 2], patch_until: usize| Fault {
                    deviation: Deviation::RoundPolyMadeUpByMask {
                        iteration,
                        round,
                        delta,
                        instance,
                    },
                    patch_until,
                };
                let identity = fault([Fr::zero(); 2], n_max);
                assert_eq!(outcome(&instances, &shape, identity), Outcome::Accepted);

                for patch_until in 0..=n_max {
                    let fault = fault(delta, patch_until);
                    let (proof, _) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
                    let at = layout.rounds[iteration][round];
                    assert_eq!(proof.messages[..at], honest.messages[..at]);
                    assert_eq!(proof.messages[at], honest.messages[at] + delta[0]);
                    assert_eq!(proof.messages[at + 1], honest.messages[at + 1] + delta[1]);

                    // The cheater that bends the round and makes up for it
                    // nowhere before the last round.
                    let unaided = Fault {
                        deviation: Deviation::RoundPoly {
                            iteration,
                            round,
                            delta,
                        },
                        patch_until,
                    };
                    let (plain, _) =
                        naive_prove_batch(&instances, &mut transcript(), Some(unaided));
                    if round < k && k < iteration {
                        let mask = layout.masks[&(iteration, instance)].clone();
                        assert_eq!(proof.messages[..mask.start], plain.messages[..mask.start]);
                        assert_ne!(proof.messages[mask.clone()], plain.messages[mask]);
                    }

                    if round >= k {
                        // The mask went out before the false message, and
                        // this cheater is that one.
                        assert_eq!(proof, plain);
                        assert_eq!(
                            outcome_of(&instances, &shape, &proof),
                            expected_outcome(patch_until, n_max),
                            "{fault:?}"
                        );
                    } else if iteration + 1 == n_max {
                        // The reference prover has checked that the masks
                        // of this iteration come to its claim. It is the
                        // last one and the mask is of the input layer:
                        // `verify_batch` ACCEPTS without any mask patched
                        // after the last round, and the false claim is the
                        // one on the inputs of that instance, left to the
                        // CALLER'S OPENING.
                        let claims = verify_batch(&shape, &proof, &mut transcript()).unwrap();
                        let truth = direct_inputs(&instances, &shape, &claims.point);
                        for (i, (claim, truth)) in claims.inputs.iter().zip(&truth).enumerate() {
                            assert_eq!(claim != truth, i == instance, "{fault:?}");
                        }
                    } else {
                        // The claim folded from that mask is false, and the
                        // LAYER CHECK of the next iteration fails, or of the
                        // first later one that is not patched.
                        assert_eq!(
                            outcome_of(&instances, &shape, &proof),
                            expected_outcome(patch_until, n_max),
                            "{fault:?}"
                        );
                    }
                }
                if round < k && k < iteration {
                    early += 1;
                }
            }
        }
    }
    // The instances of size 3 after the first round of iteration 2 and
    // after either of the first two of iteration 3, the one of size 2 after
    // the first round of iteration 3.
    assert_eq!(early, 7);
}

#[test]
fn cheating_prover_is_rejected_at_final_mask() {
    let instances = random_batch(&[(3, false), (3, true), (2, true), (1, false)], 73);
    let shape = shape_of(&instances);
    let n_max = 3;
    let (honest, honest_claims) = naive_prove_batch(&instances, &mut transcript(), None);
    let layout = layout(&shape);

    // The mask each instance sends on its input layer: after the last round
    // for the two largest, after the first round for the third, and as its
    // first layer for the smallest. Both the four-value mask of a general
    // instance and the two-value mask of a unit-numerator one can be moved
    // without changing their value.
    for instance in 0..instances.len() {
        let fault = Fault {
            deviation: Deviation::Mask {
                iteration: n_max - 1,
                instance,
                delta: Fr::from(9u64),
            },
            patch_until: 0,
        };
        let (proof, _) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
        // The proof is the honest one up to that mask. The masks of the
        // largest instances are the last thing sent, so there it differs in
        // nothing else.
        let mask = match shape[instance].n_vars {
            1 => layout.first[instance].clone(),
            _ => layout.masks[&(n_max - 1, instance)].clone(),
        };
        assert_eq!(proof.messages[..mask.start], honest.messages[..mask.start]);
        assert_ne!(proof.messages[mask.clone()], honest.messages[mask.clone()]);
        if shape[instance].n_vars == n_max {
            assert_eq!(proof.messages[mask.end..], honest.messages[mask.end..]);
        }
        assert_eq!(roots_in(&shape, &proof), honest_claims.roots);

        // There is no later layer check to fail: `verify_batch` ACCEPTS, and
        // the input claim of that instance is false. This is the case that
        // rests entirely on the CALLER'S OPENING of the input layers at
        // `point[..n_i]`.
        let claims = verify_batch(&shape, &proof, &mut transcript()).unwrap();
        let truth = direct_inputs(&instances, &shape, &claims.point);
        for (i, (claim, truth)) in claims.inputs.iter().zip(&truth).enumerate() {
            assert_eq!(claim != truth, i == instance);
        }
        assert_eq!(outcome_of(&instances, &shape, &proof), Outcome::FalseInputs);
        // The mask is absorbed before the last challenge, so the point
        // moves with it: the cheater cannot aim the false claim at a point
        // of its choice.
        assert_ne!(claims.point[0], honest_claims.point[0]);
    }
}

#[test]
fn values_instance_proved_but_shape_says_one_is_rejected() {
    let instances = random_batch(&[(3, false), (3, true), (2, false)], 74);
    let n_max = 3;
    for instance in [0, 2] {
        let mut shape = shape_of(&instances);
        shape[instance].numerator_is_one = true;

        // The honest proof of the true statement has a four-value input
        // mask where the statement allows two: rejected by the LENGTH
        // CHECK, before anything is absorbed. The converse likewise.
        let (proof, _) = prove_batch(instances.clone(), &mut transcript()).unwrap();
        assert_eq!(outcome_of(&instances, &shape, &proof), Outcome::Rejected);
        let mut converse = shape_of(&instances);
        converse[1].numerator_is_one = false;
        assert_eq!(outcome_of(&instances, &converse, &proof), Outcome::Rejected);

        // A cheater that formats its proof for the statement instead: the
        // tree was built on the real numerators, so with p0 = p1 = 1 filled
        // in by the verifier the LAYER CHECK of the last iteration fails.
        // Patching that check turns the lie into a false input claim.
        for patch_until in 0..=n_max {
            let fault = Fault {
                deviation: Deviation::DeclareOne { instance },
                patch_until,
            };
            assert_eq!(
                outcome(&instances, &shape, fault),
                expected_outcome(patch_until, n_max),
                "{fault:?}"
            );
        }
    }
}

#[test]
fn one_instance_nv0_root_numerator_must_be_one() {
    let forged = FractionInstance {
        num: Numerator::Values(vec![Fr::from(3u64)]),
        den: vec![Fr::from(11u64)],
    };
    let honest = FractionInstance {
        num: Numerator::One,
        den: vec![Fr::from(11u64)],
    };
    let one = GkrShape {
        n_vars: 0,
        numerator_is_one: true,
    };

    // A zero-variable instance goes through no layer, so the verifier never
    // fills in its numerator: the root the prover sends is the claim. The
    // POST-CONDITION on unit numerators is the only thing between a forged
    // root numerator and the caller's relation on the roots.
    for others in [vec![], vec![(3, false), (2, true)]] {
        let fault = Fault {
            deviation: Deviation::DeclareOne { instance: 0 },
            patch_until: 3,
        };
        let mut instances = vec![forged.clone()];
        instances.extend(random_batch(&others, 75));
        let mut shape = shape_of(&instances);
        shape[0] = one;
        let (proof, _) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
        assert_eq!(
            roots_in(&shape, &proof)[0],
            [Fr::from(3u64), Fr::from(11u64)]
        );
        assert_eq!(outcome_of(&instances, &shape, &proof), Outcome::Rejected);

        // With the root numerator at 1 the same batch is fine.
        instances[0] = honest.clone();
        let (proof, _) = naive_prove_batch(&instances, &mut transcript(), None);
        assert_eq!(outcome_of(&instances, &shape, &proof), Outcome::Accepted);
    }
}

/// The post-condition covers every instance, not only the first.
#[test]
fn one_instance_nv0_root_numerator_must_be_one_at_every_position() {
    let forged = FractionInstance {
        num: Numerator::Values(vec![Fr::from(3u64)]),
        den: vec![Fr::from(11u64)],
    };
    for position in 0..=2 {
        let mut instances = random_batch(&[(3, false), (2, true)], 75);
        instances.insert(position, forged.clone());
        let mut shape = shape_of(&instances);
        shape[position].numerator_is_one = true;
        let fault = Fault {
            deviation: Deviation::DeclareOne { instance: position },
            patch_until: 3,
        };
        let (proof, _) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
        assert_eq!(
            roots_in(&shape, &proof)[position],
            [Fr::from(3u64), Fr::from(11u64)]
        );
        assert_eq!(
            outcome_of(&instances, &shape, &proof),
            Outcome::Rejected,
            "position {position}"
        );
    }
}

#[test]
fn zero_denominator_root_is_rejected() {
    // With a zero denominator the root is 0/0 whatever the other fractions
    // are, so the root says nothing about the sum. The honest prover does
    // not refuse such a statement; the verifier's ROOT DENOMINATOR CHECK
    // does, on the root it works out from the first layer.
    for (batch, instance, index) in [
        (vec![(3, false)], 0, 5),
        (vec![(2, true)], 0, 0),
        (vec![(1, true)], 0, 1),
        (vec![(1, false)], 0, 0),
        (vec![(0, false)], 0, 0),
        (vec![(0, true)], 0, 0),
        (vec![(3, true), (2, false), (0, false)], 1, 3),
        (vec![(3, true), (2, false), (0, false)], 2, 0),
    ] {
        let mut instances = random_batch(&batch, 76);
        let shape = shape_of(&instances);
        instances[instance].den[index] = Fr::zero();
        let (proof, claims) = prove_batch(instances.clone(), &mut transcript()).unwrap();
        assert!(claims.roots[instance][1].is_zero());
        assert_eq!(roots_in(&shape, &proof), claims.roots);
        assert_eq!(outcome_of(&instances, &shape, &proof), Outcome::Rejected);
    }
}

/// A root with a zero denominator is refused like a wrong length: before
/// the transcript has absorbed anything, whether the root was sent or
/// worked out from a first layer.
#[test]
fn zero_denominator_root_is_refused_with_the_transcript_untouched() {
    for (batch, instance) in [
        (vec![(2, true)], 0),
        (vec![(1, false)], 0),
        (vec![(0, false)], 0),
        (vec![(3, true), (2, false), (0, false)], 1),
    ] {
        let mut instances = random_batch(&batch, 76);
        let shape = shape_of(&instances);
        instances[instance].den[0] = Fr::zero();
        let (proof, claims) = prove_batch(instances, &mut transcript()).unwrap();
        assert!(claims.roots[instance][1].is_zero());

        let mut tr = Tr::default();
        assert!(is_check_failure(&verify_batch(&shape, &proof, &mut tr)));
        // A transcript nothing was absorbed into refuses to give challenges.
        assert!(tr.get_and_append_challenge(b"probe").is_err(), "{batch:?}");
    }
}

// ─── Malformed proofs ────────────────────────────────────────────────────

#[test]
fn malformed_proof_returns_error_not_panic() {
    let instances = random_batch(&[(3, false), (3, true), (1, true), (0, false)], 80);
    let shape = shape_of(&instances);
    let (honest, _) = prove_batch(instances, &mut transcript()).unwrap();
    assert!(verify_batch(&shape, &honest, &mut transcript()).is_ok());
    let filler = Fr::from(2u64);
    let len = honest.messages.len();
    assert_eq!(len, 3 * 2 + 12 + 10 + 2 + 2);

    // Nothing in a proof says where a message ends, so its one length is
    // all there is to get wrong: every length but the statement's is
    // refused, cut short or padded, at either end.
    for wrong in (0..len).chain(len + 1..=len + 64) {
        let mut padded = honest.messages.clone();
        padded.resize(wrong, filler);
        let mut shifted = vec![filler; wrong.saturating_sub(len)];
        shifted.extend(&honest.messages[len.saturating_sub(wrong)..]);
        for messages in [padded, shifted, vec![filler; wrong]] {
            assert_eq!(messages.len(), wrong);
            assert!(is_check_failure(&verify_batch(
                &shape,
                &LogupGkrProof { messages },
                &mut transcript()
            )));
        }
    }

    // Statements the verifier must refuse whatever the proof says.
    let with_size = |n_vars: usize| GkrShape {
        n_vars,
        numerator_is_one: false,
    };
    let mut longer = shape.clone();
    longer.push(with_size(0));
    let bad_shapes = [
        vec![],
        vec![with_size(MAX_GKR_VARS + 1)],
        vec![with_size(usize::MAX)],
        vec![with_size(3), with_size(usize::MAX)],
        shape[..3].to_vec(),
        longer,
    ];
    for bad in &bad_shapes {
        for proof in [&honest, &LogupGkrProof::default()] {
            assert!(is_check_failure(&verify_batch(
                bad,
                proof,
                &mut transcript()
            )));
        }
    }
    // The bound itself is a legal size: the proof is rejected for its
    // length, not the statement for its size.
    let at_bound = [with_size(MAX_GKR_VARS)];
    assert!(is_check_failure(&verify_batch(
        &at_bound,
        &honest,
        &mut transcript()
    )));
}

/// The length is checked against the statement before anything is read: a
/// proof one value short or long is refused with the transcript untouched,
/// whatever its values, and the right length is read to the last value.
#[test]
fn proof_length_is_validated_before_the_transcript_is_touched() {
    let untouched = |tr: &mut Tr<Fr>| {
        // A transcript nothing was absorbed into refuses to give challenges.
        tr.get_and_append_challenge(b"probe").is_err()
    };
    for (seed, batch) in [
        vec![(4, false), (4, true), (2, true), (1, false), (0, true)],
        vec![(1, true)],
        vec![(0, false)],
        vec![(2, false), (5, true)],
    ]
    .into_iter()
    .enumerate()
    {
        let instances = random_batch(&batch, 82 + seed as u64);
        let shape = shape_of(&instances);
        let (honest, _) = prove_batch(instances, &mut transcript()).unwrap();
        assert_eq!(Some(honest.messages.len()), proof_len(&shape));

        for change in [-2i64, -1, 1, 2, 4] {
            let mut proof = honest.clone();
            let len = (proof.messages.len() as i64 + change).max(0) as usize;
            proof.messages.resize(len, Fr::from(2u64));
            let mut tr = Tr::default();
            assert!(is_check_failure(&verify_batch(&shape, &proof, &mut tr)));
            assert!(untouched(&mut tr), "{batch:?} {change}");
        }

        // Every value is read: changing any one of them changes the
        // outcome or the claims.
        let claims = verify_batch(&shape, &honest, &mut transcript()).unwrap();
        for at in 0..honest.messages.len() {
            let mut proof = honest.clone();
            proof.messages[at] += Fr::one();
            let result = verify_batch(&shape, &proof, &mut transcript());
            assert!(result.is_err() || result.unwrap() != claims, "value {at}");
        }
    }
}

// ─── Self-consistent malformed proofs ────────────────────────────────────

/// How a simulated transcript departs from the format the statement dictates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Malformation {
    None,
    /// One first layer more than there are instances.
    ExtraFirstLayer,
    /// The input mask of the first unit-numerator instance is sent as
    /// `[1, 1, q0, q1]`.
    LongInputMask,
    /// The first four-value mask sent in the sumcheck of `iteration` has
    /// unit numerators and is sent as `[q0, q1]`.
    ShortMask {
        iteration: usize,
    },
    /// One mask more after the last round of `iteration`.
    ExtraMask {
        iteration: usize,
    },
}

/// A prover without a witness: every message is random except one mask value
/// per iteration, which is solved so that the layer check passes.
/// `verify_batch` opens nothing, so it accepts such a transcript; only the
/// caller's openings would not. That makes it the right probe for the length
/// check: an honest proof edited after the fact derails every later
/// challenge and is rejected by the layer check whatever the length check
/// does, whereas here the surplus or missing values are absorbed like any
/// other by the prover that sends them, and where they come last nothing
/// but the length check itself can reject. It also reaches sizes no honest
/// prover can.
fn simulate_batch(shape: &[GkrShape], seed: u64, malformation: Malformation) -> LogupGkrProof<Fr> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut tr = transcript();
    let n_max = shape.iter().map(|s| s.n_vars).max().unwrap();
    let joins = |i: usize| n_max - shape[i].n_vars;

    tr.append_message(DOMAIN_LABEL, b"v2").unwrap();
    tr.append_serializable_element(COUNT_LABEL, &(shape.len() as u64))
        .unwrap();
    for s in shape {
        tr.append_serializable_element(SHAPE_LABEL, &(s.n_vars as u64, s.numerator_is_one as u8))
            .unwrap();
    }

    // A random mask for a slot the statement wants in two values (`short`)
    // or in four, with whether its numerators are one and whether it goes
    // out in two values. The two differ from `short` for the one mask this
    // run sends in the other format, if any.
    let mut reformatted = false;
    let mut random_mask = |rng: &mut StdRng, short: bool, sumcheck_of: Option<usize>| {
        let reformat = !reformatted
            && match malformation {
                Malformation::LongInputMask => short,
                Malformation::ShortMask { iteration } => !short && sumcheck_of == Some(iteration),
                _ => false,
            };
        reformatted |= reformat;
        let unit = short || reformat;
        let numerator = |rng: &mut StdRng| if unit { Fr::one() } else { Fr::rand(rng) };
        let (p0, p1) = (numerator(rng), numerator(rng));
        let gate = [p0, p1, Fr::rand(rng), Fr::rand(rng)];
        (gate, unit, short != reformat)
    };

    let mut gates = vec![[Fr::zero(); 4]; shape.len()];
    let mut claims = vec![[Fr::zero(); 2]; shape.len()];
    let mut messages = Vec::new();
    for (i, s) in shape.iter().enumerate() {
        if s.n_vars == 0 {
            // The root of a zero-variable instance is its input claim.
            let numerator = if s.numerator_is_one {
                Fr::one()
            } else {
                Fr::rand(&mut rng)
            };
            claims[i] = [numerator, Fr::rand(&mut rng)];
            messages.extend(claims[i]);
        } else {
            let short = s.numerator_is_one && s.n_vars == 1;
            let (gate, _, two_values) = random_mask(&mut rng, short, None);
            gates[i] = gate;
            messages.extend(sent(gate, two_values));
        }
    }
    if malformation == Malformation::ExtraFirstLayer {
        messages.extend([Fr::rand(&mut rng), Fr::rand(&mut rng)]);
    }
    tr.append_serializable_element(FIRST_LAYERS_LABEL, &messages)
        .unwrap();

    let mut point: Vec<Fr> = Vec::new();
    for t in 0..n_max {
        let mut rho: Vec<Fr> = Vec::new();
        if t > 0 {
            let lambda = tr.get_and_append_challenge(LAMBDA_LABEL).unwrap();
            let alpha = tr.get_and_append_challenge(ALPHA_LABEL).unwrap();
            let running: Vec<(usize, usize, Fr)> = (0..shape.len())
                .filter(|i| joins(*i) < t)
                .map(|i| (i, t - joins(i), alpha.pow([i as u64])))
                .collect();
            let mut claim: Fr = running
                .iter()
                .map(|&(i, k, weight)| {
                    weight
                        * Fr::from(2u64).pow([(t - k) as u64])
                        * (claims[i][0] + lambda * claims[i][1])
                })
                .sum();
            let mut done = Fr::zero();
            for j in 0..t {
                let message = [Fr::rand(&mut rng), Fr::rand(&mut rng)];
                tr.append_serializable_element(ROUND_LABEL, &message)
                    .unwrap();
                let r = tr.get_and_append_challenge(RHO_LABEL).unwrap();
                claim = claim_after_round(claim, done, t - 1 - j, point[j], message, r);
                rho.push(r);
                messages.extend(message);

                let finished: Vec<&(usize, usize, Fr)> =
                    running.iter().filter(|(_, k, _)| *k == j + 1).collect();
                let bound = eq_points(&point[..j + 1], &rho);
                // Per finished instance, whether its mask has unit
                // numerators and whether it goes out in two values.
                let mut formats = Vec::new();
                for &&(i, k, _) in &finished {
                    let short = shape[i].numerator_is_one && k + 1 == shape[i].n_vars;
                    let (gate, unit, two_values) = random_mask(&mut rng, short, Some(t));
                    gates[i] = gate;
                    formats.push((unit, two_values));
                }
                let total = |gates: &[[Fr; 4]]| -> Fr {
                    let finished = finished.iter();
                    done + finished
                        .map(|&&(i, _, weight)| weight * bound * gate(gates[i], lambda))
                        .sum::<Fr>()
                };
                if j + 1 == t {
                    // The largest instance is in every iteration, so after
                    // the last round there is always a first mask to solve.
                    let &&(i, _, weight) = &finished[0];
                    let need = (claim - total(&gates)) / (weight * bound);
                    gates[i] = bend_mask(gates[i], formats[0].0, need, lambda);
                    assert_eq!(total(&gates), claim);
                }
                done = total(&gates);
                let mut group: Vec<Fr> = finished
                    .iter()
                    .zip(&formats)
                    .flat_map(|(&&(i, _, _), (_, two_values))| sent(gates[i], *two_values))
                    .collect();
                if malformation == (Malformation::ExtraMask { iteration: t }) && j + 1 == t {
                    group.extend((0..4).map(|_| Fr::rand(&mut rng)));
                }
                if !group.is_empty() {
                    tr.append_serializable_element(MASKS_LABEL, &group).unwrap();
                    messages.extend(group);
                }
            }
        }

        let mu = tr.get_and_append_challenge(MU_LABEL).unwrap();
        for i in (0..shape.len()).filter(|i| joins(*i) <= t) {
            let [p0, p1, q0, q1] = gates[i];
            claims[i] = [
                (Fr::one() - mu) * p0 + mu * p1,
                (Fr::one() - mu) * q0 + mu * q1,
            ];
        }
        point = std::iter::once(mu).chain(rho).collect();
    }
    LogupGkrProof { messages }
}

fn shapes(batch: &[(usize, bool)]) -> Vec<GkrShape> {
    batch
        .iter()
        .map(|&(n_vars, numerator_is_one)| GkrShape {
            n_vars,
            numerator_is_one,
        })
        .collect()
}

/// The number of first layers and the format of every mask are dictated by
/// the statement: a transcript that is consistent in itself but sends a
/// first layer too many, or a mask in the other format, is refused for that
/// alone.
#[test]
fn self_consistent_malformed_proof_is_rejected_by_the_length_checks() {
    let shape = shapes(&[(3, false), (3, true), (1, true), (0, false), (0, true)]);
    let n_max = 3;
    let mut malformations = vec![Malformation::ExtraFirstLayer, Malformation::LongInputMask];
    for iteration in 1..n_max {
        malformations.push(Malformation::ShortMask { iteration });
        malformations.push(Malformation::ExtraMask { iteration });
    }
    for seed in 0..4 {
        // The simulator is not what gets the malformed transcripts rejected.
        let proof = simulate_batch(&shape, seed, Malformation::None);
        let claims = verify_batch(&shape, &proof, &mut transcript()).unwrap();
        assert_eq!(claims.point.len(), n_max);
        assert_eq!(claims.roots, roots_in(&shape, &proof));

        for malformation in &malformations {
            let malformed = simulate_batch(&shape, seed, *malformation);
            assert_ne!(
                malformed.messages.len(),
                proof.messages.len(),
                "{malformation:?}"
            );
            assert!(
                is_check_failure(&verify_batch(&shape, &malformed, &mut transcript())),
                "{malformation:?}"
            );
        }
    }
}

/// A proof for 2^49 fractions is only 49 iterations long, so a prover that
/// does not hold the fractions can send one, and nothing but the size bound
/// refuses it: the same transcript at the bound verifies.
#[test]
fn size_bound_rejects_a_proof_that_would_otherwise_verify() {
    for one in [false, true] {
        for at_bound in [
            shapes(&[(MAX_GKR_VARS, one)]),
            shapes(&[(MAX_GKR_VARS, one), (0, true), (17, false)]),
        ] {
            let proof = simulate_batch(&at_bound, 81, Malformation::None);
            let claims = verify_batch(&at_bound, &proof, &mut transcript()).unwrap();
            assert_eq!(claims.point.len(), MAX_GKR_VARS);
        }

        for above in [
            shapes(&[(MAX_GKR_VARS + 1, one)]),
            shapes(&[(2, true), (MAX_GKR_VARS + 1, one), (0, false)]),
        ] {
            let proof = simulate_batch(&above, 81, Malformation::None);
            assert_eq!(Some(proof.messages.len()), proof_len(&above));
            assert!(is_check_failure(&verify_batch(
                &above,
                &proof,
                &mut transcript()
            )));
        }
    }
}

/// A proof with exactly the length `shape` dictates and random values.
/// Returns `None` for shapes no proof can match.
fn well_formed_random_proof(shape: &[GkrShape], rng: &mut StdRng) -> Option<LogupGkrProof<Fr>> {
    let n_max = shape.iter().map(|s| s.n_vars).max()?;
    if n_max > MAX_GKR_VARS {
        return None;
    }
    Some(LogupGkrProof {
        messages: (0..layout(shape).len).map(|_| Fr::rand(rng)).collect(),
    })
}

/// A proof of random length.
fn shapeless_random_proof(rng: &mut StdRng) -> LogupGkrProof<Fr> {
    LogupGkrProof {
        messages: (0..rng.gen_range(0..200)).map(|_| Fr::rand(rng)).collect(),
    }
}

/// Changes the length or one value of `proof` at random.
fn mutate_randomly(proof: &mut LogupGkrProof<Fr>, rng: &mut StdRng) {
    let value = Fr::rand(rng);
    let messages = &mut proof.messages;
    match rng.gen_range(0..6) {
        0 => {
            messages.pop();
        }
        1 => messages.push(value),
        2 => messages.truncate(rng.gen_range(0..=messages.len())),
        3 => messages.extend(vec![value; rng.gen_range(1..8)]),
        choice if !messages.is_empty() => {
            let at = rng.gen_range(0..messages.len());
            messages[at] = if choice == 4 { value } else { Fr::zero() };
        }
        _ => messages.push(Fr::zero()),
    }
}

fn fuzz_shape_strategy() -> impl Strategy<Value = Vec<(usize, bool)>> {
    let n_vars = prop_oneof![
        6 => 0usize..=6,
        2 => (MAX_GKR_VARS - 3)..=(MAX_GKR_VARS + 3),
        1 => prop_oneof![Just(usize::MAX), Just(usize::MAX - 1), Just(1usize << 40)],
    ];
    prop::collection::vec((n_vars, any::<bool>()), 0..=5)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Random statements against random proofs: wrong lengths, right
    /// lengths with random values, and honest proofs with their length or
    /// one value changed. Any outcome is fine except a panic.
    #[test]
    fn verify_batch_never_panics_on_random_proofs(
        shape in fuzz_shape_strategy(),
        mode in 0u8..5,
        mutations in 0usize..3,
        seed in any::<u64>(),
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let shape: Vec<GkrShape> = shape
            .into_iter()
            .map(|(n_vars, numerator_is_one)| GkrShape { n_vars, numerator_is_one })
            .collect();
        let provable = !shape.is_empty() && shape.iter().all(|s| s.n_vars <= 6);
        let mut proof = match mode {
            0 => shapeless_random_proof(&mut rng),
            1 | 2 => well_formed_random_proof(&shape, &mut rng).unwrap_or_default(),
            _ if provable => {
                let batch: Vec<(usize, bool)> =
                    shape.iter().map(|s| (s.n_vars, s.numerator_is_one)).collect();
                let instances = random_batch(&batch, seed);
                prove_batch(instances, &mut transcript()).unwrap().0
            }
            _ => shapeless_random_proof(&mut rng),
        };
        let honest = mode >= 3 && provable && mutations == 0;
        if mode != 1 {
            for _ in 0..mutations {
                mutate_randomly(&mut proof, &mut rng);
            }
        }
        let result = verify_batch(&shape, &proof, &mut transcript());
        prop_assert!(result.is_ok() || is_check_failure(&result));
        if honest {
            prop_assert!(result.is_ok());
        }
    }
}

// ─── Timing ──────────────────────────────────────────────────────────────

/// Prints prover and verifier seconds for 4 unit-numerator instances and
/// one general instance of 2^18 fractions each. Run with
/// `cargo test --features test-utils logup_gkr_timing -- --ignored --nocapture`
/// (the test profile is optimised), under `RAYON_NUM_THREADS` as needed.
///
/// The test profile keeps debug assertions, and `sum_of_products` in ark-ff
/// has one that recomputes every product: the prover then runs about 1.4
/// times slower than in a release build. For release figures add
/// `CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=false` and
/// `CARGO_PROFILE_TEST_OVERFLOW_CHECKS=false` to the environment.
#[test]
#[ignore = "timing only, asserts nothing about time"]
fn logup_gkr_timing_n18() {
    let n = 18;
    let instances = random_batch(
        &[(n, true), (n, true), (n, true), (n, true), (n, false)],
        90,
    );
    let shape = shape_of(&instances);
    #[cfg(feature = "parallel")]
    let threads = rayon::current_num_threads();
    #[cfg(not(feature = "parallel"))]
    let threads = 1;

    for run in 0..3 {
        let input = instances.clone();
        let start = Instant::now();
        let (proof, claims) = prove_batch(input, &mut transcript()).unwrap();
        let prove_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let verified = verify_batch(&shape, &proof, &mut transcript()).unwrap();
        let verify_s = start.elapsed().as_secs_f64();
        assert_eq!(verified, claims);
        println!(
            "logup_gkr timing: n={n} instances=4xOne+1xValues threads={threads} run={run} \
             prove_s={prove_s:.4} verify_s={verify_s:.6} proof_bytes={}",
            proof.compressed_size()
        );
    }
}
