//! Tests of the LogUp-GKR core. The reference prover below is written from
//! the protocol definition alone (dense evaluation of every layer MLE,
//! brute-force round polynomials) and shares no code with `prover.rs`.

use std::time::Instant;

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

fn eq_points(a: &[Fr], b: &[Fr]) -> Fr {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(a, b)| *a * b + (Fr::one() - a) * (Fr::one() - b))
        .product()
}

/// The polynomial of degree below `ys.len()` through `(i, ys[i])`, at `x`.
fn lagrange_eval(ys: &[Fr], x: Fr) -> Fr {
    (0..ys.len())
        .map(|i| {
            let basis: Fr = (0..ys.len())
                .filter(|j| *j != i)
                .map(|j| (x - Fr::from(j as u64)) / (Fr::from(i as u64) - Fr::from(j as u64)))
                .product();
            ys[i] * basis
        })
        .sum()
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

// ─── Reference prover ────────────────────────────────────────────────────

/// Where a cheating reference prover leaves the protocol.
#[derive(Clone, Copy, Debug)]
enum Deviation {
    /// The root of `instance` is sent as the equal fraction
    /// `(scale·P, scale·Q)`.
    ScaleRoot { instance: usize, scale: Fr },
    /// The roots of two instances are exchanged, which keeps their sum.
    SwapRoots { a: usize, b: usize },
    /// `delta·X(X-1)` is added to one round polynomial: it keeps
    /// `s(0) + s(1)` and changes the polynomial everywhere else.
    RoundPoly {
        iteration: usize,
        round: usize,
        delta: Fr,
    },
    /// The mask of `instance` in `iteration` is moved by `delta` along a
    /// direction that keeps the value of its gate.
    Mask {
        iteration: usize,
        instance: usize,
        delta: Fr,
    },
    /// `instance` has arbitrary numerators but is run as a unit-numerator
    /// instance: declared so in the transcript and with its input-layer
    /// mask (or, on zero variables, its root) sent in that format.
    DeclareOne { instance: usize },
}

/// A deviation plus how long the cheater keeps the lie alive. Everything it
/// sends is absorbed before the challenges that follow, as in a real attack;
/// nothing is edited after the fact.
#[derive(Clone, Copy, Debug)]
struct Fault {
    deviation: Deviation,
    /// In every iteration before this one the cheater bends one mask so
    /// that the layer check passes, carrying its false claim one layer
    /// down. From this iteration on it sends true masks again.
    patch_until: usize,
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

/// Reference prover. With `fault = None` it is the honest prover and also
/// asserts, by brute force, the identities the protocol rests on (every
/// round polynomial sums to the running claim, every layer check holds).
fn naive_prove_batch(
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

    tr.append_message(DOMAIN_LABEL, b"v1").unwrap();
    tr.append_serializable_element(COUNT_LABEL, &(instances.len() as u64))
        .unwrap();
    for (n, one) in sizes.iter().zip(&declared_one) {
        tr.append_serializable_element(SHAPE_LABEL, &(*n as u64, *one as u8))
            .unwrap();
    }

    let layers: Vec<_> = instances.iter().map(naive_layers).collect();
    let mut roots: Vec<[Fr; 2]> = layers
        .iter()
        .map(|layers| [layers[0].0[0], layers[0].1[0]])
        .collect();
    match deviation {
        Some(Deviation::ScaleRoot { instance, scale }) => {
            roots[instance] = roots[instance].map(|value| value * scale);
        }
        Some(Deviation::SwapRoots { a, b }) => roots.swap(a, b),
        _ => {}
    }
    tr.append_serializable_element(ROOTS_LABEL, &roots).unwrap();

    // The claims the verifier holds, which stop being true once the prover
    // has deviated.
    let mut claims = roots.clone();
    let mut point: Vec<Fr> = Vec::new();
    let mut round_polys = Vec::new();
    let mut masks = Vec::new();
    for t in 0..n_max {
        let lambda = tr.get_and_append_challenge(LAMBDA_LABEL).unwrap();
        let alpha = tr.get_and_append_challenge(ALPHA_LABEL).unwrap();
        // (instance, variables of its claimed layer)
        let active: Vec<(usize, usize)> = (0..instances.len())
            .filter(|i| sizes[*i] + t >= n_max)
            .map(|i| (i, sizes[i] + t - n_max))
            .collect();
        let weights: Vec<Fr> = active.iter().map(|(i, _)| alpha.pow([*i as u64])).collect();
        // The batched polynomial G of iteration t at a point of F^t.
        let g = |y: &[Fr]| -> Fr {
            active
                .iter()
                .zip(&weights)
                .map(|(&(i, k), weight)| {
                    let gate = gate(children(&layers[i][k + 1], &y[..k]), lambda);
                    *weight * eq_points(&point[..k], &y[..k]) * gate
                })
                .sum()
        };

        let mut claim: Fr = active
            .iter()
            .zip(&weights)
            .map(|(&(i, k), weight)| {
                *weight * Fr::from(1u64 << (t - k)) * (claims[i][0] + lambda * claims[i][1])
            })
            .sum();
        let mut rho: Vec<Fr> = Vec::new();
        let mut rounds = Vec::new();
        for j in 0..t {
            let free = t - 1 - j;
            let s = |x: u64| -> Fr {
                (0..1u64 << free)
                    .map(|bits| {
                        let mut y = rho.clone();
                        y.push(Fr::from(x));
                        y.extend((0..free).map(|bit| Fr::from((bits >> bit) & 1)));
                        g(&y)
                    })
                    .sum()
            };
            let mut evals = [s(0), s(2), s(3)];
            if fault.is_none() {
                assert_eq!(s(0) + s(1), claim, "round {j} of iteration {t}");
            }
            if let Some(Deviation::RoundPoly {
                iteration,
                round,
                delta,
            }) = deviation
                && (iteration, round) == (t, j)
            {
                // delta·X(X-1) at X = 2 and X = 3.
                evals[1] += delta * Fr::from(2u64);
                evals[2] += delta * Fr::from(6u64);
            }
            tr.append_serializable_element(ROUND_LABEL, &evals).unwrap();
            let r = tr.get_and_append_challenge(RHO_LABEL).unwrap();
            claim = lagrange_eval(&[evals[0], claim - evals[0], evals[1], evals[2]], r);
            rho.push(r);
            rounds.push(evals);
        }

        // The masks as the verifier will read them: on the input layer of a
        // declared unit-numerator instance it supplies p0 = p1 = 1 itself.
        let short: Vec<bool> = active
            .iter()
            .map(|&(i, k)| declared_one[i] && k + 1 == sizes[i])
            .collect();
        let mut gates: Vec<[Fr; 4]> = active
            .iter()
            .zip(&short)
            .map(|(&(i, k), short)| {
                let [p0, p1, q0, q1] = children(&layers[i][k + 1], &rho[..k]);
                if *short {
                    [Fr::one(), Fr::one(), q0, q1]
                } else {
                    [p0, p1, q0, q1]
                }
            })
            .collect();
        if let Some(Deviation::Mask {
            iteration,
            instance,
            delta,
        }) = deviation
            && iteration == t
        {
            let slot = active.iter().position(|(i, _)| *i == instance).unwrap();
            let [p0, p1, q0, q1] = gates[slot];
            gates[slot] = if short[slot] {
                // Keeps q0 + q1 + lambda·q0·q1.
                let moved = q0 + delta;
                let other = (gate(gates[slot], lambda) - moved) / (Fr::one() + lambda * moved);
                [p0, p1, moved, other]
            } else {
                // Keeps p0·q1 + p1·q0, and the denominators.
                [p0 + delta * q0, p1 - delta * q1, q0, q1]
            };
        }
        let expected = |gates: &[[Fr; 4]]| -> Fr {
            active
                .iter()
                .zip(&weights)
                .zip(gates)
                .map(|((&(_, k), weight), mask)| {
                    *weight * eq_points(&point[..k], &rho[..k]) * gate(*mask, lambda)
                })
                .sum()
        };
        if fault.is_none() {
            assert_eq!(expected(&gates), claim, "layer check of iteration {t}");
        }
        if t < patch_until && expected(&gates) != claim {
            // Bend the first active mask until the layer check passes.
            let k = active[0].1;
            let need =
                (claim - expected(&gates)) / (weights[0] * eq_points(&point[..k], &rho[..k]));
            let [p0, p1, q0, q1] = gates[0];
            gates[0] = if short[0] {
                let target = gate(gates[0], lambda) + need;
                [p0, p1, (target - q1) / (Fr::one() + lambda * q1), q1]
            } else {
                [p0 + need / q1, p1, q0, q1]
            };
            assert_eq!(expected(&gates), claim);
        }

        let iteration_masks: Vec<Vec<Fr>> = gates
            .iter()
            .zip(&short)
            .map(|(mask, short)| mask[if *short { 2 } else { 0 }..].to_vec())
            .collect();
        tr.append_serializable_element(MASKS_LABEL, &iteration_masks)
            .unwrap();
        let mu = tr.get_and_append_challenge(MU_LABEL).unwrap();
        for (&(i, _), [p0, p1, q0, q1]) in active.iter().zip(&gates) {
            claims[i] = [
                (Fr::one() - mu) * p0 + mu * p1,
                (Fr::one() - mu) * q0 + mu * q1,
            ];
        }
        point = std::iter::once(mu).chain(rho).collect();
        round_polys.push(rounds);
        masks.push(iteration_masks);
    }

    let proof = LogupGkrProof {
        roots: roots.clone(),
        round_polys,
        masks,
    };
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

/// At 2^15 fractions no table is split into more than four work items of
/// the largest size, so a fault in a later one would not show.
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

/// What every fault below comes to, by how long the cheater keeps patching:
/// - it stops before the last iteration: the first iteration that gets true
///   masks while the running claim is false fails its LAYER CHECK (step e,
///   claim against the gate of the absorbed masks);
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
    let (honest, _) = naive_prove_batch(&instances, &mut transcript(), None);

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
    // the roots, so the caller's relation on the roots cannot see them. The
    // false root enters the claim of the iteration in which the instance
    // joins (0 for the size-3 instances, 1 for the size-2 ones), and the
    // layer check of that iteration, or of the first later one the cheater
    // does not patch, rejects.
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
            let (proof, _) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
            assert_ne!(proof.roots, honest.roots);
            assert_eq!(root_sum(&proof.roots), root_sum(&honest.roots));
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

#[test]
fn cheating_prover_is_rejected_at_round_poly() {
    let instances = random_batch(&[(4, false), (4, true), (2, true), (1, false)], 71);
    let shape = shape_of(&instances);
    let n_max = 4;
    let (honest, _) = naive_prove_batch(&instances, &mut transcript(), None);

    for iteration in 1..n_max {
        for round in 0..iteration {
            let identity = Fault {
                deviation: Deviation::RoundPoly {
                    iteration,
                    round,
                    delta: Fr::zero(),
                },
                patch_until: n_max,
            };
            assert_eq!(outcome(&instances, &shape, identity), Outcome::Accepted);

            // The altered polynomial still has s(0) + s(1) equal to the
            // claim (the verifier derives s(1), so that much is free), but
            // its value at the challenge is not the true partial sum. The
            // remaining rounds cannot repair that, so the LAYER CHECK at the
            // end of the same iteration fails; a cheater that patches the
            // mask there is caught one iteration later, and so on.
            for patch_until in 0..=n_max {
                let fault = Fault {
                    deviation: Deviation::RoundPoly {
                        iteration,
                        round,
                        delta: Fr::from(7u64),
                    },
                    patch_until,
                };
                let (proof, _) = naive_prove_batch(&instances, &mut transcript(), Some(fault));
                assert_eq!(proof.roots, honest.roots);
                assert_eq!(
                    proof.round_polys[iteration][round][0],
                    honest.round_polys[iteration][round][0]
                );
                assert_ne!(
                    proof.round_polys[iteration][round],
                    honest.round_polys[iteration][round]
                );
                assert_eq!(
                    outcome_of(&instances, &shape, &proof),
                    expected_outcome(patch_until, n_max),
                    "{fault:?}"
                );
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

#[test]
fn cheating_prover_is_rejected_at_final_mask() {
    let instances = random_batch(&[(3, false), (3, true), (2, true), (1, false)], 73);
    let shape = shape_of(&instances);
    let n_max = 3;
    let (honest, honest_claims) = naive_prove_batch(&instances, &mut transcript(), None);

    // Both the four-value mask of a general instance and the two-value mask
    // of a unit-numerator one can be moved without changing their gate.
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
        // The proof differs from the honest one in that single mask.
        assert_eq!(proof.roots, honest.roots);
        assert_eq!(proof.round_polys, honest.round_polys);
        assert_eq!(proof.masks[..n_max - 1], honest.masks[..n_max - 1]);

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
        // CHECKS, before anything is absorbed. The converse likewise.
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
        assert_eq!(proof.roots[0], [Fr::from(3u64), Fr::from(11u64)]);
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
        assert_eq!(proof.roots[position], [Fr::from(3u64), Fr::from(11u64)]);
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
    // does.
    for (batch, instance, index) in [
        (vec![(3, false)], 0, 5),
        (vec![(2, true)], 0, 0),
        (vec![(0, false)], 0, 0),
        (vec![(0, true)], 0, 0),
        (vec![(3, true), (2, false), (0, false)], 1, 3),
        (vec![(3, true), (2, false), (0, false)], 2, 0),
    ] {
        let mut instances = random_batch(&batch, 76);
        let shape = shape_of(&instances);
        instances[instance].den[index] = Fr::zero();
        let (proof, _) = prove_batch(instances.clone(), &mut transcript()).unwrap();
        assert!(proof.roots[instance][1].is_zero());
        assert_eq!(outcome_of(&instances, &shape, &proof), Outcome::Rejected);
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

    type Proof = LogupGkrProof<Fr>;
    type Mutation = Box<dyn Fn(&mut Proof)>;
    let mut mutations: Vec<Mutation> = vec![
        Box::new(|p: &mut Proof| *p = LogupGkrProof::default()),
        Box::new(|p: &mut Proof| p.roots.clear()),
        Box::new(|p: &mut Proof| p.roots.truncate(3)),
        Box::new(move |p: &mut Proof| p.roots.push([filler; 2])),
        Box::new(|p: &mut Proof| p.round_polys.clear()),
        Box::new(|p: &mut Proof| p.round_polys.truncate(2)),
        Box::new(move |p: &mut Proof| p.round_polys.push(vec![[filler; 3]; 3])),
        Box::new(|p: &mut Proof| p.masks.clear()),
        Box::new(|p: &mut Proof| p.masks.truncate(2)),
        Box::new(move |p: &mut Proof| p.masks.push(vec![vec![filler; 4]; 2])),
        Box::new(|p: &mut Proof| {
            p.round_polys.truncate(2);
            p.masks.truncate(2);
        }),
        Box::new(move |p: &mut Proof| {
            p.round_polys.push(vec![[filler; 3]; 3]);
            p.masks.push(vec![vec![filler; 4]; 2]);
        }),
    ];
    for t in 0..3 {
        mutations.push(Box::new(move |p: &mut Proof| {
            p.round_polys[t].push([filler; 3])
        }));
        mutations.push(Box::new(move |p: &mut Proof| p.round_polys[t].clear()));
        mutations.push(Box::new(move |p: &mut Proof| {
            p.round_polys[t].pop();
        }));
        mutations.push(Box::new(move |p: &mut Proof| p.masks[t].clear()));
        mutations.push(Box::new(move |p: &mut Proof| {
            p.masks[t].pop();
        }));
        mutations.push(Box::new(move |p: &mut Proof| {
            p.masks[t].push(vec![filler; 4])
        }));
        mutations.push(Box::new(move |p: &mut Proof| {
            p.masks[t].push(vec![filler; 2])
        }));
        for i in 0..2 {
            mutations.push(Box::new(move |p: &mut Proof| p.masks[t][i].clear()));
            mutations.push(Box::new(move |p: &mut Proof| p.masks[t][i].truncate(1)));
            mutations.push(Box::new(move |p: &mut Proof| {
                p.masks[t][i].pop();
            }));
            mutations.push(Box::new(move |p: &mut Proof| p.masks[t][i].push(filler)));
            mutations.push(Box::new(move |p: &mut Proof| {
                p.masks[t][i].extend([filler; 2])
            }));
            mutations.push(Box::new(move |p: &mut Proof| {
                p.masks[t][i].extend([filler; 60])
            }));
        }
    }
    let mut rejected = 0;
    for mutate in &mutations {
        let mut proof = honest.clone();
        mutate(&mut proof);
        // Popping from an empty list changes nothing; everything else must
        // be rejected.
        if proof != honest {
            assert!(is_check_failure(&verify_batch(
                &shape,
                &proof,
                &mut transcript()
            )));
            rejected += 1;
        }
    }
    assert!(rejected >= mutations.len() - 3);

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
    // lengths, not the statement for its size.
    let at_bound = [with_size(MAX_GKR_VARS)];
    assert!(is_check_failure(&verify_batch(
        &at_bound,
        &honest,
        &mut transcript()
    )));
}

// ─── Self-consistent malformed proofs ────────────────────────────────────

/// How a simulated transcript departs from the format the statement dictates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Malformation {
    None,
    /// One root more than there are instances.
    ExtraRoot,
    /// The input mask of the first unit-numerator instance is sent as
    /// `[1, 1, q0, q1]`.
    LongInputMask,
    /// The first four-value mask of `iteration` has unit numerators and is
    /// sent as `[q0, q1]`.
    ShortMask {
        iteration: usize,
    },
    /// One mask more than there are active instances in `iteration`.
    ExtraMask {
        iteration: usize,
    },
}

/// A prover without a witness: every message is random except one mask value
/// per iteration, which is solved so that the layer check passes.
/// `verify_batch` opens nothing, so it accepts such a transcript; only the
/// caller's openings would not. That makes it the right probe for the format
/// checks: an honest proof edited after the fact derails every later
/// challenge and is rejected by the layer check whatever the format checks
/// do, whereas here the malformed message is absorbed like any other and
/// nothing but the format check itself can reject. It also reaches sizes no
/// honest prover can.
fn simulate_batch(shape: &[GkrShape], seed: u64, malformation: Malformation) -> LogupGkrProof<Fr> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut tr = transcript();
    let n_max = shape.iter().map(|s| s.n_vars).max().unwrap();

    tr.append_message(DOMAIN_LABEL, b"v1").unwrap();
    tr.append_serializable_element(COUNT_LABEL, &(shape.len() as u64))
        .unwrap();
    for s in shape {
        tr.append_serializable_element(SHAPE_LABEL, &(s.n_vars as u64, s.numerator_is_one as u8))
            .unwrap();
    }
    let mut roots: Vec<[Fr; 2]> = shape
        .iter()
        .map(|s| {
            // The root of a zero-variable instance is its input claim.
            let numerator = if s.numerator_is_one && s.n_vars == 0 {
                Fr::one()
            } else {
                Fr::rand(&mut rng)
            };
            [numerator, Fr::rand(&mut rng)]
        })
        .collect();
    let mut claims = roots.clone();
    if malformation == Malformation::ExtraRoot {
        roots.push([Fr::rand(&mut rng), Fr::rand(&mut rng)]);
    }
    tr.append_serializable_element(ROOTS_LABEL, &roots).unwrap();

    let mut point: Vec<Fr> = Vec::new();
    let mut round_polys = Vec::new();
    let mut masks = Vec::new();
    for t in 0..n_max {
        let lambda = tr.get_and_append_challenge(LAMBDA_LABEL).unwrap();
        let alpha = tr.get_and_append_challenge(ALPHA_LABEL).unwrap();
        let active: Vec<(usize, usize)> = (0..shape.len())
            .filter(|i| shape[*i].n_vars + t >= n_max)
            .map(|i| (i, shape[i].n_vars + t - n_max))
            .collect();
        let weights: Vec<Fr> = active.iter().map(|(i, _)| alpha.pow([*i as u64])).collect();

        let mut claim: Fr = active
            .iter()
            .zip(&weights)
            .map(|(&(i, k), weight)| {
                *weight
                    * Fr::from(2u64).pow([(t - k) as u64])
                    * (claims[i][0] + lambda * claims[i][1])
            })
            .sum();
        let mut rho: Vec<Fr> = Vec::new();
        let mut rounds = Vec::new();
        for _ in 0..t {
            let evals = [Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)];
            tr.append_serializable_element(ROUND_LABEL, &evals).unwrap();
            let r = tr.get_and_append_challenge(RHO_LABEL).unwrap();
            claim = lagrange_eval(&[evals[0], claim - evals[0], evals[1], evals[2]], r);
            rho.push(r);
            rounds.push(evals);
        }

        // Masks the statement wants in two values, and the one this run
        // sends in the other format.
        let short: Vec<bool> = active
            .iter()
            .map(|(i, _)| shape[*i].numerator_is_one && t + 1 == n_max)
            .collect();
        let reformatted = match malformation {
            Malformation::LongInputMask if t + 1 == n_max => short.iter().position(|short| *short),
            Malformation::ShortMask { iteration } if iteration == t => {
                short.iter().position(|short| !*short)
            }
            _ => None,
        };
        let unit = |slot: usize| short[slot] || reformatted == Some(slot);
        let mut gates: Vec<[Fr; 4]> = (0..active.len())
            .map(|slot| {
                let numerator =
                    |rng: &mut StdRng| if unit(slot) { Fr::one() } else { Fr::rand(rng) };
                let (p0, p1) = (numerator(&mut rng), numerator(&mut rng));
                [p0, p1, Fr::rand(&mut rng), Fr::rand(&mut rng)]
            })
            .collect();
        let expected = |gates: &[[Fr; 4]]| -> Fr {
            active
                .iter()
                .zip(&weights)
                .zip(gates)
                .map(|((&(_, k), weight), mask)| {
                    *weight * eq_points(&point[..k], &rho[..k]) * gate(*mask, lambda)
                })
                .sum()
        };
        // The largest instance is active in every iteration, so there is
        // always a first mask to solve for.
        let k = active[0].1;
        let need = (claim - expected(&gates)) / (weights[0] * eq_points(&point[..k], &rho[..k]));
        let [p0, p1, q0, q1] = gates[0];
        gates[0] = if unit(0) {
            let target = gate(gates[0], lambda) + need;
            [p0, p1, (target - q1) / (Fr::one() + lambda * q1), q1]
        } else {
            [p0 + need / q1, p1, q0, q1]
        };
        assert_eq!(expected(&gates), claim);

        let mut iteration_masks: Vec<Vec<Fr>> = gates
            .iter()
            .enumerate()
            .map(|(slot, mask)| {
                let two_values = short[slot] != (reformatted == Some(slot));
                mask[if two_values { 2 } else { 0 }..].to_vec()
            })
            .collect();
        if malformation == (Malformation::ExtraMask { iteration: t }) {
            iteration_masks.push((0..4).map(|_| Fr::rand(&mut rng)).collect());
        }
        tr.append_serializable_element(MASKS_LABEL, &iteration_masks)
            .unwrap();
        let mu = tr.get_and_append_challenge(MU_LABEL).unwrap();
        for (&(i, _), [p0, p1, q0, q1]) in active.iter().zip(&gates) {
            claims[i] = [
                (Fr::one() - mu) * p0 + mu * p1,
                (Fr::one() - mu) * q0 + mu * q1,
            ];
        }
        point = std::iter::once(mu).chain(rho).collect();
        round_polys.push(rounds);
        masks.push(iteration_masks);
    }
    LogupGkrProof {
        roots,
        round_polys,
        masks,
    }
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

/// The number of roots and the format of every mask are dictated by the
/// statement: a transcript that is consistent in itself but sends a root too
/// many, or a mask in the other format, is refused for that alone.
#[test]
fn self_consistent_malformed_proof_is_rejected_by_the_length_checks() {
    let shape = shapes(&[(3, false), (3, true), (1, true), (0, false), (0, true)]);
    let n_max = 3;
    let mut malformations = vec![Malformation::ExtraRoot, Malformation::LongInputMask];
    for iteration in 0..n_max {
        malformations.push(Malformation::ShortMask { iteration });
        malformations.push(Malformation::ExtraMask { iteration });
    }
    for seed in 0..4 {
        // The simulator is not what gets the malformed transcripts rejected.
        let proof = simulate_batch(&shape, seed, Malformation::None);
        let claims = verify_batch(&shape, &proof, &mut transcript()).unwrap();
        assert_eq!(claims.point.len(), n_max);
        assert_eq!(claims.roots, proof.roots);

        for malformation in &malformations {
            let malformed = simulate_batch(&shape, seed, *malformation);
            assert_ne!(malformed, proof, "{malformation:?}");
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
            assert!(is_check_failure(&verify_batch(
                &above,
                &proof,
                &mut transcript()
            )));
        }
    }
}

/// A proof with exactly the lengths `shape` dictates and random values.
/// Returns `None` for shapes no proof can match.
fn well_formed_random_proof(shape: &[GkrShape], rng: &mut StdRng) -> Option<LogupGkrProof<Fr>> {
    let n_max = shape.iter().map(|s| s.n_vars).max()?;
    if n_max > MAX_GKR_VARS {
        return None;
    }
    let roots = shape
        .iter()
        .map(|_| [Fr::rand(rng), Fr::rand(rng)])
        .collect();
    let mut round_polys = Vec::new();
    let mut masks = Vec::new();
    for t in 0..n_max {
        round_polys.push(
            (0..t)
                .map(|_| [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)])
                .collect(),
        );
        let mut iteration = Vec::new();
        for s in shape.iter().filter(|s| s.n_vars + t >= n_max) {
            let len = if s.numerator_is_one && t + 1 == n_max {
                2
            } else {
                4
            };
            iteration.push((0..len).map(|_| Fr::rand(rng)).collect());
        }
        masks.push(iteration);
    }
    Some(LogupGkrProof {
        roots,
        round_polys,
        masks,
    })
}

/// A proof whose every length is random.
fn shapeless_random_proof(rng: &mut StdRng) -> LogupGkrProof<Fr> {
    let iterations = rng.gen_range(0..8);
    LogupGkrProof {
        roots: (0..rng.gen_range(0..8))
            .map(|_| [Fr::rand(rng), Fr::rand(rng)])
            .collect(),
        round_polys: (0..iterations)
            .map(|t| {
                let rounds = if rng.gen_bool(0.7) {
                    t
                } else {
                    rng.gen_range(0..8)
                };
                (0..rounds)
                    .map(|_| [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)])
                    .collect()
            })
            .collect(),
        masks: (0..if rng.gen_bool(0.7) {
            iterations
        } else {
            rng.gen_range(0..8)
        })
            .map(|_| {
                (0..rng.gen_range(0..6))
                    .map(|_| (0..rng.gen_range(0..6)).map(|_| Fr::rand(rng)).collect())
                    .collect()
            })
            .collect(),
    }
}

/// Changes one length or one value of `proof` at random.
fn mutate_randomly(proof: &mut LogupGkrProof<Fr>, rng: &mut StdRng) {
    let value = Fr::rand(rng);
    let iterations = proof.masks.len().min(proof.round_polys.len());
    let t = if iterations == 0 {
        0
    } else {
        rng.gen_range(0..iterations)
    };
    match rng.gen_range(0..10) {
        0 => {
            proof.roots.pop();
        }
        1 => proof.roots.push([value; 2]),
        2 => {
            if let Some(root) = proof.roots.last_mut() {
                root[rng.gen_range(0..2)] = if rng.gen_bool(0.5) { value } else { Fr::zero() };
            }
        }
        3 => {
            proof.round_polys.pop();
        }
        4 => {
            proof.masks.pop();
        }
        5 if iterations > 0 => proof.round_polys[t].push([value; 3]),
        6 if iterations > 0 => {
            if let Some(round) = proof.round_polys[t].last_mut() {
                round[rng.gen_range(0..3)] = value;
            }
        }
        7 if iterations > 0 => proof.masks[t].push(vec![value; rng.gen_range(0..6)]),
        8 if iterations > 0 => {
            if let Some(mask) = proof.masks[t].last_mut() {
                if rng.gen_bool(0.5) {
                    mask.pop();
                } else {
                    mask.push(value);
                }
            }
        }
        _ if iterations > 0 => {
            if let Some(slot) = proof.masks[t].last_mut().and_then(|mask| mask.last_mut()) {
                *slot = value;
            }
        }
        _ => proof.masks.push(vec![vec![value; 4]]),
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

    /// Random statements against random proofs: wrong lengths everywhere,
    /// right lengths with random values, and honest proofs with one length
    /// or value changed. Any outcome is fine except a panic.
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
