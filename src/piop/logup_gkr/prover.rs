//! Prover side of batched LogUp-GKR: a degree-3 sumcheck specialised to the
//! fraction-addition gate, run over all instances of a batch at once.

use ark_ff::{PrimeField, batch_inversion};

use super::{
    ALPHA_LABEL, FractionInstance, GkrClaims, GkrShape, LAMBDA_LABEL, LogupGkrProof, MASKS_LABEL,
    MAX_GKR_VARS, MU_LABEL, Numerator, RHO_LABEL, ROOTS_LABEL, ROUND_LABEL, absorb_shape,
    layer::{Layer, build_layer_stacks, eq_table, map_jobs, pool_threads},
    powers_of_two,
};
use crate::{
    errors::{SnarkError, SnarkResult},
    piop::errors::PolyIOPErrors,
    transcript::Tr,
};

/// Largest number of gate pairs in one item of a round's work list.
const CHUNK_PAIRS: usize = 1 << 11;

/// Smallest number of gate pairs worth an item of their own.
const MIN_CHUNK_PAIRS: usize = 1 << 6;

/// Below this many gate pairs over all instances a round runs serially:
/// a few tens of microseconds of work, about what waking the pool costs.
const SERIAL_BELOW_PAIRS: usize = 1 << 8;

/// Gate pairs per work item for a round of `total_pairs`: a few items per
/// thread, so that a round a little above the serial threshold still uses
/// the whole pool.
fn chunk_pairs(total_pairs: usize) -> usize {
    (total_pairs / (4 * pool_threads())).clamp(MIN_CHUNK_PAIRS, CHUNK_PAIRS)
}

fn live_pairs<F>(active: &[Active<'_, F>], round: usize) -> usize {
    let live = active.iter().filter(|a| a.k > round);
    live.map(|a| 1usize << (a.k - round - 1)).sum()
}

fn invalid(reason: &str) -> SnarkError {
    PolyIOPErrors::InvalidParameters(reason.to_string()).into()
}

fn shape_of<F>(instance: &FractionInstance<F>) -> SnarkResult<GkrShape> {
    let len = instance.den.len();
    if !len.is_power_of_two() {
        return Err(invalid("LogUp-GKR instance size is not a power of two"));
    }
    let n_vars = len.ilog2() as usize;
    if n_vars > MAX_GKR_VARS {
        return Err(invalid("LogUp-GKR instance is too large"));
    }
    let numerator_is_one = match &instance.num {
        Numerator::One => true,
        Numerator::Values(values) if values.len() == len => false,
        Numerator::Values(_) => {
            return Err(invalid(
                "LogUp-GKR numerators and denominators differ in length",
            ));
        }
    };
    Ok(GkrShape {
        n_vars,
        numerator_is_one,
    })
}

/// One instance across the iterations of a batch.
struct InstanceState<F> {
    n_vars: usize,
    /// Index into the eq tables, shared by the instances of one size.
    eq: usize,
    /// Layers below the claimed one; `pop` yields the next.
    layers: Vec<Layer<F>>,
    /// `bufs[0]` is the layer the current iteration reduces to, and its
    /// folds ping-pong between `bufs[1]` and `bufs[2]`. Those two are the
    /// layers of the previous two iterations: exactly the sizes needed, so
    /// the sumchecks allocate nothing.
    bufs: [Layer<F>; 3],
    /// `(P, Q)` claimed on the layer the next iteration starts from.
    claim: [F; 2],
}

/// An instance taking part in the current iteration.
struct Active<'a, F> {
    state: &'a mut InstanceState<F>,
    /// Variables of the claimed layer: the instance is live in rounds
    /// `0..k` and constant afterwards.
    k: usize,
    /// The layer below is the numerator-free input layer.
    singles: bool,
    /// `alpha^idx`, with `idx` the position in the full instance list.
    alpha_pow: F,
    /// `alpha^idx · 2^(t-k)`, the weight of the instance's own round
    /// polynomial while it is live.
    weight: F,
    /// Running claim of the instance's own sumcheck, without batching weight
    /// and without the eq factor of the variables bound so far (which is the
    /// same for every live instance). It is part of the proof, not a
    /// cross-check: a round gets its polynomial at 1 from it, which is what
    /// lets the round be computed from two sums instead of three, and once
    /// the instance has bound its last variable it is the instance's
    /// constant term in the later rounds of the iteration (`done` below).
    claim: F,
}

/// The eq table of the instances of one size. The eq factor of the round
/// variable is taken out of the round sums, so in round `j` the table is
/// over the variables after `j` only: half the size of the gate tables, and
/// binding a variable is summing it out.
struct EqTables<F> {
    n_vars: usize,
    /// Variables of the claimed layer in the current iteration, if the size
    /// is active.
    k: Option<usize>,
    /// Round `j` folds `bufs[j % 2]` into the other; `bufs[1]` starts as the
    /// table of the previous iteration, which has the size the first fold
    /// needs.
    bufs: [Vec<F>; 2],
}

/// Index of the buffer a live instance's tables are in at the start of `round`.
fn src_buf(round: usize) -> usize {
    match round {
        0 => 0,
        r if r % 2 == 1 => 1,
        _ => 2,
    }
}

/// Source and destination of the fold that ends `round`.
fn fold_bufs<T>(bufs: &mut [T; 3], round: usize) -> (&T, &mut T) {
    let [layer, a, b] = bufs;
    match round {
        0 => (layer, a),
        r if r % 2 == 1 => (a, b),
        _ => (b, a),
    }
}

/// A chunk of one instance's gates in one round. With `x` the round
/// variable, a pair of gates is four consecutive entries of `p` and of `q`
/// (children 0 and 1 at `x = 0`, then at `x = 1`) and one of `eq`.
struct SumJob<'a, F> {
    slot: usize,
    /// Empty for a numerator-free layer.
    p: &'a [F],
    q: &'a [F],
    eq: &'a [F],
}

impl<F: PrimeField> SumJob<'_, F> {
    /// Sum over the chunk of `eq·h(x)` at `x = 0` and its coefficient of
    /// `x^2`, for the gate `h = p0·q1 + p1·q0 + lambda·q0·q1` with `p0, q0`
    /// the even and `p1, q1` the odd children. The gate is evaluated as
    /// `(p0 + lambda·q0)·q1 + p1·q0`; its leading coefficient is the same
    /// expression on the differences along `x`.
    fn sums(&self, lambda: F) -> [F; 2] {
        if self.p.is_empty() {
            // With unit numerators the gate is q0 + q1 + lambda·q0·q1, and
            // lambda is applied once to the whole chunk.
            let [linear, h0, c] = weighted_sums(self.eq, |i| {
                let q = &self.q[4 * i..4 * i + 4];
                [q[0] + q[1], q[0] * q[1], (q[2] - q[0]) * (q[3] - q[1])]
            });
            [linear + lambda * h0, lambda * c]
        } else {
            weighted_sums(self.eq, |i| {
                let (p, q) = (&self.p[4 * i..4 * i + 4], &self.q[4 * i..4 * i + 4]);
                let a0 = p[0] + lambda * q[0];
                let a1 = p[2] + lambda * q[2];
                [
                    F::sum_of_products(&[a0, p[1]], &[q[1], q[0]]),
                    F::sum_of_products(&[a1 - a0, p[3] - p[1]], &[q[3] - q[1], q[2] - q[0]]),
                ]
            })
        }
    }
}

/// `sum_i weights[i] · terms(i)`, componentwise. The products are taken two
/// at a time: a sum of two products costs one reduction, not two.
pub(super) fn weighted_sums<F: PrimeField, const T: usize>(
    weights: &[F],
    terms: impl Fn(usize) -> [F; T],
) -> [F; T] {
    let mut acc = [F::zero(); T];
    let pairs = weights.chunks_exact(2);
    if let [w] = pairs.remainder() {
        let last = terms(weights.len() - 1);
        for (sum, term) in acc.iter_mut().zip(last) {
            *sum += *w * term;
        }
    }
    for (i, w) in pairs.enumerate() {
        let (even, odd) = (terms(2 * i), terms(2 * i + 1));
        for ((sum, even), odd) in acc.iter_mut().zip(even).zip(odd) {
            *sum += F::sum_of_products(&[w[0], w[1]], &[even, odd]);
        }
    }
    acc
}

/// Binds the round variable of a chunk of one table, writing the half-size
/// result to `dst`. A layer table is interleaved and bound to `r`, the two
/// children keeping their slots; an eq table (`stride` 1) no longer has the
/// round variable and loses the next one by summing over it.
struct FoldJob<'a, F> {
    src: &'a [F],
    dst: &'a mut [F],
    stride: usize,
}

impl<F: PrimeField> FoldJob<'_, F> {
    fn run(self, r: F) {
        if self.stride == 1 {
            for (d, src) in self.dst.iter_mut().zip(self.src.chunks_exact(2)) {
                *d = src[0] + src[1];
            }
            return;
        }
        for (dst, src) in self.dst.chunks_exact_mut(2).zip(self.src.chunks_exact(4)) {
            dst[0] = src[0] + r * (src[2] - src[0]);
            dst[1] = src[1] + r * (src[3] - src[1]);
        }
    }
}

/// Queues the fold of `src` into `dst`, which is half as long. The output
/// chunks are disjoint, which is what lets them run in parallel: an in-place
/// fold of an interleaved table would have one chunk write what another
/// still reads.
fn push_fold_jobs<'a, F>(
    jobs: &mut Vec<FoldJob<'a, F>>,
    src: &'a [F],
    dst: &'a mut [F],
    stride: usize,
    chunk: usize,
) {
    let src_chunks = src.chunks(2 * stride * chunk);
    let dst_chunks = dst.chunks_mut(stride * chunk);
    jobs.extend(
        src_chunks
            .zip(dst_chunks)
            .map(|(src, dst)| FoldJob { src, dst, stride }),
    );
}

/// Per active instance, its own round polynomial without the eq factor of
/// the round variable: the value at 0 and the leading coefficient (zero for
/// an instance that ran out of variables).
fn sum_round<F: PrimeField>(
    active: &[Active<'_, F>],
    eqs: &[EqTables<F>],
    round: usize,
    lambda: F,
) -> Vec<[F; 2]> {
    let mut jobs = Vec::new();
    let total_pairs = live_pairs(active, round);
    let chunk = chunk_pairs(total_pairs);
    for (slot, a) in active.iter().enumerate().filter(|(_, a)| a.k > round) {
        let pairs = 1usize << (a.k - round - 1);
        let tables = &a.state.bufs[src_buf(round)];
        let eq = &eqs[a.state.eq].bufs[round % 2];
        for start in (0..pairs).step_by(chunk) {
            let end = (start + chunk).min(pairs);
            let p: &[F] = if a.singles {
                &[]
            } else {
                &tables.p[4 * start..4 * end]
            };
            jobs.push(SumJob {
                slot,
                p,
                q: &tables.q[4 * start..4 * end],
                eq: &eq[start..end],
            });
        }
    }
    let parts = map_jobs(jobs, total_pairs >= SERIAL_BELOW_PAIRS, |job| {
        (job.slot, job.sums(lambda))
    });
    let mut sums = vec![[F::zero(); 2]; active.len()];
    for (slot, part) in parts {
        for (sum, value) in sums[slot].iter_mut().zip(part) {
            *sum += value;
        }
    }
    sums
}

/// Binds the round variable to `r` in every live table.
fn fold_round<F: PrimeField>(
    active: &mut [Active<'_, F>],
    eqs: &mut [EqTables<F>],
    round: usize,
    r: F,
) {
    let mut jobs = Vec::new();
    let total_pairs = live_pairs(active, round);
    let chunk = chunk_pairs(total_pairs);
    for a in active.iter_mut().filter(|a| a.k > round) {
        let pairs = 1usize << (a.k - round - 1);
        let (src, dst) = fold_bufs(&mut a.state.bufs, round);
        push_fold_jobs(
            &mut jobs,
            &src.q[..4 * pairs],
            &mut dst.q[..2 * pairs],
            2,
            chunk,
        );
        if !a.singles {
            push_fold_jobs(
                &mut jobs,
                &src.p[..4 * pairs],
                &mut dst.p[..2 * pairs],
                2,
                chunk,
            );
        }
    }
    for eq in eqs.iter_mut() {
        // Nothing to prepare after the size's last round.
        let Some(k) = eq.k.filter(|k| *k > round + 1) else {
            continue;
        };
        let pairs = 1usize << (k - round - 2);
        let [a, b] = &mut eq.bufs;
        let (src, dst) = if round.is_multiple_of(2) {
            (&*a, b)
        } else {
            (&*b, a)
        };
        push_fold_jobs(&mut jobs, &src[..2 * pairs], &mut dst[..pairs], 1, chunk);
    }
    map_jobs(jobs, total_pairs >= SERIAL_BELOW_PAIRS, |job| job.run(r));
}

/// Proves a batch of instances and returns the proof with the claims the
/// caller has to discharge (see the module docs).
///
/// The statement is NOT checked: an instance with a zero denominator or a
/// batch whose roots do not satisfy the caller's relation still yields a
/// proof, which the verifier side rejects.
pub(crate) fn prove_batch<F: PrimeField>(
    instances: Vec<FractionInstance<F>>,
    tr: &mut Tr<F>,
) -> SnarkResult<(LogupGkrProof<F>, GkrClaims<F>)> {
    if instances.is_empty() {
        return Err(invalid("LogUp-GKR batch without instances"));
    }
    let shape = instances
        .iter()
        .map(shape_of)
        .collect::<SnarkResult<Vec<_>>>()?;
    let n_max = shape.iter().map(|s| s.n_vars).max().unwrap_or(0);
    absorb_shape(&shape, tr)?;

    // One eq table per distinct size: instances of one size are on the same
    // layer in every iteration.
    let mut sizes: Vec<usize> = shape.iter().map(|s| s.n_vars).collect();
    sizes.sort_unstable();
    sizes.dedup();
    let mut eqs: Vec<EqTables<F>> = sizes
        .iter()
        .map(|&n_vars| EqTables {
            n_vars,
            k: None,
            bufs: Default::default(),
        })
        .collect();
    let mut states: Vec<InstanceState<F>> = build_layer_stacks(instances)
        .into_iter()
        .zip(&shape)
        .map(|(stack, s)| InstanceState {
            n_vars: s.n_vars,
            eq: sizes.binary_search(&s.n_vars).unwrap_or(0),
            layers: stack.layers,
            bufs: Default::default(),
            claim: stack.root,
        })
        .collect();

    let roots: Vec<[F; 2]> = states.iter().map(|state| state.claim).collect();
    tr.append_serializable_element(ROOTS_LABEL, &roots)?;

    let pow2 = powers_of_two::<F>(n_max);
    let mut point: Vec<F> = Vec::with_capacity(n_max);
    let mut round_polys = Vec::with_capacity(n_max);
    let mut masks = Vec::with_capacity(n_max);

    for t in 0..n_max {
        let lambda = tr.get_and_append_challenge(LAMBDA_LABEL)?;
        let alpha = tr.get_and_append_challenge(ALPHA_LABEL)?;

        // A round derives its polynomial at 1 from the running claim, which
        // takes a division by the round's coordinate of the point. A zero
        // coordinate has probability 1/|F| per challenge and depends on
        // nothing the caller chose, so the prover gives up on it instead of
        // keeping a three-sum path that no test could reach.
        let mut point_inv = point.clone();
        batch_inversion(&mut point_inv);
        if point_inv.iter().any(|z| z.is_zero()) {
            return Err(invalid("LogUp-GKR challenge is zero"));
        }
        let mut active = Vec::new();
        let mut alpha_pow = F::one();
        for state in states.iter_mut() {
            if let Some(k) = (state.n_vars + t).checked_sub(n_max) {
                let Some(layer) = state.layers.pop() else {
                    return Err(invalid("LogUp-GKR layer stack ran out"));
                };
                let singles = layer.p.is_empty();
                state.bufs[0] = layer;
                if singles {
                    // The scratch numerators stay idle from here on.
                    state.bufs[1].p = Vec::new();
                    state.bufs[2].p = Vec::new();
                }
                active.push(Active {
                    k,
                    singles,
                    alpha_pow,
                    weight: alpha_pow * pow2[t - k],
                    claim: state.claim[0] + lambda * state.claim[1],
                    state,
                });
            }
            alpha_pow *= alpha;
        }

        // Built only now, and after releasing the table it replaces: the
        // iteration's peak is then below what the layers took at the start.
        for eq in eqs.iter_mut() {
            eq.k = (eq.n_vars + t).checked_sub(n_max);
            if let Some(k) = eq.k.filter(|k| *k > 0) {
                eq.bufs[0] = Vec::new();
                eq.bufs[0] = eq_table(&point[1..k]);
            }
        }

        // Sum of alpha^idx · claim over the instances that have no variable
        // left; in round j each of the t-1-j later variables doubles it.
        let mut done: F = active
            .iter()
            .filter(|a| a.k == 0)
            .map(|a| a.alpha_pow * a.claim)
            .sum();
        let mut rho = Vec::with_capacity(t);
        let mut rounds = Vec::with_capacity(t);
        // eq of the point and the challenges over the variables bound so
        // far: the same for every instance that is still live.
        let mut bound = F::one();
        for round in 0..t {
            let sums = sum_round(&active, &eqs, round, lambda);
            // A live instance's round polynomial is
            // `bound · eq(z, x) · h(x)` with `z = point[round]` and `h`
            // quadratic. The sums give `h(0)` and its leading coefficient
            // `c`; `h(1)` follows from `(1-z)·h(0) + z·h(1) = claim`.
            let z = point[round];
            let not_z = F::one() - z;
            let slope = z - not_z;
            let mut inner = [F::zero(); 3];
            // Per instance, the coefficients of `h`.
            let mut polys = vec![[F::zero(); 3]; active.len()];
            let live = active.iter().zip(&sums).zip(&mut polys);
            for ((a, sum), poly) in live.filter(|((a, _), _)| a.k > round) {
                let [h0, c] = *sum;
                let h1 = (a.claim - not_z * h0) * point_inv[round];
                let h2 = h1.double() - h0 + c.double();
                let h3 = h2.double() - h1 + c.double();
                *poly = [h0, h1 - h0 - c, c];
                for (sum, h) in inner.iter_mut().zip([h0, h2, h3]) {
                    *sum += a.weight * h;
                }
            }
            // eq(z, x) at 0, 2 and 3.
            let eq2 = z + slope;
            let lines = [not_z, eq2, eq2 + slope];
            let mut evals = [pow2[t - 1 - round] * done; 3];
            for ((eval, line), sum) in evals.iter_mut().zip(lines).zip(inner) {
                *eval += bound * line * sum;
            }
            tr.append_serializable_element(ROUND_LABEL, &evals)?;
            let r = tr.get_and_append_challenge(RHO_LABEL)?;

            bound *= not_z + r * slope;
            for (a, poly) in active.iter_mut().zip(&polys).filter(|(a, _)| a.k > round) {
                let [h0, b, c] = *poly;
                a.claim = h0 + r * (b + r * c);
                if a.k == round + 1 {
                    done += a.alpha_pow * bound * a.claim;
                }
            }
            fold_round(&mut active, &mut eqs, round, r);
            rho.push(r);
            rounds.push(evals);
        }

        // After its k folds an instance's tables are down to the two
        // children of one gate: the mask.
        let gates: Vec<[F; 4]> = active
            .iter()
            .map(|a| {
                let top = &a.state.bufs[if a.k == 0 { 0 } else { 2 - a.k % 2 }];
                let [q0, q1] = [top.q[0], top.q[1]];
                let [p0, p1] = if a.singles {
                    [F::one(); 2]
                } else {
                    [top.p[0], top.p[1]]
                };
                // The verifier's layer check, per instance and on the
                // prover's own values: it holds for any input, true
                // statement or not.
                debug_assert_eq!(a.claim, p0 * q1 + p1 * q0 + lambda * q0 * q1);
                [p0, p1, q0, q1]
            })
            .collect();
        let iteration_masks: Vec<Vec<F>> = active
            .iter()
            .zip(&gates)
            .map(|(a, gate)| gate[if a.singles { 2 } else { 0 }..].to_vec())
            .collect();
        tr.append_serializable_element(MASKS_LABEL, &iteration_masks)?;
        let mu = tr.get_and_append_challenge(MU_LABEL)?;

        for (a, [p0, p1, q0, q1]) in active.into_iter().zip(gates) {
            a.state.claim = [p0 + mu * (p1 - p0), q0 + mu * (q1 - q0)];
            // The layer just read and the larger scratch become the scratch
            // of the next iteration; the smaller scratch is released when
            // the next layer takes its slot.
            a.state.bufs.rotate_right(1);
        }
        for eq in eqs.iter_mut().filter(|eq| eq.k.is_some()) {
            eq.bufs.swap(0, 1);
        }
        point.clear();
        point.push(mu);
        point.extend(rho);
        round_polys.push(rounds);
        masks.push(iteration_masks);
    }

    let inputs = states.iter().map(|state| state.claim).collect();
    let proof = LogupGkrProof {
        roots: roots.clone(),
        round_polys,
        masks,
    };
    let claims = GkrClaims {
        point,
        roots,
        inputs,
    };
    Ok((proof, claims))
}
