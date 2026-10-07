//! Reduction of keyed-sum relations to sumcheck claims through LogUp-GKR.
//!
//! A relation `(fxs, mfxs, gxs, mgxs)` asserts
//! `sum_i sum_x mf_i(x)/(f_i(x) - gamma) == sum_j sum_x mg_j(x)/(g_j(x) - gamma)`
//! for a random `gamma`. Each term runs over its own hypercube of
//! `claim_nv = max(nv_col, nv_mult)` variables, the smaller of the two
//! repeated cyclically, and a missing multiplicity is 1.
//!
//! Several relations are reduced together under one `gamma`:
//! 1. the entries are laid out as GKR instances ([`plan_instances`]);
//! 2. the instances are proved in one or more GKR runs ([`gkr_runs`]), each
//!    of which ends in an evaluation point and, per instance, the values of
//!    its numerator and denominator MLEs there;
//! 3. every such value is turned into a sumcheck claim on the polynomials
//!    the statement names ([`push_input_claims`]), which is what ties the
//!    GKR to them;
//! 4. after the last run, the verifier compares the two sides of every
//!    relation on the roots, wherever in the runs its instances fell.
//!
//! Everything that consumes a tracker id, touches the transcript or pushes
//! a claim is written once, over [`TrackerCore`]; the two sides differ only
//! in how a run is carried out ([`Party`]).
//!
//! Soundness needs every column and multiplicity to be fixed before `gamma`:
//! each committed leaf must already be in the transcript (a commitment or
//! constant of this proof) or be an external commitment the caller has
//! bound to the statement, and uncommitted leaves must be computable by the
//! verifier.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use ark_ff::Field;
use ark_std::{cfg_into_iter, cfg_iter};
use either::Either;
use indexmap::IndexMap;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    piop::{
        errors::PolyIOPErrors,
        logup_gkr::{FractionInstance, GkrClaims, GkrShape, MAX_GKR_VARS, Numerator},
    },
    prover::{ArgProver, tracker::ProverTracker},
    tracker_core::TrackerCore,
    types::TrackerID,
    verifier::{ArgVerifier, errors::VerifierError, tracker::VerifierTracker},
};

/// A column or multiplicity of a keyed sum, as the statement names it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum KeyedTerm<F> {
    /// A tracked polynomial. Its size is the one the tracker holds for the
    /// id: a handle's own log size can differ between the two sides.
    Poly(TrackerID),
    /// The same value in each of `2^nv` rows.
    Constant { value: F, nv: usize },
}

/// One keyed-sum relation; `mfxs[i]` and `mgxs[i]` are the multiplicities of
/// `fxs[i]` and `gxs[i]`, `None` standing for all ones.
#[derive(Clone, Debug)]
pub(crate) struct KeyedSumRelation<F> {
    pub fxs: Vec<KeyedTerm<F>>,
    pub mfxs: Vec<Option<KeyedTerm<F>>>,
    pub gxs: Vec<KeyedTerm<F>>,
    pub mgxs: Vec<Option<KeyedTerm<F>>>,
}

/// Evaluations the caller already holds, by tracker id, so that the prover
/// does not materialise a column a second time.
pub(crate) type ColumnEvals<F> = BTreeMap<TrackerID, Vec<F>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Side {
    F,
    G,
}

/// The columns, or the multiplicities, of one instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Operand<F> {
    /// Checked in the clear against the GKR's claim; never a tracker claim.
    Constant(F),
    /// `2^stack_log` polynomials of `nv` variables each.
    Polys { ids: Vec<TrackerID>, nv: usize },
}

impl<F> Operand<F> {
    fn ids(&self) -> &[TrackerID] {
        match self {
            Operand::Constant(_) => &[],
            Operand::Polys { ids, .. } => ids,
        }
    }
}

/// One GKR instance and the statement entries it stands for.
///
/// The instance has `claim_nv + stack_log` variables. Entry `i` of the stack
/// occupies the rows `i·2^claim_nv + x`: the row variables are the low ones
/// and the entry index is the high ones, so the instance's MLE at a point is
/// the entries' MLEs at its low part, weighted by `eq(high part, i)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InstancePlan<F> {
    pub relation: usize,
    pub side: Side,
    pub claim_nv: usize,
    pub stack_log: usize,
    pub cols: Operand<F>,
    /// `None` when every numerator is 1. This follows the statement alone,
    /// never the values: a multiplicity that happens to be all ones is still
    /// an operand with a claim.
    pub mults: Option<Operand<F>>,
}

impl<F> InstancePlan<F> {
    pub(super) fn n_vars(&self) -> usize {
        self.claim_nv + self.stack_log
    }

    pub(super) fn shape(&self) -> GkrShape {
        GkrShape {
            n_vars: self.n_vars(),
            numerator_is_one: self.mults.is_none(),
        }
    }

    /// What a GKR run holds for this instance, in the unit of
    /// [`crate::types::SharedArgConfig::logup_gkr_run_budget`]. Saturates,
    /// which only happens far above the sizes either side accepts.
    fn weighted_size(&self) -> u128 {
        let per_fraction: u128 = if self.mults.is_none() { 3 } else { 4 };
        u32::try_from(self.n_vars())
            .ok()
            .and_then(|n_vars| 1u128.checked_shl(n_vars))
            .map_or(u128::MAX, |rows| rows.saturating_mul(per_fraction))
    }

    fn poly_ids(&self) -> impl Iterator<Item = TrackerID> + '_ {
        let mults = self.mults.as_ref().map_or(&[][..], Operand::ids);
        self.cols.ids().iter().chain(mults).copied()
    }
}

/// What the prover and the verifier do differently in a reduction.
pub(super) trait Party<T: TrackerCore> {
    /// Carry out one GKR run on `plan[run]` and return its claims. `plan` is
    /// the whole batch, for a party that wants to look ahead.
    fn run(
        &mut self,
        tracker: &mut T,
        plan: &[InstancePlan<T::F>],
        run: Range<usize>,
        gamma: T::F,
    ) -> SnarkResult<GkrClaims<T::F>>;

    /// The error this party reports when the shared schedule cannot go on.
    fn reject(&self, reason: String) -> SnarkError;
}

/// A reduction's instances with the root fraction `(P, Q)` of each.
pub(super) struct Reduction<F> {
    pub plan: Vec<InstancePlan<F>>,
    pub roots: Vec<[F; 2]>,
}

/// The size the tracker holds for `id`. Unknown ids are refused here because
/// the tracker algebra below panics on them.
fn tracked_nv<T: TrackerCore>(tracker: &T, id: TrackerID) -> Result<usize, String> {
    if tracker.is_material(id) || tracker.virtual_poly(id).is_some() {
        Ok(tracker.poly_nv(id))
    } else {
        Err(format!("keyed sum names untracked polynomial {id}"))
    }
}

fn resolve<T: TrackerCore>(
    tracker: &T,
    term: &KeyedTerm<T::F>,
) -> Result<(Either<TrackerID, T::F>, usize), String> {
    Ok(match *term {
        KeyedTerm::Poly(id) => (Either::Left(id), tracked_nv(tracker, id)?),
        KeyedTerm::Constant { value, nv } => (Either::Right(value), nv),
    })
}

fn standalone_operand<F>(term: Either<TrackerID, F>, nv: usize) -> Operand<F> {
    match term {
        Either::Left(id) => Operand::Polys { ids: vec![id], nv },
        Either::Right(value) => Operand::Constant(value),
    }
}

/// Lays one side of a relation out as instances, appended to `plan`.
///
/// An entry with a constant column or multiplicity is an instance of its
/// own. The others are grouped by `(nv_col, nv_mult)` and each group is cut
/// into stacks of `2^s` entries, largest first, by the binary digits of its
/// size: one instance per stack, so a group of `S` entries costs
/// `popcount(S)` instances instead of `S`.
///
/// Instances come out in the order of the entries, a group at the position
/// of its first entry.
fn plan_side<T: TrackerCore>(
    tracker: &T,
    relation: usize,
    side: Side,
    cols: &[KeyedTerm<T::F>],
    mults: &[Option<KeyedTerm<T::F>>],
    plan: &mut Vec<InstancePlan<T::F>>,
) -> Result<(), String> {
    if cols.len() != mults.len() {
        return Err(format!(
            "keyed sum has {} columns but {} multiplicities",
            cols.len(),
            mults.len()
        ));
    }

    type Signature = (usize, Option<usize>);
    enum Slot<F> {
        Standalone(InstancePlan<F>),
        Group(Signature),
    }
    let mut slots = Vec::new();
    let mut groups: IndexMap<Signature, (Vec<TrackerID>, Vec<TrackerID>)> = IndexMap::new();
    for (col, mult) in cols.iter().zip(mults) {
        let (col, nv_col) = resolve(tracker, col)?;
        let mult = mult.as_ref().map(|m| resolve(tracker, m)).transpose()?;
        let nv_mult = mult.map(|(_, nv)| nv);
        let stacked = match (col, mult) {
            (Either::Left(col), None) => Some((col, None)),
            (Either::Left(col), Some((Either::Left(mult), _))) => Some((col, Some(mult))),
            _ => None,
        };
        match stacked {
            Some((col, mult)) => {
                let signature = (nv_col, nv_mult);
                if !groups.contains_key(&signature) {
                    slots.push(Slot::Group(signature));
                }
                let (group_cols, group_mults) = groups.entry(signature).or_default();
                group_cols.push(col);
                group_mults.extend(mult);
            }
            None => slots.push(Slot::Standalone(InstancePlan {
                relation,
                side,
                claim_nv: nv_col.max(nv_mult.unwrap_or(0)),
                stack_log: 0,
                cols: standalone_operand(col, nv_col),
                mults: mult.map(|(mult, nv)| standalone_operand(mult, nv)),
            })),
        }
    }

    for slot in slots {
        let (nv_col, nv_mult) = match slot {
            Slot::Standalone(instance) => {
                plan.push(instance);
                continue;
            }
            Slot::Group(signature) => signature,
        };
        let (group_cols, group_mults) = &groups[&(nv_col, nv_mult)];
        let mut start = 0;
        for stack_log in (0..usize::BITS as usize).rev() {
            let size = 1usize << stack_log;
            if group_cols.len() & size == 0 {
                continue;
            }
            let stack = start..start + size;
            start += size;
            plan.push(InstancePlan {
                relation,
                side,
                claim_nv: nv_col.max(nv_mult.unwrap_or(0)),
                stack_log,
                cols: Operand::Polys {
                    ids: group_cols[stack.clone()].to_vec(),
                    nv: nv_col,
                },
                mults: nv_mult.map(|nv| Operand::Polys {
                    ids: group_mults[stack].to_vec(),
                    nv,
                }),
            });
        }
    }
    Ok(())
}

/// The instances of a batch of relations: relations in order, the `f` side
/// of each before its `g` side. A function of the statement and of the
/// tracker's sizes only, so both sides arrive at the same list.
pub(super) fn plan_instances<T: TrackerCore>(
    tracker: &T,
    relations: &[KeyedSumRelation<T::F>],
) -> Result<Vec<InstancePlan<T::F>>, String> {
    let mut plan = Vec::new();
    for (index, relation) in relations.iter().enumerate() {
        let sides = [
            (Side::F, &relation.fxs, &relation.mfxs),
            (Side::G, &relation.gxs, &relation.mgxs),
        ];
        for (side, cols, mults) in sides {
            plan_side(tracker, index, side, cols, mults, &mut plan)?;
        }
    }
    Ok(plan)
}

/// Cuts a batch into consecutive GKR runs of at most `budget` each, so that
/// the prover never holds more than one run's layers. Instances are taken in
/// order and a run is closed when the next instance would not fit; an
/// instance above the budget is a run of its own.
///
/// The cut depends on the plan and the shared configuration only, so both
/// sides arrive at the same one. Should they not, the first run that differs
/// has a different number of instances on the two sides, which the GKR
/// verifier rejects.
fn gkr_runs<F>(plan: &[InstancePlan<F>], budget: usize) -> Vec<Range<usize>> {
    let budget = budget as u128;
    let mut runs = Vec::new();
    let mut start = 0;
    let mut size = 0u128;
    for (index, instance) in plan.iter().enumerate() {
        let instance_size = instance.weighted_size();
        if index > start && size.saturating_add(instance_size) > budget {
            runs.push(start..index);
            start = index;
            size = 0;
        }
        size = size.saturating_add(instance_size);
    }
    if start < plan.len() {
        runs.push(start..plan.len());
    }
    runs
}

/// `eq(point, i)` for every `i`, variable 0 being the lowest bit of `i`.
fn selector_weights<F: Field>(point: &[F]) -> Vec<F> {
    let mut weights = vec![F::one()];
    for coordinate in point {
        let low = weights.iter().map(|w| *w * (F::one() - coordinate));
        let high = weights.iter().map(|w| *w * coordinate);
        weights = low.chain(high).collect();
    }
    weights
}

/// `sum_i weights[i]·ids[i]` as one tracked polynomial, built left to right.
/// A single polynomial has weight 1 and is used as it is.
fn weighted_sum<T: TrackerCore>(tracker: &mut T, ids: &[TrackerID], weights: &[T::F]) -> TrackerID {
    if let [id] = ids {
        return *id;
    }
    let mut terms = ids.iter().zip(weights);
    let (first, weight) = terms.next().expect("a stack holds at least one entry");
    let mut acc = tracker.mul_scalar(*first, *weight);
    for (id, weight) in terms {
        let term = tracker.mul_scalar(*id, *weight);
        acc = tracker.add_polys(acc, term);
    }
    acc
}

/// Discharges the GKR's claim `value` on one operand of an instance.
fn push_operand_claim<T: TrackerCore, P: Party<T>>(
    tracker: &mut T,
    party: &P,
    eqs: &BTreeMap<usize, TrackerID>,
    operand: &Operand<T::F>,
    weights: &[T::F],
    value: T::F,
) -> SnarkResult<()> {
    let (ids, nv) = match operand {
        Operand::Constant(constant) if *constant == value => return Ok(()),
        Operand::Constant(_) => {
            return Err(
                party.reject("LogUp-GKR claim on a constant is not the constant".to_string())
            );
        }
        Operand::Polys { ids, nv } => (ids, *nv),
    };
    let acc = weighted_sum(tracker, ids, weights);
    // The MLE of a table at a point is the sum of the table against `eq`
    // of the point. A polynomial without variables is its own evaluation.
    let claimed = match eqs.get(&nv) {
        Some(eq) => tracker.mul_polys(*eq, acc),
        None => acc,
    };
    // The claim is over the hypercube of the tracker's size for `claimed`;
    // were that not `nv`, it would bind a different statement than the
    // instance the GKR ran on.
    if tracker.poly_nv(claimed) != nv {
        return Err(party.reject(format!(
            "LogUp-GKR input claim spans {} variables, its instance {nv}",
            tracker.poly_nv(claimed)
        )));
    }
    tracker.push_raw_sumcheck_claim(claimed, value)
}

/// Turns the claims of one GKR run into sumcheck claims on the statement's
/// polynomials. This is the canonical schedule: prover and verifier must
/// make the same tracker calls in the same order, so they both make them
/// here.
///
/// First one `eq(point[..nv], ·)` per distinct size `nv > 0` among the
/// run's polynomials, ascending. Then, instance by instance, the column
/// claim `sum_x eq(x)·(sum_i w_i·col_i(x)) = Q + gamma` followed, unless the
/// numerators are 1, by the multiplicity claim
/// `sum_x eq(x)·(sum_i w_i·m_i(x)) = P`, where `(P, Q)` are the run's input
/// claims and `w_i = eq(point[claim_nv..], i)` selects entry `i` of a stack.
///
/// The claims are raw: their sums are fixed here, on both sides, and are
/// never read from the proof.
pub(super) fn push_input_claims<T: TrackerCore, P: Party<T>>(
    tracker: &mut T,
    party: &P,
    instances: &[InstancePlan<T::F>],
    gamma: T::F,
    claims: &GkrClaims<T::F>,
) -> SnarkResult<()> {
    let widest = instances.iter().map(InstancePlan::n_vars).max();
    if claims.inputs.len() != instances.len() || Some(claims.point.len()) != widest {
        return Err(party.reject("LogUp-GKR claims do not match their instances".to_string()));
    }
    let point = &claims.point;

    let sizes: BTreeSet<usize> = instances
        .iter()
        .flat_map(|instance| std::iter::once(&instance.cols).chain(&instance.mults))
        .filter_map(|operand| match operand {
            Operand::Polys { nv, .. } if *nv > 0 => Some(*nv),
            _ => None,
        })
        .collect();
    let mut eqs = BTreeMap::new();
    for nv in sizes {
        eqs.insert(nv, tracker.track_eq_x_r(&point[..nv], nv)?);
    }

    for (instance, [numerator, denominator]) in instances.iter().zip(&claims.inputs) {
        let weights = selector_weights(&point[instance.claim_nv..instance.n_vars()]);
        // The denominators are `col - gamma`.
        let column = *denominator + gamma;
        push_operand_claim(tracker, party, &eqs, &instance.cols, &weights, column)?;
        if let Some(mults) = &instance.mults {
            push_operand_claim(tracker, party, &eqs, mults, &weights, *numerator)?;
        }
    }
    Ok(())
}

/// Reduces `relations` to sumcheck claims under one `gamma`. Returns the
/// instances with their roots; comparing those is left to the verifier, so
/// that a prover on a false statement still produces a proof to reject.
pub(super) fn reduce_keyed_sums<T: TrackerCore, P: Party<T>>(
    tracker: &mut T,
    party: &mut P,
    relations: &[KeyedSumRelation<T::F>],
) -> SnarkResult<Reduction<T::F>> {
    let plan = plan_instances(tracker, relations).map_err(|reason| party.reject(reason))?;
    let mut roots = Vec::with_capacity(plan.len());
    if plan.is_empty() {
        return Ok(Reduction { plan, roots });
    }
    let gamma = tracker.get_and_append_challenge(b"gamma")?;
    let budget = tracker.config().logup_gkr_run_budget;
    for run in gkr_runs(&plan, budget) {
        let claims = party.run(tracker, &plan, run.clone(), gamma)?;
        if claims.roots.len() != run.len() {
            return Err(party.reject("LogUp-GKR roots do not match their instances".to_string()));
        }
        push_input_claims(tracker, party, &plan[run], gamma, &claims)?;
        roots.extend(claims.roots);
    }
    Ok(Reduction { plan, roots })
}

/// Checks `sum_f P/Q == sum_g P/Q` for every relation. The sums are kept as
/// fractions and compared by cross-multiplication.
fn check_relation_sums<F: Field>(
    reduction: &Reduction<F>,
    n_relations: usize,
) -> Result<(), String> {
    let mut sums = vec![[(F::zero(), F::one()); 2]; n_relations];
    for (instance, [p, q]) in reduction.plan.iter().zip(&reduction.roots) {
        // A zero denominator would make both products below vanish.
        if q.is_zero() {
            return Err("LogUp-GKR root has a zero denominator".to_string());
        }
        let (num, den) = &mut sums[instance.relation][instance.side as usize];
        *num = *num * q + *p * *den;
        *den *= q;
    }
    for (relation, [(f_num, f_den), (g_num, g_den)]) in sums.into_iter().enumerate() {
        if f_num * g_den != g_num * f_den {
            return Err(format!(
                "the two sides of keyed sum {relation} have different sums"
            ));
        }
    }
    Ok(())
}

/// The prover's side of a reduction: it reads the columns and proves.
pub(super) struct ProvingParty<F> {
    pub evals: ColumnEvals<F>,
}

impl<F: Field> ProvingParty<F> {
    /// The instances of `plan[run]` with `gamma` subtracted from the
    /// columns. Reads every column once, however often it is used.
    pub(super) fn instances<B: SnarkBackend<F = F>>(
        &mut self,
        tracker: &mut ProverTracker<B>,
        plan: &[InstancePlan<F>],
        run: Range<usize>,
        gamma: F,
    ) -> SnarkResult<Vec<FractionInstance<F>>> {
        for instance in &plan[run.clone()] {
            if instance.n_vars() > MAX_GKR_VARS {
                return Err(invalid_parameters(format!(
                    "LogUp-GKR instance of {} variables is too large",
                    instance.n_vars()
                )));
            }
            for operand in std::iter::once(&instance.cols).chain(&instance.mults) {
                let Operand::Polys { ids, nv } = operand else {
                    continue;
                };
                for id in ids {
                    let evals = self
                        .evals
                        .entry(*id)
                        .or_insert_with(|| tracker.evaluations(*id));
                    if evals.len() != 1 << nv {
                        return Err(invalid_parameters(format!(
                            "polynomial {id} has {} evaluations, expected 2^{nv}",
                            evals.len()
                        )));
                    }
                }
            }
        }

        let evals = &self.evals;
        let instances = cfg_iter!(plan[run.clone()])
            .map(|instance| {
                let rows = 1usize << instance.n_vars();
                let table = |operand: &Operand<F>, shift: F| match operand {
                    Operand::Constant(value) => vec![*value - shift; rows],
                    Operand::Polys { ids, nv } => {
                        let entries: Vec<&[F]> = ids.iter().map(|id| &evals[id][..]).collect();
                        let row_mask = (1usize << nv) - 1;
                        cfg_into_iter!(0..rows)
                            .map(|j| entries[j >> instance.claim_nv][j & row_mask] - shift)
                            .collect()
                    }
                };
                FractionInstance {
                    num: match &instance.mults {
                        None => Numerator::One,
                        Some(mults) => Numerator::Values(table(mults, F::zero())),
                    },
                    den: table(&instance.cols, gamma),
                }
            })
            .collect();

        // The instances hold their own copies; keep only what a later run
        // will read.
        let later: BTreeSet<TrackerID> = plan[run.end..]
            .iter()
            .flat_map(InstancePlan::poly_ids)
            .collect();
        self.evals.retain(|id, _| later.contains(id));
        Ok(instances)
    }
}

fn invalid_parameters(reason: String) -> SnarkError {
    SnarkError::from(PolyIOPErrors::InvalidParameters(reason))
}

impl<B: SnarkBackend> Party<ProverTracker<B>> for ProvingParty<B::F> {
    fn run(
        &mut self,
        tracker: &mut ProverTracker<B>,
        plan: &[InstancePlan<B::F>],
        run: Range<usize>,
        gamma: B::F,
    ) -> SnarkResult<GkrClaims<B::F>> {
        let instances = self.instances(tracker, plan, run, gamma)?;
        tracker.prove_logup_gkr(instances)
    }

    fn reject(&self, reason: String) -> SnarkError {
        invalid_parameters(reason)
    }
}

/// The verifier's side of a reduction: it checks the proof's next subproof.
pub(super) struct VerifyingParty;

impl VerifyingParty {
    fn check_failed(reason: String) -> SnarkError {
        SnarkError::VerifierError(VerifierError::VerifierCheckFailed(reason))
    }
}

impl<B: SnarkBackend> Party<VerifierTracker<B>> for VerifyingParty {
    fn run(
        &mut self,
        tracker: &mut VerifierTracker<B>,
        plan: &[InstancePlan<B::F>],
        run: Range<usize>,
        _gamma: B::F,
    ) -> SnarkResult<GkrClaims<B::F>> {
        let shape: Vec<GkrShape> = plan[run].iter().map(InstancePlan::shape).collect();
        tracker.verify_logup_gkr(&shape)
    }

    fn reject(&self, reason: String) -> SnarkError {
        Self::check_failed(reason)
    }
}

/// Proves `relations` in one batch. `evals` may hold the evaluations of any
/// of their polynomials; the rest is read from the tracker.
pub(crate) fn prove_keyed_sums<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    relations: &[KeyedSumRelation<B::F>],
    evals: ColumnEvals<B::F>,
) -> SnarkResult<()> {
    let tracker = prover.tracker();
    let mut tracker = tracker.borrow_mut();
    reduce_keyed_sums(&mut *tracker, &mut ProvingParty { evals }, relations)?;
    Ok(())
}

/// Verifies `relations` in one batch, mirroring [`prove_keyed_sums`].
pub(crate) fn verify_keyed_sums<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    relations: &[KeyedSumRelation<B::F>],
) -> SnarkResult<()> {
    let tracker = verifier.tracker();
    let mut tracker = tracker.borrow_mut();
    let checked =
        reduce_keyed_sums(&mut *tracker, &mut VerifyingParty, relations).and_then(|reduction| {
            check_relation_sums(&reduction, relations.len()).map_err(VerifyingParty::check_failed)
        });
    if checked.is_err() {
        // The roots and the constants are compared here and nowhere else.
        // The claims pushed up to the failure can all be true, and the
        // subproofs are consumed, so a verifier that went on would accept.
        tracker.reject();
    }
    checked
}
