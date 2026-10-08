//! Reduction of keyed-sum relations to sumcheck and zerocheck claims through
//! LogUp with committed helpers.
//!
//! The relations and what each of their terms ranges over are those of
//! [`super::reduction`]; only the argument differs. A relation is reduced
//! under a `gamma` of its own, term by term:
//! 1. the prover commits to the helper `h = 1/(col - gamma)` of the term's
//!    column, on the column's hypercube. Two adjacent columns of one size
//!    that have no multiplicities share the helper
//!    `1/(a - gamma) + 1/(b - gamma)`;
//! 2. the prover sends the term's sum, `sum_x m(x)·h(x)` over the term's
//!    hypercube, and both sides bind it to the transcript;
//! 3. both sides claim that sum of `m·h`, and that the helper is what it
//!    should be on every row: `h·(col - gamma) = 1`, or for a shared one
//!    `h·(a - gamma)·(b - gamma) = (a - gamma) + (b - gamma)`.
//!
//! The verifier then compares the two sides of the relation on the sums it
//! was sent ([`check_relation_sums`]).
//!
//! The sums are sent before anything further is drawn, and their claims
//! are raw: the sumcheck is about the values the transcript holds. Were
//! they taken from the proof's claim map instead, which the transcript does
//! not bind, a prover could wait for the challenges that batch the
//! sumcheck claims and then pick sums that are wrong for single terms but
//! right in both the batch and the comparison of the sides.
//!
//! A constant column has no helper: the verifier inverts `col - gamma`
//! itself, and what is left of the term to prove is the sum of its
//! multiplicity, if it has one that is not constant too.
//!
//! As in [`super::reduction`], everything that touches the transcript or
//! pushes a claim is written once, over [`TrackerCore`], and the two sides
//! differ only in where a helper and a sum come from ([`Party`]). The same
//! condition on the statement applies: every column and multiplicity has to
//! be fixed before the reduction starts.

use ark_ff::{Field, One, Zero, batch_inversion};
use ark_poly::DenseMultilinearExtension;
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut};
use either::Either;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::reduction::{
    ColumnEvals, KeyedSumRelation, KeyedTerm, check_failed, invalid_parameters, resolve,
};
use crate::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::tracker::ProverTracker,
    tracker_core::TrackerCore,
    types::TrackerID,
    verifier::tracker::VerifierTracker,
};

/// A column or multiplicity with the size the tracker or the statement
/// gives it.
type Sized<F> = (Either<TrackerID, F>, usize);

/// One term of a side of a relation, or two that share a helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Term<F> {
    /// Two adjacent columns of `nv` variables each, neither with a
    /// multiplicity.
    Pair { cols: [TrackerID; 2], nv: usize },
    /// A column with its multiplicity, `None` standing for all ones.
    Single {
        col: Sized<F>,
        mult: Option<Sized<F>>,
    },
}

/// The terms of the `f` side and of the `g` side of a relation.
pub(super) type RelationPlan<F> = [Vec<Term<F>>; 2];

/// What the prover and the verifier do differently in a reduction.
pub(super) trait Party<T: TrackerCore> {
    /// The helper of `cols`, `sum_c 1/(c - gamma)` on their hypercube, as a
    /// tracked polynomial, together with the sum of `mult` times the helper
    /// over the larger of their hypercubes, of the helper alone without a
    /// `mult`. The prover commits to the one and sends the other; the
    /// verifier takes the proof's next commitment and its next sum.
    fn helper(
        &mut self,
        tracker: &mut T,
        cols: &[TrackerID],
        mult: Option<TrackerID>,
        gamma: T::F,
    ) -> SnarkResult<(TrackerID, T::F)>;

    /// The sum of `poly` over its hypercube: sent by the prover, the
    /// proof's next sum for the verifier.
    fn sum(&mut self, tracker: &mut T, poly: TrackerID) -> SnarkResult<T::F>;

    /// The error this party reports when the shared schedule cannot go on.
    fn reject(&self, reason: String) -> SnarkError;
}

/// `2^exponent` in the field. The exponents are sizes the statement names,
/// which no machine word has to hold a power of.
fn two_to_the<F: Field>(exponent: usize) -> F {
    F::from(2u64).pow([exponent as u64])
}

/// The terms of one side. Which columns share a helper follows from the
/// statement and the tracker's sizes alone, so both sides pair the same
/// ones: two adjacent tracked columns of one size, neither with a
/// multiplicity. A column is in at most one pair, the first it can be in.
fn plan_side<T: TrackerCore>(
    tracker: &T,
    cols: &[KeyedTerm<T::F>],
    mults: &[Option<KeyedTerm<T::F>>],
) -> Result<Vec<Term<T::F>>, String> {
    if cols.len() != mults.len() {
        return Err(format!(
            "keyed sum has {} columns but {} multiplicities",
            cols.len(),
            mults.len()
        ));
    }
    let mut entries = Vec::with_capacity(cols.len());
    for (col, mult) in cols.iter().zip(mults) {
        let col = resolve(tracker, col)?;
        let mult = mult.as_ref().map(|m| resolve(tracker, m)).transpose()?;
        entries.push((col, mult));
    }
    let unit_column = |(col, mult): &(Sized<T::F>, Option<Sized<T::F>>)| match (col, mult) {
        ((Either::Left(id), nv), None) => Some((*id, *nv)),
        _ => None,
    };
    let mut terms = Vec::with_capacity(entries.len());
    let mut at = 0;
    while at < entries.len() {
        let first = unit_column(&entries[at]);
        let second = entries.get(at + 1).and_then(unit_column);
        match (first, second) {
            (Some((first, nv)), Some((second, second_nv))) if nv == second_nv => {
                terms.push(Term::Pair {
                    cols: [first, second],
                    nv,
                });
                at += 2;
            }
            _ => {
                let (col, mult) = entries[at];
                terms.push(Term::Single { col, mult });
                at += 1;
            }
        }
    }
    Ok(terms)
}

/// The terms of every relation. Laid out before the first `gamma`, so that
/// a statement the reduction cannot carry out is refused with nothing sent.
pub(super) fn plan_relations<T: TrackerCore>(
    tracker: &T,
    relations: &[KeyedSumRelation<T::F>],
) -> Result<Vec<RelationPlan<T::F>>, String> {
    relations
        .iter()
        .map(|relation| {
            Ok([
                plan_side(tracker, &relation.fxs, &relation.mfxs)?,
                plan_side(tracker, &relation.gxs, &relation.mgxs)?,
            ])
        })
        .collect()
}

/// Takes the helper of `cols` and the sum that goes with it from `party`,
/// binds the sum and claims it. Returns both.
fn claim_helper<T: TrackerCore, P: Party<T>>(
    tracker: &mut T,
    party: &mut P,
    cols: &[TrackerID],
    nv: usize,
    mult: Option<TrackerID>,
    gamma: T::F,
) -> SnarkResult<(TrackerID, T::F)> {
    let (helper, sum) = party.helper(tracker, cols, mult, gamma)?;
    // The size of the helper is the prover's to choose with its
    // commitment. One of another size than its columns would be summed
    // over another hypercube than the term's.
    if tracker.poly_nv(helper) != nv {
        return Err(party.reject(format!(
            "LogUp helper has {} variables, its columns {nv}",
            tracker.poly_nv(helper)
        )));
    }
    tracker.append_field_element(b"keyed term sum", &sum)?;
    let summed = match mult {
        Some(mult) => tracker.mul_polys(helper, mult),
        None => helper,
    };
    tracker.push_raw_sumcheck_claim(summed, sum)?;
    Ok((helper, sum))
}

/// Carries out one term and returns its sum,
/// `sum_x mult(x)/(col(x) - gamma)` over the larger of the two hypercubes.
pub(super) fn reduce_term<T: TrackerCore, P: Party<T>>(
    tracker: &mut T,
    party: &mut P,
    term: &Term<T::F>,
    gamma: T::F,
) -> SnarkResult<T::F> {
    match *term {
        Term::Pair { cols, nv } => {
            let (helper, sum) = claim_helper(tracker, party, &cols, nv, None, gamma)?;
            // h·(a - gamma)·(b - gamma) - (a - gamma) - (b - gamma) = 0
            let [a, b] = cols.map(|col| tracker.add_scalar(col, -gamma));
            let product = tracker.mul_polys(helper, a);
            let product = tracker.mul_polys(product, b);
            let rest = tracker.sub_polys(product, a);
            let rest = tracker.sub_polys(rest, b);
            tracker.add_zerocheck_claim(rest)?;
            Ok(sum)
        }
        Term::Single {
            col: (Either::Left(col), nv),
            mult,
        } => {
            // A constant multiplicity is taken out of the sum, and the
            // rows it has beyond the column's repeat the column.
            let (summed_mult, scale) = match mult {
                None => (None, T::F::one()),
                Some((Either::Left(mult), _)) => (Some(mult), T::F::one()),
                Some((Either::Right(constant), mult_nv)) => (
                    None,
                    constant * two_to_the::<T::F>(mult_nv.saturating_sub(nv)),
                ),
            };
            let (helper, sum) = claim_helper(tracker, party, &[col], nv, summed_mult, gamma)?;
            // h·col - gamma·h - 1 = 0
            let product = tracker.mul_polys(col, helper);
            let shifted = tracker.mul_scalar(helper, gamma);
            let rest = tracker.sub_polys(product, shifted);
            let rest = tracker.add_scalar(rest, -T::F::one());
            tracker.add_zerocheck_claim(rest)?;
            Ok(scale * sum)
        }
        Term::Single {
            col: (Either::Right(constant), nv),
            mult,
        } => {
            let inverse = (constant - gamma).inverse().ok_or_else(|| {
                party.reject("gamma is the value of a constant column".to_string())
            })?;
            // The numerators add up to the column's rows, each as often as
            // the term's hypercube repeats it.
            let numerators = match mult {
                None => two_to_the::<T::F>(nv),
                Some((Either::Right(mult), mult_nv)) => mult * two_to_the::<T::F>(nv.max(mult_nv)),
                Some((Either::Left(mult), mult_nv)) => {
                    let sum = party.sum(tracker, mult)?;
                    tracker.append_field_element(b"keyed term sum", &sum)?;
                    tracker.push_raw_sumcheck_claim(mult, sum)?;
                    sum * two_to_the::<T::F>(nv.saturating_sub(mult_nv))
                }
            };
            Ok(numerators * inverse)
        }
    }
}

/// Reduces `relations` to sumcheck and zerocheck claims. Returns the sum of
/// the `f` side and of the `g` side of each; comparing them is left to the
/// verifier, so that a prover on a false statement still produces a proof
/// to reject.
///
/// A relation draws its `gamma` when its turn comes, after the helpers and
/// sums of the relations before it. That is as good as drawing all of them
/// first: the columns and multiplicities of every relation are fixed before
/// the reduction starts, and the helpers of a relation come after its
/// `gamma` in either order. A relation without entries has no column to
/// take a `gamma` off and draws none.
pub(super) fn reduce_keyed_sums<T: TrackerCore, P: Party<T>>(
    tracker: &mut T,
    party: &mut P,
    relations: &[KeyedSumRelation<T::F>],
) -> SnarkResult<Vec<[T::F; 2]>> {
    let plan = plan_relations(tracker, relations).map_err(|reason| party.reject(reason))?;
    let mut sums = Vec::with_capacity(plan.len());
    for sides in &plan {
        let mut relation_sums = [T::F::zero(); 2];
        if sides.iter().any(|side| !side.is_empty()) {
            let gamma = tracker.get_and_append_challenge(b"gamma")?;
            for (side, sum) in sides.iter().zip(&mut relation_sums) {
                for term in side {
                    *sum += reduce_term(tracker, party, term, gamma)?;
                }
            }
        }
        sums.push(relation_sums);
    }
    Ok(sums)
}

/// Checks that the two sides of every relation have the same sum. The sums
/// are those the prover sent, which the sumchecks tie to the helpers and
/// the zerochecks to the columns; here they only have to balance.
pub(super) fn check_relation_sums<F: Field>(sums: &[[F; 2]]) -> Result<(), String> {
    match sums.iter().position(|[f, g]| f != g) {
        Some(relation) => Err(format!(
            "the two sides of keyed sum {relation} have different sums"
        )),
        None => Ok(()),
    }
}

/// The prover's side of a reduction: it reads the columns, commits to their
/// helpers and sends the sums.
pub(super) struct ProvingParty<F> {
    pub evals: ColumnEvals<F>,
}

impl<F: Field> ProvingParty<F> {
    /// The `2^nv` evaluations of `id`. One the caller holds is handed over
    /// rather than copied: a column is read by one term as a rule, and the
    /// tracker has it for any other.
    fn take<B: SnarkBackend<F = F>>(
        &mut self,
        tracker: &mut ProverTracker<B>,
        id: TrackerID,
        nv: usize,
    ) -> SnarkResult<Vec<F>> {
        let evals = self
            .evals
            .remove(&id)
            .unwrap_or_else(|| tracker.evaluations(id));
        if u32::try_from(nv).ok().and_then(|nv| 1usize.checked_shl(nv)) != Some(evals.len()) {
            return Err(invalid_parameters(format!(
                "polynomial {id} has {} evaluations, expected 2^{nv}",
                evals.len()
            )));
        }
        Ok(evals)
    }

    /// Commits to the helper of `cols` and returns it with the sum
    /// [`Party::helper`] asks for, which is left for the caller to send.
    pub(super) fn commit_helper<B: SnarkBackend<F = F>>(
        &mut self,
        tracker: &mut ProverTracker<B>,
        cols: &[TrackerID],
        mult: Option<TrackerID>,
        gamma: F,
    ) -> SnarkResult<(TrackerID, F)> {
        let nv = tracker.poly_nv(cols[0]);
        // Each column is inverted where it was read, and a second one is
        // added into the first. The inversion keeps a table of running
        // products beside the one it inverts: two tables at the peak for
        // the helper of one column, three for a shared one.
        let mut helper: Vec<F> = Vec::new();
        for col in cols {
            let mut inverses = self.take(tracker, *col, nv)?;
            // A row equal to `gamma` has no inverse. The inversion would
            // leave a zero there, and the prover a helper that fails its
            // zerocheck in a proof that says nothing of it.
            let at_gamma: usize = cfg_iter_mut!(inverses)
                .map(|value| {
                    *value -= gamma;
                    usize::from(value.is_zero())
                })
                .sum();
            if at_gamma != 0 {
                return Err(invalid_parameters(format!(
                    "gamma is the value of {at_gamma} rows of polynomial {col}"
                )));
            }
            batch_inversion(&mut inverses);
            if helper.is_empty() {
                helper = inverses;
            } else {
                cfg_iter_mut!(helper)
                    .zip(inverses)
                    .for_each(|(sum, inverse)| *sum += inverse);
            }
        }
        let sum: F = match mult {
            None => cfg_iter!(helper).sum(),
            Some(mult) => {
                let mult_nv = tracker.poly_nv(mult);
                let mult = self.take(tracker, mult, mult_nv)?;
                let (helper_mask, mult_mask) = (helper.len() - 1, mult.len() - 1);
                cfg_into_iter!(0..helper.len().max(mult.len()))
                    .map(|row| helper[row & helper_mask] * mult[row & mult_mask])
                    .sum()
            }
        };

        let helper = MLE::from_evaluations_vec(nv, helper);
        let id = match tracker.track_and_commit_mat_mv_p(&helper, false)? {
            // A constant is sent as its value and tracked by id alone. The
            // claims need a polynomial under that id.
            Either::Right((id, constant)) => {
                let value = DenseMultilinearExtension::from_evaluations_vec(0, vec![constant]);
                tracker.register_mat_mv_poly(id, MLE::new(value, (nv > 0).then_some(nv)));
                id
            }
            Either::Left(id) => {
                drop(helper);
                // The committed table is not needed again as a table: the
                // sumcheck can read `1/(col - gamma)` off the columns the
                // tracker holds anyway. A virtual column has no table to
                // read it off, and its helper stays as it is.
                let sources: Option<Vec<_>> = cols
                    .iter()
                    .map(|col| tracker.mat_mv_poly(*col).cloned())
                    .collect();
                match sources.as_deref() {
                    Some([source]) => {
                        let lazy = MLE::from_lazy_inverse_shifted(source.clone(), gamma);
                        tracker.register_mat_mv_poly(id, lazy);
                    }
                    Some([first, second]) => {
                        let lazy = MLE::from_lazy_inverse_shifted_sum(
                            first.clone(),
                            second.clone(),
                            gamma,
                        );
                        tracker.register_mat_mv_poly(id, lazy);
                    }
                    _ => {}
                }
                id
            }
        };
        Ok((id, sum))
    }

    /// The sum of `poly` over its hypercube, for the caller to send.
    pub(super) fn sum_of<B: SnarkBackend<F = F>>(
        &mut self,
        tracker: &mut ProverTracker<B>,
        poly: TrackerID,
    ) -> SnarkResult<F> {
        let nv = tracker.poly_nv(poly);
        let evals = self.take(tracker, poly, nv)?;
        Ok(cfg_iter!(evals).sum())
    }
}

impl<B: SnarkBackend> Party<ProverTracker<B>> for ProvingParty<B::F> {
    fn helper(
        &mut self,
        tracker: &mut ProverTracker<B>,
        cols: &[TrackerID],
        mult: Option<TrackerID>,
        gamma: B::F,
    ) -> SnarkResult<(TrackerID, B::F)> {
        let (helper, sum) = self.commit_helper(tracker, cols, mult, gamma)?;
        tracker.send_logup_sum(sum);
        Ok((helper, sum))
    }

    fn sum(&mut self, tracker: &mut ProverTracker<B>, poly: TrackerID) -> SnarkResult<B::F> {
        let sum = self.sum_of(tracker, poly)?;
        tracker.send_logup_sum(sum);
        Ok(sum)
    }

    fn reject(&self, reason: String) -> SnarkError {
        invalid_parameters(reason)
    }
}

/// The verifier's side of a reduction: it takes the helpers and the sums
/// off the proof, in the order the prover produced them.
pub(super) struct VerifyingParty;

impl<B: SnarkBackend> Party<VerifierTracker<B>> for VerifyingParty {
    fn helper(
        &mut self,
        tracker: &mut VerifierTracker<B>,
        _cols: &[TrackerID],
        _mult: Option<TrackerID>,
        _gamma: B::F,
    ) -> SnarkResult<(TrackerID, B::F)> {
        let next = tracker.peek_next_id();
        let (_, helper) = tracker.track_mv_com_by_id(next)?;
        Ok((helper, tracker.next_logup_sum()?))
    }

    fn sum(&mut self, tracker: &mut VerifierTracker<B>, _poly: TrackerID) -> SnarkResult<B::F> {
        tracker.next_logup_sum()
    }

    fn reject(&self, reason: String) -> SnarkError {
        check_failed(reason)
    }
}
