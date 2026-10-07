//! Virtual-polynomial preprocessing for proof compilation: conversion to the
//! hyperplonk interface, linear-term dedup, and nv equalization.

use super::super::*;
use crate::arithmetic::mat_poly::{mle::MLEStorage, rows::add_scaled_product};
use std::collections::BinaryHeap;

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    // TODO: Is this only used to be compatible with the hyperplonk code?
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn to_hp_virtual_poly(&self, id: TrackerID) -> HPVirtualPolynomial<B::F> {
        let mat_poly = self.state.mv_pcs_substate.materialized_polys.get(&id);
        if let Some(poly) = mat_poly {
            return HPVirtualPolynomial::new_from_mle(poly, B::F::one());
        }

        let poly = self.state.virtual_polys.get(&id);
        if poly.is_none() {
            panic!("Unknown poly id: {:?}", id);
        }
        let poly = poly.unwrap(); // Invariant: contains only material PolyIDs
        if poly.is_empty() {
            return HPVirtualPolynomial::new(1);
        }
        // Use the tracker's registered nv: a bare-constant term has an empty
        // factor list (peeking would panic), and the registered value is what
        // `equalize_mat_poly_nv_to` scaled the sumcheck claim to expect — a
        // material nv bumped by an earlier bucket would no longer match.
        let nv = self.poly_nv(id);

        // Optimize away linear combinations of committed polynomials by
        // materializing them into fresh MLEs (no new commitments). Identical
        // linear combos are deduplicated so (a+b)*d + (a+b)*e becomes c*d + c*e.
        let (poly_terms, optimized_terms) = self.optimize_linear_terms(poly, nv);

        let mut arith_virt_poly: HPVirtualPolynomial<B::F> = HPVirtualPolynomial::new(nv);
        for (prod_coef, prod) in poly_terms.iter() {
            let prod_mle_list = prod
                .iter()
                .map(|poly_id| self.mat_mv_poly(*poly_id).unwrap().clone())
                .collect::<Vec<Arc<MLE<B::F>>>>();
            arith_virt_poly
                .add_mle_list(prod_mle_list, *prod_coef)
                .unwrap();
        }

        for (coef, mles) in optimized_terms {
            arith_virt_poly.add_mle_list(mles, coef).unwrap();
        }

        arith_virt_poly
    }

    /// Splits terms of `poly` into groups that agree in all factors but one,
    /// each to be folded into `(sum_i c_i·factor_i) · context`. Returns, per
    /// group, the shared context, the linear combination and the indices of
    /// its terms; a term is in at most one group.
    ///
    /// Which factor of a term is the odd one out is a choice. The groups are
    /// formed largest first, so a term goes where it shares its context with
    /// the most others: `eq·act·(sum_i w_i·col_i)` is one product whatever
    /// the ids of `act` and the `col_i` are. Among equally large groups the
    /// one that pulls out the smallest ids wins.
    #[allow(clippy::type_complexity)]
    fn linear_groups(
        &self,
        poly: &VirtualPoly<B::F>,
        nv: usize,
    ) -> Vec<(Vec<TrackerID>, Vec<(TrackerID, B::F)>, Vec<usize>)> {
        // The combination is materialized over `nv` variables from the
        // factors' evaluations. A lazy backing would pay, in that pass, the
        // 2^nv inversions it exists to avoid; the sumcheck streams it.
        let combinable = |id: TrackerID| {
            self.mat_mv_poly(id).is_some_and(|mle| {
                mle.num_vars() == nv
                    && !matches!(
                        mle.storage(),
                        MLEStorage::LazyInverseShifted { .. }
                            | MLEStorage::LazyInverseShiftedSum { .. }
                    )
            })
        };

        // context -> [(term, factor)], over every way to split a term.
        let mut candidates: BTreeMap<Vec<TrackerID>, Vec<(usize, TrackerID)>> = BTreeMap::new();
        for (idx, (_, prod)) in poly.iter().enumerate() {
            let mut sorted = prod.clone();
            sorted.sort();
            for (pos, factor) in sorted.iter().enumerate() {
                // Equal factors leave the same context behind.
                if (pos > 0 && sorted[pos - 1] == *factor) || !combinable(*factor) {
                    continue;
                }
                let mut context = sorted.clone();
                context.remove(pos);
                candidates.entry(context).or_default().push((idx, *factor));
            }
        }

        let mut queue: BinaryHeap<(usize, &Vec<TrackerID>)> = candidates
            .iter()
            .filter(|(_, terms)| terms.len() >= 2)
            .map(|(context, terms)| (terms.len(), context))
            .collect();
        let mut grouped = vec![false; poly.len()];
        let mut groups: BTreeMap<_, (Vec<(TrackerID, B::F)>, Vec<usize>)> = BTreeMap::new();
        while let Some((size, context)) = queue.pop() {
            let free: Vec<(usize, TrackerID)> = candidates[context]
                .iter()
                .copied()
                .filter(|(idx, _)| !grouped[*idx])
                .collect();
            if free.len() < size {
                // Some of its terms joined a larger group in the meantime.
                if free.len() >= 2 {
                    queue.push((free.len(), context));
                }
                continue;
            }

            let mut signature: BTreeMap<TrackerID, B::F> = BTreeMap::new();
            for (idx, factor) in &free {
                *signature.entry(*factor).or_insert_with(B::F::zero) += poly[*idx].0;
            }
            signature.retain(|_, c| !c.is_zero());
            // A single MLE gains nothing from being copied.
            if signature.len() <= 1 {
                continue;
            }

            let terms: Vec<usize> = free.iter().map(|(idx, _)| *idx).collect();
            for idx in &terms {
                grouped[*idx] = true;
            }
            groups.insert(context.clone(), (signature.into_iter().collect(), terms));
        }

        groups
            .into_iter()
            .map(|(context, (signature, terms))| (context, signature, terms))
            .collect()
    }

    /// Pulls out linear terms (single committed MLEs and constants) from a virtual
    /// polynomial and materializes them into fresh MLEs. Identical linear combos
    /// are deduplicated so (a+b)*d + (a+b)*e becomes c*d + c*e.
    ///
    /// This only changes how the prover writes the polynomial down: a folded
    /// product has as many factors as each of the terms it replaces, so the
    /// polynomial, its degree and every sumcheck message stay what they
    /// were.
    #[allow(clippy::type_complexity)]
    fn optimize_linear_terms(
        &self,
        poly: &VirtualPoly<B::F>,
        nv: usize,
    ) -> (
        Vec<(B::F, Vec<TrackerID>)>,
        Vec<(B::F, Vec<Arc<MLE<B::F>>>)>,
    ) {
        let mut constant = B::F::zero();
        let mut term_used = vec![false; poly.len()];
        let mut other_terms: Vec<(B::F, Vec<TrackerID>)> = Vec::new();
        let mut optimized_terms: Vec<(B::F, Vec<Arc<MLE<B::F>>>)> = Vec::new();

        for (idx, (coeff, prod)) in poly.iter().enumerate() {
            if prod.is_empty() {
                constant += *coeff;
                term_used[idx] = true;
            }
        }

        // Cache linear combos to deduplicate across different contexts.
        let mut linear_cache: Vec<(Vec<(TrackerID, B::F)>, Arc<MLE<B::F>>)> = Vec::new();

        for (context, signature, entries) in self.linear_groups(poly, nv) {
            // Reuse or build the linear combo MLE.
            let linear_mle =
                if let Some((_, mle)) = linear_cache.iter().find(|(sig, _)| *sig == signature) {
                    mle.clone()
                } else {
                    let mut evals = vec![B::F::zero(); 1 << nv];
                    for (id, coeff) in &signature {
                        let mle = self.mat_mv_poly(*id).unwrap();
                        add_scaled_product(&mut evals, *coeff, &[mle]);
                    }
                    let mle = Arc::new(MLE::from_evaluations_vec(nv, evals));
                    linear_cache.push((signature.clone(), mle.clone()));
                    mle
                };

            // Mark terms as used.
            for idx in entries {
                term_used[idx] = true;
            }

            // Build product: linear_mle * context_mles
            let mut mles: Vec<Arc<MLE<B::F>>> = Vec::with_capacity(1 + context.len());
            mles.push(linear_mle);
            for id in &context {
                mles.push(self.mat_mv_poly(*id).unwrap().clone());
            }
            optimized_terms.push((B::F::one(), mles));
        }

        // Add remaining unused terms as-is.
        for (idx, (coeff, prod)) in poly.iter().enumerate() {
            if !term_used[idx] {
                other_terms.push((*coeff, prod.clone()));
            }
        }

        // If a constant remains, store as a compact scalar MLE (inner nv=0).
        // The sumcheck prover detects mat_mle().num_vars == 0 and folds these
        // into the coefficient instead of iterating over evaluations.
        if !constant.is_zero() {
            let constant_mle = MLE::new(
                ark_poly::DenseMultilinearExtension::from_evaluations_vec(0, vec![constant]),
                (nv > 0).then_some(nv),
            );
            optimized_terms.push((B::F::one(), vec![Arc::new(constant_mle)]));
        }

        (other_terms, optimized_terms)
    }

    /// Lift every materialized poly with `num_vars < target_nv` to
    /// `target_nv` via a virtual override; wider polys are untouched.
    /// Sumcheck claims scale by `2^(target_nv - poly_nv)` (repetition
    /// multiplies the hypercube sum) and eval-claim points are only ever
    /// extended. Called once per bucket.
    #[instrument(level = "debug", skip(self))]
    pub(super) fn equalize_mat_poly_nv_to(&mut self, target_nv: usize) {
        for poly in self.state.mv_pcs_substate.materialized_polys.values_mut() {
            let old_nv = poly.num_vars();
            if old_nv < target_nv {
                // Zero-cost path: bump the virtual nv on the existing
                // storage (cyclic repetition happens on access), never
                // materializing compressed polys to a full Vec<F>.
                //
                // `Arc::make_mut`, not `get_mut`: keyed_sumcheck lazy
                // backings hold extra Arc refs to their source, on which
                // `get_mut` would panic. When shared, the lazy backing keeps
                // a pre-bump snapshot — fine, since lazy `lift(i)` cycles
                // modulo inner_len and produces the same values.
                let inner_poly = Arc::make_mut(poly);
                inner_poly.set_virtual_nv(target_nv);
            }
        }

        for claim in &mut self.state.mv_pcs_substate.sum_check_claims {
            let nv = self.state.num_vars[&claim.id()];
            if nv < target_nv {
                claim.set_claim(claim.claim() * B::F::from(1u64 << (target_nv - nv)));
            }
        }

        for claim in self.state.mv_pcs_substate.eval_claims.iter_mut() {
            if claim.point().len() < target_nv {
                let mut point = claim.point().clone();
                point.resize(target_nv, B::F::zero());
                claim.set_point(point);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DefaultSnarkBackend, arithmetic::virt_poly::hp_interface::HPVirtualPolynomial,
        piop::sum_check::SumCheck, setup::KeyGenerator, transcript::Tr,
    };
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    type B = DefaultSnarkBackend;
    type F = <B as SnarkBackend>::F;

    const NV: usize = 5;

    fn make_tracker() -> ProverTracker<B> {
        let (pk, _vk) = KeyGenerator::<B>::new()
            .with_num_mv_vars(10)
            .gen_keys()
            .unwrap();
        ProverTracker::new_from_pk(pk)
    }

    /// A column of small integers, which the tracker stores compressed.
    fn small_column(
        tracker: &mut ProverTracker<B>,
        nv: usize,
        seed: u64,
        modulus: u64,
    ) -> TrackerID {
        let evals = (0..1u64 << nv)
            .map(|i| F::from((i * 2654435761 + seed * 40503) % modulus))
            .collect();
        tracker.track_mat_mv_poly(MLE::from_evaluations_vec(nv, evals))
    }

    fn field_column(tracker: &mut ProverTracker<B>, nv: usize) -> TrackerID {
        let mut rng = test_rng();
        let evals = (0..1 << nv).map(|_| F::rand(&mut rng)).collect();
        tracker.track_mat_mv_poly(MLE::from_evaluations_vec(nv, evals))
    }

    /// `sum_j weights[j]·ids[j]`, built the way the lookup reduction builds
    /// the combination of a stack.
    fn weighted_sum(tracker: &mut ProverTracker<B>, ids: &[TrackerID], weights: &[F]) -> TrackerID {
        let mut acc = tracker.mul_scalar(ids[0], weights[0]);
        for (id, weight) in ids.iter().zip(weights).skip(1) {
            let term = tracker.mul_scalar(*id, *weight);
            acc = tracker.add_polys(acc, term);
        }
        acc
    }

    fn weights(n: usize) -> Vec<F> {
        let mut rng = test_rng();
        (0..n).map(|_| F::rand(&mut rng)).collect()
    }

    /// The polynomial as its terms spell it out, with nothing folded.
    fn spelled_out(tracker: &ProverTracker<B>, id: TrackerID, nv: usize) -> HPVirtualPolynomial<F> {
        let mut plain = HPVirtualPolynomial::new(nv);
        for (coeff, prod) in tracker.virt_poly(id).unwrap() {
            if prod.is_empty() {
                let constant = MLE::new(
                    ark_poly::DenseMultilinearExtension::from_evaluations_vec(0, vec![*coeff]),
                    Some(nv),
                );
                plain.add_mle_list([Arc::new(constant)], F::one()).unwrap();
            } else {
                let mles = prod
                    .iter()
                    .map(|factor| tracker.mat_mv_poly(*factor).unwrap().clone());
                plain.add_mle_list(mles, *coeff).unwrap();
            }
        }
        plain
    }

    /// Checks that the form the sumcheck gets for `id` is the polynomial its
    /// terms spell out, with the same shape and so the same proof, and
    /// returns that form.
    fn assert_folding_is_invisible(
        tracker: &ProverTracker<B>,
        id: TrackerID,
        nv: usize,
    ) -> HPVirtualPolynomial<F> {
        let folded = tracker.to_hp_virtual_poly(id);
        let plain = spelled_out(tracker, id, nv);
        assert_eq!(folded.aux_info, plain.aux_info);

        assert_eq!(
            folded.materialize().evaluations(),
            plain.materialize().evaluations()
        );
        let mut rng = test_rng();
        for _ in 0..4 {
            let point: Vec<F> = (0..nv).map(|_| F::rand(&mut rng)).collect();
            assert_eq!(
                folded.evaluate(&point).unwrap(),
                plain.evaluate(&point).unwrap()
            );
        }

        let mut transcript = Tr::<F>::new(b"folding");
        transcript.append_message(b"seed", b"fixed").unwrap();
        let folded_proof = SumCheck::prove(&folded, &mut transcript.clone()).unwrap();
        let plain_proof = SumCheck::prove(&plain, &mut transcript.clone()).unwrap();
        assert_eq!(folded_proof, plain_proof);
        folded
    }

    /// The claim a lookup reduction leaves on a stack of `chunk·activator`
    /// columns is one product, wherever the activator's id falls among the
    /// chunks'.
    #[test]
    fn columns_sharing_an_activator_fold_into_one_product_whatever_the_ids() {
        for activator_first in [true, false] {
            let mut tracker = make_tracker();
            let tracked_first = small_column(&mut tracker, NV, 1, 2);
            let chunks: Vec<TrackerID> = (0..5)
                .map(|j| small_column(&mut tracker, NV, 10 + j, 1 << 16))
                .collect();
            let tracked_last = small_column(&mut tracker, NV, 2, 2);
            let activator = if activator_first {
                tracked_first
            } else {
                tracked_last
            };
            let eq = field_column(&mut tracker, NV);

            let columns: Vec<TrackerID> = chunks
                .iter()
                .map(|chunk| tracker.mul_polys(*chunk, activator))
                .collect();
            let combination = weighted_sum(&mut tracker, &columns, &weights(columns.len()));
            let claimed = tracker.mul_polys(eq, combination);

            let folded = assert_folding_is_invisible(&tracker, claimed, NV);
            assert_eq!(folded.products.len(), 1);
            assert_eq!(folded.flattened_ml_extensions.len(), 3);
            assert_eq!(folded.aux_info.max_degree, 3);
        }
    }

    /// Two stacks with an activator each, next to everything a term can be
    /// that must be left alone or folded with care.
    #[test]
    fn folded_terms_are_the_same_polynomial_with_the_same_proof() {
        let mut tracker = make_tracker();
        let activators = [
            small_column(&mut tracker, NV, 1, 2),
            small_column(&mut tracker, NV, 2, 2),
        ];
        let chunks: Vec<TrackerID> = (0..7)
            .map(|j| small_column(&mut tracker, NV, 10 + j, 1 << 16))
            .collect();
        // Fewer variables than the claim: repeated along the others.
        let narrow = small_column(&mut tracker, NV - 2, 3, 200);
        let bytes = small_column(&mut tracker, NV, 4, 256);
        let wide = field_column(&mut tracker, NV);
        let eq = field_column(&mut tracker, NV);
        tracker.equalize_mat_poly_nv_to(NV);

        let mut columns: Vec<TrackerID> = chunks[..4]
            .iter()
            .map(|chunk| tracker.mul_polys(*chunk, activators[0]))
            .collect();
        columns.extend(
            chunks[4..]
                .iter()
                .map(|chunk| tracker.mul_polys(*chunk, activators[1])),
        );
        // A column of two terms over both activators, one without any, and
        // one that is narrower than its activator.
        let gated = tracker.mul_polys(bytes, activators[0]);
        let other = tracker.mul_polys(bytes, activators[1]);
        let other = tracker.mul_scalar(other, -F::from(3u64));
        columns.push(tracker.add_polys(gated, other));
        columns.push(wide);
        columns.push(tracker.mul_polys(narrow, activators[1]));
        let combination = weighted_sum(&mut tracker, &columns, &weights(columns.len()));
        let mut claimed = tracker.mul_polys(eq, combination);

        // A square, a term that shares nothing, a constant, and a pair that
        // cancels when folded.
        let square = tracker.mul_polys(wide, wide);
        let square = tracker.mul_polys(square, eq);
        claimed = tracker.add_polys(claimed, square);
        let lone = tracker.mul_polys(narrow, bytes);
        claimed = tracker.add_polys(claimed, lone);
        claimed = tracker.add_scalar(claimed, F::from(7u64));
        let pair = tracker.mul_polys(chunks[0], chunks[1]);
        claimed = tracker.add_polys(claimed, pair);
        let pair = tracker.mul_polys(chunks[0], chunks[1]);
        claimed = tracker.sub_polys(claimed, pair);

        let terms = tracker.virt_poly(claimed).unwrap().len();
        let folded = assert_folding_is_invisible(&tracker, claimed, NV);
        assert!(folded.products.len() < terms);
    }

    /// A term that could fold two ways goes with the larger group.
    #[test]
    fn a_term_folds_with_the_largest_group_it_fits() {
        let mut tracker = make_tracker();
        let a = small_column(&mut tracker, NV, 1, 1 << 16);
        let b = small_column(&mut tracker, NV, 2, 1 << 16);
        let x = small_column(&mut tracker, NV, 3, 1 << 16);
        let [y, z, w] = [4, 5, 6].map(|seed| small_column(&mut tracker, NV, seed, 1 << 16));

        // a·x·y + b·x·y + a·x·z + a·x·w: the first term shares `x·y` with
        // one term and `a·x` with two.
        let mut claimed = None;
        for (first, last) in [(a, y), (b, y), (a, z), (a, w)] {
            let term = tracker.mul_polys(first, x);
            let term = tracker.mul_polys(term, last);
            claimed = Some(match claimed {
                Some(sum) => tracker.add_polys(sum, term),
                None => term,
            });
        }

        let folded = assert_folding_is_invisible(&tracker, claimed.unwrap(), NV);
        // (y + z + w)·a·x and b·x·y.
        assert_eq!(folded.products.len(), 2);
    }

    /// A lazily inverted factor is never read out into a combination.
    #[test]
    fn a_lazy_factor_is_not_folded() {
        let mut tracker = make_tracker();
        let source = Arc::new(MLE::from_evaluations_vec(
            NV,
            (1..=1u64 << NV).map(F::from).collect(),
        ));
        let lazy = [5u64, 9].map(|shift| {
            tracker.track_mat_arc_mv_poly(Arc::new(MLE::from_lazy_inverse_shifted(
                source.clone(),
                -F::from(shift),
            )))
        });
        let eq = field_column(&mut tracker, NV);
        let first = tracker.mul_polys(lazy[0], eq);
        let second = tracker.mul_polys(lazy[1], eq);
        let claimed = tracker.add_polys(first, second);

        let folded = tracker.to_hp_virtual_poly(claimed);
        assert_eq!(folded.products.len(), 2);
        assert_eq!(folded.flattened_ml_extensions.len(), 3);
    }
}
