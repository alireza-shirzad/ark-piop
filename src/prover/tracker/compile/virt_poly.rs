//! Virtual-polynomial preprocessing for proof compilation: conversion to the
//! hyperplonk interface, linear-term dedup, and nv equalization.

use super::super::*;

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
        // Use the tracker's registered nv rather than peeking at the first
        // factor: with the empty-product convention for bare constants
        // (see `add_scalar`), a term may have an empty factor list and
        // `poly[0].1[0]` would panic.
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

    /// Pulls out linear terms (single committed MLEs and constants) from a virtual
    /// polynomial and materializes them into fresh MLEs. Identical linear combos
    /// are deduplicated so (a+b)*d + (a+b)*e becomes c*d + c*e.
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

        // context -> [(term_idx, factor_id, coeff)]
        // We pick a single, deterministic split per term to avoid double counting.
        let mut context_map: BTreeMap<Vec<TrackerID>, Vec<(usize, TrackerID, B::F)>> =
            BTreeMap::new();

        for (idx, (coeff, prod)) in poly.iter().enumerate() {
            if prod.is_empty() {
                constant += *coeff;
                term_used[idx] = true;
                continue;
            }

            let mut sorted_prod = prod.clone();
            sorted_prod.sort();

            // Deterministically choose the linear factor as the smallest id.
            let factor = sorted_prod[0];
            let context = sorted_prod[1..].to_vec();

            context_map
                .entry(context)
                .or_default()
                .push((idx, factor, *coeff));
        }

        // Cache linear combos to deduplicate across different contexts.
        let mut linear_cache: Vec<(Vec<(TrackerID, B::F)>, Arc<MLE<B::F>>)> = Vec::new();

        for (context, entries) in context_map.into_iter() {
            let active_entries: Vec<(usize, TrackerID, B::F)> = entries
                .into_iter()
                .filter(|(idx, _, _)| !term_used[*idx])
                .collect();
            if active_entries.len() < 2 {
                continue;
            }

            // Build linear combo signature for this context.
            let mut signature_map: BTreeMap<TrackerID, B::F> = BTreeMap::new();
            for (_, factor, coeff) in &active_entries {
                *signature_map.entry(*factor).or_insert_with(B::F::zero) += *coeff;
            }
            signature_map.retain(|_, c| !c.is_zero());
            // Skip single-MLE linear terms (a) or degenerate combos.
            if signature_map.len() <= 1 {
                continue;
            }

            // Ensure all factors have matching nv.
            if signature_map.iter().any(|(id, _)| {
                self.mat_mv_poly(*id)
                    .map(|mle| mle.num_vars() != nv)
                    .unwrap_or(true)
            }) {
                continue;
            }

            let signature: Vec<(TrackerID, B::F)> = signature_map.into_iter().collect();

            // Reuse or build the linear combo MLE.
            let linear_mle =
                if let Some((_, mle)) = linear_cache.iter().find(|(sig, _)| *sig == signature) {
                    mle.clone()
                } else {
                    let mut evals = vec![B::F::zero(); 1 << nv];
                    for (id, coeff) in &signature {
                        let mle = self.mat_mv_poly(*id).unwrap();
                        cfg_iter_mut!(evals)
                            .zip(mle.evaluations())
                            .for_each(|(acc, v)| *acc += *coeff * v);
                    }
                    let mle = Arc::new(MLE::from_evaluations_vec(nv, evals));
                    linear_cache.push((signature.clone(), mle.clone()));
                    mle
                };

            // Mark terms as used.
            for (idx, _, _) in &active_entries {
                term_used[*idx] = true;
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

    /// Lift every materialized polynomial with `num_vars < target_nv` to
    /// `target_nv` via a virtual override; polynomials already at or above
    /// `target_nv` are left untouched. Sumcheck claims scaled by
    /// `2^(target_nv - poly_nv)` (padding a poly by repetition multiplies
    /// its hypercube sum by the repeat factor), and eval-claim points are
    /// only *extended* — never truncated. Called once per bucket during
    /// sumcheck compile so polys that don't participate in a bucket keep
    /// their native size.
    #[instrument(level = "debug", skip(self))]
    pub(super) fn equalize_mat_poly_nv_to(&mut self, target_nv: usize) {
        for poly in self.state.mv_pcs_substate.materialized_polys.values_mut() {
            let old_nv = poly.num_vars();
            if old_nv < target_nv {
                // Zero-cost path: just update the virtual nv on the existing
                // storage. For Field-backed polys this is unchanged behaviour
                // (nv semantics do the cyclic repetition on access); for
                // compressed-backed polys this critically avoids materializing
                // to a full-size Vec<F>, keeping the tracker's memory
                // footprint at inner-size for the whole compile pipeline.
                let inner_poly = Arc::get_mut(poly).unwrap();
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
