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
        let first_id = poly[0].1[0];
        let nv: usize = self.mat_mv_poly(first_id).unwrap().num_vars();

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

    /// Iterates through the materialized polynomials and increases the number
    /// of variables to the max number of variables in the tracker
    /// Used as a preprocessing step before batching polynomials,
    // TODO: This can be potentially reduced
    #[instrument(level = "debug", skip(self))]
    pub(super) fn equalize_mat_poly_nv(&mut self) -> usize {
        // calculate the max nv
        let max_nv = self.state.num_vars.values().max().copied().unwrap_or(0);

        for poly in self.state.mv_pcs_substate.materialized_polys.values_mut() {
            let old_nv = poly.num_vars();
            if old_nv != max_nv {
                let inner_poly = Arc::get_mut(poly).unwrap();
                // Use mat_mle() (immutable) + clone for polynomials that already
                // have a virtual nv set (e.g. compact constant MLEs), since
                // mat_mle_mut() panics when nv is Some.
                let inner = inner_poly.mat_mle().clone();
                *poly = Arc::new(MLE::new(inner, Some(max_nv)));
            }
        }

        for claim in &mut self.state.mv_pcs_substate.sum_check_claims {
            let nv = self.state.num_vars[&claim.id()];
            claim.set_claim(claim.claim() * B::F::from(1 << (max_nv - nv)))
        }

        for claim in self.state.mv_pcs_substate.eval_claims.iter_mut() {
            let mut point = claim.point().clone();
            point.resize(max_nv, B::F::zero());
            claim.set_point(point);
        }
        max_nv
    }
}
