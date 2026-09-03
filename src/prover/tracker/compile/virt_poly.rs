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

            // Factors must share an nv and must not be lazy-backed: the
            // `.evaluations()` fold below would trigger the 2^nv on-demand
            // inversions the lazy backing exists to avoid. Sumcheck consumes
            // lazy polys directly via its streaming path.
            if signature_map.iter().any(|(id, _)| {
                self.mat_mv_poly(*id)
                    .map(|mle| {
                        mle.num_vars() != nv
                            || matches!(
                                mle.storage(),
                                crate::arithmetic::mat_poly::mle::MLEStorage::LazyInverseShifted { .. }
                                    | crate::arithmetic::mat_poly::mle::MLEStorage::LazyInverseShiftedSum { .. }
                            )
                    })
                    .unwrap_or(true)
            }) {
                continue;
            }

            let signature: Vec<(TrackerID, B::F)> = signature_map.into_iter().collect();

            // Reuse or build the linear combo MLE.
            let linear_mle = if let Some((_, mle)) =
                linear_cache.iter().find(|(sig, _)| *sig == signature)
            {
                mle.clone()
            } else {
                let mut evals = vec![B::F::zero(); 1 << nv];
                for (id, coeff) in &signature {
                    let mle = self.mat_mv_poly(*id).unwrap();
                    // Fix 6b: skip the 2^nv Vec allocation when the
                    // factor is Constant-backed — the added contribution
                    // is a uniform `coeff * value` per slot, so we just
                    // add that scalar across the accumulator without
                    // materialising a same-valued eval vector.
                    if let crate::arithmetic::mat_poly::mle::MLEStorage::Constant {
                        value, ..
                    } = mle.storage()
                    {
                        let cv = *coeff * *value;
                        cfg_iter_mut!(evals).for_each(|acc| *acc += cv);
                    } else {
                        cfg_iter_mut!(evals)
                            .zip(mle.evaluations())
                            .for_each(|(acc, v)| *acc += *coeff * v);
                    }
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
