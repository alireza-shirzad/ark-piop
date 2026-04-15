//! Polynomial evaluation — materializing virtual polynomials and evaluating at points.

use super::*;

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    pub(super) fn materialize_poly(&mut self, id: TrackerID) -> Arc<MLE<B::F>> {
        match self.mat_mv_poly(id) {
            Some(mat_poly) => mat_poly.clone(), // already materialized
            None => {
                let virt_poly = self.state.virtual_polys[&id].clone();
                // Invariant: contains only material PolyIDs
                assert!(
                    virt_poly
                        .iter()
                        .all(|(_, ids)| ids.iter().all(|id| self.mat_mv_poly(*id).is_some()))
                );
                // Ensure all the product polynomials have the same number of variables
                // assert_eq!(
                //     virt_poly
                //         .iter()
                //         .flat_map(|(_, ids)| ids.iter().map(|id| self.poly_nv(*id)))
                //         .collect::<HashSet<_>>()
                //         .len(),
                //     1
                // );
                let nv = self.poly_nv(id);

                let evals = virt_poly.iter().fold(
                    vec![B::F::ZERO; 1 << nv],
                    |mut acc, (coeff, products)| {
                        let t = products.iter().fold(vec![*coeff; 1 << nv], |mut acc, id| {
                            cfg_iter_mut!(acc)
                                .zip(self.mat_mv_poly(*id).unwrap().evaluations())
                                .for_each(|(a, b)| *a *= b);
                            acc
                        });
                        cfg_iter_mut!(acc).zip(t).for_each(|(a, b)| *a += b);
                        acc
                    },
                );
                Arc::new(MLE::from_evaluations_vec(nv, evals))
            }
        }
    }

    pub fn evaluate_uv(&self, id: TrackerID, pt: &B::F) -> Option<B::F> {
        let mat_poly = self.state.uv_pcs_substate.materialized_polys.get(&id);
        // TODO: Change this to_vec
        mat_poly.map(|poly| poly.evaluate(pt))
    }

    pub fn batch_evaluate_mv(&self, ids: &[TrackerID], pt: &[B::F]) -> Option<Vec<B::F>> {
        // Find max nv needed
        let mut needed_nvs = BTreeSet::new();
        for &id in ids {
            self.collect_needed_nvs(id, &mut needed_nvs);
        }
        let max_nv = *needed_nvs.iter().max()?;
        let min_nv = *needed_nvs.iter().min()?;

        // Build largest eq once: O(2^max_nv)
        let largest_eq = build_eq_x_r(&pt[..max_nv]).unwrap();

        // Derive smaller eq tables by summing pairs, O(2^max_nv) total work
        let mut eq_evals: BTreeMap<usize, MLE<B::F>> = BTreeMap::new();
        eq_evals.insert(max_nv, largest_eq);

        for nv in (min_nv..max_nv).rev() {
            let prev_evals = &eq_evals[&(nv + 1)].mat_mle().evaluations;
            let half = prev_evals.len() / 2;
            let evals = cfg_iter!(prev_evals[..half])
                .zip(&prev_evals[half..])
                .map(|(a, b)| *a + *b)
                .collect::<Vec<_>>();
            eq_evals.insert(nv, MLE::from_evaluations_vec(nv, evals));
        }
        // Handle nv=0 case
        if needed_nvs.contains(&0) {
            eq_evals.insert(0, MLE::from_evaluations_vec(0, vec![B::F::one()]));
        }

        let mat_mles = &self.state.mv_pcs_substate.materialized_polys;
        cfg_iter!(ids)
            .map(|&id| Self::evaluate_mat_mv_with_eq_evals(id, &eq_evals, mat_mles))
            .collect()
    }

    /// Recursively collects all nv values of underlying materialized polynomials
    /// reachable from this id.
    fn collect_needed_nvs(&self, id: TrackerID, nvs: &mut BTreeSet<usize>) {
        match self.state.mv_pcs_substate.materialized_polys.get(&id) {
            Some(poly) => {
                nvs.insert(poly.mat_mle().num_vars);
            }
            None => {
                let p = self.virt_poly(id).unwrap();
                for (_, prod) in p.iter() {
                    for &poly_id in prod.iter() {
                        self.collect_needed_nvs(poly_id, nvs);
                    }
                }
            }
        }
    }

    /// Evaluates a polynomial at a point
    pub fn evaluate_mv(&self, id: TrackerID, pt: &[B::F]) -> Option<B::F> {
        match self.state.mv_pcs_substate.materialized_polys.get(&id) {
            Some(poly) => {
                let nv = poly.mat_mle().num_vars;
                if nv == 0 {
                    // Avoid build_eq_x_r([]) for constant polynomials.
                    return poly.mat_mle().evaluations.first().copied();
                }
                let eq_eval = build_eq_x_r(&pt[..nv]).unwrap();
                Some(evaluate_with_eq(poly, &eq_eval))
            }
            None => {
                let p = self.virt_poly(id).unwrap();
                // calculate the evaluation of each product list
                let result = p
                    .iter()
                    .map(|(coeff, prod)| {
                        *coeff
                            * prod
                                .iter()
                                .map(|poly| self.evaluate_mv(*poly, pt).unwrap())
                                .product::<B::F>()
                    })
                    .sum::<B::F>();
                Some(result)
            }
        }
    }

    /// Evaluates a polynomial at a point given the evaluations of the eq polynomial at that point.
    /// This assumes that `eq_evals` contains the evaluations of the eq polynomial for each number
    /// of variables of the *actual* underlying `DenseMultilinearExtension` of the materialized polynomials.
    pub fn evaluate_mat_mv_with_eq_evals(
        id: TrackerID,
        eq_evals: &BTreeMap<usize, MLE<B::F>>,
        materialized_polys: &BTreeMap<TrackerID, Arc<MLE<B::F>>>,
    ) -> Option<B::F> {
        let poly = materialized_polys.get(&id).unwrap();

        let nv = poly.mat_mle().num_vars;
        Some(evaluate_with_eq(poly, &eq_evals[&nv]))
    }

    /// Evaluates a polynomial at a point given the evaluations of the eq polynomial at that point.
    /// This assumes that `eq_evals` contains the evaluations of the eq polynomial for each number
    /// of variables of the *actual* underlying `DenseMultilinearExtension` of the materialized polynomials.
    pub fn evaluate_mv_with_eq_evals(
        &self,
        id: TrackerID,
        eq_evals: &BTreeMap<usize, MLE<B::F>>,
    ) -> Option<B::F> {
        match self.state.mv_pcs_substate.materialized_polys.get(&id) {
            Some(poly) => {
                let nv = poly.mat_mle().num_vars;
                Some(evaluate_with_eq(poly, &eq_evals[&nv]))
            }
            None => {
                let p = self.virt_poly(id).unwrap();
                let result = p
                    .iter()
                    .map(|(coeff, prod)| {
                        *coeff
                            * prod
                                .iter()
                                .map(|poly| {
                                    self.evaluate_mv_with_eq_evals(*poly, eq_evals).unwrap()
                                })
                                .product::<B::F>()
                    })
                    .sum::<B::F>();
                Some(result)
            }
        }
    }

    /// Returns the evaluations of a polynomial on the boolean hypercube
    pub fn evaluations(&mut self, id: TrackerID) -> Vec<B::F> {
        // Ensure the polynomial is materialized before getting evaluations
        let mat_poly = self.materialize_poly(id);

        mat_poly.evaluations()
    }
}
