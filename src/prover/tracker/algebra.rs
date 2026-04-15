//! Virtual polynomial algebra — arithmetic composition of tracked polynomials.

use super::*;

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    pub(super) fn extract_mv_openable_ids(&self, id: TrackerID) -> BTreeSet<TrackerID> {
        if self
            .state
            .mv_pcs_substate
            .materialized_comms
            .contains_key(&id)
        {
            return BTreeSet::from([id]);
        }
        let poly = self.virt_poly(id).unwrap();
        // 1)  Initialise the DFS stack with every TrackerID mentioned up-front
        let mut stack: Vec<TrackerID> = poly
            .iter()
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();

        let mut openable = BTreeSet::new();
        let mut visited = HashSet::new();

        // 2)  Standard iterative DFS
        while let Some(id) = stack.pop() {
            if !visited.insert(id) {
                continue; // already explored
            }

            // a) leaf with concrete commitment?
            if self
                .state
                .mv_pcs_substate
                .materialized_comms
                .contains_key(&id)
            {
                openable.insert(id);
                continue; // do *not* push children
            }

            // b) otherwise follow the virtual-poly reference if it exists
            if let Some(vpoly) = self.state.virtual_polys.get(&id) {
                for (_, child_ids) in vpoly.iter() {
                    stack.extend(child_ids.iter().copied());
                }
            }
            // c) dangling reference => silently ignore
        }

        openable
    }

    pub(super) fn extract_uv_openable_ids(&self, id: TrackerID) -> BTreeSet<TrackerID> {
        if self
            .state
            .uv_pcs_substate
            .materialized_comms
            .contains_key(&id)
        {
            return BTreeSet::from([id]);
        }
        let poly = self.virt_poly(id).unwrap();
        // 1)  Initialise the DFS stack with every TrackerID mentioned up-front
        let mut stack: Vec<TrackerID> = poly
            .iter()
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();

        let mut openable = BTreeSet::new();
        let mut visited = HashSet::new();

        // 2)  Standard iterative DFS
        while let Some(id) = stack.pop() {
            if !visited.insert(id) {
                continue; // already explored
            }

            // a) leaf with concrete commitment?
            if self
                .state
                .uv_pcs_substate
                .materialized_comms
                .contains_key(&id)
            {
                openable.insert(id);
                continue; // do *not* push children
            }

            // b) otherwise follow the virtual-poly reference if it exists
            if let Some(vpoly) = self.state.virtual_polys.get(&id) {
                for (_, child_ids) in vpoly.iter() {
                    stack.extend(child_ids.iter().copied());
                }
            }
            // c) dangling reference => silently ignore
        }

        openable
    }

    /// Get the number of variables of a polynomial, by its TrackerID
    pub fn poly_nv(&self, id: TrackerID) -> usize {
        self.state.num_vars.get(&id).copied().unwrap()
    }

    /// Return the max multiplicative degree (max number of MLEs in any product)
    /// of the virtual-poly tree rooted at `id`, matching HPVirtualPolynomial::max_degree.
    pub fn virt_poly_degree(&self, id: TrackerID) -> usize {
        let mut memo = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        self.virt_poly_degree_inner(id, &mut memo, &mut visiting)
    }

    pub(super) fn virt_poly_degree_inner(
        &self,
        id: TrackerID,
        memo: &mut BTreeMap<TrackerID, usize>,
        visiting: &mut BTreeSet<TrackerID>,
    ) -> usize {
        if let Some(&cached) = memo.get(&id) {
            return cached;
        }
        if self.mat_mv_poly(id).is_some() {
            memo.insert(id, 1);
            return 1;
        }
        let Some(vpoly) = self.state.virtual_polys.get(&id) else {
            return 0;
        };
        if !visiting.insert(id) {
            return 0;
        }
        let mut max_degree = 0;
        for (_, prod_ids) in vpoly.iter() {
            let mut term_degree = 0;
            for child_id in prod_ids {
                term_degree += self.virt_poly_degree_inner(*child_id, memo, visiting);
            }
            if term_degree > max_degree {
                max_degree = term_degree;
            }
        }
        visiting.remove(&id);
        memo.insert(id, max_degree);
        max_degree
    }

    /// Adds/Subtracts two polynomials together
    /// The two polynomials are identified by their TrackerIDs, Each one can be
    /// either materialized or virtual
    /// The output is a tracker to a new virtual polynomial
    pub fn add_sub_polys(&mut self, p1: TrackerID, p2: TrackerID, do_sub: bool) -> TrackerID {
        let sign_coeff: B::F = if do_sub { -B::F::one() } else { B::F::one() };

        let p1_mat = self.mat_mv_poly(p1);
        let p1_virt = self.virt_poly(p1);
        let p2_mat = self.mat_mv_poly(p2);
        let p2_virt = self.virt_poly(p2);

        let mut new = VirtualPoly::new(); // Invariant: contains only material TrackerIDs
        match (p1_mat, p1_virt, p2_mat, p2_virt) {
            (Some(_), None, Some(_), None) => {
                new.push((B::F::one(), vec![p1]));
                new.push((sign_coeff, vec![p2]));
            }

            // p1: materialized, p2: virtual
            (Some(_), None, None, Some(p2)) => {
                new.push((B::F::one(), vec![p1]));
                new.extend(
                    p2.iter()
                        .map(|(coeff, prod)| (*coeff * sign_coeff, prod.clone())),
                );
            }
            // p1: virtual, p2: materialized
            (None, Some(p1), Some(_), None) => {
                new.push((sign_coeff, vec![p2]));
                new.extend_from_slice(p1);
            }
            (None, Some(p1), None, Some(p2)) => {
                new.extend_from_slice(p1);
                new.extend(
                    p2.iter()
                        .map(|(coeff, prod)| (*coeff * sign_coeff, prod.clone())),
                );
            }
            (None, None, _, _) => panic!("Unknown p1 TrackerID {p1:?}"),
            (_, _, None, None) => panic!("Unknown p2 TrackerID {p2:?}"),
            (_, _, _, _) => unreachable!(),
        }
        self.track_virt_poly(new)
    }

    /// Adds two polynomials together
    /// The two polynomials are identified by their TrackerIDs, Each one can be
    /// either materialized or virtual
    /// The output is a tracker to a new virtual polynomial
    pub fn add_polys(&mut self, p1_id: TrackerID, p2_id: TrackerID) -> TrackerID {
        self.add_sub_polys(p1_id, p2_id, false)
    }

    /// Subtracts p2 from p1
    /// The two polynomials are identified by their TrackerIDs, Each one can be
    /// either materialized or virtual
    /// The output is a tracker to a new virtual polynomial
    pub fn sub_polys(&mut self, p1_id: TrackerID, p2_id: TrackerID) -> TrackerID {
        self.add_sub_polys(p1_id, p2_id, true)
    }

    /// Multiplies two polynomials together
    /// The two polynomials are identified by their TrackerIDs, Each one can be
    /// either materialized or virtual
    /// The output is a tracker to a new virtual polynomial
    pub fn mul_polys(&mut self, p1: TrackerID, p2: TrackerID) -> TrackerID {
        let p1_mat = self.mat_mv_poly(p1);
        let p1_virt = self.virt_poly(p1);
        let p2_mat = self.mat_mv_poly(p2);
        let p2_virt = self.virt_poly(p2);

        let mut new = VirtualPoly::new(); // Invariant: contains only material TrackerIDs
        match (p1_mat, p1_virt, p2_mat, p2_virt) {
            // Bad Case: p1 not found
            (None, None, ..) => panic!("Unknown p1 TrackerID {p1:?}"),
            // Bad Case: p2 not found
            (_, _, None, None) => panic!("Unknown p1 TrackerID {p2:?}"),
            // Case 1: both p1 and p2 are materialized
            (Some(_), None, Some(_), None) => new.push((B::F::one(), vec![p1, p2])),
            // Case 2: p1 is materialized and p2 is virtual
            (Some(_), None, None, Some(p)) => {
                p.iter().cloned().for_each(|(coeff, mut prod)| {
                    prod.push(p1);
                    new.push((coeff, prod));
                });
            }
            (None, Some(p), Some(_), None) => {
                p.iter().cloned().for_each(|(coeff, mut prod)| {
                    prod.push(p2);
                    new.push((coeff, prod));
                });
            }
            // Case 3: both p1 and p2 are virtual
            (None, Some(p1), None, Some(p2)) => {
                for (coeff1, prod1) in p1 {
                    for (coeff2, prod2) in p2 {
                        let mut prod1 = prod1.clone();
                        prod1.extend_from_slice(prod2);
                        new.push((*coeff1 * *coeff2, prod1));
                    }
                }
            }
            (_, _, _, _) => unreachable!(),
        };
        self.track_virt_poly(new)
    }

    /// Adds a scalar to a polynomial, returns a new virtual polynomial
    // TODO: Can we do it more efficiently?
    pub fn add_scalar(&mut self, poly_id: TrackerID, c: B::F) -> TrackerID {
        let nv = self.poly_nv(poly_id);
        let scalar_mle = MLE::from_evaluations_vec(nv, vec![c; 2_usize.pow(nv as u32)]);
        let scalar_id = self.track_mat_mv_poly(scalar_mle);
        self.add_polys(poly_id, scalar_id)
    }

    /// Multiplies a polynomial by a scalar, returns a new virtual polynomial
    pub fn mul_scalar(&mut self, poly_id: TrackerID, c: B::F) -> TrackerID {
        let mut new = VirtualPoly::new();
        match self.mat_mv_poly(poly_id) {
            Some(_) => new.push((c, vec![poly_id])),
            None => {
                let p = self.virt_poly(poly_id).unwrap();
                p.iter().for_each(|(coeff, prod)| {
                    new.push((*coeff * c, prod.clone()));
                });
            }
        }
        self.track_virt_poly(new)
    }
}
