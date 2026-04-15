//! Virtual oracle arithmetic for the verifier.

use super::*;

impl<B: SnarkBackend> VerifierTracker<B> {
    // TODO: Lots of code duplication here for add, sub, mul, etc. need to refactor.
    pub fn add_polys(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        let o1_terms = self.state.virtual_polys.get(&o1_id).unwrap().clone();
        let o2_terms = self.state.virtual_polys.get(&o2_id).unwrap().clone();
        let o1_degree = self.state.poly_degrees.get(&o1_id).copied().unwrap_or(0);
        let o2_degree = self.state.poly_degrees.get(&o2_id).copied().unwrap_or(0);
        let o1_kind = *self.state.poly_kinds.get(&o1_id).unwrap();
        let o2_kind = *self.state.poly_kinds.get(&o2_id).unwrap();
        let res_kind = self.combine_kinds(o1_kind, o2_kind);
        let o1_mat = *self.state.poly_is_material.get(&o1_id).unwrap_or(&false);
        let o2_mat = *self.state.poly_is_material.get(&o2_id).unwrap_or(&false);

        let log_size = self
            .state
            .poly_log_sizes
            .get(&o1_id)
            .copied()
            .unwrap_or(0)
            .max(self.state.poly_log_sizes.get(&o2_id).copied().unwrap_or(0));

        let mut res_terms = VirtualOracle::new();
        if !o1_mat && o2_mat {
            res_terms.extend(o2_terms);
            res_terms.extend(o1_terms);
        } else {
            res_terms.extend(o1_terms);
            res_terms.extend(o2_terms);
        }
        let res_id = self.gen_id();
        self.state.virtual_polys.insert(res_id, res_terms);
        self.state.poly_log_sizes.insert(res_id, log_size);
        self.state.poly_kinds.insert(res_id, res_kind);
        self.state.poly_is_material.insert(res_id, false);
        self.state
            .poly_degrees
            .insert(res_id, o1_degree.max(o2_degree));
        res_id
    }

    pub fn sub_polys(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        let o1_terms = self.state.virtual_polys.get(&o1_id).unwrap().clone();
        let o2_terms = self.state.virtual_polys.get(&o2_id).unwrap().clone();
        let o1_degree = self.state.poly_degrees.get(&o1_id).copied().unwrap_or(0);
        let o2_degree = self.state.poly_degrees.get(&o2_id).copied().unwrap_or(0);
        let o1_kind = *self.state.poly_kinds.get(&o1_id).unwrap();
        let o2_kind = *self.state.poly_kinds.get(&o2_id).unwrap();
        let res_kind = self.combine_kinds(o1_kind, o2_kind);
        let o1_mat = *self.state.poly_is_material.get(&o1_id).unwrap_or(&false);
        let o2_mat = *self.state.poly_is_material.get(&o2_id).unwrap_or(&false);

        let log_size = self
            .state
            .poly_log_sizes
            .get(&o1_id)
            .copied()
            .unwrap_or(0)
            .max(self.state.poly_log_sizes.get(&o2_id).copied().unwrap_or(0));

        let mut res_terms = VirtualOracle::new();
        if !o1_mat && o2_mat {
            res_terms.extend(o2_terms.into_iter().map(|(coeff, ids)| (-coeff, ids)));
            res_terms.extend(o1_terms);
        } else {
            res_terms.extend(o1_terms);
            res_terms.extend(o2_terms.into_iter().map(|(coeff, ids)| (-coeff, ids)));
        }
        let res_id = self.gen_id();
        self.state.virtual_polys.insert(res_id, res_terms);
        self.state.poly_log_sizes.insert(res_id, log_size);
        self.state.poly_kinds.insert(res_id, res_kind);
        self.state.poly_is_material.insert(res_id, false);
        self.state
            .poly_degrees
            .insert(res_id, o1_degree.max(o2_degree));
        res_id
    }

    pub fn mul_polys(&mut self, o1_id: TrackerID, o2_id: TrackerID) -> TrackerID {
        let o1_terms = self.state.virtual_polys.get(&o1_id).unwrap().clone();
        let o2_terms = self.state.virtual_polys.get(&o2_id).unwrap().clone();
        let o1_degree = self.state.poly_degrees.get(&o1_id).copied().unwrap_or(0);
        let o2_degree = self.state.poly_degrees.get(&o2_id).copied().unwrap_or(0);
        let o1_kind = *self.state.poly_kinds.get(&o1_id).unwrap();
        let o2_kind = *self.state.poly_kinds.get(&o2_id).unwrap();
        let res_kind = self.combine_kinds(o1_kind, o2_kind);
        let o1_mat = *self.state.poly_is_material.get(&o1_id).unwrap_or(&false);
        let o2_mat = *self.state.poly_is_material.get(&o2_id).unwrap_or(&false);

        let log_size = self
            .state
            .poly_log_sizes
            .get(&o1_id)
            .copied()
            .unwrap_or(0)
            .max(self.state.poly_log_sizes.get(&o2_id).copied().unwrap_or(0));

        let mut res_terms = VirtualOracle::new();
        if o1_mat && o2_mat {
            let coeff1 = o1_terms.first().map(|(c, _)| *c).unwrap_or(B::F::one());
            let coeff2 = o2_terms.first().map(|(c, _)| *c).unwrap_or(B::F::one());
            res_terms.push((coeff1 * coeff2, vec![o1_id, o2_id]));
        } else if o1_mat && !o2_mat {
            let coeff1 = o1_terms.first().map(|(c, _)| *c).unwrap_or(B::F::one());
            for (coeff2, prod2) in o2_terms.iter() {
                let mut ids = prod2.clone();
                ids.push(o1_id);
                res_terms.push((coeff1 * *coeff2, ids));
            }
        } else if !o1_mat && o2_mat {
            let coeff2 = o2_terms.first().map(|(c, _)| *c).unwrap_or(B::F::one());
            for (coeff1, prod1) in o1_terms.iter() {
                let mut ids = prod1.clone();
                ids.push(o2_id);
                res_terms.push((*coeff1 * coeff2, ids));
            }
        } else {
            for (coeff1, prod1) in o1_terms.iter() {
                for (coeff2, prod2) in o2_terms.iter() {
                    let mut ids = prod1.clone();
                    ids.extend_from_slice(prod2);
                    res_terms.push((*coeff1 * *coeff2, ids));
                }
            }
        }
        let res_id = self.gen_id();
        self.state.virtual_polys.insert(res_id, res_terms);
        self.state.poly_log_sizes.insert(res_id, log_size);
        self.state.poly_kinds.insert(res_id, res_kind);
        self.state.poly_is_material.insert(res_id, false);
        self.state
            .poly_degrees
            .insert(res_id, o1_degree + o2_degree);
        res_id
    }

    pub fn add_scalar(&mut self, o1_id: TrackerID, scalar: B::F) -> TrackerID {
        let o1_terms = self.state.virtual_polys.get(&o1_id).unwrap().clone();
        let o1_degree = self.state.poly_degrees.get(&o1_id).copied().unwrap_or(0);
        let log_size = self.state.poly_log_sizes.get(&o1_id).copied().unwrap_or(0);
        let o1_kind = *self.state.poly_kinds.get(&o1_id).unwrap();

        let scalar_id = self.gen_id();
        let scalar_oracle = match o1_kind {
            crate::verifier::structs::oracle::OracleKind::Multivariate => {
                Oracle::new_multivariate(log_size, move |_pt: Vec<B::F>| Ok(scalar))
            }
            crate::verifier::structs::oracle::OracleKind::Univariate => {
                Oracle::new_univariate(log_size, move |_pt: B::F| Ok(scalar))
            }
            crate::verifier::structs::oracle::OracleKind::Constant => {
                Oracle::new_constant(log_size, scalar)
            }
        };
        let mut scalar_terms = VirtualOracle::new();
        scalar_terms.push((B::F::one(), vec![scalar_id]));
        self.state.base_oracles.insert(scalar_id, scalar_oracle);
        self.state.virtual_polys.insert(scalar_id, scalar_terms);
        self.state.poly_log_sizes.insert(scalar_id, log_size);
        self.state.poly_kinds.insert(scalar_id, o1_kind);
        self.state.poly_is_material.insert(scalar_id, true);
        self.state.poly_degrees.insert(scalar_id, 1);

        let o1_mat = *self.state.poly_is_material.get(&o1_id).unwrap_or(&false);
        let mut res_terms = VirtualOracle::new();
        if o1_mat {
            res_terms.extend(o1_terms);
            res_terms.push((B::F::one(), vec![scalar_id]));
        } else {
            res_terms.push((B::F::one(), vec![scalar_id]));
            res_terms.extend(o1_terms);
        }
        let res_id = self.gen_id();
        self.state.virtual_polys.insert(res_id, res_terms);
        self.state.poly_log_sizes.insert(res_id, log_size);
        self.state.poly_kinds.insert(res_id, o1_kind);
        self.state.poly_is_material.insert(res_id, false);
        self.state.poly_degrees.insert(res_id, o1_degree.max(1));
        // Return the new TrackerID
        res_id
    }

    pub fn sub_scalar(&mut self, o1_id: TrackerID, scalar: B::F) -> TrackerID {
        self.add_scalar(o1_id, -scalar)
    }

    pub fn mul_scalar(&mut self, o1_id: TrackerID, scalar: B::F) -> TrackerID {
        let o1_terms = self.state.virtual_polys.get(&o1_id).unwrap().clone();
        let o1_degree = self.state.poly_degrees.get(&o1_id).copied().unwrap_or(0);
        let log_size = self.state.poly_log_sizes.get(&o1_id).copied().unwrap_or(0);
        let o1_kind = *self.state.poly_kinds.get(&o1_id).unwrap();

        let mut res_terms = VirtualOracle::new();
        for (coeff, ids) in o1_terms.into_iter() {
            res_terms.push((coeff * scalar, ids));
        }
        let res_id = self.gen_id();
        self.state.virtual_polys.insert(res_id, res_terms);
        self.state.poly_log_sizes.insert(res_id, log_size);
        self.state.poly_kinds.insert(res_id, o1_kind);
        self.state.poly_is_material.insert(res_id, false);
        self.state.poly_degrees.insert(res_id, o1_degree);
        // Return the new TrackerID
        res_id
    }

    /// Return the max multiplicative degree of the oracle rooted at `id`.
    pub fn virt_poly_degree(&self, id: TrackerID) -> usize {
        self.state.poly_degrees.get(&id).copied().unwrap_or(0)
    }

    pub(super) fn oracle_kind_from_inner(
        inner: &InnerOracle<B::F>,
    ) -> crate::verifier::structs::oracle::OracleKind {
        use crate::verifier::structs::oracle::OracleKind;
        match inner {
            InnerOracle::Univariate(_) => OracleKind::Univariate,
            InnerOracle::Multivariate(_) => OracleKind::Multivariate,
            InnerOracle::Constant(_) => OracleKind::Constant,
        }
    }

    pub(super) fn combine_kinds(
        &self,
        k1: crate::verifier::structs::oracle::OracleKind,
        k2: crate::verifier::structs::oracle::OracleKind,
    ) -> crate::verifier::structs::oracle::OracleKind {
        use crate::verifier::structs::oracle::OracleKind;
        match (k1, k2) {
            (OracleKind::Constant, k) | (k, OracleKind::Constant) => k,
            (OracleKind::Univariate, OracleKind::Univariate) => OracleKind::Univariate,
            (OracleKind::Multivariate, OracleKind::Multivariate) => OracleKind::Multivariate,
            _ => panic!("Mismatched oracle types"),
        }
    }
}
