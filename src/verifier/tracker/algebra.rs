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

    /// Adds a scalar to an oracle, returns a new virtual oracle.
    ///
    /// Represents the scalar as a bare-constant term `(scalar, vec![])` —
    /// the empty factor list means "empty product = 1", so the term
    /// contributes exactly `scalar` at every point. This matches the
    /// prover-side `add_scalar` convention (see
    /// `prover/tracker/algebra.rs`) so both sides construct structurally
    /// identical virtual polys.
    ///
    /// Adding a constant does not change the max multiplicative degree
    /// of the sum, so the result's degree equals the input's degree.
    pub fn add_scalar(&mut self, o1_id: TrackerID, scalar: B::F) -> TrackerID {
        let o1_terms = self.state.virtual_polys.get(&o1_id).unwrap().clone();
        let o1_degree = self.state.poly_degrees.get(&o1_id).copied().unwrap_or(0);
        let log_size = self.state.poly_log_sizes.get(&o1_id).copied().unwrap_or(0);
        let o1_kind = *self.state.poly_kinds.get(&o1_id).unwrap();

        let mut res_terms = VirtualOracle::new();
        res_terms.extend(o1_terms);
        if !scalar.is_zero() {
            // Bare constant term: empty factor list, coefficient is the scalar.
            res_terms.push((scalar, Vec::new()));
        }
        let res_id = self.gen_id();
        self.state.virtual_polys.insert(res_id, res_terms);
        self.state.poly_log_sizes.insert(res_id, log_size);
        self.state.poly_kinds.insert(res_id, o1_kind);
        self.state.poly_is_material.insert(res_id, false);
        self.state.poly_degrees.insert(res_id, o1_degree);
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
