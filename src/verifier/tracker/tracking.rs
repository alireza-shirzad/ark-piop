//! Oracle and commitment tracking for the verifier.

use super::*;

impl<B: SnarkBackend> VerifierTracker<B> {
    pub fn track_mv_com_by_id(&mut self, id: TrackerID) -> SnarkResult<(usize, TrackerID)> {
        self.check_tracker_ids()?;
        // Idempotent: a caller that visits a subset of the prover's
        // commitments (`TrackedTableOracle::from_tracked_table`) may ask for
        // an id that is already registered.
        if let Some(comm) = self
            .state
            .mv_pcs_substate
            .materialized_comms
            .get(&id)
            .cloned()
        {
            return Ok((comm.log_size() as usize, id));
        }

        // A constant polynomial has no commitment.
        if let Some(&cnst) = self.proof_or_err()?.mv_pcs_subproof.constants.get(&id) {
            // Constants carry their num_vars in the subproof so that the
            // verifier's poly_log_sizes matches the prover's state.num_vars.
            let num_vars = self
                .proof_or_err()?
                .mv_pcs_subproof
                .constant_num_vars
                .get(&id)
                .copied()
                .unwrap_or(0);
            return self.track_mv_constant_by_id(id, cnst, num_vars);
        }

        let comm: <B::MvPCS as PCS<B::F>>::Commitment;
        {
            // Scope the immutable borrow
            let comm_opt: Option<&<B::MvPCS as PCS<B::F>>::Commitment> =
                self.proof_or_err()?.mv_pcs_subproof.comitments.get(&id);
            match comm_opt {
                Some(value) => {
                    comm = value.clone();
                }
                None => {
                    return Err(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(format!(
                            "mv commitment for tracker id {} not in proof",
                            id
                        )),
                    ));
                }
            }
        }
        let nv = comm.log_size();

        // Register under the caller's `id`, not `gen_id`: subset-transfer
        // callers (`from_tracked_table`) visit prover ids in a non-contiguous
        // order.
        self.register_mv_com_at_id(id, comm.clone(), CommitmentBinding::ProofEmitted)?;
        Ok((nv as usize, id))
    }

    /// Register a materialized multivariate commitment under `id`, bypassing
    /// `gen_id`. Advances the tracker's counter to `id + 1` if it was behind,
    /// so that later `gen_id()` calls never reuse `id`.
    fn register_mv_com_at_id(
        &mut self,
        id: TrackerID,
        comm: <B::MvPCS as PCS<B::F>>::Commitment,
        binding: CommitmentBinding,
    ) -> SnarkResult<()> {
        let next = self.state.num_tracked_polys;
        if id.to_int() >= next {
            self.state.num_tracked_polys = id.to_int() + 1;
        }
        let mv_queries_clone = self.proof_or_err()?.mv_pcs_subproof.query_map.clone();
        let mv_points_clone = self.proof_or_err()?.mv_pcs_subproof.point_map.clone();
        let mv_point_to_id: BTreeMap<Vec<B::F>, crate::types::PointID> = mv_points_clone
            .iter()
            .map(|(point_id, point)| (point.clone(), *point_id))
            .collect();

        let oracle = Oracle::new_multivariate(comm.log_size() as usize, move |point: Vec<B::F>| {
            let point_id = mv_point_to_id.get(&point).ok_or(SnarkError::VerifierError(
                VerifierError::OracleEvalNotProvided(id.to_int(), f_vec_short_str(&point)),
            ))?;
            let query_res = *mv_queries_clone
                .get(&id)
                .and_then(|queries_by_point| queries_by_point.get(point_id))
                .ok_or(SnarkError::VerifierError(
                    VerifierError::OracleEvalNotProvided(id.to_int(), f_vec_short_str(&point)),
                ))?;
            Ok(query_res)
        });
        let mut terms = VirtualOracle::new();
        terms.push((B::F::one(), vec![id]));
        self.state.base_oracles.insert(id, oracle);
        self.state.virtual_polys.insert(id, terms);
        self.state
            .poly_log_sizes
            .insert(id, comm.log_size() as usize);
        self.state.poly_kinds.insert(
            id,
            crate::verifier::structs::oracle::OracleKind::Multivariate,
        );
        self.state.poly_is_material.insert(id, true);

        if binding == CommitmentBinding::ProofEmitted {
            // Subset-transfer callers append in a different order than the
            // prover, but drop the verifier before its transcript is ever
            // consumed; a live verify run has to register in prover order.
            self.state
                .transcript
                .append_serializable_element(b"comm", &comm)?;
        } else {
            self.state
                .mv_pcs_substate
                .external_materialized_comm_ids
                .insert(id);
        }
        self.state
            .mv_pcs_substate
            .materialized_comms
            .insert(id, comm);
        self.state.poly_degrees.insert(id, 1);
        Ok(())
    }

    /// Tracks a constant polynomial from the proof and binds its value to
    /// the transcript, as the prover does. `num_vars` is the prover's, taken
    /// from the proof so that `poly_log_sizes[id]` matches the prover's
    /// `state.num_vars[id]`.
    fn track_mv_constant_by_id(
        &mut self,
        expected_id: TrackerID,
        cnst: B::F,
        num_vars: usize,
    ) -> SnarkResult<(usize, TrackerID)> {
        // Idempotent, as `track_mv_com_by_id` is: a repeat visit must not
        // append to the transcript again.
        if self
            .state
            .poly_kinds
            .get(&expected_id)
            .is_some_and(|k| matches!(k, crate::verifier::structs::oracle::OracleKind::Constant))
        {
            return Ok((num_vars, expected_id));
        }
        let id = expected_id;
        let next = self.state.num_tracked_polys;
        if id.to_int() >= next {
            self.state.num_tracked_polys = id.to_int() + 1;
        }

        // Register a constant oracle so virtual polynomial evaluation works.
        let oracle = Oracle::new_constant(num_vars, cnst);
        let mut terms = VirtualOracle::new();
        terms.push((B::F::one(), vec![id]));
        self.state.base_oracles.insert(id, oracle);
        self.state.virtual_polys.insert(id, terms);
        self.state.poly_log_sizes.insert(id, num_vars);
        self.state
            .poly_kinds
            .insert(id, crate::verifier::structs::oracle::OracleKind::Constant);
        self.state.poly_is_material.insert(id, true);
        self.state.poly_degrees.insert(id, 0);

        self.state
            .transcript
            .append_serializable_element(b"cnst", &cnst)?;

        Ok((num_vars, id))
    }

    pub fn track_uv_com_by_id(&mut self, id: TrackerID) -> SnarkResult<(usize, TrackerID)> {
        self.check_tracker_ids()?;
        let comm: <B::UvPCS as PCS<B::F>>::Commitment;
        {
            // Scope the immutable borrow
            let proof = self.proof_or_err()?;
            let comm_opt: Option<&<B::UvPCS as PCS<B::F>>::Commitment> =
                proof.uv_pcs_subproof.comitments.get(&id);
            match comm_opt {
                Some(value) => {
                    comm = value.clone();
                }
                None => {
                    return Err(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(format!(
                            "uv commitment for tracker id {} not in proof",
                            id
                        )),
                    ));
                }
            }
        }
        let log_degree = comm.log_size();
        // Unlike the mv path (see `register_mv_com_at_id`), this one draws
        // the id from `gen_id` and asserts it is the caller's: no caller
        // visits uv ids out of contiguous order.
        let new_id: TrackerID = self
            .track_mat_uv_com_with_binding(comm, CommitmentBinding::ProofEmitted)
            .unwrap();

        #[cfg(debug_assertions)]
        {
            assert_eq!(
                id, new_id,
                "VerifierTracker Error: attempted to transfer prover comm, but ids don't match: {}, {}",
                id, new_id
            );
        }
        Ok((log_degree as usize, new_id))
    }

    /// `binding` mirrors prover-side commitment ownership so the verifier uses
    /// the same transcript and proof-payload semantics.
    pub(crate) fn track_mat_mv_com_with_binding(
        &mut self,
        comm: <B::MvPCS as PCS<B::F>>::Commitment,
        binding: CommitmentBinding,
    ) -> SnarkResult<TrackerID> {
        let id = self.gen_id();
        self.check_tracker_ids()?;

        match self.proof.as_ref() {
            Some(proof) => {
                let mv_queries_clone = proof.mv_pcs_subproof.query_map.clone();
                let mv_points_clone = proof.mv_pcs_subproof.point_map.clone();
                let mv_point_to_id: BTreeMap<Vec<B::F>, crate::types::PointID> = mv_points_clone
                    .iter()
                    .map(|(point_id, point)| (point.clone(), *point_id))
                    .collect();

                let oracle =
                    Oracle::new_multivariate(comm.log_size() as usize, move |point: Vec<B::F>| {
                        let point_id = mv_point_to_id.get(&point).ok_or(
                            SnarkError::VerifierError(VerifierError::OracleEvalNotProvided(
                                id.to_int(),
                                f_vec_short_str(&point),
                            )),
                        )?;
                        let query_res = *mv_queries_clone
                            .get(&id)
                            .and_then(|queries_by_point| queries_by_point.get(point_id))
                            .ok_or(SnarkError::VerifierError(
                                VerifierError::OracleEvalNotProvided(
                                    id.to_int(),
                                    f_vec_short_str(&point),
                                ),
                            ))?;
                        Ok(query_res)
                    });
                let mut terms = VirtualOracle::new();
                terms.push((B::F::one(), vec![id]));
                self.state.base_oracles.insert(id, oracle);
                self.state.virtual_polys.insert(id, terms);
                self.state
                    .poly_log_sizes
                    .insert(id, comm.log_size() as usize);
                self.state.poly_kinds.insert(
                    id,
                    crate::verifier::structs::oracle::OracleKind::Multivariate,
                );
                self.state.poly_is_material.insert(id, true);
            }
            None => {
                panic!("Should not be called");
            }
        }

        if binding == CommitmentBinding::ProofEmitted {
            // Proof-owned commitments must feed the transcript in prover order.
            self.state
                .transcript
                .append_serializable_element(b"comm", &comm)?;
        } else {
            // External commitments are available for oracle queries but are not
            // reintroduced into the proof transcript or payload.
            self.state
                .mv_pcs_substate
                .external_materialized_comm_ids
                .insert(id);
        }
        self.state
            .mv_pcs_substate
            .materialized_comms
            .insert(id, comm);
        self.state.poly_degrees.insert(id, 1);
        Ok(id)
    }

    pub(crate) fn track_mat_mv_poly(&mut self, polynomial: MLE<B::F>) -> SnarkResult<TrackerID> {
        let id = self.gen_id();
        self.check_tracker_ids()?;
        let nv = polynomial.num_vars();
        let polynomial = std::sync::Arc::new(polynomial);
        let oracle_poly = polynomial.clone();
        let oracle = Oracle::new_multivariate(nv, move |mut point: Vec<B::F>| {
            if point.len() > nv {
                point.truncate(nv);
            } else if point.len() < nv {
                point.resize(nv, B::F::zero());
            }
            Ok(oracle_poly.evaluate(&point))
        });
        let mut terms = VirtualOracle::new();
        terms.push((B::F::one(), vec![id]));
        self.state.base_oracles.insert(id, oracle);
        self.state.virtual_polys.insert(id, terms);
        self.state.poly_log_sizes.insert(id, nv);
        self.state.poly_kinds.insert(
            id,
            crate::verifier::structs::oracle::OracleKind::Multivariate,
        );
        self.state.poly_is_material.insert(id, true);
        self.state.poly_degrees.insert(id, 1);
        self.state
            .transcript
            .append_serializable_element(b"mv_poly", polynomial.as_ref())?;
        Ok(id)
    }

    pub fn track_mat_uv_com_with_binding(
        &mut self,
        comm: <B::UvPCS as PCS<B::F>>::Commitment,
        binding: CommitmentBinding,
    ) -> SnarkResult<TrackerID> {
        let id = self.gen_id();
        self.check_tracker_ids()?;

        match self.proof.as_ref() {
            Some(proof) => {
                let uv_queries_clone = proof.uv_pcs_subproof.query_map.clone();
                let uv_points_clone = proof.uv_pcs_subproof.point_map.clone();
                let uv_point_to_id: BTreeMap<B::F, crate::types::PointID> = uv_points_clone
                    .iter()
                    .map(|(point_id, point)| (*point, *point_id))
                    .collect();
                let oracle =
                    Oracle::new_univariate(comm.log_size() as usize, move |point: B::F| {
                        let point_id = uv_point_to_id.get(&point).ok_or(
                            SnarkError::VerifierError(VerifierError::OracleEvalNotProvided(
                                id.to_int(),
                                point.to_string(),
                            )),
                        )?;
                        let query_res = uv_queries_clone
                            .get(&id)
                            .and_then(|queries_by_point| queries_by_point.get(point_id))
                            .ok_or(SnarkError::VerifierError(
                                VerifierError::OracleEvalNotProvided(
                                    id.to_int(),
                                    point.to_string(),
                                ),
                            ))?;
                        Ok(*query_res)
                    });
                let mut terms = VirtualOracle::new();
                terms.push((B::F::one(), vec![id]));
                self.state.base_oracles.insert(id, oracle);
                self.state.virtual_polys.insert(id, terms);
                self.state
                    .poly_log_sizes
                    .insert(id, comm.log_size() as usize);
                self.state
                    .poly_kinds
                    .insert(id, crate::verifier::structs::oracle::OracleKind::Univariate);
                self.state.poly_is_material.insert(id, true);
            }
            None => {
                panic!("Should not be called");
            }
        }

        if binding == CommitmentBinding::ProofEmitted {
            // Proof-owned commitments must feed the transcript in prover order.
            self.state
                .transcript
                .append_serializable_element(b"comm", &comm)?;
        } else {
            // External commitments are available for oracle queries but are not
            // reintroduced into the proof transcript or payload.
            self.state
                .uv_pcs_substate
                .external_materialized_comm_ids
                .insert(id);
        }
        self.state
            .uv_pcs_substate
            .materialized_comms
            .insert(id, comm);
        self.state.poly_degrees.insert(id, 1);
        Ok(id)
    }

    pub fn track_base_oracle(&mut self, oracle: Oracle<B::F>) -> TrackerID {
        let id = self.gen_id();
        let log_size = oracle.log_size();
        let kind = Self::oracle_kind_from_inner(oracle.inner());
        let degree = match oracle.inner() {
            InnerOracle::Constant(_) => 0,
            InnerOracle::Multivariate(_) | InnerOracle::Univariate(_) => 1,
        };
        let mut terms = VirtualOracle::new();
        terms.push((B::F::one(), vec![id]));
        self.state.base_oracles.insert(id, oracle);
        self.state.virtual_polys.insert(id, terms);
        self.state.poly_log_sizes.insert(id, log_size);
        self.state.poly_kinds.insert(id, kind);
        self.state.poly_is_material.insert(id, true);
        self.state.poly_degrees.insert(id, degree);
        id
    }

    pub(super) fn track_empty_virtual_poly(
        &mut self,
        log_size: usize,
        kind: crate::verifier::structs::oracle::OracleKind,
    ) -> TrackerID {
        let id = self.gen_id();
        self.state.virtual_polys.insert(id, VirtualOracle::new());
        self.state.poly_log_sizes.insert(id, log_size);
        self.state.poly_kinds.insert(id, kind);
        self.state.poly_is_material.insert(id, false);
        self.state.poly_degrees.insert(id, 0);
        id
    }
}
