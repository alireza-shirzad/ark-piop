//! PCS-side of proof compilation: batched openings for materialized
//! multivariate and univariate commitments, with deduplication by commitment
//! bytes and evaluation point.

use super::super::*;

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    /// Compiles the PCS subproof, a proof containg (a) a list of comitments to
    /// the polynomials that the verifier needs oracle access to (b) a query
    /// map, which is the list of all the possible verifier queries to these
    /// comitments (c) a batch opening proof corresponding to the query map
    #[instrument(level = "debug", skip(self))]
    pub fn compile_mv_pcs_subproof(&mut self) -> SnarkResult<PCSSubproof<B::F, B::MvPCS>> {
        // -- Step 1: Build the CommitmentID dedup map FIRST --
        // We need this before building openings so we can deduplicate by
        // (CommitmentID, PointID) instead of (TrackerID, PointID).
        let mut unique_comitments: BTreeMap<CommitmentID, _> = BTreeMap::new();
        let mut comitment_map: BTreeMap<TrackerID, CommitmentID> = BTreeMap::new();
        let mut comm_to_id: BTreeMap<Vec<u8>, CommitmentID> = BTreeMap::new();
        let mut next_comm_id = 0usize;
        let external_ids = &self.state.mv_pcs_substate.external_materialized_comm_ids;

        for (tracker_id, comm) in self.state.mv_pcs_substate.materialized_comms.iter() {
            let mut buf = Vec::new();
            comm.serialize_compressed(&mut buf).unwrap();
            let is_external = external_ids.contains(tracker_id);
            let comm_id = *comm_to_id.entry(buf).or_insert_with(|| {
                let id = CommitmentID::from_usize(next_comm_id);
                next_comm_id += 1;
                id
            });
            if !is_external {
                unique_comitments
                    .entry(comm_id)
                    .or_insert_with(|| comm.clone());
            }
            comitment_map.insert(*tracker_id, comm_id);
        }

        // -- Step 2: Evaluate all claims, deduplicate by (CommitmentID, PointID) --
        let mut query_map: BTreeMap<CommitmentID, BTreeMap<PointID, B::F>> = BTreeMap::new();
        let mut point_map: BTreeMap<PointID, Vec<B::F>> = BTreeMap::new();
        let mut point_to_id: BTreeMap<Vec<B::F>, PointID> = BTreeMap::new();
        let mut next_point_id = 0usize;
        let mut mat_polys = Vec::new();
        let mut points = Vec::new();
        let mut evals = Vec::new();
        // Track which (CommitmentID, PointID) pairs we've already added to the
        // opening lists, so each unique polynomial is opened at each point only once.
        let mut opened: BTreeSet<(CommitmentID, PointID)> = BTreeSet::new();

        // Group claims by point
        let mut deduped_claims: BTreeMap<Vec<B::F>, Vec<_>> = BTreeMap::new();
        self.state
            .mv_pcs_substate
            .eval_claims
            .iter()
            .for_each(|claim| {
                deduped_claims
                    .entry(claim.point().clone())
                    .or_default()
                    .push(claim);
            });

        // For each unique point, batch-evaluate all needed mat_ids once
        let mut id_to_eval: BTreeMap<(TrackerID, PointID), B::F> = BTreeMap::new();
        for (point, claims_for_point) in &deduped_claims {
            let point_id = *point_to_id.entry(point.clone()).or_insert_with(|| {
                let pid = PointID::from_usize(next_point_id);
                next_point_id += 1;
                point_map.insert(pid, point.clone());
                pid
            });

            let all_mat_ids: Vec<TrackerID> = claims_for_point
                .iter()
                .flat_map(|claim| self.extract_mv_openable_ids(claim.id()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            let all_evals = self.batch_evaluate_mv(&all_mat_ids, point).unwrap();

            for (mat_id, eval) in all_mat_ids.into_iter().zip(all_evals) {
                id_to_eval.insert((mat_id, point_id), eval);
            }
        }

        // Build openings, deduplicating by (CommitmentID, PointID)
        for claim in &self.state.mv_pcs_substate.eval_claims {
            let eval_id = claim.id();
            let point = claim.point();
            let point_id = *point_to_id.get(point).unwrap();
            let mat_ids = self.extract_mv_openable_ids(eval_id);
            for mat_id in mat_ids {
                let eval = *id_to_eval.get(&(mat_id, point_id)).unwrap();
                let comm_id = comitment_map[&mat_id];

                // Always populate the CommitmentID-keyed query map.
                query_map.entry(comm_id).or_default().insert(point_id, eval);

                // Only add to the opening lists if this (CommitmentID, PointID)
                // hasn't been opened yet.
                if opened.insert((comm_id, point_id)) {
                    mat_polys.push(self.mat_mv_poly(mat_id).unwrap().clone());
                    points.push(point.clone());
                    evals.push(eval);
                }
            }
        }

        // -- Step 3: Build the batch opening proof --
        let opening_proof: PCSOpeningProof<B::F, B::MvPCS>;
        if mat_polys.len() == 1 {
            let single_proof = B::MvPCS::open(
                self.pk.mv_pcs_param.as_ref(),
                &mat_polys[0],
                &points[0],
                None,
            )?;
            opening_proof = PCSOpeningProof::SingleProof(single_proof.0);
            assert!(single_proof.1 == evals[0]);
        } else if mat_polys.len() > 1 {
            let batch_proof = B::MvPCS::multi_open(
                self.pk.mv_pcs_param.as_ref(),
                &mat_polys,
                &points,
                &evals,
                &mut self.state.transcript,
            )?;
            opening_proof = PCSOpeningProof::BatchProof(batch_proof);
        } else {
            opening_proof = PCSOpeningProof::Empty;
        }

        // -- Step 4: Deduplicate constants --
        let mut unique_constants: BTreeMap<ConstantID, B::F> = BTreeMap::new();
        let mut constant_map: BTreeMap<TrackerID, ConstantID> = BTreeMap::new();
        let mut val_to_const_id: BTreeMap<B::F, ConstantID> = BTreeMap::new();
        let mut next_const_id = 0usize;

        for (tracker_id, cnst) in &self.state.mv_pcs_substate.constants {
            let const_id = *val_to_const_id.entry(*cnst).or_insert_with(|| {
                let id = ConstantID::from_usize(next_const_id);
                next_const_id += 1;
                unique_constants.insert(id, *cnst);
                id
            });
            constant_map.insert(*tracker_id, const_id);
        }

        Ok(PCSSubproof {
            query_map,
            point_map,
            opening_proof,
            unique_comitments,
            comitment_map,
            unique_constants,
            constant_map,
        })
    }

    /// Compiles the PCS subproof, a proof containg (a) a list of comitments to
    /// the polynomials that the verifier needs oracle access to (b) a query
    /// map, which is the list of all the possible verifier queries to these
    /// comitments (c) a batch opening proof corresponding to the query map
    #[instrument(level = "debug", skip(self))]
    pub fn compile_uv_pcs_subproof(&mut self) -> SnarkResult<PCSSubproof<B::F, B::UvPCS>> {
        let mut tracker_query_map: BTreeMap<TrackerID, BTreeMap<PointID, B::F>> = BTreeMap::new();
        let mut point_map: BTreeMap<PointID, B::F> = BTreeMap::new();
        let mut point_to_id: BTreeMap<B::F, PointID> = BTreeMap::new();
        let mut next_point_id = 0usize;
        let mut mat_polys = Vec::new();
        let mut points = Vec::new();
        let mut evals = Vec::new();
        for claim in &self.state.uv_pcs_substate.eval_claims {
            let eval_id = claim.id();
            let eval_point = claim.point();
            let mat_ids = self.extract_uv_openable_ids(eval_id);
            let point_id = *point_to_id.entry(*eval_point).or_insert_with(|| {
                let pid = PointID::from_usize(next_point_id);
                next_point_id += 1;
                point_map.insert(pid, *eval_point);
                pid
            });
            for mat_id in mat_ids {
                let eval = self.evaluate_uv(mat_id, eval_point).unwrap();
                tracker_query_map
                    .entry(mat_id)
                    .or_default()
                    .insert(point_id, eval);
                mat_polys.push(self.mat_uv_poly(mat_id).unwrap().clone());
                points.push(*eval_point);
                evals.push(eval);
            }
        }

        let opening_proof: PCSOpeningProof<B::F, B::UvPCS>;
        if mat_polys.len() == 1 {
            let single_proof = B::UvPCS::open(
                self.pk.uv_pcs_param.as_ref(),
                &mat_polys[0],
                &points[0],
                None,
            )?;
            opening_proof = PCSOpeningProof::SingleProof(single_proof.0);
            assert!(single_proof.1 == evals[0]);
        } else if mat_polys.len() > 1 {
            let batch_proof = B::UvPCS::multi_open(
                self.pk.uv_pcs_param.as_ref(),
                &mat_polys,
                &points,
                &evals,
                &mut self.state.transcript,
            )?;
            opening_proof = PCSOpeningProof::BatchProof(batch_proof);
        } else {
            opening_proof = PCSOpeningProof::Empty;
        }

        // Perform the batch-opening

        // Deduplicate UV commitments (same logic as MV).
        let mut unique_comitments: BTreeMap<CommitmentID, _> = BTreeMap::new();
        let mut comitment_map: BTreeMap<TrackerID, CommitmentID> = BTreeMap::new();
        let mut comm_to_id: BTreeMap<Vec<u8>, CommitmentID> = BTreeMap::new();
        let mut next_comm_id = 0usize;

        for (tracker_id, comm) in
            self.state
                .uv_pcs_substate
                .materialized_comms
                .iter()
                .filter(|(id, _)| {
                    !self
                        .state
                        .uv_pcs_substate
                        .external_materialized_comm_ids
                        .contains(id)
                })
        {
            let mut buf = Vec::new();
            comm.serialize_compressed(&mut buf).unwrap();
            let comm_id = *comm_to_id.entry(buf).or_insert_with(|| {
                let id = CommitmentID::from_usize(next_comm_id);
                next_comm_id += 1;
                unique_comitments.insert(id, comm.clone());
                id
            });
            comitment_map.insert(*tracker_id, comm_id);
        }

        // Convert TrackerID-keyed query_map to CommitmentID-keyed.
        let mut query_map: BTreeMap<CommitmentID, BTreeMap<PointID, B::F>> = BTreeMap::new();
        for (tracker_id, evals_by_point) in tracker_query_map {
            if let Some(comm_id) = comitment_map.get(&tracker_id) {
                query_map
                    .entry(*comm_id)
                    .or_default()
                    .extend(evals_by_point);
            }
        }

        Ok(PCSSubproof {
            query_map,
            point_map,
            opening_proof,
            unique_comitments,
            comitment_map,
            unique_constants: BTreeMap::new(),
            constant_map: BTreeMap::new(),
        })
    }
}
