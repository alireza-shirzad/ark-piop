//! Verification pipeline for the verifier.

use super::*;

impl<B: SnarkBackend> VerifierTracker<B> {
    /// Batch all zerocheck claims into one via random linear combination.
    /// Delegates to the generic pipeline.
    #[instrument(level = "debug", skip_all)]
    fn batch_z_check_claims(&mut self, _max_nv: usize) -> SnarkResult<()> {
        crate::tracker_core::pipeline::batch_z_check_claims(self)
    }

    #[instrument(level = "debug", skip(self))]
    fn batch_nozero_check_claims(&mut self, _max_nv: usize) -> SnarkResult<()> {
        let nozero_chunk_size = self.config.nozero_chunk_size;
        let nozero_claims = take(&mut self.state.mv_pcs_substate.no_zero_check_claims);
        if nozero_claims.is_empty() {
            return Ok(());
        }

        let num_claims = nozero_claims.len();
        let mut chunk_comm_ids = Vec::new();
        let mut master_prod_id = None;

        for chunk in nozero_claims.chunks(nozero_chunk_size) {
            let mut iter = chunk.iter();
            let first = iter
                .next()
                .expect("nozero_claims chunk should be non-empty");
            let mut chunk_prod_id = first.id();
            for claim in iter {
                chunk_prod_id = self.mul_polys(chunk_prod_id, claim.id());
            }

            // Track the committed chunk product and link it via a zerocheck.
            let chunk_comm_id = self.peek_next_id();
            let _ = self.track_mv_com_by_id(chunk_comm_id)?;
            let diff_id = self.sub_polys(chunk_comm_id, chunk_prod_id);
            self.add_mv_zerocheck_claim(diff_id);

            master_prod_id = Some(match master_prod_id {
                None => chunk_comm_id,
                Some(acc) => self.mul_polys(acc, chunk_comm_id),
            });
            chunk_comm_ids.push(chunk_comm_id);
        }

        let master_prod_id = master_prod_id.expect("nozero_claims should be non-empty");

        // Track the committed inverse polynomial by id provided in the proof.
        let inverses_poly_id = self.peek_next_id();
        let _ = self.track_mv_com_by_id(inverses_poly_id)?;

        debug!(
            "{} nozerocheck polynomials chunked into {}; final degree {}",
            num_claims,
            chunk_comm_ids.len(),
            self.virt_poly_degree(master_prod_id)
        );

        let prod_inv_id = self.mul_polys(master_prod_id, inverses_poly_id);
        let diff_id = self.add_scalar(prod_inv_id, -B::F::one());
        self.add_mv_zerocheck_claim(diff_id);

        Ok(())
    }

    /// Convert the single batched zerocheck claim to a sumcheck claim.
    /// Delegates to the generic pipeline.
    #[instrument(level = "debug", skip(self))]
    fn z_check_claim_to_s_check_claim(&mut self, max_nv: usize) -> SnarkResult<()> {
        crate::tracker_core::pipeline::z_check_claim_to_s_check_claim(self, max_nv)
    }

    /// Aggregate the sumcheck claims via random linear combination.
    /// Delegates to the generic pipeline (return value ignored).
    #[instrument(level = "debug", skip_all)]
    fn batch_s_check_claims(&mut self, _max_nv: usize) -> SnarkResult<()> {
        let _ = crate::tracker_core::pipeline::batch_s_check_claims(self)?;
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn perform_single_sumcheck(&mut self) -> SnarkResult<()> {
        if self.state.mv_pcs_substate.sum_check_claims.is_empty() {
            debug!("No sumcheck claims to verify",);
            return Ok(());
        }
        assert_eq!(self.state.mv_pcs_substate.sum_check_claims.len(), 1);

        let sumcheck_aggr_claim = self.state.mv_pcs_substate.sum_check_claims.last().unwrap();

        let sc_subclaim = SumCheck::verify(
            sumcheck_aggr_claim.claim(),
            self.proof
                .as_ref()
                .unwrap()
                .sc_subproof
                .as_ref()
                .expect("No sumcheck subproof in the proof")
                .sc_proof(),
            self.proof
                .as_ref()
                .unwrap()
                .sc_subproof
                .as_ref()
                .expect("No sumcheck subproof in the proof")
                .sc_aux_info(),
            &mut self.state.transcript,
        )?;
        self.add_mv_eval_claim(
            sumcheck_aggr_claim.id(),
            &sc_subclaim.point,
            sc_subclaim.expected_evaluation,
        )?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn perform_eval_check(&mut self) -> SnarkResult<()> {
        let claims = &self.state.mv_pcs_substate.eval_claims;
        if claims.is_empty() {
            return Ok(());
        }

        let mut iter = claims.iter();
        let (first_key, _) = iter.next().expect("non-empty eval claims");
        let (_, first_point) = first_key;
        let all_same_point = iter.all(|((_, point), _)| point == first_point);

        if all_same_point {
            let equalized = self.equalized_mv_point(first_point)?;
            let mut cache: HashMap<TrackerID, B::F> = HashMap::new();
            for ((id, _point), expected_eval) in claims {
                if self.eval_virtual_mv_cached(*id, &equalized, &mut cache)? != *expected_eval {
                    return Err(SnarkError::VerifierError(
                        crate::verifier::errors::VerifierError::VerifierCheckFailed(format!(
                            "Evaluation check failed for id: {}, point: {:?}, expected eval: {:?}",
                            id, first_point, expected_eval
                        )),
                    ));
                }
            }
            return Ok(());
        }

        for ((id, point), expected_eval) in claims {
            if self.query_mv(*id, point.clone())? != *expected_eval {
                return Err(SnarkError::VerifierError(
                    crate::verifier::errors::VerifierError::VerifierCheckFailed(format!(
                        "Evaluation check failed for id: {}, point: {:?}, expected eval: {:?}",
                        id, point, expected_eval
                    )),
                ));
            }
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn equalize_sumcheck_claims(&mut self, max_nv: usize) -> SnarkResult<()> {
        let poly_log_sizes: IndexMap<TrackerID, usize> = self.state.poly_log_sizes.clone();
        let proof_claims = self
            .proof
            .as_ref()
            .and_then(|proof| proof.sc_subproof.as_ref())
            .map(|subproof| subproof.sumcheck_claims().clone());

        for claim in &mut self.state.mv_pcs_substate.sum_check_claims {
            if let Some(proof_claims) = proof_claims.as_ref()
                && let Some(proof_claim) = proof_claims.get(&claim.id())
                && claim.claim() == *proof_claim
            {
                continue;
            }

            let nv = poly_log_sizes.get(&claim.id()).copied().unwrap_or(max_nv);
            if nv < max_nv {
                claim.set_claim(claim.claim() * B::F::from(1 << (max_nv - nv)));
            }
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn verify_sc_proofs(&mut self, max_nv: usize) -> SnarkResult<()> {
        self.batch_nozero_check_claims(max_nv)?;
        // Batch all the zero check claims into one
        self.batch_z_check_claims(max_nv)?;
        // Convert the only zero check claim to a sumcheck claim
        self.z_check_claim_to_s_check_claim(max_nv)?;
        // Ensure sumcheck claims are consistent with the max nv used in the protocol
        self.equalize_sumcheck_claims(max_nv)?;
        // aggregate the sumcheck claims
        self.batch_s_check_claims(max_nv)?;
        // Reduce high-degree terms deterministically before sumcheck.
        self.reduce_sumcheck_dgree()?;
        // Batch all the zero check claims into one
        self.batch_z_check_claims(max_nv)?;
        // Convert the only zero check claim to a sumcheck claim
        self.z_check_claim_to_s_check_claim(max_nv)?;
        // Ensure sumcheck claims are consistent with the max nv used in the protocol
        // self.equalize_sumcheck_claims(max_nv)?;
        // aggregate the sumcheck claims
        self.batch_s_check_claims(max_nv)?;
        // verify the sumcheck proof
        self.perform_single_sumcheck()?;
        // Verify the evaluation claims
        self.perform_eval_check()?;

        Ok(())
    }

    /// Deterministically reduces the degree of the single aggregated sumcheck claim.
    ///
    /// Verifier mirrors prover-side degree reduction:
    /// 1) Expand each claim term only until factors are *atoms* (linear or material).
    /// 2) Repeatedly pick the most frequent contiguous size-`LIMIT` chunk across
    ///    oversized terms.
    /// 3) Track a fresh commitment id for that chunk, replace chunk occurrences,
    ///    and add zerocheck links.
    ///
    /// The same tie-breaking/order is used to keep this fully deterministic.
    fn reduce_sumcheck_dgree(&mut self) -> SnarkResult<()> {
        debug_assert!(
            self.state.mv_pcs_substate.zero_check_claims.is_empty(),
            "reduce_sumcheck_dgree expects no zerocheck claims"
        );
        debug_assert_eq!(
            self.state.mv_pcs_substate.sum_check_claims.len(),
            1,
            "reduce_sumcheck_dgree expects exactly one sumcheck claim"
        );

        let mut chunk_cache: BTreeMap<Vec<TrackerID>, TrackerID> = BTreeMap::new();
        let mut atom_cache: BTreeMap<TrackerID, bool> = BTreeMap::new();
        let mut extra_zero_claims: Vec<TrackerID> = Vec::new();
        let mut committed_chunks: usize = 0;
        let mut oversized_terms_reduced: usize = 0;
        let mut claims_reduced: usize = 0;
        let mut rounds: usize = 0;
        let mut replacements: usize = 0;
        let mut expanded_terms_total: usize = 0;
        let mut expanded_oversized_terms: usize = 0;
        let mut total_terms: usize = 0;

        fn is_atom<B: SnarkBackend>(
            tracker: &VerifierTracker<B>,
            id: TrackerID,
            memo: &mut BTreeMap<TrackerID, bool>,
        ) -> bool {
            if let Some(v) = memo.get(&id) {
                return *v;
            }
            let ans = tracker
                .state
                .poly_is_material
                .get(&id)
                .copied()
                .unwrap_or(false)
                || tracker
                    .state
                    .virtual_polys
                    .get(&id)
                    .map(|voracle| {
                        voracle.iter().all(|(_, term)| {
                            term.len() <= 1
                                && term.iter().all(|child| is_atom(tracker, *child, memo))
                        })
                    })
                    .unwrap_or(false);
            memo.insert(id, ans);
            ans
        }

        #[allow(clippy::type_complexity)]
        fn expand_to_atoms<B: SnarkBackend>(
            tracker: &VerifierTracker<B>,
            id: TrackerID,
            atom_memo: &mut BTreeMap<TrackerID, bool>,
            expand_memo: &mut BTreeMap<TrackerID, Vec<(B::F, Vec<TrackerID>)>>,
        ) -> Vec<(B::F, Vec<TrackerID>)> {
            if let Some(cached) = expand_memo.get(&id) {
                return cached.clone();
            }
            if is_atom(tracker, id, atom_memo)
                || tracker
                    .state
                    .poly_is_material
                    .get(&id)
                    .copied()
                    .unwrap_or(false)
            {
                return vec![(B::F::one(), vec![id])];
            }
            let Some(voracle) = tracker.state.virtual_polys.get(&id) else {
                return vec![(B::F::one(), vec![id])];
            };

            let mut out: Vec<(B::F, Vec<TrackerID>)> = Vec::new();
            for (coeff, factors) in voracle.iter() {
                let mut acc: Vec<(B::F, Vec<TrackerID>)> = vec![(B::F::one(), Vec::new())];
                for factor_id in factors.iter().copied() {
                    let factor_terms = expand_to_atoms(tracker, factor_id, atom_memo, expand_memo);
                    let mut next: Vec<(B::F, Vec<TrackerID>)> =
                        Vec::with_capacity(acc.len() * factor_terms.len());
                    for (lhs_coeff, lhs_ids) in acc.into_iter() {
                        for (rhs_coeff, rhs_ids) in factor_terms.iter() {
                            let mut ids = lhs_ids.clone();
                            ids.extend_from_slice(rhs_ids);
                            next.push((lhs_coeff * *rhs_coeff, ids));
                        }
                    }
                    acc = next;
                }
                for (acc_coeff, ids) in acc.into_iter() {
                    out.push((*coeff * acc_coeff, ids));
                }
            }
            expand_memo.insert(id, out.clone());
            out
        }

        fn find_subslice(haystack: &[TrackerID], needle: &[TrackerID]) -> Option<usize> {
            if needle.is_empty() || haystack.len() < needle.len() {
                return None;
            }
            haystack.windows(needle.len()).position(|w| w == needle)
        }

        #[allow(clippy::too_many_arguments, clippy::type_complexity)]
        fn reduce_poly<B: SnarkBackend>(
            tracker: &mut VerifierTracker<B>,
            poly_id: TrackerID,
            chunk_cache: &mut BTreeMap<Vec<TrackerID>, TrackerID>,
            atom_cache: &mut BTreeMap<TrackerID, bool>,
            extra_zero_claims: &mut Vec<TrackerID>,
            committed_chunks: &mut usize,
            oversized_terms_reduced: &mut usize,
            rounds: &mut usize,
            replacements: &mut usize,
            expanded_terms_total: &mut usize,
            expanded_oversized_terms: &mut usize,
        ) -> SnarkResult<TrackerID> {
            let max_term_degree = tracker.config.sumcheck_term_degree_limit - 1;

            let terms = match tracker.state.virtual_polys.get(&poly_id) {
                Some(terms) => terms.clone(),
                None => return Ok(poly_id),
            };

            let mut expand_memo: BTreeMap<TrackerID, Vec<(B::F, Vec<TrackerID>)>> = BTreeMap::new();
            let mut expanded_terms: Vec<(B::F, Vec<TrackerID>)> = Vec::new();
            for (coeff, ids) in terms.iter() {
                let mut acc: Vec<(B::F, Vec<TrackerID>)> = vec![(B::F::one(), Vec::new())];
                for factor_id in ids.iter().copied() {
                    let expanded =
                        expand_to_atoms(tracker, factor_id, atom_cache, &mut expand_memo);
                    let mut next: Vec<(B::F, Vec<TrackerID>)> =
                        Vec::with_capacity(acc.len() * expanded.len());
                    for (lhs_coeff, lhs_ids) in acc.into_iter() {
                        for (rhs_coeff, rhs_ids) in expanded.iter() {
                            let mut joined = lhs_ids.clone();
                            joined.extend_from_slice(rhs_ids);
                            next.push((lhs_coeff * *rhs_coeff, joined));
                        }
                    }
                    acc = next;
                }
                for (acc_coeff, acc_ids) in acc.into_iter() {
                    let c = *coeff * acc_coeff;
                    if !c.is_zero() {
                        expanded_terms.push((c, acc_ids));
                    }
                }
            }
            let claim_term_count = expanded_terms.len();
            let claim_oversized = expanded_terms
                .iter()
                .filter(|(_, ids)| ids.len() > max_term_degree)
                .count();
            let claim_max_degree = expanded_terms
                .iter()
                .map(|(_, ids)| ids.len())
                .max()
                .unwrap_or(0);
            *oversized_terms_reduced += claim_oversized;
            *expanded_terms_total += claim_term_count;
            *expanded_oversized_terms += claim_oversized;
            debug!(
                claim_id = ?poly_id,
                claim_term_count,
                claim_oversized,
                claim_max_degree,
                "sumcheck degree reduction claim stats"
            );

            let atom_refs = expanded_terms
                .iter()
                .flat_map(|(_, ids)| ids.iter())
                .filter(|id| is_atom(tracker, **id, atom_cache))
                .count();
            debug!(
                claim_id = ?poly_id,
                atom_refs,
                "sumcheck degree reduction atomized claim"
            );

            fn track_chunk<B: SnarkBackend>(
                tracker: &mut VerifierTracker<B>,
                chunk: &[TrackerID],
                chunk_cache: &mut BTreeMap<Vec<TrackerID>, TrackerID>,
                extra_zero_claims: &mut Vec<TrackerID>,
                committed_chunks: &mut usize,
            ) -> SnarkResult<TrackerID> {
                if let Some(id) = chunk_cache.get(chunk).copied() {
                    return Ok(id);
                }

                let chunk_len = chunk.len();
                // Mirror prover-side behavior: chunk commitments are tracked at the
                // global max multivariate log-size so reduced terms never mix domains.
                let chunk_log_size = tracker
                    .state
                    .poly_log_sizes
                    .values()
                    .copied()
                    .max()
                    .unwrap_or(0);
                let new_id = tracker.peek_next_id();
                let _ = tracker.track_mv_com_by_id(new_id)?;
                chunk_cache.insert(chunk.to_vec(), new_id);
                *committed_chunks += 1;
                // Add zerocheck: committed - product(chunk) == 0.
                let prod_id = {
                    let id = tracker.gen_id();
                    let mut prod_terms = VirtualOracle::new();
                    prod_terms.push((B::F::one(), chunk.to_vec()));
                    tracker.state.virtual_polys.insert(id, prod_terms);
                    tracker.state.poly_log_sizes.insert(id, chunk_log_size);
                    tracker.state.poly_kinds.insert(
                        id,
                        crate::verifier::structs::oracle::OracleKind::Multivariate,
                    );
                    tracker.state.poly_is_material.insert(id, false);
                    tracker.state.poly_degrees.insert(id, chunk_len);
                    id
                };
                let neg_committed = tracker.mul_scalar(new_id, -B::F::one());
                let diff_id = tracker.add_polys(prod_id, neg_committed);
                extra_zero_claims.push(diff_id);

                Ok(new_id)
            }

            while expanded_terms
                .iter()
                .any(|(_, ids)| ids.len() > max_term_degree)
            {
                *rounds += 1;
                let mut freq: BTreeMap<Vec<TrackerID>, usize> = BTreeMap::new();
                for (_, ids) in expanded_terms
                    .iter()
                    .filter(|(_, ids)| ids.len() > max_term_degree)
                {
                    for window in ids.windows(max_term_degree) {
                        *freq.entry(window.to_vec()).or_insert(0) += 1;
                    }
                }
                let mut candidates: Vec<(Vec<TrackerID>, usize)> = freq.into_iter().collect();
                candidates.sort_by(|(a_ids, a_cnt), (b_ids, b_cnt)| {
                    b_cnt.cmp(a_cnt).then_with(|| a_ids.cmp(b_ids))
                });
                let chosen = if let Some((chunk, _)) = candidates.first() {
                    chunk.clone()
                } else {
                    expanded_terms
                        .iter()
                        .find(|(_, ids)| ids.len() > max_term_degree)
                        .and_then(|(_, ids)| ids.get(0..max_term_degree).map(|s| s.to_vec()))
                        .expect("at least one oversized term must exist")
                };

                let committed_id = track_chunk(
                    tracker,
                    &chosen,
                    chunk_cache,
                    extra_zero_claims,
                    committed_chunks,
                )?;

                let mut replaced_in_round = 0usize;
                for (_, ids) in expanded_terms
                    .iter_mut()
                    .filter(|(_, ids)| ids.len() > max_term_degree)
                {
                    while ids.len() > max_term_degree {
                        let Some(pos) = find_subslice(ids, &chosen) else {
                            break;
                        };
                        ids.splice(pos..pos + chosen.len(), [committed_id]);
                        replaced_in_round += 1;
                    }
                }
                if replaced_in_round == 0
                    && let Some((_, ids)) = expanded_terms
                        .iter_mut()
                        .find(|(_, ids)| ids.len() > max_term_degree)
                {
                    ids.splice(0..max_term_degree, [committed_id]);
                    replaced_in_round = 1;
                }
                *replacements += replaced_in_round;
            }

            let new_log_size = expanded_terms
                .iter()
                .flat_map(|(_, ids)| {
                    ids.iter()
                        .filter_map(|id| tracker.state.poly_log_sizes.get(id).copied())
                })
                .max()
                .unwrap_or(0);
            let mut new_terms = VirtualOracle::new();
            for (coeff, ids) in expanded_terms.into_iter() {
                if !coeff.is_zero() {
                    new_terms.push((coeff, ids));
                }
            }
            let new_id = tracker.gen_id();
            tracker.state.virtual_polys.insert(new_id, new_terms);
            tracker.state.poly_log_sizes.insert(new_id, new_log_size);
            tracker.state.poly_kinds.insert(
                new_id,
                crate::verifier::structs::oracle::OracleKind::Multivariate,
            );
            tracker.state.poly_is_material.insert(new_id, false);
            let new_degree = tracker.state.virtual_polys[&new_id]
                .iter()
                .map(|(_, ids)| ids.len())
                .max()
                .unwrap_or(0);
            tracker.state.poly_degrees.insert(new_id, new_degree);

            Ok(new_id)
        }

        let reduce_span = tracing::debug_span!("reduce_sumcheck_degree");
        let _reduce_guard = reduce_span.enter();

        let sum_claims = take(&mut self.state.mv_pcs_substate.sum_check_claims);
        for claim in sum_claims.into_iter() {
            claims_reduced += 1;
            let new_id = reduce_poly(
                self,
                claim.id(),
                &mut chunk_cache,
                &mut atom_cache,
                &mut extra_zero_claims,
                &mut committed_chunks,
                &mut oversized_terms_reduced,
                &mut rounds,
                &mut replacements,
                &mut expanded_terms_total,
                &mut expanded_oversized_terms,
            )?;
            self.state
                .mv_pcs_substate
                .sum_check_claims
                .push(TrackerSumcheckClaim::new(new_id, claim.claim()));
            if let Some(terms) = self.state.virtual_polys.get(&new_id) {
                total_terms += terms.len();
            }
        }

        let extra_zero_claims_len = extra_zero_claims.len();
        for id in extra_zero_claims {
            self.add_mv_zerocheck_claim(id);
        }

        debug!(
            committed_chunks,
            extra_zerochecks_added = extra_zero_claims_len,
            oversized_terms_reduced,
            rounds,
            replacements,
            expanded_terms_total,
            expanded_oversized_terms,
            claims_reduced,
            total_terms,
            "sumcheck degree reduction stats"
        );

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn verify_mv_pcs_proof(&mut self) -> SnarkResult<bool> {
        // Fetch the deduped evaluation claims (CommitmentID-keyed).
        // Build a CommitmentID → Commitment lookup from both proof-owned and
        // external commitments via the comitment_map.
        let proof = self.proof_or_err()?;
        let eval_claims = &proof.mv_pcs_subproof.deduped_query_map;
        let point_map = &proof.mv_pcs_subproof.point_map;

        // Build CommitmentID → Commitment by finding any TrackerID for each
        // CommitmentID and looking up its materialized commitment.
        let comm_id_to_comm: BTreeMap<CommitmentID, _> = proof
            .mv_pcs_subproof
            .comitment_map
            .iter()
            .filter_map(|(tracker_id, comm_id)| {
                self.state
                    .mv_pcs_substate
                    .materialized_comms
                    .get(tracker_id)
                    .map(|comm| (*comm_id, comm.clone()))
            })
            .collect();

        // Assemble (commitment, point, eval) triples, returning a verifier
        // error rather than panicking if the proof's query_map references a
        // CommitmentID or PointID that was not populated.
        let mut mat_coms = Vec::new();
        let mut points = Vec::new();
        let mut evals = Vec::new();
        for (comm_id, queries_by_point) in eval_claims.iter() {
            let com = comm_id_to_comm.get(comm_id).ok_or_else(|| {
                SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                    "query_map references unknown commitment id {:?}",
                    comm_id
                )))
            })?;
            for (point_id, eval) in queries_by_point.iter() {
                let point = point_map.get(point_id).ok_or_else(|| {
                    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                        "query_map references point id {:?} not in point_map",
                        point_id
                    )))
                })?;
                mat_coms.push(com.clone());
                points.push(point.clone());
                evals.push(*eval);
            }
        }
        // Invoke the batch verify function
        let pcs_res: bool;
        if mat_coms.len() == 1 {
            let opening_proof = match self.proof_or_err()?.mv_pcs_subproof.opening_proof {
                PCSOpeningProof::SingleProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(
                            "expected single opening proof for single commitment".to_string(),
                        ),
                    ));
                }
            };
            pcs_res = <B::MvPCS as PCS<B::F>>::verify(
                &self.vk.mv_pcs_param,
                &mat_coms[0],
                &points[0],
                &evals[0],
                opening_proof,
            )?;
        } else if mat_coms.len() > 1 {
            // Use direct field access so the borrow of self.proof doesn't
            // conflict with the later &mut borrow of self.state.transcript.
            let opening_proof = match self
                .proof
                .as_ref()
                .ok_or(SnarkError::VerifierError(VerifierError::ProofNotReceived))?
                .mv_pcs_subproof
                .opening_proof
            {
                PCSOpeningProof::BatchProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(
                            "expected batch opening proof for multiple commitments".to_string(),
                        ),
                    ));
                }
            };

            pcs_res = <B::MvPCS as PCS<B::F>>::batch_verify(
                &self.vk.mv_pcs_param,
                &mat_coms,
                points.as_slice(),
                &evals,
                opening_proof,
                &mut self.state.transcript,
            )?;
        } else {
            pcs_res = true;
        }

        Ok(pcs_res)
    }

    #[instrument(level = "debug", skip_all)]
    fn verify_uv_pcs_proof(&mut self) -> SnarkResult<bool> {
        let proof = self.proof_or_err()?;
        let eval_claims = &proof.uv_pcs_subproof.deduped_query_map;
        let point_map = &proof.uv_pcs_subproof.point_map;

        let comm_id_to_comm: BTreeMap<CommitmentID, _> = proof
            .uv_pcs_subproof
            .comitment_map
            .iter()
            .filter_map(|(tracker_id, comm_id)| {
                self.state
                    .uv_pcs_substate
                    .materialized_comms
                    .get(tracker_id)
                    .map(|comm| (*comm_id, comm.clone()))
            })
            .collect();

        // Assemble (commitment, point, eval) triples, rejecting malformed proofs
        // with a verifier error rather than panicking.
        let mut mat_coms = Vec::new();
        let mut points = Vec::new();
        let mut evals = Vec::new();
        for (comm_id, queries_by_point) in eval_claims.iter() {
            let com = comm_id_to_comm.get(comm_id).ok_or_else(|| {
                SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                    "query_map references unknown commitment id {:?}",
                    comm_id
                )))
            })?;
            for (point_id, eval) in queries_by_point.iter() {
                let point = point_map.get(point_id).ok_or_else(|| {
                    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                        "query_map references point id {:?} not in point_map",
                        point_id
                    )))
                })?;
                mat_coms.push(com.clone());
                points.push(*point);
                evals.push(*eval);
            }
        }
        // Invoke the batch verify function
        let pcs_res: bool;
        if mat_coms.len() == 1 {
            let opening_proof = match self.proof_or_err()?.uv_pcs_subproof.opening_proof {
                PCSOpeningProof::SingleProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(
                            "expected single opening proof for single commitment".to_string(),
                        ),
                    ));
                }
            };
            pcs_res = <B::UvPCS as PCS<B::F>>::verify(
                &self.vk.uv_pcs_param,
                &mat_coms[0],
                &points[0],
                &evals[0],
                opening_proof,
            )?;
        } else if mat_coms.len() > 1 {
            // Use direct field access so the borrow of self.proof doesn't
            // conflict with the later &mut borrow of self.state.transcript.
            let opening_proof = match self
                .proof
                .as_ref()
                .ok_or(SnarkError::VerifierError(VerifierError::ProofNotReceived))?
                .uv_pcs_subproof
                .opening_proof
            {
                PCSOpeningProof::BatchProof(ref proof) => proof,
                _ => {
                    return Err(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(
                            "expected batch opening proof for multiple commitments".to_string(),
                        ),
                    ));
                }
            };

            pcs_res = <B::UvPCS as PCS<B::F>>::batch_verify(
                &self.vk.uv_pcs_param,
                &mat_coms,
                points.as_slice(),
                &evals,
                opening_proof,
                &mut self.state.transcript,
            )?;
        } else {
            pcs_res = true;
        }

        Ok(pcs_res)
    }

    // Get the max_nv which is the number of variabels for the sumchekck protocol
    // TODO: The aux info should be derivable by the verifier looking at the sql
    // query and io tables
    #[instrument(level = "debug", skip_all)]
    fn equalize_mat_com_nv(&self) -> usize {
        // Returns 1 when there are no materialized commitments rather than
        // panicking — the claim pipeline tolerates an empty commitment set.
        self.state
            .mv_pcs_substate
            .materialized_comms
            .values()
            .map(|p| p.log_size() as usize)
            .max()
            .unwrap_or(1)
    }

    /// Verify the claims of the proof
    /// 1. Verify the sumcheck proofs
    /// 2. Verify the multivariate evaluation claims using the multivariate PCS
    /// 3. Verify the univariate evaluation claims using the univariate PCS
    #[instrument(level = "debug", skip_all)]
    pub fn verify(&mut self) -> SnarkResult<()> {
        // Fail fast if the caller forgot to set a proof.
        self.proof_or_err()?;
        let max_nv = self.equalize_mat_com_nv();
        // Verify the sumcheck proofs
        self.verify_sc_proofs(max_nv)?;
        // Verify the multivariate pcs proofs
        // assert!(self.verify_mv_pcs_proof(max_nv)?);
        self.verify_mv_pcs_proof()?;
        // Verify the multivariate pcs proofs
        // assert!(self.verify_uv_pcs_proof()?);
        self.verify_uv_pcs_proof()?;
        Ok(())
    }
}
