//! Sumcheck-side of proof compilation: claim batching, degree reduction,
//! the single aggregated sumcheck invocation, nozerocheck batching, and the
//! orchestrating `compile_sc_subproof`.

use super::super::*;

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    /// Converts all the zerocheck claims into a single zero claim via random
    /// linear combination. Delegates to the generic pipeline.
    #[instrument(level = "debug", skip(self))]
    fn batch_z_check_claims(&mut self) -> SnarkResult<()> {
        debug!(
            "Zerocheck claims with degrees: {}",
            self.state
                .mv_pcs_substate
                .zero_check_claims
                .iter()
                .map(|claim| self.virt_poly_degree(claim.id()))
                .collect::<Vec<usize>>()
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );
        crate::tracker_core::pipeline::batch_z_check_claims(self)
    }

    /// Aggregate the sumcheck claims via random linear combination.
    /// Delegates to the generic pipeline.
    #[instrument(level = "debug", skip(self))]
    fn batch_s_check_claims(&mut self) -> SnarkResult<BTreeMap<TrackerID, B::F>> {
        crate::tracker_core::pipeline::batch_s_check_claims(self)
    }

    /// Convert the single batched zerocheck claim to a sumcheck claim.
    /// Delegates to the generic pipeline.
    #[instrument(level = "debug", skip(self))]
    fn z_check_claim_to_s_check_claim(&mut self, max_nv: usize) -> SnarkResult<()> {
        crate::tracker_core::pipeline::z_check_claim_to_s_check_claim(self, max_nv)
    }

    #[allow(clippy::type_complexity)]
    #[instrument(level = "debug", skip(self))]
    fn perform_single_sumcheck(
        &mut self,
    ) -> SnarkResult<(
        SumcheckProof<B::F>,
        VPAuxInfo<B::F>,
        SumcheckInvocationStats,
    )> {
        assert!(self.state.mv_pcs_substate.sum_check_claims.len() == 1);

        // Get the sumcheck claim polynomial id
        let sumcheck_aggr_id = self
            .state
            .mv_pcs_substate
            .sum_check_claims
            .last()
            .unwrap()
            .id();
        // Generate a sumcheck proof

        let sc_avp = self.to_hp_virtual_poly(sumcheck_aggr_id);
        debug!(
            "The final virtual polynomial for sumcheck has {} terms, {} degree, and {} number of variables",
            sc_avp.products.len(),
            sc_avp.aux_info.max_degree,
            sc_avp.aux_info.num_variables
        );
        let sc_aux_info = sc_avp.aux_info.clone();
        let sc_prove_started = Instant::now();
        let sc_proof = SumCheck::prove(&sc_avp, &mut self.state.transcript)?;
        let sumcheck_stats = SumcheckInvocationStats {
            degree: sc_avp.aux_info.max_degree,
            num_terms: sc_avp.products.len(),
            prove_time_s: sc_prove_started.elapsed().as_secs_f64(),
        };
        let _ = self.add_mv_eval_claim(sumcheck_aggr_id, &sc_proof.point);
        Ok((sc_proof, sc_aux_info, sumcheck_stats))
    }

    /// Deterministically reduces the degree of the single aggregated sumcheck claim.
    ///
    /// Algorithm:
    /// 1) Expand each claim term only until it is a product of *atoms*.
    ///    - Atom = material MLE, or a linear virtual polynomial
    ///      (sum of single-factor terms / scalar-times-MLE).
    ///    - We do *not* distribute atom products. For example, `(a+b)(c+d)` stays
    ///      as two factors if both factors are atoms.
    /// 2) While some terms exceed `SUMCHECK_TERM_DEGREE_LIMIT`, find the most
    ///    frequent contiguous size-`LIMIT` chunk among oversized terms.
    /// 3) Commit that chunk polynomial once, replace chunk occurrences by the new
    ///    tracked id, and add the corresponding zerocheck link constraint.
    ///
    /// The procedure is fully deterministic (stable ordering/tie-breaks) and
    /// mirrors verifier-side reduction.
    fn reduce_sumcheck_dgree(&mut self) -> SnarkResult<ReduceSumcheckDegreeStats> {
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
        let mut eval_cache: BTreeMap<(TrackerID, usize), Vec<B::F>> = BTreeMap::new();
        let mut committed_chunks: usize = 0;
        let mut oversized_terms_reduced: usize = 0;
        let mut claims_reduced: usize = 0;
        let mut rounds: usize = 0;
        let mut replacements: usize = 0;
        let mut expanded_terms_total: usize = 0;
        let mut expanded_oversized_terms: usize = 0;
        let mut total_terms: usize = 0;

        fn is_atom<B: SnarkBackend>(
            tracker: &ProverTracker<B>,
            id: TrackerID,
            memo: &mut BTreeMap<TrackerID, bool>,
        ) -> bool {
            if let Some(v) = memo.get(&id) {
                return *v;
            }
            let ans = if tracker.mat_mv_poly(id).is_some() {
                true
            } else if let Some(vpoly) = tracker.virt_poly(id) {
                vpoly.iter().all(|(_, term)| {
                    term.len() <= 1 && term.iter().all(|child| is_atom(tracker, *child, memo))
                })
            } else {
                false
            };
            memo.insert(id, ans);
            ans
        }

        #[allow(clippy::type_complexity)]
        fn expand_to_atoms<B: SnarkBackend>(
            tracker: &ProverTracker<B>,
            id: TrackerID,
            atom_memo: &mut BTreeMap<TrackerID, bool>,
            expand_memo: &mut BTreeMap<TrackerID, Vec<(B::F, Vec<TrackerID>)>>,
        ) -> Vec<(B::F, Vec<TrackerID>)> {
            if let Some(cached) = expand_memo.get(&id) {
                return cached.clone();
            }
            if is_atom(tracker, id, atom_memo) || tracker.mat_mv_poly(id).is_some() {
                return vec![(B::F::one(), vec![id])];
            }
            let Some(vpoly) = tracker.virt_poly(id) else {
                return vec![(B::F::one(), vec![id])];
            };

            let mut out: Vec<(B::F, Vec<TrackerID>)> = Vec::new();
            for (coeff, factors) in vpoly.iter() {
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

        fn eval_vector<B: SnarkBackend>(
            tracker: &ProverTracker<B>,
            id: TrackerID,
            target_nv: usize,
            cache: &mut BTreeMap<(TrackerID, usize), Vec<B::F>>,
        ) -> Vec<B::F> {
            if let Some(v) = cache.get(&(id, target_nv)) {
                return v.clone();
            }

            let target_len = 1usize << target_nv;
            let res = if let Some(mat) = tracker.mat_mv_poly(id) {
                let base = mat.evaluations();
                if base.len() == target_len {
                    base
                } else {
                    let mut expanded = Vec::with_capacity(target_len);
                    let repeat = target_len / base.len();
                    for _ in 0..repeat {
                        expanded.extend_from_slice(&base);
                    }
                    expanded
                }
            } else if let Some(vpoly) = tracker.virt_poly(id) {
                let mut acc = vec![B::F::zero(); target_len];
                for (coeff, factors) in vpoly.iter() {
                    let mut term = vec![*coeff; target_len];
                    for fid in factors.iter().copied() {
                        let fv = eval_vector(tracker, fid, target_nv, cache);
                        cfg_iter_mut!(term).zip(fv).for_each(|(a, b)| *a *= b);
                    }
                    cfg_iter_mut!(acc).zip(term).for_each(|(a, b)| *a += b);
                }
                acc
            } else {
                vec![B::F::zero(); target_len]
            };
            cache.insert((id, target_nv), res.clone());
            res
        }

        fn find_subslice(haystack: &[TrackerID], needle: &[TrackerID]) -> Option<usize> {
            if needle.is_empty() || haystack.len() < needle.len() {
                return None;
            }
            haystack.windows(needle.len()).position(|w| w == needle)
        }

        #[allow(clippy::too_many_arguments, clippy::type_complexity)]
        fn reduce_poly<B: SnarkBackend>(
            tracker: &mut ProverTracker<B>,
            poly_id: TrackerID,
            chunk_cache: &mut BTreeMap<Vec<TrackerID>, TrackerID>,
            atom_cache: &mut BTreeMap<TrackerID, bool>,
            extra_zero_claims: &mut Vec<TrackerID>,
            eval_cache: &mut BTreeMap<(TrackerID, usize), Vec<B::F>>,
            committed_chunks: &mut usize,
            oversized_terms_reduced: &mut usize,
            rounds: &mut usize,
            replacements: &mut usize,
            expanded_terms_total: &mut usize,
            expanded_oversized_terms: &mut usize,
        ) -> SnarkResult<TrackerID> {
            let max_term_degree = tracker.config.sumcheck_term_degree_limit - 1;

            if tracker.mat_mv_poly(poly_id).is_some() {
                return Ok(poly_id);
            }
            let virt_poly = match tracker.virt_poly(poly_id) {
                Some(poly) => poly.clone(),
                None => return Ok(poly_id),
            };

            let mut expand_memo: BTreeMap<TrackerID, Vec<(B::F, Vec<TrackerID>)>> = BTreeMap::new();
            let mut terms: Vec<(B::F, Vec<TrackerID>)> = Vec::new();
            for (coeff, ids) in virt_poly.iter() {
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
                        terms.push((c, acc_ids));
                    }
                }
            }
            let claim_term_count = terms.len();
            let claim_oversized = terms
                .iter()
                .filter(|(_, ids)| ids.len() > max_term_degree)
                .count();
            let claim_max_degree = terms.iter().map(|(_, ids)| ids.len()).max().unwrap_or(0);
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

            let atom_refs = terms
                .iter()
                .flat_map(|(_, ids)| ids.iter())
                .filter(|id| is_atom(tracker, **id, atom_cache))
                .count();
            debug!(
                claim_id = ?poly_id,
                atom_refs,
                "sumcheck degree reduction atomized claim"
            );

            fn commit_chunk<B: SnarkBackend>(
                tracker: &mut ProverTracker<B>,
                chunk: &[TrackerID],
                chunk_cache: &mut BTreeMap<Vec<TrackerID>, TrackerID>,
                extra_zero_claims: &mut Vec<TrackerID>,
                eval_cache: &mut BTreeMap<(TrackerID, usize), Vec<B::F>>,
                committed_chunks: &mut usize,
            ) -> SnarkResult<TrackerID> {
                if let Some(id) = chunk_cache.get(chunk).copied() {
                    return Ok(id);
                }
                // Keep all newly committed chunk polynomials on the global max domain.
                // `equalize_mat_poly_nv` already lifted existing materialized polynomials
                // to this nv before sumcheck compilation; using a smaller nv here would
                // re-introduce mixed-nv products and break HP virtual-poly construction.
                let nv = tracker.state.num_vars.values().max().copied().unwrap_or(0);
                let mut evals = vec![B::F::one(); 1 << nv];
                for id in chunk.iter().copied() {
                    let v = eval_vector(tracker, id, nv, eval_cache);
                    cfg_iter_mut!(evals).zip(v).for_each(|(a, b)| *a *= b);
                }
                let mle = Arc::new(MLE::from_evaluations_vec(nv, evals.clone()));
                let prover_param = tracker.pk.mv_pcs_param.clone();
                let com = B::MvPCS::commit(prover_param.as_ref(), &mle)?;
                let committed_id = tracker.track_mat_mv_p_with_commitment(
                    &mle,
                    com,
                    CommitmentBinding::ProofEmitted,
                    false,
                )?;
                chunk_cache.insert(chunk.to_vec(), committed_id);
                *committed_chunks += 1;
                eval_cache.insert((committed_id, nv), evals);
                let mut chunk_poly = VirtualPoly::new();
                chunk_poly.push((B::F::one(), chunk.to_vec()));
                let chunk_id = tracker.track_virt_poly(chunk_poly);
                let neg_committed = tracker.mul_scalar(committed_id, -B::F::one());
                let diff_id = tracker.add_polys(chunk_id, neg_committed);
                extra_zero_claims.push(diff_id);
                Ok(committed_id)
            }

            while terms.iter().any(|(_, ids)| ids.len() > max_term_degree) {
                *rounds += 1;
                let mut freq: BTreeMap<Vec<TrackerID>, usize> = BTreeMap::new();
                for (_, ids) in terms.iter().filter(|(_, ids)| ids.len() > max_term_degree) {
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
                    terms
                        .iter()
                        .find(|(_, ids)| ids.len() > max_term_degree)
                        .and_then(|(_, ids)| ids.get(0..max_term_degree).map(|s| s.to_vec()))
                        .expect("at least one oversized term must exist")
                };

                let committed_id = commit_chunk(
                    tracker,
                    &chosen,
                    chunk_cache,
                    extra_zero_claims,
                    eval_cache,
                    committed_chunks,
                )?;

                let mut replaced_in_round = 0usize;
                for (_, ids) in terms
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
                    && let Some((_, ids)) = terms
                        .iter_mut()
                        .find(|(_, ids)| ids.len() > max_term_degree)
                {
                    ids.splice(0..max_term_degree, [committed_id]);
                    replaced_in_round = 1;
                }
                *replacements += replaced_in_round;
            }

            let mut new_poly = VirtualPoly::new();
            for (coeff, ids) in terms.into_iter() {
                if !coeff.is_zero() {
                    new_poly.push((coeff, ids));
                }
            }
            let new_id = tracker.track_virt_poly(new_poly);
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
                &mut eval_cache,
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
            if let Some(vpoly) = self.virt_poly(new_id) {
                total_terms += vpoly.len();
            }
        }

        let extra_zero_claims_len = extra_zero_claims.len();
        for id in extra_zero_claims {
            self.add_mv_zerocheck_claim(id)?;
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

        Ok(ReduceSumcheckDegreeStats {
            max_degree: self.config.sumcheck_term_degree_limit,
            num_committed: committed_chunks,
        })
    }

    #[instrument(level = "debug", skip(self))]
    fn batch_nozero_check_claims(&mut self) -> SnarkResult<()> {
        let nozero_chunk_size = self.config.nozero_chunk_size;
        let nozero_claims = take(&mut self.state.mv_pcs_substate.no_zero_check_claims);
        if nozero_claims.is_empty() {
            return Ok(());
        }

        // Use the largest nv in the tracker so all committed chunk polys share a domain.
        let max_nv = self.state.num_vars.values().max().copied().unwrap_or(0);
        let num_claims = nozero_claims.len();
        let mut chunk_comm_ids = Vec::new(); // committed chunk products (materialized)
        let mut master_prod_id = None; // virtual product of chunk commitments
        let mut master_evals: Option<Vec<B::F>> = None; // evals of the same product

        for chunk in nozero_claims.chunks(nozero_chunk_size) {
            let mut iter = chunk.iter();
            let first = iter
                .next()
                .expect("nozero_claims chunk should be non-empty");
            // 1) Multiply polynomials in the chunk (virtual product + evals).
            let mut chunk_prod_id = first.id();
            let mut chunk_evals = self.evaluations(first.id());
            for claim in iter {
                let id = claim.id();
                chunk_prod_id = self.mul_polys(chunk_prod_id, id);
                let evals = self.evaluations(id);
                debug_assert_eq!(chunk_evals.len(), evals.len());
                cfg_iter_mut!(chunk_evals)
                    .zip(evals)
                    .for_each(|(a, b)| *a *= b);
            }

            // 2) Expand evals to max_nv (by repetition) and commit to the chunk product.
            let base_len = chunk_evals.len();
            debug_assert!(base_len.is_power_of_two());
            let base_nv = base_len.trailing_zeros() as usize;
            if base_nv < max_nv {
                let expand = 1usize << (max_nv - base_nv);
                let mut expanded = Vec::with_capacity(base_len * expand);
                // Keep evaluation ordering consistent with `MLE::new(..., Some(max_nv))`,
                // which repeats the whole evaluation vector cyclically.
                for _ in 0..expand {
                    expanded.extend_from_slice(&chunk_evals);
                }
                chunk_evals = expanded;
            }
            let chunk_mle = MLE::from_evaluations_vec(max_nv, chunk_evals.clone());
            let result = self.track_and_commit_mat_mv_p(&chunk_mle, false)?;
            let chunk_comm_id = match result {
                Either::Left(id) => id,
                Either::Right((id, _cnst)) => {
                    // Constant chunk: register the MLE so tracker-level
                    // operations (sub_polys, mul_polys) can find it.
                    self.register_mat_mv_poly(id, chunk_mle);
                    id
                }
            };
            // Link committed chunk to its virtual definition: c_i - prod_i == 0.
            let diff_id = self.sub_polys(chunk_comm_id, chunk_prod_id);
            self.add_mv_zerocheck_claim(diff_id)?;

            // 3) Accumulate committed chunks into a master product (virtual + evals).
            master_prod_id = Some(match master_prod_id {
                None => chunk_comm_id,
                Some(acc) => self.mul_polys(acc, chunk_comm_id),
            });
            master_evals = Some(match master_evals {
                None => chunk_evals,
                Some(mut acc) => {
                    debug_assert_eq!(acc.len(), chunk_evals.len());
                    cfg_iter_mut!(acc)
                        .zip(chunk_evals)
                        .for_each(|(a, b)| *a *= b);
                    acc
                }
            });
            chunk_comm_ids.push(chunk_comm_id);
        }

        let master_prod_id = master_prod_id.expect("nozero_claims should be non-empty");
        let mut master_evals = master_evals.expect("nozero_claims should be non-empty");

        debug!(
            "{} nozerocheck polynomials chunked into {}; final degree {}",
            num_claims,
            chunk_comm_ids.len(),
            self.virt_poly_degree(master_prod_id)
        );

        // 4) Commit to the inverse of the master product and enforce prod * inv == 1.
        batch_inversion(&mut master_evals);
        let inverses_mle = MLE::from_evaluations_vec(max_nv, master_evals);
        let inv_result = self.track_and_commit_mat_mv_p(&inverses_mle, false)?;
        let inverses_poly_id = match inv_result {
            Either::Left(id) => id,
            Either::Right((id, _cnst)) => {
                self.register_mat_mv_poly(id, inverses_mle);
                id
            }
        };

        let prod_inv_id = self.mul_polys(master_prod_id, inverses_poly_id);
        let diff_id = self.add_scalar(prod_inv_id, -B::F::one());
        self.add_mv_zerocheck_claim(diff_id)?;

        Ok(())
    }

    /// Reduces every zero-check claim, sum-check claim in
    /// the prover state, into a list of evaluation claims. These evaluation
    /// claims will be proved using a PCS
    #[instrument(level = "debug", skip(self))]
    pub(super) fn compile_sc_subproof(
        &mut self,
        max_nv: usize,
    ) -> SnarkResult<Option<SumcheckSubproof<B::F>>> {
        let mut timing_breakdown = ScCompileTimingBreakdown::default();
        let before_initial = self.current_claim_stage_stats();
        let nozero_batching_started = Instant::now();
        self.batch_nozero_check_claims()?;
        timing_breakdown.nozerocheck_batching_time_s =
            nozero_batching_started.elapsed().as_secs_f64();
        let before_after_nozero_batching = self.current_claim_stage_stats();
        // Batch all the zero-check claims into one claim, remove old zerocheck claims
        let first_batch_zerocheck_started = Instant::now();
        self.batch_z_check_claims()?;
        timing_breakdown.first_batch_zerocheck_time_s =
            first_batch_zerocheck_started.elapsed().as_secs_f64();
        let before_after_zero_batching = self.current_claim_stage_stats();
        // Convert the only zerocheck claim to a sumcheck claim
        let first_zerocheck_to_sumcheck_started = Instant::now();
        self.z_check_claim_to_s_check_claim(max_nv)?;
        timing_breakdown.first_zerocheck_to_sumcheck_time_s =
            first_zerocheck_to_sumcheck_started.elapsed().as_secs_f64();
        // Batch all the sumcheck claims into one sumcheck claim
        let first_batch_sumcheck_started = Instant::now();
        let mut individual_sumcheck_claims = self.batch_s_check_claims()?;
        timing_breakdown.first_batch_sumcheck_time_s =
            first_batch_sumcheck_started.elapsed().as_secs_f64();
        let before_after_sum_batching = self.current_claim_stage_stats();
        if self.state.mv_pcs_substate.sum_check_claims.is_empty() {
            debug!("No sumcheck claims to prove",);
            let after_initial = ClaimStageStats::default();
            let after_after_zero_batching = ClaimStageStats::default();
            let after_after_sum_batching = ClaimStageStats::default();
            self.emit_claim_pipeline_stats(
                &before_initial,
                &before_after_nozero_batching,
                &before_after_zero_batching,
                &before_after_sum_batching,
                &after_initial,
                &after_after_zero_batching,
                &after_after_sum_batching,
            );
            self.emit_sc_compile_timing_breakdown(timing_breakdown);
            return Ok(None);
        }

        // Reduce high-degree terms deterministically before sumcheck.
        let reduce_sumcheck_started = Instant::now();
        let _reduce_stats = self.reduce_sumcheck_dgree()?;
        timing_breakdown.reduce_sumcheck_time_s = reduce_sumcheck_started.elapsed().as_secs_f64();
        let after_initial = self.current_claim_stage_stats();

        // Batch all the zero-check claims into one claim, remove old zerocheck claims
        let second_batch_zerocheck_started = Instant::now();
        self.batch_z_check_claims()?;
        timing_breakdown.second_batch_zerocheck_time_s =
            second_batch_zerocheck_started.elapsed().as_secs_f64();
        let after_after_zero_batching = self.current_claim_stage_stats();
        // Convert the only zerocheck claim to a sumcheck claim
        let second_zerocheck_to_sumcheck_started = Instant::now();
        self.z_check_claim_to_s_check_claim(max_nv)?;
        timing_breakdown.second_zerocheck_to_sumcheck_time_s =
            second_zerocheck_to_sumcheck_started.elapsed().as_secs_f64();
        // Batch all the sumcheck claims into one sumcheck claim
        let additional_sumcheck_claims = self.batch_s_check_claims()?;
        let after_after_sum_batching = self.current_claim_stage_stats();
        for (id, claim) in additional_sumcheck_claims {
            individual_sumcheck_claims.entry(id).or_insert(claim);
        }
        // if self.state.mv_pcs_substate.sum_check_claims.is_empty() {
        //     debug!("No sumcheck claims to prove",);
        //     return Ok(None);
        // }
        // Perform the one batched sumcheck
        let sumcheck_started = Instant::now();
        let (sc_proof, sc_aux_info, _sumcheck_stats) = self.perform_single_sumcheck()?;
        timing_breakdown.sumcheck_time_s = sumcheck_started.elapsed().as_secs_f64();
        self.emit_claim_pipeline_stats(
            &before_initial,
            &before_after_nozero_batching,
            &before_after_zero_batching,
            &before_after_sum_batching,
            &after_initial,
            &after_after_zero_batching,
            &after_after_sum_batching,
        );
        self.emit_sc_compile_timing_breakdown(timing_breakdown);
        // Assemble the sumcheck subproof of the prover
        let sc_subproof = SumcheckSubproof::new(
            sc_proof.clone(),
            sc_aux_info.clone(),
            individual_sumcheck_claims,
        );
        Ok(Some(sc_subproof))
    }
}
