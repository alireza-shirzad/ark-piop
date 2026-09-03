//! Sumcheck-side of proof compilation: claim batching, degree reduction,
//! the single aggregated sumcheck invocation, nozerocheck batching, and the
//! orchestrating `compile_piop_subproof`.

use super::super::*;
// Mid-function span wrapper for the bucket-pipeline stages; whole functions
// use `#[piop_stage]` instead.
use super::region;

use crate::pcs::PolynomialCommitment;
impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    /// Converts all the zerocheck claims into a single zero-check claim via random
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
    fn perform_single_sumcheck(&mut self) -> SnarkResult<(SumcheckProof<B::F>, VPAuxInfo<B::F>)> {
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
        let sc_proof = SumCheck::prove(&sc_avp, &mut self.state.transcript)?;
        let _ = self.add_mv_eval_claim(sumcheck_aggr_id, &sc_proof.point);
        Ok((sc_proof, sc_aux_info))
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
    fn reduce_sumcheck_dgree(&mut self, target_nv: usize) -> SnarkResult<()> {
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

        /// Evaluate poly `id` to a `Vec<F>` at its NATIVE size (never larger
        /// than `1 << target_nv`): leaf polys at their inner storage size,
        /// virtual polys at the max native size of their factors. Consumers
        /// cyclically broadcast (`v[i % v.len()]`) up to target positions.
        /// This is the key memory optimization for large buckets — full
        /// target-size intermediates at nv 28 were 8 GiB each.
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
                // Read via `lift` so the virtual-nv repetition is never
                // materialized.
                let inner_len = 1usize << mat.storage().inner_num_vars();
                let native_len = inner_len.min(target_len).max(1);
                (0..native_len).map(|i| mat.storage().lift(i)).collect()
            } else if let Some(vpoly) = tracker.virt_poly(id) {
                // Evaluate factors first to size `acc` at the max native
                // length; smaller factors broadcast cyclically into `term`.
                let mut term_factors: Vec<Vec<Vec<B::F>>> = Vec::with_capacity(vpoly.len());
                let mut max_len: usize = 1;
                for (_, factors) in vpoly.iter() {
                    let mut fv_list: Vec<Vec<B::F>> = Vec::with_capacity(factors.len());
                    for fid in factors.iter().copied() {
                        let fv = eval_vector(tracker, fid, target_nv, cache);
                        max_len = max_len.max(fv.len());
                        fv_list.push(fv);
                    }
                    term_factors.push(fv_list);
                }
                let max_len = max_len.min(target_len).max(1);
                let mut acc = vec![B::F::zero(); max_len];
                for ((coeff, _), fv_list) in vpoly.iter().zip(term_factors.into_iter()) {
                    let mut term = vec![*coeff; max_len];
                    for fv in fv_list {
                        let fv_len = fv.len();
                        if fv_len == max_len {
                            cfg_iter_mut!(term).zip(fv).for_each(|(a, b)| *a *= b);
                        } else {
                            // Cyclic broadcast: term[i] *= fv[i % fv_len].
                            cfg_iter_mut!(term)
                                .enumerate()
                                .for_each(|(i, a)| *a *= fv[i % fv_len]);
                        }
                    }
                    cfg_iter_mut!(acc).zip(term).for_each(|(a, b)| *a += b);
                }
                acc
            } else {
                vec![B::F::zero(); 1]
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
            target_nv: usize,
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
                target_nv: usize,
            ) -> SnarkResult<TrackerID> {
                if let Some(id) = chunk_cache.get(chunk).copied() {
                    return Ok(id);
                }
                // Chunks commit at the bucket's own target_nv, keeping a
                // smaller bucket's chunks off a larger bucket's hypercube.
                let nv = target_nv;
                let target_len = 1usize << nv;
                let mut evals = vec![B::F::one(); target_len];
                for id in chunk.iter().copied() {
                    let v = eval_vector(tracker, id, nv, eval_cache);
                    let v_len = v.len();
                    if v_len == target_len {
                        cfg_iter_mut!(evals).zip(v).for_each(|(a, b)| *a *= b);
                    } else {
                        // Cyclic broadcast up to the target hypercube.
                        cfg_iter_mut!(evals)
                            .enumerate()
                            .for_each(|(i, a)| *a *= v[i % v_len]);
                    }
                }
                // Move `evals` into the MLE — cloning an 8 GiB Vec here was a
                // major transient memory spike.
                let mle = Arc::new(MLE::from_evaluations_vec(nv, evals));
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
                // Do NOT re-cache `evals`: the poly is now a tracker leaf
                // that `eval_vector` reads natively; keeping a huge Vec alive
                // in the cache would defeat the native-size point.
                let _ = eval_cache;
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
                    target_nv,
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
                target_nv,
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

        Ok(())
    }

    /// Discharge every pending nozerocheck claim, one `num_vars` group at a
    /// time, leaving the link constraints on the zerocheck list. Runs before
    /// bucketing so the partitioner never sees a nozerocheck claim. Groups
    /// are walked in ascending nv so both sides commit — and the verifier
    /// tracks ids off `peek_next_id` — in the same order.
    #[instrument(level = "debug", skip(self))]
    fn batch_nozero_check_claims_by_nv(&mut self) -> SnarkResult<()> {
        let claims = take(&mut self.state.mv_pcs_substate.no_zero_check_claims);
        if claims.is_empty() {
            return Ok(());
        }

        let mut by_nv: BTreeMap<usize, Vec<TrackerNoZerocheckClaim>> = BTreeMap::new();
        for claim in claims {
            by_nv
                .entry(self.poly_nv(claim.id()))
                .or_default()
                .push(claim);
        }

        for (nv, group) in by_nv {
            self.state.mv_pcs_substate.no_zero_check_claims = group;
            self.batch_nozero_check_claims(nv)?;
        }

        Ok(())
    }

    #[instrument(level = "debug", skip(self))]
    fn batch_nozero_check_claims(&mut self, target_nv: usize) -> SnarkResult<()> {
        let nozero_chunk_size = self.config.nozero_chunk_size;
        let nozero_claims = take(&mut self.state.mv_pcs_substate.no_zero_check_claims);
        if nozero_claims.is_empty() {
            return Ok(());
        }

        // Commit chunk polys at `target_nv`. Called per nv group, so this is
        // the group's own width and the expansion below is a no-op; the
        // branch stays for any caller whose claims sit under `target_nv`.
        let max_nv = target_nv;
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

    /// Run the full sumcheck compile pipeline for **one bucket** at its
    /// `target_nv`: installs the bucket's claims into `state`, and produces
    /// at most one [`SumcheckBucketProof`], the pre-batching claim map to
    /// embed in the proof, and a [`BucketRunStats`] snapshot. Emits no
    /// `bench_stats` events itself (deferred to the caller so buckets don't
    /// overwrite each other) and measures no timings (the nested tracing
    /// spans carry those).
    #[allow(clippy::type_complexity)]
    #[instrument(
        target = "bench_stats",
        level = "info",
        name = "sc_bucket",
        skip(self, bucket),
        fields(target_nv = bucket.target_nv)
    )]
    #[piop_stage(
        snapshot_start = "bucket_{bucket_index}_start",
        snapshot_end = "bucket_{bucket_index}_end"
    )]
    fn run_bucket(
        &mut self,
        bucket_index: usize,
        bucket: SumcheckBucket<B>,
    ) -> SnarkResult<(
        Option<SumcheckBucketProof<B::F>>,
        BTreeMap<TrackerID, B::F>,
        BucketRunStats,
    )> {
        let SumcheckBucket {
            target_nv,
            included_nvs,
            sum_check_claims,
        } = bucket;

        // Zero/nozero counts are zero by construction — both kinds were
        // discharged before partitioning; kept so the record keeps its shape.
        let mut stats = BucketRunStats {
            bucket_index,
            target_nv,
            included_nvs,
            n_zerocheck_claims: 0,
            n_sumcheck_claims: sum_check_claims.len(),
            n_nozerocheck_claims: 0,
            ..Default::default()
        };

        // `equalize_mat_poly_nv_to` only lifts polys below `target_nv`, so
        // polys native to a smaller bucket keep their own size.
        self.state.mv_pcs_substate.sum_check_claims = sum_check_claims;
        self.equalize_mat_poly_nv_to(target_nv);

        stats.before_initial = self.current_claim_stage_stats();
        // Identical by construction; kept so the stats record keeps its shape.
        stats.before_after_nozero_batching = self.current_claim_stage_stats();
        stats.before_after_zero_batching = self.current_claim_stage_stats();
        let mut individual_sumcheck_claims =
            region!("first_batch_sumcheck", self.batch_s_check_claims()?);
        stats.before_after_sum_batching = self.current_claim_stage_stats();
        if self.state.mv_pcs_substate.sum_check_claims.is_empty() {
            debug!("No sumcheck claims to prove in this bucket");
            return Ok((None, individual_sumcheck_claims, stats));
        }

        region!("reduce_sumcheck", self.reduce_sumcheck_dgree(target_nv)?);
        stats.after_initial = self.current_claim_stage_stats();

        region!("second_batch_zerocheck", self.batch_z_check_claims()?);
        stats.after_after_zero_batching = self.current_claim_stage_stats();
        region!(
            "second_zerocheck_to_sumcheck",
            self.z_check_claim_to_s_check_claim(target_nv)?
        );
        // Untimed so the reported breakdown keeps its shape.
        let additional_sumcheck_claims = self.batch_s_check_claims()?;
        stats.after_after_sum_batching = self.current_claim_stage_stats();
        for (id, claim) in additional_sumcheck_claims {
            individual_sumcheck_claims.entry(id).or_insert(claim);
        }
        let (sc_proof, sc_aux_info) = region!("sumcheck", self.perform_single_sumcheck()?);

        // `perform_single_sumcheck` reads but doesn't consume the aggregated
        // claim; clear it so the next bucket starts clean.
        self.state.mv_pcs_substate.sum_check_claims.clear();

        Ok((
            Some(SumcheckBucketProof::new(sc_proof, sc_aux_info)),
            individual_sumcheck_claims,
            stats,
        ))
    }

    /// Drain the sumcheck claims and partition them into buckets.
    #[instrument(level = "debug", skip(self))]
    fn create_buckets(&mut self) -> Vec<SumcheckBucket<B>> {
        // 1. First check that all the zerocheck and nozercheck claims are drained
        assert!(
            self.state.mv_pcs_substate.zero_check_claims.is_empty()
                && self.state.mv_pcs_substate.no_zero_check_claims.is_empty(),
            "claims reached bucketing unconverted: {} zerocheck, {} nozerocheck",
            self.state.mv_pcs_substate.zero_check_claims.len(),
            self.state.mv_pcs_substate.no_zero_check_claims.len(),
        );
        // 2. Drain all the sumcheck claims
        let sum_check_claims = take(&mut self.state.mv_pcs_substate.sum_check_claims);
        // 3. Get the cost model for bucketing from the prover configuration
        let model =
            crate::tracker_core::bucketing::CostModel::new(self.config.sumcheck_term_degree_limit);
        // 4. Build the buckets
        crate::tracker_core::bucketing::build_buckets::<B, _>(self, sum_check_claims, model)
    }

    /// Merge one bucket's pre-batching sumcheck claims into the proof-wide
    /// map, rescaling each sum from the bucket's `target_nv` up to the common
    /// `global_max_nv` frame. Feeds the `SumcheckSubproof::sumcheck_claims`
    /// side channel only; each bucket's own sumcheck is unaffected.
    fn merge_bucket_claims(
        all_claims: &mut BTreeMap<TrackerID, B::F>,
        bucket_claims: BTreeMap<TrackerID, B::F>,
        target_nv: usize,
        global_max_nv: usize,
    ) {
        let scale = if global_max_nv > target_nv {
            B::F::from(1u64 << (global_max_nv - target_nv))
        } else {
            B::F::one()
        };
        for (id, value) in bucket_claims {
            all_claims.entry(id).or_insert(value * scale);
        }
    }

    /// Prove every bucket in order, collecting its proof, its rescaled
    /// claims, and its stats, then emit the stats events for the run.
    fn run_all_buckets(&mut self, buckets: Vec<SumcheckBucket<B>>) -> SnarkResult<BucketRun<B::F>> {
        let global_max_nv = self
            .state
            .mv_pcs_substate
            .materialized_comms
            .values()
            .map(|c| c.log_size() as usize)
            .max()
            .unwrap_or(1);
        let mut run = BucketRun::with_capacity(buckets.len());
        for (bucket_index, bucket) in buckets.into_iter().enumerate() {
            let target_nv = bucket.target_nv;
            let (proof, claims, stats) = self.run_bucket(bucket_index, bucket)?;
            run.proofs.extend(proof);
            Self::merge_bucket_claims(&mut run.claims, claims, target_nv, global_max_nv);
            run.stats.push(stats);
        }
        self.emit_aggregate_bucket_stats(&run.stats);
        self.emit_per_bucket_stats(&run.stats);
        Ok(run)
    }

    /// Run the PIOP based protocols and get the PIOP subproof
    #[piop_stage(
        span = "compile_piop_subproof",
        snapshot_start = "compile_start",
        snapshot_end = "after_compile_piop_subproof"
    )]
    pub(super) fn compile_piop_subproof(&mut self) -> SnarkResult<Option<SumcheckSubproof<B::F>>> {
        region!(
            "nozerocheck_batching",
            self.batch_nozero_check_claims_by_nv()?
        );
        region!(
            "first_zerocheck_to_sumcheck",
            crate::tracker_core::pipeline::convert_zerochecks_by_nv(self)?
        );
        let buckets = self.create_buckets();
        if buckets.is_empty() {
            return Ok(None);
        }
        let run = self.run_all_buckets(buckets)?;
        Ok(run.into_subproof())
    }
}
