//! Claim registration — adding sumcheck, zerocheck, nozerocheck, lookup, and eval claims.

use super::*;
use crate::piop::errors::PolyIOPErrors;

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    /// Generate the challenge from the current transcript
    /// and append it to the transcript.
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<B::F> {
        self.state
            .transcript
            .get_and_append_challenge(label)
            .map_err(SnarkError::from)
    }

    /// Adds a sumcheck claim to the list of the sumcheck claims of the prover
    /// a sumcheck claim is of the form (poly_id, claimed_sum) which means that
    /// the prover claims that the sum of the evaluations of the polynomial with
    /// poly_id is claimed_sum
    // TODO: Remove the claimed_sum
    pub fn add_mv_sumcheck_claim(
        &mut self,
        poly_id: TrackerID,
        claimed_sum: B::F,
    ) -> SnarkResult<()> {
        #[cfg(feature = "honest-prover")]
        {
            let evals = self.evaluations(poly_id);
            let real_sum = cfg_iter!(evals).sum::<B::F>();
            if real_sum != claimed_sum {
                tracing::error!(
                    "honest prover sumcheck mismatch: real_sum={:?} claimed_sum={:?}",
                    real_sum,
                    claimed_sum
                );
                return Err(ProverError(HonestProverError(FalseClaim)));
            }
        }
        self.state
            .mv_pcs_substate
            .sum_check_claims
            .push(TrackerSumcheckClaim::new(poly_id, claimed_sum));
        Ok(())
    }

    /// Adds a zerocheck claim to the list of the zerocheck claims of the prover
    /// a zerocheck claim is of the form (poly_id) which means that the prover
    /// claims that the polynomial with poly_id evaluates to zero all over the
    /// boolean hypercube
    pub fn add_mv_zerocheck_claim(&mut self, poly_id: TrackerID) -> SnarkResult<()> {
        if let Some(poly) = self.virt_poly(poly_id) {
            trace!(?poly_id, ?poly, "add_mv_zerocheck_claim virtual");
        } else {
            trace!(?poly_id, "add_mv_zerocheck_claim materialized");
        }
        #[cfg(feature = "honest-prover")]
        {
            let evals = self.evaluations(poly_id);
            if cfg_iter!(evals).any(|eval| *eval != B::F::zero()) {
                tracing::error!("The emitted Zerocheck claim is false");
                return Err(ProverError(HonestProverError(FalseClaim)));
            }
        }
        self.state
            .mv_pcs_substate
            .zero_check_claims
            .push(TrackerZerocheckClaim::new(poly_id));
        Ok(())
    }

    /// Adds a nozerocheck claim to the list of the nozerocheck claims of the prover
    /// a nozerocheck claim is of the form (poly_id) which means that the prover
    /// claims that the polynomial with poly_id evaluates to zero all over the
    /// boolean hypercube
    pub fn add_mv_nozerocheck_claim(&mut self, poly_id: TrackerID) -> SnarkResult<()> {
        if let Some(poly) = self.virt_poly(poly_id) {
            trace!(?poly_id, ?poly, "add_mv_nozerocheck_claim virtual");
        } else {
            trace!(?poly_id, "add_mv_nozerocheck_claim materialized");
        }
        #[cfg(feature = "honest-prover")]
        {
            let evals = self.evaluations(poly_id);
            if cfg_iter!(evals).any(|eval| *eval == B::F::zero()) {
                tracing::error!("error");
                return Err(ProverError(HonestProverError(FalseClaim)));
            }
        }
        self.state
            .mv_pcs_substate
            .no_zero_check_claims
            .push(TrackerNoZerocheckClaim::new(poly_id));
        Ok(())
    }

    /// Add a multivariate lookup claim to the proof
    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_lookup_claim(
        &mut self,
        super_id: TrackerID,
        sub_id: TrackerID,
    ) -> SnarkResult<()> {
        #[cfg(feature = "honest-prover")]
        {
            let super_evals = self.evaluations(super_id);
            let sub_evals = self.evaluations(sub_id);
            let super_eval_set: HashSet<B::F> = super_evals.into_iter().collect();
            if cfg_iter!(sub_evals).any(|eval| !super_eval_set.contains(eval)) {
                let mut missing_examples = Vec::new();
                let mut missing_count = 0usize;
                for eval in sub_evals.iter() {
                    if !super_eval_set.contains(eval) {
                        missing_count += 1;
                        if missing_examples.len() < 4 {
                            missing_examples.push(*eval);
                        }
                    }
                }
                tracing::error!(
                    ?super_id,
                    ?sub_id,
                    missing_count,
                    ?missing_examples,
                    "add_mv_lookup_claim honest subset failed"
                );
                return Err(ProverError(HonestProverError(FalseClaim)));
            }
        }
        self.state
            .mv_pcs_substate
            .lookup_claims
            .push(TrackerLookupClaim::new(super_id, sub_id));
        Ok(())
    }

    pub(crate) fn take_lookup_claims(&mut self) -> Vec<TrackerLookupClaim> {
        take(&mut self.state.mv_pcs_substate.lookup_claims)
    }

    /// Adds an evaluation claim to the list of the zerocheck claims of the
    /// prover a zerocheck claim is of the form (poly_id) which means that
    /// the prover claims that the polynomial with poly_id evaluates to zero
    /// all over the boolean hypercube
    pub fn add_uv_eval_claim(&mut self, poly_id: TrackerID, point: B::F) -> SnarkResult<()> {
        self.state
            .uv_pcs_substate
            .eval_claims
            .push(TrackerEvalClaim::new(poly_id, point));
        Ok(())
    }

    pub fn insert_miscellaneous_field(&mut self, key: String, field: B::F) {
        self.state.miscellaneous_field_elements.insert(key, field);
    }

    pub fn miscellaneous_field_element(&self, label: &str) -> SnarkResult<B::F> {
        self.state
            .miscellaneous_field_elements
            .get(label)
            .cloned()
            .ok_or_else(|| {
                SnarkError::from(PolyIOPErrors::InvalidParameters(format!(
                    "prover state has no miscellaneous field element with label {:?}",
                    label
                )))
            })
    }

    pub fn add_mv_eval_claim(&mut self, poly_id: TrackerID, point: &[B::F]) -> SnarkResult<()> {
        self.state
            .mv_pcs_substate
            .eval_claims
            .push(TrackerEvalClaim::new(poly_id, point.to_vec()));
        Ok(())
    }

    pub fn get_or_build_contig_one_poly(
        &mut self,
        nv: usize,
        n: usize,
    ) -> SnarkResult<TrackedPoly<B>> {
        self.get_or_build_contig_skipped_one_poly(nv, n, 0)
    }

    pub fn get_or_build_contig_skipped_one_poly(
        &mut self,
        nv: usize,
        n: usize,
        s: usize,
    ) -> SnarkResult<TrackedPoly<B>> {
        let label = format!("contig_one_nv{}_skip{}_n{}", nv, s, n);
        if let Some(poly) = self.state.indexed_tracked_polys.get(&label) {
            return Ok(poly.clone());
        }

        let total = 1usize << nv;
        let end = s.checked_add(n).ok_or_else(|| {
            SnarkError::SetupError(NoRangePoly(format!(
                "contig_one_poly has overflow in s + n: s={}, n={}, nv={}",
                s, n, nv
            )))
        })?;
        if end > total {
            return Err(SnarkError::SetupError(NoRangePoly(format!(
                "contig_one_poly has s + n > 2^nv: s={}, n={}, nv={}",
                s, n, nv
            ))));
        }

        let mut evals = vec![B::F::zero(); total];
        evals[s..end].fill(B::F::one());
        let mle = MLE::from_evaluations_vec(nv, evals);
        let poly_id = self.track_mat_mv_poly(mle);

        let tracker_rc = if let Some(poly) = self.state.indexed_tracked_polys.values().next() {
            poly.tracker()
        } else if let Some(self_rc) = &self.self_rc {
            let tracker_rc: Rc<RefCell<ProverTracker<B>>> =
                Weak::upgrade(self_rc).ok_or_else(|| {
                    SnarkError::SetupError(NoRangePoly(
                        "contig_one_poly requires a tracker handle; self_rc is dead".to_string(),
                    ))
                })?;
            tracker_rc
        } else {
            return Err(SnarkError::SetupError(NoRangePoly(
                "contig_one_poly requires a tracker handle; none available".to_string(),
            )));
        };

        let tracked = TrackedPoly::new(Either::Left(poly_id), nv, tracker_rc);
        self.state
            .indexed_tracked_polys
            .insert(label, tracked.clone());
        Ok(tracked)
    }
}
