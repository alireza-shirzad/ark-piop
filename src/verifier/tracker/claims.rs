//! Claim registration and indexed oracles for the verifier.

use super::*;
use crate::piop::keyed_sumcheck::reduction::KeyedSumRelation;

impl<B: SnarkBackend> VerifierTracker<B> {
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<B::F> {
        self.state
            .transcript
            .get_and_append_challenge(label)
            .map_err(SnarkError::from)
    }

    pub fn miscellaneous_field_element(&self, label: &str) -> SnarkResult<B::F> {
        self.proof
            .as_ref()
            .and_then(|proof| proof.miscellaneous_field_elements.get(label).cloned())
            .ok_or_else(|| {
                SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                    "proof has no miscellaneous field element with label {:?}",
                    label
                )))
            })
    }

    pub fn miscellaneous_field_vector(&self, label: &str) -> SnarkResult<Vec<B::F>> {
        self.proof
            .as_ref()
            .and_then(|proof| proof.miscellaneous_field_vectors.get(label).cloned())
            .ok_or_else(|| {
                SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                    "proof has no miscellaneous field vector with label {:?}",
                    label
                )))
            })
    }

    /// Adds a claim that `poly_id` sums to `claimed_sum`.
    ///
    /// The sum is over the polynomial's own hypercube, unless it is the one
    /// the verifier read for this polynomial with
    /// [`Self::prover_claimed_sum`]: that one is in the frame of the proof's
    /// claim map. Which of the two it is depends on what the verifier did,
    /// never on what the map holds for a polynomial it was not read for.
    ///
    /// A polynomial whose sum was read from the proof should not also be
    /// claimed with a sum of the verifier's own: one that equals the map's
    /// entry cannot be told from the one that was read.
    pub fn add_mv_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: B::F) {
        let read_from_proof = self.state.claimed_sums_read.contains(&poly_id)
            && self.proof_claimed_sum(poly_id) == Some(claimed_sum);
        let claim = match read_from_proof {
            true => TrackerSumcheckClaim::new_from_proof(poly_id, claimed_sum),
            false => TrackerSumcheckClaim::new(poly_id, claimed_sum),
        };
        self.state.mv_pcs_substate.sum_check_claims.push(claim);
    }

    /// Adds a sumcheck claim whose sum the verifier derived itself, over the
    /// polynomial's own hypercube. The proof's claim map is not bound by the
    /// transcript, so such a claim must never be compared against it: the
    /// sum is lifted to the bucket by the verifier alone. The prover has to
    /// add the same claim with its raw entry point.
    pub(crate) fn add_mv_sumcheck_claim_raw(&mut self, poly_id: TrackerID, claimed_sum: B::F) {
        self.state
            .mv_pcs_substate
            .sum_check_claims
            .push(TrackerSumcheckClaim::new_raw(poly_id, claimed_sum));
    }

    /// The pending sumcheck claims as `(id, claimed sum, raw)`, in order.
    #[cfg(test)]
    pub(crate) fn sumcheck_claims_snapshot(&self) -> Vec<(TrackerID, B::F, bool)> {
        self.state
            .mv_pcs_substate
            .sum_check_claims
            .iter()
            .map(|claim| (claim.id(), claim.claim(), claim.is_raw()))
            .collect()
    }

    pub fn add_mv_zerocheck_claim(&mut self, poly_id: TrackerID) {
        if let Some(terms) = self.state.virtual_polys.get(&poly_id) {
            trace!(?poly_id, ?terms, "add_mv_zerocheck_claim virtual");
        } else {
            trace!(?poly_id, "add_mv_zerocheck_claim materialized");
        }
        self.state
            .mv_pcs_substate
            .zero_check_claims
            .push(TrackerZerocheckClaim::new(poly_id));
    }

    /// Adds a nozerocheck claim to the verifier state.
    pub fn add_mv_nozerocheck_claim(&mut self, poly_id: TrackerID) {
        if let Some(terms) = self.state.virtual_polys.get(&poly_id) {
            trace!(?poly_id, ?terms, "add_mv_nozerocheck_claim virtual");
        } else {
            trace!(?poly_id, "add_mv_nozerocheck_claim materialized");
        }
        self.state
            .mv_pcs_substate
            .no_zero_check_claims
            .push(TrackerNoZerocheckClaim::new(poly_id));
    }

    pub fn add_mv_lookup_claim(
        &mut self,
        super_id: TrackerID,
        sub_id: TrackerID,
    ) -> SnarkResult<()> {
        self.state
            .mv_pcs_substate
            .lookup_claims
            .push(TrackerLookupClaim::new(super_id, sub_id));
        Ok(())
    }

    pub(crate) fn take_lookup_claims(&mut self) -> Vec<TrackerLookupClaim> {
        take(&mut self.state.mv_pcs_substate.lookup_claims)
    }

    /// Queue a keyed sum for the reduction that runs before the proof is
    /// verified. The caller has checked its shape.
    pub(crate) fn add_mv_keyed_sum_claim(&mut self, relation: KeyedSumRelation<B::F>) {
        self.state.keyed_sum_claims.push(relation);
    }

    pub(crate) fn take_keyed_sum_claims(&mut self) -> Vec<KeyedSumRelation<B::F>> {
        take(&mut self.state.keyed_sum_claims)
    }

    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_eval_claim(
        &mut self,
        poly_id: TrackerID,
        point: &[B::F],
        eval: B::F,
    ) -> SnarkResult<()> {
        self.state
            .mv_pcs_substate
            .eval_claims
            .insert(((poly_id, point.to_vec()), eval));
        Ok(())
    }

    // Set range comitments for the tracker
    pub(crate) fn set_indexed_tracked_polys(
        &mut self,
        range_tr_comms: BTreeMap<String, TrackedOracle<B>>,
    ) {
        self.state.indexed_tracked_polys = range_tr_comms;
    }

    pub fn add_indexed_tracked_poly(
        &mut self,
        label: String,
        oracle: TrackedOracle<B>,
    ) -> Option<TrackedOracle<B>> {
        self.state.indexed_tracked_polys.insert(label, oracle)
    }

    // Get a range commitment for the given label
    pub(crate) fn indexed_tracked_poly(&self, label: String) -> SnarkResult<TrackedOracle<B>> {
        match self.state.indexed_tracked_polys.get(&label) {
            Some(poly) => Ok(poly.clone()),
            _ => Err(SnarkError::SetupError(NoRangePoly(format!("{:?}", label)))),
        }
    }

    pub fn get_or_build_contig_one_poly(
        &mut self,
        nv: usize,
        n: usize,
    ) -> SnarkResult<TrackedOracle<B>>
    where
        B::F: PrimeField,
    {
        self.get_or_build_contig_skipped_one_poly(nv, n, 0)
    }

    pub fn get_or_build_contig_skipped_one_poly(
        &mut self,
        nv: usize,
        n: usize,
        s: usize,
    ) -> SnarkResult<TrackedOracle<B>>
    where
        B::F: PrimeField,
    {
        let label = format!("contig_one_nv{}_skip{}_n{}", nv, s, n);
        if let Some(oracle) = self.state.indexed_tracked_polys.get(&label) {
            return Ok(oracle.clone());
        }

        let total = 1usize << nv;
        let end = s.checked_add(n).ok_or_else(|| {
            SnarkError::SetupError(NoRangePoly(format!(
                "contig_one_oracle has overflow in s + n: s={}, n={}, nv={}",
                s, n, nv
            )))
        })?;
        if end > total {
            return Err(SnarkError::SetupError(NoRangePoly(format!(
                "contig_one_oracle has s + n > 2^nv: s={}, n={}, nv={}",
                s, n, nv
            ))));
        }

        let oracle = if n == 0 {
            Oracle::new_constant(nv, B::F::zero())
        } else if s == 0 && n == total {
            Oracle::new_constant(nv, B::F::one())
        } else {
            // MLE evaluation order is little-endian (x_0 is LSB). We compare
            // idx(x) < bound using MSB-first logic, so we iterate x_{nv-1}..x_0.
            let start_bits_lsb: Vec<bool> = (0..nv).map(|i| ((s >> i) & 1) == 1).collect();
            let end_bits_lsb: Vec<bool> = (0..nv).map(|i| ((end >> i) & 1) == 1).collect();
            let start_is_zero = s == 0;
            let end_is_total = end == total;
            Oracle::new_multivariate(nv, move |mut point: Vec<B::F>| {
                if point.len() > nv {
                    point.truncate(nv);
                } else if point.len() < nv {
                    point.resize(nv, B::F::zero());
                }

                let lt_end = if end_is_total {
                    B::F::one()
                } else {
                    eval_lt_bound::<B::F>(&point, &end_bits_lsb, nv)
                };
                let lt_start = if start_is_zero {
                    B::F::zero()
                } else {
                    eval_lt_bound::<B::F>(&point, &start_bits_lsb, nv)
                };
                Ok(lt_end - lt_start)
            })
        };

        let tracker_rc = if let Some(oracle) = self.state.indexed_tracked_polys.values().next() {
            oracle.tracker()
        } else if let Some(self_rc) = &self.self_rc {
            let tracker_rc: Rc<RefCell<VerifierTracker<B>>> =
                Weak::upgrade(self_rc).ok_or_else(|| {
                    SnarkError::SetupError(NoRangePoly(
                        "contig_one_oracle requires a tracker handle; self_rc is dead".to_string(),
                    ))
                })?;
            tracker_rc
        } else {
            return Err(SnarkError::SetupError(NoRangePoly(
                "contig_one_oracle requires a tracker handle; none available".to_string(),
            )));
        };

        let oracle_id = self.track_base_oracle(oracle);
        let tracked = TrackedOracle::new(Either::Left(oracle_id), tracker_rc, nv);
        self.state
            .indexed_tracked_polys
            .insert(label, tracked.clone());
        Ok(tracked)
    }

    pub fn prover_comm(&self, id: TrackerID) -> Option<<B::MvPCS as PCS<B::F>>::Commitment> {
        self.proof
            .as_ref()
            .unwrap()
            .mv_pcs_subproof
            .comitments
            .get(&id)
            .cloned()
    }

    // TODO: See if we can remove this
    pub fn commitment_num_vars(&self, id: TrackerID) -> SnarkResult<usize> {
        let proof = self.proof_or_err()?;
        if proof.mv_pcs_subproof.constants.contains_key(&id) {
            return Ok(0);
        }
        match proof.mv_pcs_subproof.comitments.get(&id).cloned() {
            Some(comm) => Ok(comm.log_size() as usize),
            None => Err(SnarkError::from(PolyIOPErrors::InvalidVerifier(
                "Commitment not found".to_string(),
            ))),
        }
    }

    pub(crate) fn oracle_log_size(&self, id: TrackerID) -> Option<usize> {
        self.state.poly_log_sizes.get(&id).copied()
    }
}
