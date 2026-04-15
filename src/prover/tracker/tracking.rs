//! Polynomial tracking — registering, committing, and looking up tracked polynomials.

use super::*;

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    /// Tracks a materialized polynomial.
    ///
    /// moves the polynomial to heap, assigns a TracckerID to it in map and
    /// returns the TrackerID
    pub fn track_mat_mv_poly(&mut self, polynomial: MLE<B::F>) -> TrackerID {
        let polynomial = Arc::new(polynomial);
        self.track_mat_arc_mv_poly(polynomial)
    }

    /// Tracks a materialized polynomial.
    ///
    /// moves the polynomial to heap, assigns a TracckerID to it in map and
    /// returns the TrackerID
    pub fn track_mat_uv_poly(&mut self, polynomial: LDE<B::F>) -> TrackerID {
        let polynomial = Arc::new(polynomial);
        self.track_mat_arc_uv_poly(polynomial)
    }
    /// Tracks materialized polynomial by reference.
    ///
    /// Assumes the input polynomial is already on the heap and assigns a
    /// TrackerID to it in the map
    pub(super) fn track_mat_arc_mv_poly(
        &mut self,
        polynomial: impl Into<Arc<MLE<B::F>>>,
    ) -> TrackerID {
        let polynomial = polynomial.into();
        // Create the new TrackerID
        let poly_id = self.gen_id();

        // Add the polynomial to the materialized map
        self.state
            .mv_pcs_substate
            .materialized_polys
            .insert(poly_id, polynomial.clone());
        self.state.num_vars.insert(poly_id, polynomial.num_vars());
        // Return the new TrackerID
        poly_id
    }

    /// Returns true if a materialized MV polynomial exists for the given ID.
    pub fn has_materialized_mv_poly(&self, id: TrackerID) -> bool {
        self.state
            .mv_pcs_substate
            .materialized_polys
            .contains_key(&id)
    }

    /// Registers a materialized polynomial under an **existing** TrackerID.
    /// Used for lazy materialization of constants: the ID was already allocated
    /// by `gen_id()`, but the MLE is only created when actually needed.
    pub fn register_mat_mv_poly(&mut self, id: TrackerID, polynomial: impl Into<Arc<MLE<B::F>>>) {
        let polynomial = polynomial.into();
        self.state.num_vars.insert(id, polynomial.num_vars());
        self.state
            .mv_pcs_substate
            .materialized_polys
            .insert(id, polynomial);
    }

    fn track_mat_arc_uv_poly(&mut self, polynomial: Arc<LDE<B::F>>) -> TrackerID {
        // Create the new TrackerID
        let poly_id = self.gen_id();

        // Add the polynomial to the materialized map
        self.state
            .uv_pcs_substate
            .materialized_polys
            .insert(poly_id, polynomial.clone());

        // Return the new TrackerID
        poly_id
    }

    /// Tracks a materialized polynomial and sends a commitment to the verifier.
    /// If the polynomial is constant, skips the expensive PCS commitment and
    /// instead transcript-binds the constant value. The polynomial is still
    /// tracked with a TrackerID so it can participate in sumcheck/zerocheck claims.
    /// Returns `Left(id)` for normal polynomials, `Right((id, cnst))` for constants.
    pub fn track_and_commit_mat_mv_p(
        &mut self,
        polynomial: &MLE<B::F>,
        use_cache: bool,
    ) -> SnarkResult<Either<TrackerID, (TrackerID, B::F)>> {
        if polynomial.is_constant() {
            let cnst = polynomial[0];
            let id = self.track_and_commit_mv_constant(cnst, polynomial.num_vars())?;
            return Ok(Either::Right((id, cnst)));
        }
        let polynomial = Arc::new(polynomial.clone());
        let commitment = if use_cache {
            let digest = crate::arithmetic::mat_poly::digest::mle_digest(polynomial.as_ref());
            if let Some(cached) = self.state.mv_pcs_substate.commitment_cache.get(&digest) {
                cached.clone()
            } else {
                let comm = B::MvPCS::commit(self.pk.mv_pcs_param.as_ref(), &polynomial)?;
                self.state
                    .mv_pcs_substate
                    .commitment_cache
                    .insert(digest, comm.clone());
                comm
            }
        } else {
            B::MvPCS::commit(self.pk.mv_pcs_param.as_ref(), &polynomial)?
        };
        Ok(Either::Left(self.track_mat_mv_p_with_commitment(
            &polynomial,
            commitment,
            CommitmentBinding::ProofEmitted,
            use_cache,
        )?))
    }

    /// Tracks a constant polynomial: generates an ID, stores the constant in
    /// the proof, transcript-binds it, and registers a materialized MLE so the
    /// polynomial can be referenced in sumcheck/zerocheck claims.
    fn track_and_commit_mv_constant(
        &mut self,
        cnst: B::F,
        num_vars: usize,
    ) -> SnarkResult<TrackerID> {
        // Just generate an ID and transcript-bind the constant value.
        // No MLE is created — the constant propagates as Either::Right(cnst)
        // through TrackedPoly arithmetic. If .id() is ever called on the
        // TrackedPoly (rare: standalone sumcheck claim on a constant), it
        // lazily materializes at that point.
        let id = self.gen_id();
        self.state.num_vars.insert(id, num_vars);
        // Store constant in proof (instead of a commitment).
        self.state.mv_pcs_substate.constants.insert(id, cnst);
        // Transcript-bind so the verifier derives the same challenges.
        self.state
            .transcript
            .append_serializable_element(b"cnst", &cnst)?;
        Ok(id)
    }

    /// Tracks a materialized polynomial using a supplied commitment.
    ///
    /// `binding` controls whether the commitment is transcript-bound as part of
    /// this proof or merely referenced from external context.
    pub fn track_mat_mv_p_with_commitment(
        &mut self,
        polynomial: &MLE<B::F>,
        commitment: <B::MvPCS as PCS<B::F>>::Commitment,
        binding: CommitmentBinding,
        use_cache: bool,
    ) -> SnarkResult<TrackerID> {
        let polynomial = Arc::new(polynomial.clone());

        if use_cache {
            // Populate the commitment cache so future commits to the same
            // polynomial can skip the expensive MSM.
            let digest = crate::arithmetic::mat_poly::digest::mle_digest(polynomial.as_ref());
            self.state
                .mv_pcs_substate
                .commitment_cache
                .entry(digest)
                .or_insert_with(|| commitment.clone());
        }

        // track the polynomial and get its id
        let poly_id = self.track_mat_arc_mv_poly(polynomial);

        // add the commitment to the commitment map with the same poly_id
        self.state
            .mv_pcs_substate
            .materialized_comms
            .insert(poly_id, commitment.clone());

        match binding {
            CommitmentBinding::ProofEmitted => {
                // Proof-owned commitments are transcript-bound here so the
                // verifier derives challenges from the same commitment stream.
                self.state
                    .transcript
                    .append_serializable_element(b"comm", &commitment)?;
            }
            CommitmentBinding::External => {
                // External commitments stay addressable by tracker id, but they
                // are not re-emitted or transcript-bound by this proof.
                self.state
                    .mv_pcs_substate
                    .external_materialized_comm_ids
                    .insert(poly_id);
            }
        }

        Ok(poly_id)
    }

    pub fn track_and_commit_mat_uv_poly(
        &mut self,
        polynomial: LDE<B::F>,
    ) -> SnarkResult<TrackerID> {
        let polynomial = Arc::new(polynomial);
        // commit to the polynomial
        let commitment = B::UvPCS::commit(self.pk.uv_pcs_param.as_ref(), &polynomial)?;
        self.track_mat_uv_p_with_commitment(
            &polynomial,
            commitment,
            CommitmentBinding::ProofEmitted,
        )
    }

    /// Tracks a materialized univariate polynomial using a supplied
    /// commitment.
    ///
    /// `binding` controls whether the commitment is transcript-bound as part of
    /// this proof or merely referenced from external context.
    pub fn track_mat_uv_p_with_commitment(
        &mut self,
        polynomial: &LDE<B::F>,
        commitment: <B::UvPCS as PCS<B::F>>::Commitment,
        binding: CommitmentBinding,
    ) -> SnarkResult<TrackerID> {
        let polynomial = Arc::new(polynomial.clone());

        // track the polynomial and get its id
        let poly_id = self.track_mat_arc_uv_poly(polynomial);

        // add the commitment to the commitment map with the same poly_id
        self.state
            .uv_pcs_substate
            .materialized_comms
            .insert(poly_id, commitment.clone());

        match binding {
            CommitmentBinding::ProofEmitted => {
                // Proof-owned commitments are transcript-bound here so the
                // verifier derives challenges from the same commitment stream.
                self.state
                    .transcript
                    .append_serializable_element(b"comm", &commitment)?;
            }
            CommitmentBinding::External => {
                // External commitments stay addressable by tracker id, but they
                // are not re-emitted or transcript-bound by this proof.
                self.state
                    .uv_pcs_substate
                    .external_materialized_comm_ids
                    .insert(poly_id);
            }
        }

        Ok(poly_id)
    }

    /// Tracks a virtual polynomial
    ///
    /// generates a new TrackerID and adds the virtual polynomial to the map
    pub(super) fn track_virt_poly(&mut self, p: VirtualPoly<B::F>) -> TrackerID {
        let poly_id = self.gen_id();

        let nv = p
            .iter()
            .flat_map(|(_, prod_ids)| prod_ids.iter().map(|id| self.state.num_vars[id]))
            .max()
            .unwrap_or_default();
        self.state.num_vars.insert(poly_id, nv);
        self.state.virtual_polys.insert(poly_id, p);
        // No need to commit to virtual polynomials
        poly_id
    }

    /// Get a reference to a materialized multivariate polynomial on the heap,
    /// from the map, by its TrackerID
    pub fn mat_mv_poly(&self, id: TrackerID) -> Option<&Arc<MLE<B::F>>> {
        self.state.mv_pcs_substate.materialized_polys.get(&id)
    }

    /// Get a reference to a materialized univariate polynomial on the heap,
    /// from the map, by its TrackerID
    pub fn mat_uv_poly(&self, id: TrackerID) -> Option<&Arc<LDE<B::F>>> {
        self.state.uv_pcs_substate.materialized_polys.get(&id)
    }

    /// Get a virtual polynomial, from the map, by its TrackerID
    pub fn virt_poly(&self, id: TrackerID) -> Option<&VirtualPoly<B::F>> {
        self.state.virtual_polys.get(&id)
    }
}
