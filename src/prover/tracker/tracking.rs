//! Polynomial tracking: registering, committing, and looking up tracked polynomials.

use super::*;

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    pub fn track_mat_mv_poly(&mut self, polynomial: MLE<B::F>) -> TrackerID {
        // Compressed as in the committing entry points, so a polynomial
        // tracked without a commitment gets the narrow storage too.
        let polynomial = Arc::new(polynomial.compressed());
        self.track_mat_arc_mv_poly(polynomial)
    }

    /// Tracks a constant that arithmetic folded, so a claim can reference
    /// it. The verifier tracks a constant oracle at the same ID, of degree 0;
    /// recording the ID keeps this side's degree the same.
    pub fn track_derived_mv_constant(&mut self, constant: MLE<B::F>) -> TrackerID {
        let id = self.track_mat_mv_poly(constant);
        self.state.mv_pcs_substate.derived_constants.insert(id);
        id
    }

    pub fn track_mat_uv_poly(&mut self, polynomial: LDE<B::F>) -> TrackerID {
        let polynomial = Arc::new(polynomial);
        self.track_mat_arc_uv_poly(polynomial)
    }

    pub(super) fn track_mat_arc_mv_poly(
        &mut self,
        polynomial: impl Into<Arc<MLE<B::F>>>,
    ) -> TrackerID {
        let polynomial = polynomial.into();
        let poly_id = self.gen_id();
        self.state
            .mv_pcs_substate
            .materialized_polys
            .insert(poly_id, polynomial.clone());
        self.state.num_vars.insert(poly_id, polynomial.num_vars());
        poly_id
    }

    pub fn has_materialized_mv_poly(&self, id: TrackerID) -> bool {
        self.state
            .mv_pcs_substate
            .materialized_polys
            .contains_key(&id)
    }

    /// Registers a materialized polynomial under an existing TrackerID, for
    /// the lazy materialization of constants: `gen_id()` allocated the ID and
    /// the MLE is created only when it is needed.
    pub fn register_mat_mv_poly(&mut self, id: TrackerID, polynomial: impl Into<Arc<MLE<B::F>>>) {
        let polynomial = polynomial.into();
        self.state.num_vars.insert(id, polynomial.num_vars());
        self.state
            .mv_pcs_substate
            .materialized_polys
            .insert(id, polynomial);
    }

    fn track_mat_arc_uv_poly(&mut self, polynomial: Arc<LDE<B::F>>) -> TrackerID {
        let poly_id = self.gen_id();
        self.state
            .uv_pcs_substate
            .materialized_polys
            .insert(poly_id, polynomial.clone());
        poly_id
    }

    /// Tracks a materialized polynomial and commits to it. A constant
    /// polynomial skips the PCS commitment: its value is bound to the
    /// transcript instead, and it still gets a TrackerID so claims can name
    /// it. Returns `Left(id)`, or `Right((id, cnst))` for a constant.
    pub fn track_and_commit_mat_mv_p(
        &mut self,
        polynomial: &MLE<B::F>,
        use_cache: bool,
    ) -> SnarkResult<Either<TrackerID, (TrackerID, B::F)>> {
        if polynomial.is_constant() {
            // `polynomial[0]` only supports Field storage; `lift` reads
            // every variant.
            let cnst = polynomial.storage().lift(0);
            let id = self.track_and_commit_mv_constant(cnst, polynomial.num_vars())?;
            return Ok(Either::Right((id, cnst)));
        }
        // Auto-compress Field-backed polys whose elements fit a small
        // integer type into the tightest storage variant (8×-256× smaller);
        // no-op for non-Field storage.
        let polynomial = Arc::new(polynomial.clone().compressed());
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

    /// Tracks a constant polynomial: allocates an ID, stores the constant in
    /// the proof in place of a commitment and binds it to the transcript. No
    /// MLE is created: the constant propagates as `Either::Right(cnst)`
    /// through `TrackedPoly` arithmetic, and is materialized lazily if
    /// `.id()` is called on the `TrackedPoly`.
    fn track_and_commit_mv_constant(
        &mut self,
        cnst: B::F,
        num_vars: usize,
    ) -> SnarkResult<TrackerID> {
        let id = self.gen_id();
        self.state.num_vars.insert(id, num_vars);
        self.state.mv_pcs_substate.constants.insert(id, cnst);
        // The verifier needs num_vars to mirror `poly_log_sizes` and keep
        // downstream arithmetic (add/mul, chunk-commit max_nv) in sync.
        self.state
            .mv_pcs_substate
            .constants_num_vars
            .insert(id, num_vars);
        // Transcript-bind so the verifier derives the same challenges.
        self.state
            .transcript
            .append_serializable_element(b"cnst", &cnst)?;
        Ok(id)
    }

    /// Tracks a materialized polynomial under a supplied commitment.
    /// `binding` says whether this proof binds the commitment to the
    /// transcript or only references it from external context.
    pub fn track_mat_mv_p_with_commitment(
        &mut self,
        polynomial: &MLE<B::F>,
        commitment: <B::MvPCS as PCS<B::F>>::Commitment,
        binding: CommitmentBinding,
        use_cache: bool,
    ) -> SnarkResult<TrackerID> {
        // Compressed as in `track_and_commit_mat_mv_p`.
        let polynomial = Arc::new(polynomial.clone().compressed());

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

        let poly_id = self.track_mat_arc_mv_poly(polynomial);
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
        let commitment = B::UvPCS::commit(self.pk.uv_pcs_param.as_ref(), &polynomial)?;
        self.track_mat_uv_p_with_commitment(
            &polynomial,
            commitment,
            CommitmentBinding::ProofEmitted,
        )
    }

    /// The univariate [`Self::track_mat_mv_p_with_commitment`].
    pub fn track_mat_uv_p_with_commitment(
        &mut self,
        polynomial: &LDE<B::F>,
        commitment: <B::UvPCS as PCS<B::F>>::Commitment,
        binding: CommitmentBinding,
    ) -> SnarkResult<TrackerID> {
        let polynomial = Arc::new(polynomial.clone());

        let poly_id = self.track_mat_arc_uv_poly(polynomial);
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

    pub(super) fn track_virt_poly(&mut self, p: VirtualPoly<B::F>) -> TrackerID {
        let poly_id = self.gen_id();

        let nv = p
            .iter()
            .flat_map(|(_, prod_ids)| prod_ids.iter().map(|id| self.state.num_vars[id]))
            .max()
            .unwrap_or_default();
        self.state.num_vars.insert(poly_id, nv);
        self.state.virtual_polys.insert(poly_id, p);
        poly_id
    }

    pub fn mat_mv_poly(&self, id: TrackerID) -> Option<&Arc<MLE<B::F>>> {
        self.state.mv_pcs_substate.materialized_polys.get(&id)
    }

    pub fn mat_uv_poly(&self, id: TrackerID) -> Option<&Arc<LDE<B::F>>> {
        self.state.uv_pcs_substate.materialized_polys.get(&id)
    }

    pub fn virt_poly(&self, id: TrackerID) -> Option<&VirtualPoly<B::F>> {
        self.state.virtual_polys.get(&id)
    }
}
