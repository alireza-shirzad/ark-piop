//! A General Purpose Prover for the PolyIOP

///////// Modules and reexports /////////
pub mod errors;
pub mod structs;
mod tracker;
///////// Imports /////////
use crate::{
    SnarkBackend,
    arithmetic::{
        mat_poly::{lde::LDE, mle::MLE},
        virt_poly::VirtualPoly,
    },
    errors::SnarkResult,
    pcs::PCS,
    piop::{PIOP, lookup_check},
    prover::structs::polynomial::TrackedPoly,
    setup::structs::SNARKPk,
    structs::TrackerID,
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use derivative::Derivative;
use either::Either;
use indexmap::IndexMap;
use tracing::{Span, field::debug, info, instrument, trace};

use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::Arc};
use structs::proof::SNARKProof;
use tracker::ProverTracker;
///////////// Body /////////////

/// A prover for the ZKSQL protocol.
#[derive(Derivative)]
#[derivative(Clone(bound = "B::MvPCS: Clone, B::UvPCS: Clone"))]
pub struct ArgProver<B: SnarkBackend> {
    tracker_rc: Rc<RefCell<ProverTracker<B>>>,
}

/// Implement PartialEq for Prover
/// Two provers are equal if they point to the same tracker
impl<B> PartialEq for ArgProver<B>
where
    B: SnarkBackend,
    B::F: Pairing + PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

/// Prover implementation
impl<B> ArgProver<B>
where
    B: SnarkBackend,
{
    #[instrument(level = "debug", skip_all)]
    /// Create a prover from the proving key
    pub fn new_from_pk(pk: SNARKPk<B>) -> Self {
        let mut prover = Self::new_from_tracker(ProverTracker::new_from_pk(pk.clone()));
        let indexed_polys: BTreeMap<String, TrackedPoly<B>> = pk
            .indexed_tracked_polys
            .iter()
            .map(|(label, mle)| {
                let tr_poly = prover.track_mat_mv_poly(mle.clone());
                (label.clone(), tr_poly)
            })
            .collect();
        prover
            .tracker_rc
            .borrow_mut()
            .set_indexed_tracked_polys(indexed_polys);

        prover
    }
    /// Create a prover from the tracker
    #[instrument(level = "debug", skip_all)]
    pub fn new_from_tracker(prover_tracker: ProverTracker<B>) -> Self {
        Self::new_from_tracker_rc(Rc::new(RefCell::new(prover_tracker)))
    }

    /// Create a prover from the tracker rc
    #[instrument(level = "debug", skip_all)]
    pub fn new_from_tracker_rc(prover_tracker: Rc<RefCell<ProverTracker<B>>>) -> Self {
        prover_tracker
            .borrow_mut()
            .set_self_rc(Rc::downgrade(&prover_tracker));
        Self {
            tracker_rc: prover_tracker,
        }
    }

    #[instrument(level = "debug", skip_all)]
    /// Return a shared handle to the multilinear PCS prover parameters.
    pub fn mv_pcs_prover_param(&self) -> Arc<<B::MvPCS as PCS<B::F>>::ProverParam> {
        Arc::clone(&self.tracker_rc.borrow().pk.mv_pcs_param)
    }

    /// Get the range tracked polynomial given the data type
    #[instrument(level = "debug", skip(self))]
    pub fn indexed_tracked_poly(&self, label: String) -> SnarkResult<TrackedPoly<B>> {
        RefCell::borrow(&self.tracker_rc).indexed_tracked_poly(label.clone())
    }

    /// Insert or update an indexed tracked polynomial.
    #[instrument(level = "debug", skip_all)]
    pub fn add_indexed_tracked_poly(
        &mut self,
        label: String,
        poly: TrackedPoly<B>,
    ) -> Option<TrackedPoly<B>> {
        self.tracker_rc
            .borrow_mut()
            .add_indexed_tracked_poly(label, poly)
    }

    pub fn tracker(&self) -> Rc<RefCell<ProverTracker<B>>> {
        Rc::clone(&self.tracker_rc)
    }

    /// Track a materialized multivariate polynomial
    /// moves the multivariate polynomial to heap, assigns a TracckerID to it in
    /// map and returns the TrackerID
    #[instrument(level = "debug", skip_all, fields(num_vars, polynomial = tracing::field::Empty))]
    pub fn track_mat_mv_poly(&mut self, polynomial: MLE<B::F>) -> TrackedPoly<B> {
        let num_vars = polynomial.num_vars();
        Span::current().record("num_vars", num_vars);
        if tracing::level_enabled!(tracing::Level::TRACE) {
            Span::current().record("polynomial", debug(&polynomial));
        }
        TrackedPoly::new(
            Either::Left(self.tracker_rc.borrow_mut().track_mat_mv_poly(polynomial)),
            num_vars,
            self.tracker_rc.clone(),
        )
    }

    /// Track a materialized multivariate polynomial
    /// moves the multivariate polynomial to heap, assigns a TracckerID to it in
    /// map and returns the TrackerID
    #[instrument(level = "debug", skip(self))]
    pub fn track_mat_mv_cnst_poly(&mut self, nv: usize, cnst: B::F) -> TrackedPoly<B> {
        if tracing::level_enabled!(tracing::Level::TRACE) {
            Span::current().record("cnst", debug(&cnst));
        }
        let _ = self.tracker_rc.borrow_mut().gen_id();
        TrackedPoly::new(Either::Right(cnst), nv, self.tracker_rc.clone())
    }

    /// Track a materialized multivariate polynomial
    /// sends a commitment to the polynomials to the verifier, moves the
    /// multivariate polynomial to heap, assigns a TracckerID to it in map and
    /// returns the TrackerID
    #[instrument(level = "debug", skip_all, fields(num_vars, polynomial = tracing::field::Empty))]
    pub fn track_and_commit_mat_mv_poly(
        &mut self,
        polynomial: &MLE<B::F>,
    ) -> SnarkResult<TrackedPoly<B>> {
        let num_vars = polynomial.num_vars();
        Span::current().record("num_vars", num_vars);
        if tracing::level_enabled!(tracing::Level::TRACE) {
            Span::current().record("polynomial", debug(&polynomial));
        }
        let tracked_poly = TrackedPoly::new(
            Either::Left(
                self.tracker_rc
                    .borrow_mut()
                    .track_and_commit_mat_mv_p(polynomial)?,
            ),
            num_vars,
            self.tracker_rc.clone(),
        );
        trace!("assigned id {}", tracked_poly.id());
        Ok(tracked_poly)
    }

    #[instrument(level = "trace", skip_all, fields(num_vars, polynomial = tracing::field::Empty))]
    /// Track a materialized polynomial using a pre-computed commitment.
    pub fn track_mat_mv_poly_with_commitment(
        &mut self,
        polynomial: &MLE<B::F>,
        commitment: <B::MvPCS as PCS<B::F>>::Commitment,
    ) -> SnarkResult<TrackedPoly<B>> {
        let num_vars = polynomial.num_vars();
        Span::current().record("num_vars", num_vars);
        let tracked_poly = TrackedPoly::new(
            Either::Left(
                self.tracker_rc
                    .borrow_mut()
                    .track_mat_mv_p_and_commitment(polynomial, commitment)?,
            ),
            num_vars,
            self.tracker_rc.clone(),
        );
        trace!("{} {}", "id assigned:", tracked_poly.id());
        Ok(tracked_poly)
    }

    /// Track a materialized univariate polynomial
    /// moves the univariate polynomial to heap, assigns a TracckerID to it in
    /// map and returns the TrackerID
    #[instrument(level = "debug", skip_all, fields(degree, polynomial = tracing::field::Empty))]
    pub fn track_mat_uv_poly(&mut self, polynomial: LDE<B::F>) -> TrackedPoly<B> {
        let degree = polynomial.degree();
        Span::current().record("degree", degree);
        if tracing::level_enabled!(tracing::Level::TRACE) {
            Span::current().record("polynomial", debug(&polynomial));
        }
        TrackedPoly::new(
            Either::Left(self.tracker_rc.borrow_mut().track_mat_uv_poly(polynomial)),
            degree,
            self.tracker_rc.clone(),
        )
    }

    /// Track a materialized univariate polynomial
    /// sends a commitment to the polynomials to the verifier, moves the
    /// univariate polynomial to heap, assigns a TracckerID to it in map and
    /// returns the TrackerID
    #[instrument(level = "debug", skip_all, fields(degree, polynomial = tracing::field::Empty))]
    pub fn track_and_commit_mat_uv_poly(
        &mut self,
        polynomial: LDE<B::F>,
    ) -> SnarkResult<TrackedPoly<B>> {
        let degree = polynomial.degree();
        Span::current().record("degree", degree);
        if tracing::level_enabled!(tracing::Level::TRACE) {
            Span::current().record("polynomial", debug(&polynomial));
        }
        Ok(TrackedPoly::new(
            Either::Left(
                self.tracker_rc
                    .borrow_mut()
                    .track_and_commit_mat_uv_poly(polynomial)?,
            ),
            degree,
            self.tracker_rc.clone(),
        ))
    }

    /// Get a shared to the materialized multivariate polynomial given its
    /// TrackerID
    #[instrument(level = "debug", skip(self))]
    pub fn mat_mv_poly(&self, id: TrackerID) -> Arc<MLE<B::F>> {
        RefCell::borrow(&self.tracker_rc)
            .mat_mv_poly(id)
            .unwrap()
            .clone()
    }

    /// Get a shared to the materialized univariate polynomial given its
    /// TrackerID
    #[instrument(level = "debug", skip(self))]
    pub fn mat_uv_poly(&self, id: TrackerID) -> Arc<LDE<B::F>> {
        RefCell::borrow(&self.tracker_rc)
            .mat_uv_poly(id)
            .unwrap()
            .clone()
    }

    /// Get a virtual polynomial given its TrackerID
    #[instrument(level = "debug", skip(self))]
    pub fn virt_poly(&self, id: TrackerID) -> VirtualPoly<B::F> {
        RefCell::borrow(&self.tracker_rc)
            .virt_poly(id)
            .unwrap()
            .clone()
    }

    /// Sample a fiat-shamir challenge and append it to the transcript
    #[instrument(level = "debug", skip(self))]
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<B::F> {
        let res = self.tracker_rc.borrow_mut().get_and_append_challenge(label);
        trace!(?res, "challenge");
        res
    }

    pub fn add_miscellaneous_field_element(&mut self, key: String, field: B::F) -> SnarkResult<()> {
        self.tracker_rc
            .borrow_mut()
            .insert_miscellaneous_field(key, field);
        Ok(())
    }

    pub fn miscellaneous_field_element(&self, key: &str) -> SnarkResult<B::F> {
        self.tracker_rc.borrow().miscellaneous_field_element(key)
    }

    /// Add a claim about the evaluation of a univariate polynomial at a point
    #[instrument(level = "debug", skip(self))]
    pub fn add_uv_eval_claim(&mut self, poly_id: TrackerID, point: B::F) -> SnarkResult<()> {
        self.tracker_rc
            .borrow_mut()
            .add_uv_eval_claim(poly_id, point)
    }

    /// Add a claim about the evaluation of a multivariate polynomial at a point
    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_eval_claim(&mut self, poly_id: TrackerID, point: &[B::F]) -> SnarkResult<()> {
        self.tracker_rc
            .borrow_mut()
            .add_mv_eval_claim(poly_id, point)
    }

    /// Add a multivariate sumcheck claim to the proof
    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_sumcheck_claim(
        &mut self,
        poly_id: TrackerID,
        claimed_sum: B::F,
    ) -> SnarkResult<()> {
        self.tracker_rc
            .borrow_mut()
            .add_mv_sumcheck_claim(poly_id, claimed_sum)
    }

    /// Add a multivariate zerocheck claim to the proof
    #[instrument(level = "debug", skip(self), fields(virt_degree = tracing::field::Empty))]
    pub fn add_mv_zerocheck_claim(&mut self, poly_id: TrackerID) -> SnarkResult<()> {
        let mut tracker = self.tracker_rc.borrow_mut();
        let degree = tracker.virt_poly_degree(poly_id);
        Span::current().record("virt_degree", &degree);
        tracker.add_mv_zerocheck_claim(poly_id)
    }

    /// Add a multivariate nozerocheck claim to the proof
    #[instrument(level = "debug", skip(self), fields(virt_degree = tracing::field::Empty))]
    pub fn add_mv_nozerocheck_claim(&mut self, poly_id: TrackerID) -> SnarkResult<()> {
        let mut tracker = self.tracker_rc.borrow_mut();
        let degree = tracker.virt_poly_degree(poly_id);
        Span::current().record("virt_degree", &degree);
        tracker.add_mv_nozerocheck_claim(poly_id)
    }

    /// Add a multivariate lookup claim to the proof
    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_lookup_claim(
        &mut self,
        super_id: TrackerID,
        sub_id: TrackerID,
    ) -> SnarkResult<()> {
        let mut tracker = self.tracker_rc.borrow_mut();
        trace!(
            "Looking up [{:?}] in [{:?}]",
            tracker.evaluations(sub_id),
            tracker.evaluations(super_id)
        );
        tracker.add_mv_lookup_claim(super_id, sub_id)
    }

    /// Get the next TrackerID to be used
    #[instrument(level = "debug", skip_all)]
    pub fn next_tracker_id(&mut self) -> TrackerID {
        self.tracker_rc.borrow_mut().next_id()
    }

    #[instrument(level = "debug", skip_all)]
    pub fn peek_next_id(&mut self) -> TrackerID {
        self.tracker_rc.borrow_mut().peek_next_id()
    }

    #[instrument(level = "debug", skip_all)]
    fn reduce_lookup_claims(&mut self) -> SnarkResult<()> {
        let lookup_claims = self.tracker_rc.borrow_mut().take_lookup_claims();
        if lookup_claims.is_empty() {
            return Ok(());
        }

        let mut by_super: IndexMap<TrackerID, Vec<TrackerID>> = IndexMap::new();
        for claim in lookup_claims {
            by_super
                .entry(claim.super_poly())
                .or_default()
                .push(claim.sub_poly());
        }
        info!("reducing {} lookup claims", by_super.len());
        for (super_id, sub_ids) in &by_super {
            info!(
                super_poly = ?super_id,
                sub_poly_count = sub_ids.len(),
                "lookup super polynomial group"
            );
        }

        for (super_id, sub_ids) in by_super {
            let super_nv = self.tracker_rc.borrow().poly_nv(super_id);
            let super_col =
                TrackedPoly::new(Either::Left(super_id), super_nv, self.tracker_rc.clone());

            let included_cols = sub_ids
                .into_iter()
                .map(|sub_id| {
                    let nv = self.tracker_rc.borrow().poly_nv(sub_id);
                    TrackedPoly::new(Either::Left(sub_id), nv, self.tracker_rc.clone())
                })
                .collect::<Vec<_>>();

            let lookup_prover_input = lookup_check::LookupCheckProverInput {
                included_cols,
                super_col,
            };
            lookup_check::LookupCheckPIOP::prove(self, lookup_prover_input)?;
        }

        Ok(())
    }

    pub fn get_or_build_contig_one_poly(
        &mut self,
        nv: usize,
        s: usize,
    ) -> SnarkResult<TrackedPoly<B>> {
        self.tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(nv, s)
    }

    /// Build the zkSQL proof from the claims and comitments
    #[instrument(level = "debug", skip_all)]
    pub fn build_proof(&mut self) -> SnarkResult<SNARKProof<B>> {
        self.reduce_lookup_claims()?;
        self.tracker_rc.borrow_mut().compile_proof()
    }

    #[cfg(feature = "test-utils")]
    #[instrument(level = "debug", skip_all)]
    pub fn clone_underlying_tracker(&self) -> ProverTracker<B> {
        RefCell::borrow(&self.tracker_rc).clone()
    }

    #[cfg(any(feature = "test-utils", feature = "honest-prover"))]
    #[instrument(level = "debug", skip_all)]
    pub fn deep_copy(&self) -> ArgProver<B> {
        ArgProver::new_from_tracker((*RefCell::borrow(&self.tracker_rc)).clone())
    }
}
