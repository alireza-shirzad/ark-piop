//! A General Purpose Prover for the PolyIOP

///////// Modules and reexports /////////
pub mod errors;
pub mod structs;
mod tracker;
///////// Imports /////////
use crate::{
    arithmetic::{
        mat_poly::{lde::LDE, mle::MLE},
        virt_poly::VirtualPoly,
    },
    errors::SnarkResult,
    pcs::PCS,
    prover::structs::polynomial::TrackedPoly,
    setup::structs::ProvingKey,
    structs::TrackerID,
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use derivative::Derivative;
use either::Either;
use tracing::{Span, field::debug, instrument, trace};

use std::{cell::RefCell, collections::BTreeMap, rc::Rc, sync::Arc};
use structs::proof::Proof;
use tracker::ProverTracker;
///////////// Body /////////////

/// A prover for the ZKSQL protocol.
#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: Clone, UvPCS: Clone"))]
pub struct Prover<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    tracker_rc: Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>>,
}

/// Implement PartialEq for Prover
/// Two provers are equal if they point to the same tracker
impl<F: Pairing, MvPCS: PCS<F>, UvPCS: PCS<F>> PartialEq for Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

/// Prover implementation
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    #[instrument(level = "debug", skip_all)]
    /// Create a prover from the proving key
    pub fn new_from_pk(pk: ProvingKey<F, MvPCS, UvPCS>) -> Self {
        let mut prover = Self::new_from_tracker(ProverTracker::new_from_pk(pk.clone()));
        let indexed_polys: BTreeMap<String, TrackedPoly<F, MvPCS, UvPCS>> = pk
            .indexed_mles
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
    pub fn new_from_tracker(prover_tracker: ProverTracker<F, MvPCS, UvPCS>) -> Self {
        Self::new_from_tracker_rc(Rc::new(RefCell::new(prover_tracker)))
    }

    /// Create a prover from the tracker rc
    #[instrument(level = "debug", skip_all)]
    pub fn new_from_tracker_rc(
        prover_tracker: Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            tracker_rc: prover_tracker,
        }
    }

    #[instrument(level = "debug", skip_all)]
    /// Return a shared handle to the multilinear PCS prover parameters.
    pub fn mv_pcs_prover_param(&self) -> Arc<MvPCS::ProverParam> {
        Arc::clone(&self.tracker_rc.borrow().pk.mv_pcs_param)
    }

    /// Get the range tracked polynomial given the data type
    #[instrument(level = "debug", skip(self))]
    pub fn indexed_tracked_poly(&self, label: String) -> SnarkResult<TrackedPoly<F, MvPCS, UvPCS>> {
        RefCell::borrow(&self.tracker_rc).indexed_tracked_poly(label.clone())
    }

    pub fn tracker(&self) -> Rc<RefCell<ProverTracker<F, MvPCS, UvPCS>>> {
        Rc::clone(&self.tracker_rc)
    }

    /// Track a materialized multivariate polynomial
    /// moves the multivariate polynomial to heap, assigns a TracckerID to it in
    /// map and returns the TrackerID
    #[instrument(level = "debug", skip_all, fields(num_vars, polynomial = tracing::field::Empty))]
    pub fn track_mat_mv_poly(&mut self, polynomial: MLE<F>) -> TrackedPoly<F, MvPCS, UvPCS> {
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
    pub fn track_mat_mv_cnst_poly(&mut self, nv: usize, cnst: F) -> TrackedPoly<F, MvPCS, UvPCS> {
        if tracing::level_enabled!(tracing::Level::TRACE) {
            Span::current().record("cnst", debug(&cnst));
        }
        let _ = self.tracker_rc
            .borrow_mut()
            .gen_id(); 
        TrackedPoly::new(Either::Right(cnst), nv, self.tracker_rc.clone())
    }

    /// Track a materialized multivariate polynomial
    /// sends a commitment to the polynomials to the verifier, moves the
    /// multivariate polynomial to heap, assigns a TracckerID to it in map and
    /// returns the TrackerID
    #[instrument(level = "debug", skip_all, fields(num_vars, polynomial = tracing::field::Empty))]
    pub fn track_and_commit_mat_mv_poly(
        &mut self,
        polynomial: &MLE<F>,
    ) -> SnarkResult<TrackedPoly<F, MvPCS, UvPCS>> {
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
        tracing::debug!("assigned id {}", tracked_poly.id());
        Ok(tracked_poly)
    }

    #[instrument(level = "debug", skip_all, fields(num_vars, polynomial = tracing::field::Empty))]
    /// Track a materialized polynomial using a pre-computed commitment.
    pub fn track_mat_mv_poly_with_commitment(
        &mut self,
        polynomial: &MLE<F>,
        commitment: MvPCS::Commitment,
    ) -> SnarkResult<TrackedPoly<F, MvPCS, UvPCS>> {
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
    pub fn track_mat_uv_poly(&mut self, polynomial: LDE<F>) -> TrackedPoly<F, MvPCS, UvPCS> {
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
        polynomial: LDE<F>,
    ) -> SnarkResult<TrackedPoly<F, MvPCS, UvPCS>> {
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
    pub fn mat_mv_poly(&self, id: TrackerID) -> Arc<MLE<F>> {
        RefCell::borrow(&self.tracker_rc)
            .mat_mv_poly(id)
            .unwrap()
            .clone()
    }

    /// Get a shared to the materialized univariate polynomial given its
    /// TrackerID
    #[instrument(level = "debug", skip(self))]
    pub fn mat_uv_poly(&self, id: TrackerID) -> Arc<LDE<F>> {
        RefCell::borrow(&self.tracker_rc)
            .mat_uv_poly(id)
            .unwrap()
            .clone()
    }

    /// Get a virtual polynomial given its TrackerID
    #[instrument(level = "debug", skip(self))]
    pub fn virt_poly(&self, id: TrackerID) -> VirtualPoly<F> {
        RefCell::borrow(&self.tracker_rc)
            .virt_poly(id)
            .unwrap()
            .clone()
    }

    /// Sample a fiat-shamir challenge and append it to the transcript
    #[instrument(level = "debug", skip(self))]
    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> SnarkResult<F> {
        let res = self.tracker_rc.borrow_mut().get_and_append_challenge(label);
        trace!(?res, "challenge");
        res
    }

    /// Add a claim about the evaluation of a univariate polynomial at a point
    #[instrument(level = "debug", skip(self))]
    pub fn add_uv_eval_claim(&mut self, poly_id: TrackerID, point: F) -> SnarkResult<()> {
        self.tracker_rc
            .borrow_mut()
            .add_uv_eval_claim(poly_id, point)
    }

    /// Add a claim about the evaluation of a multivariate polynomial at a point
    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_eval_claim(&mut self, poly_id: TrackerID, point: &[F]) -> SnarkResult<()> {
        self.tracker_rc
            .borrow_mut()
            .add_mv_eval_claim(poly_id, point)
    }

    /// Add a multivariate sumcheck claim to the proof
    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: F) -> SnarkResult<()> {
        self.tracker_rc
            .borrow_mut()
            .add_mv_sumcheck_claim(poly_id, claimed_sum)
    }

    /// Add a multivariate zerocheck claim to the proof
    #[instrument(level = "debug", skip(self))]
    pub fn add_mv_zerocheck_claim(&mut self, poly_id: TrackerID) -> SnarkResult<()> {
        self.tracker_rc.borrow_mut().add_mv_zerocheck_claim(poly_id)
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

    /// Build the zkSQL proof from the claims and comitments
    #[instrument(level = "debug", skip_all)]
    pub fn build_proof(&mut self) -> SnarkResult<Proof<F, MvPCS, UvPCS>> {
        self.tracker_rc.borrow_mut().compile_proof()
    }

    #[cfg(feature = "test-utils")]
    #[instrument(level = "debug", skip_all)]
    pub fn clone_underlying_tracker(&self) -> ProverTracker<F, MvPCS, UvPCS> {
        RefCell::borrow(&self.tracker_rc).clone()
    }

    #[cfg(any(feature = "test-utils", feature = "honest-prover"))]
    #[instrument(level = "debug", skip_all)]
    pub fn deep_copy(&self) -> Prover<F, MvPCS, UvPCS> {
        Prover::new_from_tracker((*RefCell::borrow(&self.tracker_rc)).clone())
    }
}
