//! Oracle evaluation for the verifier.

use super::*;

impl<B: SnarkBackend> VerifierTracker<B> {
    pub(super) fn eval_base_mv(&self, oracle_id: TrackerID, point: &[B::F]) -> SnarkResult<B::F> {
        let oracle = self.state.base_oracles.get(&oracle_id).ok_or_else(|| {
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                "base oracle {} not registered on verifier",
                oracle_id
            )))
        })?;
        match oracle.inner() {
            InnerOracle::Multivariate(f) => f(point.to_vec()),
            InnerOracle::Constant(c) => Ok(*c),
            _ => Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed(format!(
                    "base oracle {} has wrong kind (expected Multivariate or Constant)",
                    oracle_id
                )),
            )),
        }
    }

    pub(super) fn eval_base_uv(&self, oracle_id: TrackerID, point: B::F) -> SnarkResult<B::F> {
        let oracle = self.state.base_oracles.get(&oracle_id).ok_or_else(|| {
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                "base oracle {} not registered on verifier",
                oracle_id
            )))
        })?;
        match oracle.inner() {
            InnerOracle::Univariate(f) => f(point),
            InnerOracle::Constant(c) => Ok(*c),
            _ => Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed(format!(
                    "base oracle {} has wrong kind (expected Univariate or Constant)",
                    oracle_id
                )),
            )),
        }
    }

    pub(super) fn eval_virtual_mv(
        &self,
        oracle_id: TrackerID,
        point: &[B::F],
    ) -> SnarkResult<B::F> {
        let terms = self.state.virtual_polys.get(&oracle_id).ok_or_else(|| {
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                "virtual oracle {} not tracked",
                oracle_id
            )))
        })?;
        let mut acc = B::F::zero();
        for (coeff, term_ids) in terms.iter() {
            let mut term_val = *coeff;
            for id in term_ids {
                term_val *= self.eval_base_mv(*id, point)?;
            }
            acc += term_val;
        }
        Ok(acc)
    }

    pub(super) fn eval_virtual_uv(&self, oracle_id: TrackerID, point: B::F) -> SnarkResult<B::F> {
        let terms = self.state.virtual_polys.get(&oracle_id).ok_or_else(|| {
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                "virtual oracle {} not tracked",
                oracle_id
            )))
        })?;
        let mut acc = B::F::zero();
        for (coeff, term_ids) in terms.iter() {
            let mut term_val = *coeff;
            for id in term_ids {
                term_val *= self.eval_base_uv(*id, point)?;
            }
            acc += term_val;
        }
        Ok(acc)
    }

    pub(super) fn eval_virtual_mv_cached(
        &self,
        oracle_id: TrackerID,
        point: &[B::F],
        cache: &mut HashMap<TrackerID, B::F>,
    ) -> SnarkResult<B::F> {
        if let Some(v) = cache.get(&oracle_id) {
            return Ok(*v);
        }
        let terms = self.state.virtual_polys.get(&oracle_id).ok_or_else(|| {
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                "virtual oracle {} not tracked",
                oracle_id
            )))
        })?;
        let mut acc = B::F::zero();
        for (coeff, term_ids) in terms.iter() {
            let mut term_val = *coeff;
            for id in term_ids {
                let v = if let Some(v) = cache.get(id) {
                    *v
                } else {
                    let v = self.eval_base_mv(*id, point)?;
                    cache.insert(*id, v);
                    v
                };
                term_val *= v;
            }
            acc += term_val;
        }
        cache.insert(oracle_id, acc);
        Ok(acc)
    }

    pub fn query_mv(&self, oracle_id: TrackerID, point: Vec<B::F>) -> SnarkResult<B::F> {
        let equalized_point = self.equalized_mv_point(&point)?;
        self.eval_virtual_mv(oracle_id, &equalized_point)
    }

    pub fn query_uv(&self, oracle_id: TrackerID, point: B::F) -> SnarkResult<B::F> {
        self.eval_virtual_uv(oracle_id, point)
    }

    pub(super) fn equalized_mv_point(&self, point: &[B::F]) -> SnarkResult<Vec<B::F>> {
        let subproof = self.proof_or_err()?.sc_subproof.as_ref().ok_or_else(|| {
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(
                "proof has no sumcheck subproof".to_string(),
            ))
        })?;
        let target_nv = subproof.sc_aux_info().num_variables;
        if point.len() == target_nv {
            return Ok(point.to_vec());
        }
        let mut equalized = point.to_vec();
        equalized.resize(target_nv, B::F::zero());
        Ok(equalized)
    }

    //TODO: This function is only used in the multiplicity-check and should be removed in the future. it should not be a part of this library, but should be optionally implemented by the used
    pub fn prover_claimed_sum(&self, id: TrackerID) -> SnarkResult<B::F> {
        let proof = self.proof_or_err()?;
        let subproof = proof.sc_subproof.as_ref().ok_or_else(|| {
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(
                "proof has no sumcheck subproof".to_string(),
            ))
        })?;
        subproof.sumcheck_claims().get(&id).cloned().ok_or_else(|| {
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
                "sumcheck subproof has no claim for tracker id {}",
                id
            )))
        })
    }

    pub fn mv_commitment(&self, id: TrackerID) -> Option<<B::MvPCS as PCS<B::F>>::Commitment> {
        self.state
            .mv_pcs_substate
            .materialized_comms
            .get(&id)
            .cloned()
    }
}
