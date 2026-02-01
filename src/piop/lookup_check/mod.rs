mod utils;
use crate::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_ff::One;
use derivative::Derivative;
use rayon::vec;
use std::marker::PhantomData;
use utils::calc_inclusion_multiplicity;

use super::keyed_sumcheck::{KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct HintedLookupCheckProverInput<B: SnarkBackend> {
    pub included_cols: Vec<TrackedPoly<B>>,
    pub super_col: TrackedPoly<B>,
    pub super_col_multiplicity: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for HintedLookupCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            included_cols: self
                .included_cols
                .iter()
                .map(|c| c.deep_clone(prover.clone()))
                .collect(),
            super_col: self.super_col.deep_clone(prover.clone()),
            super_col_multiplicity: self.super_col_multiplicity.deep_clone(prover.clone()),
        }
    }
}

pub struct HintedLookupCheckVerifierInput<B: SnarkBackend> {
    pub included_tracked_col_oracles: Vec<TrackedOracle<B>>,
    pub super_tracked_col_oracle: TrackedOracle<B>,
    pub super_col_multiplicity: TrackedOracle<B>,
}

pub struct HintedLookupCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LookupCheckProverInput<B: SnarkBackend> {
    pub included_cols: Vec<TrackedPoly<B>>,
    pub super_col: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for LookupCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            included_cols: self
                .included_cols
                .iter()
                .map(|c| c.deep_clone(prover.clone()))
                .collect(),
            super_col: self.super_col.deep_clone(prover.clone()),
        }
    }
}

pub struct LookupCheckProverOutput<B: SnarkBackend> {
    pub super_col_m: TrackedPoly<B>,
}

pub struct LookupCheckVerifierInput<B: SnarkBackend> {
    pub included_tracked_col_oracles: Vec<TrackedOracle<B>>,
    pub super_tracked_col_oracle: TrackedOracle<B>,
}

pub struct LookupCheckVerifierOutput<B: SnarkBackend> {
    pub super_col_m_comm: TrackedOracle<B>,
}

pub struct LookupCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

impl<B: SnarkBackend> PIOP<B> for HintedLookupCheckPIOP<B> {
    type ProverInput = HintedLookupCheckProverInput<B>;
    type VerifierInput = HintedLookupCheckVerifierInput<B>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use std::collections::HashSet;

        use crate::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };
        let super_col_hash_set: HashSet<B::F> =
            HashSet::from_iter(input.super_col.evaluations().iter().cloned());
        for elem in input.included_cols.iter().flat_map(|c| c.evaluations()) {
            if !super_col_hash_set.contains(&elem) {
                tracing::error!("error");
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let included_col_ms = input
            .included_cols
            .iter()
            .map(|_included_col| None)
            .collect::<Vec<_>>();

        let super_cols = vec![input.super_col.clone()];
        let super_col_multiplicity = vec![Some(input.super_col_multiplicity.clone())];
        let keyed_sumcheck_prover_input = KeyedSumcheckProverInput {
            fxs: input.included_cols.clone(),
            gxs: super_cols,
            mfxs: included_col_ms,
            mgxs: super_col_multiplicity,
        };

        KeyedSumcheck::<B>::prove(prover, keyed_sumcheck_prover_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let included_col_ms = input
            .included_tracked_col_oracles
            .iter()
            .map(|_included_col| None)
            .collect::<Vec<_>>();

        let super_cols = vec![input.super_tracked_col_oracle.clone()];
        let super_col_multiplicity = vec![Some(input.super_col_multiplicity.clone())];
        let keyed_sumcheck_verifier_input = KeyedSumcheckVerifierInput {
            fxs: input.included_tracked_col_oracles.clone(),
            gxs: super_cols,
            mfxs: included_col_ms,
            mgxs: super_col_multiplicity,
        };
        KeyedSumcheck::<B>::verify(verifier, keyed_sumcheck_verifier_input)?;
        Ok(())
    }
}

impl<B: SnarkBackend> PIOP<B> for LookupCheckPIOP<B> {
    type ProverInput = LookupCheckProverInput<B>;

    type ProverOutput = LookupCheckProverOutput<B>;

    type VerifierOutput = LookupCheckVerifierOutput<B>;

    type VerifierInput = LookupCheckVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use std::{collections::HashSet, hash::Hash};

        use crate::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let super_col_hash_set: HashSet<B::F> =
            HashSet::from_iter(input.super_col.evaluations().iter().cloned());
        for elem in input.included_cols.iter().flat_map(|c| c.evaluations()) {
            if !super_col_hash_set.contains(&elem) {
                tracing::error!("error");
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let super_col_m_mle = calc_inclusion_multiplicity(&input.included_cols, &input.super_col);
        let super_col_m = prover.track_and_commit_mat_mv_poly(&super_col_m_mle)?;

        let hinted_lookup_prover_input = HintedLookupCheckProverInput {
            included_cols: input.included_cols,
            super_col: input.super_col,
            super_col_multiplicity: super_col_m.clone(),
        };
        HintedLookupCheckPIOP::<B>::prove(prover, hinted_lookup_prover_input)?;
        Ok(LookupCheckProverOutput { super_col_m })
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let id = verifier.peek_next_id();
        let super_col_m_comm = verifier.track_mv_com_by_id(id)?;

        let hinted_lookup_verifier_input = HintedLookupCheckVerifierInput {
            included_tracked_col_oracles: input.included_tracked_col_oracles,
            super_tracked_col_oracle: input.super_tracked_col_oracle,
            super_col_multiplicity: super_col_m_comm.clone(),
        };
        HintedLookupCheckPIOP::<B>::verify(verifier, hinted_lookup_verifier_input)?;
        Ok(LookupCheckVerifierOutput { super_col_m_comm })
    }
}
