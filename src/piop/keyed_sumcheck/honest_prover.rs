use super::KeyedSumcheck;
use super::KeyedSumcheckProverInput;
#[cfg(feature = "honest-prover")]
use crate::errors::SnarkResult;
use crate::{SnarkBackend, piop::DeepClone, prover::ArgProver};
use ark_ff::One;
use ark_ff::Zero;
impl<B: SnarkBackend> DeepClone<B> for KeyedSumcheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            fxs: self
                .fxs
                .iter()
                .map(|x| x.deep_clone(prover.clone()))
                .collect(),
            gxs: self
                .gxs
                .iter()
                .map(|x| x.deep_clone(prover.clone()))
                .collect(),
            mfxs: self
                .mfxs
                .iter()
                .map(|x| x.as_ref().map(|x| x.deep_clone(prover.clone())))
                .collect(),
            mgxs: self
                .mgxs
                .iter()
                .map(|x| x.as_ref().map(|x| x.deep_clone(prover.clone())))
                .collect(),
        }
    }
}

#[cfg(feature = "honest-prover")]
impl<B> KeyedSumcheck<B>
where
    B: SnarkBackend,
{
    /// A helper function to check if the prover input is valid.
    /// Since the function is huge, we put it in a seperate file.
    // TODO: Although the performance does not matter for release, we should
    // parallelize this
    pub(crate) fn honest_prover_check_helper(
        input: &KeyedSumcheckProverInput<B>,
    ) -> SnarkResult<()> {
        // Check that we do actually have some polynomial on the left hand side

        use crate::errors::InputShapeError::EmptyInput;
        use std::collections::BTreeMap;
        if input.fxs.is_empty() {
            use crate::{
                errors::SnarkError,
                prover::errors::{HonestProverError, ProverError},
            };

            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::WrongInputShape(EmptyInput),
            )));
        }
        // Check that we have as many multiplicity polynomials as we do polynomials on
        // the left side
        if input.fxs.len() != input.mfxs.len() {
            use crate::errors::InputShapeError::InputLengthMismatch;
            use crate::errors::SnarkError;
            use crate::prover::errors::{HonestProverError, ProverError};
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::WrongInputShape(InputLengthMismatch {
                    expected: input.fxs.len(),
                    actual: input.mfxs.len(),
                }),
            )));
        }

        // Check that we do actually have some polynomial on the right hand side
        if input.gxs.is_empty() {
            use crate::errors::InputShapeError::EmptyInput;
            use crate::{
                errors::SnarkError,
                prover::errors::{HonestProverError, ProverError},
            };
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::WrongInputShape(EmptyInput),
            )));
        }
        // Check that we have as many multiplicity polynomials as we do polynomials on
        // the right side
        if input.gxs.len() != input.mgxs.len() {
            use crate::errors::InputShapeError::InputLengthMismatch;
            use crate::prover::errors::ProverError;
            use crate::{errors::SnarkError, prover::errors::HonestProverError};
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::WrongInputShape(InputLengthMismatch {
                    expected: input.gxs.len(),
                    actual: input.mgxs.len(),
                }),
            )));
        }

        let mut bookkeeping_map: BTreeMap<B::F, B::F> = BTreeMap::new();
        for (fx, mfx) in input.fxs.iter().zip(&input.mfxs) {
            match mfx {
                None => {
                    for elem in fx.evaluations() {
                        *bookkeeping_map.entry(elem).or_insert(B::F::zero()) += B::F::one();
                    }
                }
                Some(mfx) => {
                    for (elem, mf_elem) in
                        fx.evaluations().into_iter().zip(mfx.evaluations().iter())
                    {
                        *bookkeeping_map.entry(elem).or_insert(B::F::zero()) += *mf_elem;
                    }
                }
            }
        }

        for (gx, mgx) in input.gxs.iter().zip(&input.mgxs) {
            match mgx {
                None => {
                    for elem in gx.evaluations() {
                        *bookkeeping_map.entry(elem).or_insert(B::F::zero()) -= B::F::one();
                    }
                }
                Some(mgx) => {
                    for (elem, mg_elem) in
                        gx.evaluations().into_iter().zip(mgx.evaluations().iter())
                    {
                        *bookkeeping_map.entry(elem).or_insert(B::F::zero()) -= *mg_elem;
                    }
                }
            }
        }

        for (_, count) in bookkeeping_map.iter() {
            if *count != B::F::zero() {
                use crate::{
                    errors::SnarkError,
                    prover::errors::{HonestProverError, ProverError},
                };
                tracing::error!("error");
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }
}
