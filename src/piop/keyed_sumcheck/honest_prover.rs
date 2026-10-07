#[cfg(feature = "honest-prover")]
use super::KeyedSumcheck;
use super::KeyedSumcheckProverInput;
#[cfg(feature = "honest-prover")]
use crate::errors::SnarkResult;
use crate::{SnarkBackend, piop::DeepClone, prover::ArgProver};
#[cfg(feature = "honest-prover")]
use ark_ff::{One, Zero};
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
    /// Checks that the prover input is a valid multiset-equality claim.
    // TODO: parallelize
    pub(crate) fn honest_prover_check_helper(
        input: &KeyedSumcheckProverInput<B>,
    ) -> SnarkResult<()> {
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

        // Each term runs over the larger of its column's and its
        // multiplicity's hypercubes, the smaller one repeated cyclically, as
        // in the protocol.
        let mut bookkeeping_map: BTreeMap<B::F, B::F> = BTreeMap::new();
        let sides = [
            (&input.fxs, &input.mfxs, B::F::one()),
            (&input.gxs, &input.mgxs, -B::F::one()),
        ];
        for (cols, mults, sign) in sides {
            for (col, mult) in cols.iter().zip(mults) {
                let col = col.evaluations();
                let mult = mult.as_ref().map(|mult| mult.evaluations());
                let rows = col.len().max(mult.as_ref().map_or(0, Vec::len));
                for row in 0..rows {
                    let weight = mult.as_ref().map_or(sign, |m| sign * m[row % m.len()]);
                    *bookkeeping_map
                        .entry(col[row % col.len()])
                        .or_insert(B::F::zero()) += weight;
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
