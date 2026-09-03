use crate::{
    arithmetic::virt_poly::hp_interface::{HPVirtualPolynomial, VPAuxInfo},
    errors::SnarkResult,
    piop::structs::{SumcheckProverState, SumcheckVerifierState},
    transcript::Tr,
};
use ark_ff::PrimeField;
use tracing::instrument;

use std::{fmt::Debug, marker::PhantomData};

use super::structs::SumcheckProof;

mod prover;
#[cfg(test)]
mod tests;
mod verifier;
#[derive(Clone, Debug, Default, Copy, PartialEq, Eq)]
/// The SumCheck PolyIOP over prime field `F`.
pub struct SumCheck<F: PrimeField> {
    #[doc(hidden)]
    phantom: PhantomData<F>,
}

/// The claim the verifier emits at the end of a successful verification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SumCheckSubClaim<F: PrimeField> {
    /// The point at which the polynomial is claimed to evaluate.
    pub point: Vec<F>,
    /// The expected evaluation.
    pub expected_evaluation: F,
}

impl<F: PrimeField> SumCheck<F> {
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn prove(
        poly: &HPVirtualPolynomial<F>,
        transcript: &mut Tr<F>,
    ) -> SnarkResult<SumcheckProof<F>> {
        transcript.append_serializable_element(b"aux info", &poly.aux_info)?;

        let mut prover_state = SumcheckProverState::prover_init(poly)?;
        let mut challenge = None;
        let mut prover_msgs = Vec::with_capacity(poly.aux_info.num_variables);
        for _ in 0..poly.aux_info.num_variables {
            let prover_msg =
                SumcheckProverState::prove_round_and_update_state(&mut prover_state, &challenge)?;
            transcript.append_serializable_element(b"prover msg", &prover_msg)?;
            prover_msgs.push(prover_msg);
            challenge = Some(transcript.get_and_append_challenge(b"Internal round")?);
        }
        // pushing the last challenge point to the state
        if let Some(p) = challenge {
            prover_state.challenges.push(p)
        };

        Ok(SumcheckProof {
            point: prover_state.challenges,
            proofs: prover_msgs,
        })
    }

    pub(crate) fn verify(
        claimed_sum: F,
        proof: &SumcheckProof<F>,
        aux_info: &VPAuxInfo<F>,
        transcript: &mut Tr<F>,
    ) -> SnarkResult<SumCheckSubClaim<F>> {
        transcript.append_serializable_element(b"aux info", aux_info)?;
        let mut verifier_state = SumcheckVerifierState::verifier_init(aux_info);
        for i in 0..aux_info.num_variables {
            let prover_msg = proof.proofs.get(i).expect("proof is incomplete");
            transcript.append_serializable_element(b"prover msg", prover_msg)?;
            SumcheckVerifierState::verify_round_and_update_state(
                &mut verifier_state,
                prover_msg,
                transcript,
            )?;
        }

        SumcheckVerifierState::check_and_generate_subclaim(&verifier_state, &claimed_sum)
    }
}
