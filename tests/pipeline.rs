// Integration test: drive the full prover -> proof -> verifier pipeline.
#![cfg(feature = "test-utils")]

use ark_ff::Zero;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkError,
    test_utils::test_prelude,
};

#[test]
fn end_to_end_pipeline() -> Result<(), SnarkError> {
    // Use the default backend (BLS12-381 + PST13/KZG10) exposed for tests.
    type B = DefaultSnarkBackend;
    type F = <B as SnarkBackend>::F;

    // Build a prover/verifier pair with small test parameters.
    let (mut prover, mut verifier) = test_prelude::<B>()?;

    // Keep the instance tiny but non-trivial: 2^4 evaluations.
    let nv = 4usize;
    let size = 1usize << nv;

    // Synthetic polynomial evaluations (deterministic, easy to reason about).
    // [0, 1, 2, ..., size-1]
    let evals_1: Vec<F> = (0..size).map(|i| F::from(i as u64)).collect();
    // [0, 3, 6, ..., 3*(size-1)]
    let evals_2: Vec<F> = (0..size).map(|i| F::from((i as u64) * 3)).collect();
    // [0, 0, 0, ..., 0]
    let evals_zero: Vec<F> = vec![F::zero(); size];

    // Materialize the polynomials as MLEs over the Boolean hypercube.
    let poly_1 = MLE::from_evaluations_vec(nv, evals_1.clone());
    let poly_2 = MLE::from_evaluations_vec(nv, evals_2.clone());
    let poly_zero = MLE::from_evaluations_vec(nv, evals_zero);

    // Track + commit polynomials so the verifier can later query them.
    let tracked_1 = prover.track_and_commit_mat_mv_poly(&poly_1)?;
    let tracked_2 = prover.track_and_commit_mat_mv_poly(&poly_2)?;
    let tracked_zero = prover.track_and_commit_mat_mv_poly(&poly_zero)?;

    // Compute sumcheck targets (sum over the Boolean hypercube).
    let sum_1 = evals_1.iter().fold(F::zero(), |acc, v| acc + v);
    let sum_2 = evals_2.iter().fold(F::zero(), |acc, v| acc + v);

    // Prover claims: two sumchecks, one zerocheck, and a simple lookup.
    prover.add_mv_sumcheck_claim(tracked_1.id(), sum_1)?;
    prover.add_mv_sumcheck_claim(tracked_2.id(), sum_2)?;
    prover.add_mv_zerocheck_claim(tracked_zero.id())?;
    // Lookup is trivially true by using the same polynomial as super/sub.
    prover.add_mv_lookup_claim(tracked_1.id(), tracked_1.id())?;

    // Build the SNARK proof (sumcheck + PCS subproofs).
    let proof = prover.build_proof()?;

    // Hand the proof to the verifier and register the commitments it will query.
    verifier.set_proof(proof);
    let _ = verifier.track_mv_com_by_id(tracked_1.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_2.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_zero.id())?;

    // Verifier mirrors the same claims (sumcheck/zerocheck/lookup).
    verifier.add_sumcheck_claim(tracked_1.id(), sum_1);
    verifier.add_sumcheck_claim(tracked_2.id(), sum_2);
    verifier.add_zerocheck_claim(tracked_zero.id());
    verifier.add_mv_lookup_claim(tracked_1.id(), tracked_1.id())?;

    // Full verification should succeed end-to-end.
    verifier.verify()?;
    Ok(())
}
