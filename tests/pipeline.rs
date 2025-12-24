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
    // Lookup super A repeats 0..7 twice, so it contains all sub-column values.
    let evals_super_a: Vec<F> = (0..size).map(|i| F::from((i % 8) as u64)).collect();
    // Lookup sub A1 is a different permutation of 0..7 (same value set as super A).
    let evals_sub_a1: Vec<F> = (0..size).map(|i| F::from(((i * 3) % 8) as u64)).collect();
    // Lookup sub A2 is another permutation of 0..7 (same value set as super A).
    let evals_sub_a2: Vec<F> = (0..size)
        .map(|i| F::from(((size - 1 - i) % 8) as u64))
        .collect();
    // Lookup super B cycles 0..4 to create a different lookup group.
    let evals_super_b: Vec<F> = (0..size).map(|i| F::from((i % 5) as u64)).collect();
    // Lookup sub B1 permutes 0..4 (same value set as super B).
    let evals_sub_b1: Vec<F> = (0..size).map(|i| F::from(((i * 2) % 5) as u64)).collect();
    // Lookup super C cycles 0..3 to add a third lookup group.
    let evals_super_c: Vec<F> = (0..size).map(|i| F::from((i % 4) as u64)).collect();
    // Lookup sub C1 permutes 0..3 (same value set as super C).
    let evals_sub_c1: Vec<F> = (0..size).map(|i| F::from(((i * 3) % 4) as u64)).collect();

    // Materialize the polynomials as MLEs over the Boolean hypercube.
    let poly_1 = MLE::from_evaluations_vec(nv, evals_1.clone());
    let poly_2 = MLE::from_evaluations_vec(nv, evals_2.clone());
    let poly_zero = MLE::from_evaluations_vec(nv, evals_zero);
    // Materialize lookup-only polynomials (three supers, four subs).
    let poly_super_a = MLE::from_evaluations_vec(nv, evals_super_a);
    let poly_sub_a1 = MLE::from_evaluations_vec(nv, evals_sub_a1);
    let poly_sub_a2 = MLE::from_evaluations_vec(nv, evals_sub_a2);
    let poly_super_b = MLE::from_evaluations_vec(nv, evals_super_b);
    let poly_sub_b1 = MLE::from_evaluations_vec(nv, evals_sub_b1);
    let poly_super_c = MLE::from_evaluations_vec(nv, evals_super_c);
    let poly_sub_c1 = MLE::from_evaluations_vec(nv, evals_sub_c1);

    // Track + commit polynomials so the verifier can later query them.
    let tracked_1 = prover.track_and_commit_mat_mv_poly(&poly_1)?;
    let tracked_2 = prover.track_and_commit_mat_mv_poly(&poly_2)?;
    let tracked_zero = prover.track_and_commit_mat_mv_poly(&poly_zero)?;
    // Track + commit lookup polynomials for the two lookup groups.
    let tracked_super_a = prover.track_and_commit_mat_mv_poly(&poly_super_a)?;
    let tracked_sub_a1 = prover.track_and_commit_mat_mv_poly(&poly_sub_a1)?;
    let tracked_sub_a2 = prover.track_and_commit_mat_mv_poly(&poly_sub_a2)?;
    let tracked_super_b = prover.track_and_commit_mat_mv_poly(&poly_super_b)?;
    let tracked_sub_b1 = prover.track_and_commit_mat_mv_poly(&poly_sub_b1)?;
    let tracked_super_c = prover.track_and_commit_mat_mv_poly(&poly_super_c)?;
    let tracked_sub_c1 = prover.track_and_commit_mat_mv_poly(&poly_sub_c1)?;

    // Compute sumcheck targets (sum over the Boolean hypercube).
    let sum_1 = evals_1.iter().fold(F::zero(), |acc, v| acc + v);
    let sum_2 = evals_2.iter().fold(F::zero(), |acc, v| acc + v);

    // Prover claims: two sumchecks and one zerocheck.
    prover.add_mv_sumcheck_claim(tracked_1.id(), sum_1)?;
    prover.add_mv_sumcheck_claim(tracked_2.id(), sum_2)?;
    prover.add_mv_zerocheck_claim(tracked_zero.id())?;
    // Lookup claims for super A with multiple sub columns.
    prover.add_mv_lookup_claim(tracked_super_a.id(), tracked_sub_a1.id())?;
    prover.add_mv_lookup_claim(tracked_super_a.id(), tracked_sub_a2.id())?;
    // Lookup claims for other supers with a single sub column.
    prover.add_mv_lookup_claim(tracked_super_b.id(), tracked_sub_b1.id())?;
    prover.add_mv_lookup_claim(tracked_super_c.id(), tracked_sub_c1.id())?;

    // Build the SNARK proof (sumcheck + PCS subproofs).
    let proof = prover.build_proof()?;

    // Hand the proof to the verifier and register the commitments it will query.
    verifier.set_proof(proof);
    let _ = verifier.track_mv_com_by_id(tracked_1.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_2.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_zero.id())?;
    // Register lookup group commitments so the verifier can access them.
    let _ = verifier.track_mv_com_by_id(tracked_super_a.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_sub_a1.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_sub_a2.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_super_b.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_sub_b1.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_super_c.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_sub_c1.id())?;

    // Verifier mirrors the same sumcheck/zerocheck claims.
    verifier.add_sumcheck_claim(tracked_1.id(), sum_1);
    verifier.add_sumcheck_claim(tracked_2.id(), sum_2);
    verifier.add_zerocheck_claim(tracked_zero.id());
    // Verifier mirrors lookup claims for all super groups.
    verifier.add_mv_lookup_claim(tracked_super_a.id(), tracked_sub_a1.id())?;
    verifier.add_mv_lookup_claim(tracked_super_a.id(), tracked_sub_a2.id())?;
    verifier.add_mv_lookup_claim(tracked_super_b.id(), tracked_sub_b1.id())?;
    verifier.add_mv_lookup_claim(tracked_super_c.id(), tracked_sub_c1.id())?;

    // Full verification should succeed end-to-end.
    verifier.verify()?;
    Ok(())
}
