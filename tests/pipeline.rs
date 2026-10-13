// Integration test: drive the full prover -> proof -> verifier pipeline.
#![cfg(feature = "test-utils")]

use ark_ff::Zero;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkError,
    test_utils::test_prelude,
};

#[test]
fn end_to_end_pipeline() -> Result<(), SnarkError> {
    type B = DefaultSnarkBackend;
    type F = <B as SnarkBackend>::F;

    let (mut prover, mut verifier) = test_prelude::<B>()?;

    let nv = 4usize;
    let size = 1usize << nv;

    let evals_1: Vec<F> = (0..size).map(|i| F::from(i as u64)).collect();
    let evals_2: Vec<F> = (0..size).map(|i| F::from((i as u64) * 3)).collect();
    let evals_zero: Vec<F> = vec![F::zero(); size];
    // Three lookup groups: every sub holds only values of its super.
    let evals_super_a: Vec<F> = (0..size).map(|i| F::from((i % 8) as u64)).collect();
    let evals_sub_a1: Vec<F> = (0..size).map(|i| F::from(((i * 3) % 8) as u64)).collect();
    let evals_sub_a2: Vec<F> = (0..size)
        .map(|i| F::from(((size - 1 - i) % 8) as u64))
        .collect();
    let evals_super_b: Vec<F> = (0..size).map(|i| F::from((i % 5) as u64)).collect();
    let evals_sub_b1: Vec<F> = (0..size).map(|i| F::from(((i * 2) % 5) as u64)).collect();
    let evals_super_c: Vec<F> = (0..size).map(|i| F::from((i % 4) as u64)).collect();
    let evals_sub_c1: Vec<F> = (0..size).map(|i| F::from(((i * 3) % 4) as u64)).collect();

    let poly_1 = MLE::from_evaluations_vec(nv, evals_1.clone());
    let poly_2 = MLE::from_evaluations_vec(nv, evals_2.clone());
    let poly_zero = MLE::from_evaluations_vec(nv, evals_zero);
    let poly_super_a = MLE::from_evaluations_vec(nv, evals_super_a);
    let poly_sub_a1 = MLE::from_evaluations_vec(nv, evals_sub_a1);
    let poly_sub_a2 = MLE::from_evaluations_vec(nv, evals_sub_a2);
    let poly_super_b = MLE::from_evaluations_vec(nv, evals_super_b);
    let poly_sub_b1 = MLE::from_evaluations_vec(nv, evals_sub_b1);
    let poly_super_c = MLE::from_evaluations_vec(nv, evals_super_c);
    let poly_sub_c1 = MLE::from_evaluations_vec(nv, evals_sub_c1);

    let tracked_1 = prover.track_and_commit_mat_mv_poly(&poly_1)?;
    let tracked_2 = prover.track_and_commit_mat_mv_poly(&poly_2)?;
    let tracked_zero = prover.track_and_commit_mat_mv_poly(&poly_zero)?;
    let tracked_super_a = prover.track_and_commit_mat_mv_poly(&poly_super_a)?;
    let tracked_sub_a1 = prover.track_and_commit_mat_mv_poly(&poly_sub_a1)?;
    let tracked_sub_a2 = prover.track_and_commit_mat_mv_poly(&poly_sub_a2)?;
    let tracked_super_b = prover.track_and_commit_mat_mv_poly(&poly_super_b)?;
    let tracked_sub_b1 = prover.track_and_commit_mat_mv_poly(&poly_sub_b1)?;
    let tracked_super_c = prover.track_and_commit_mat_mv_poly(&poly_super_c)?;
    let tracked_sub_c1 = prover.track_and_commit_mat_mv_poly(&poly_sub_c1)?;

    let sum_1 = evals_1.iter().fold(F::zero(), |acc, v| acc + v);
    let sum_2 = evals_2.iter().fold(F::zero(), |acc, v| acc + v);

    prover.add_mv_sumcheck_claim(tracked_1.id(), sum_1)?;
    prover.add_mv_sumcheck_claim(tracked_2.id(), sum_2)?;
    prover.add_mv_zerocheck_claim(tracked_zero.id())?;
    // Super A has two subs, the other supers one each.
    prover.add_mv_lookup_claim(tracked_super_a.id(), tracked_sub_a1.id())?;
    prover.add_mv_lookup_claim(tracked_super_a.id(), tracked_sub_a2.id())?;
    prover.add_mv_lookup_claim(tracked_super_b.id(), tracked_sub_b1.id())?;
    prover.add_mv_lookup_claim(tracked_super_c.id(), tracked_sub_c1.id())?;

    let proof = prover.build_proof()?;

    verifier.set_proof(proof);
    let _ = verifier.track_mv_com_by_id(tracked_1.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_2.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_zero.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_super_a.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_sub_a1.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_sub_a2.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_super_b.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_sub_b1.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_super_c.id())?;
    let _ = verifier.track_mv_com_by_id(tracked_sub_c1.id())?;

    verifier.add_mv_sumcheck_claim(tracked_1.id(), sum_1);
    verifier.add_mv_sumcheck_claim(tracked_2.id(), sum_2);
    verifier.add_mv_zerocheck_claim(tracked_zero.id());
    verifier.add_mv_lookup_claim(tracked_super_a.id(), tracked_sub_a1.id())?;
    verifier.add_mv_lookup_claim(tracked_super_a.id(), tracked_sub_a2.id())?;
    verifier.add_mv_lookup_claim(tracked_super_b.id(), tracked_sub_b1.id())?;
    verifier.add_mv_lookup_claim(tracked_super_c.id(), tracked_sub_c1.id())?;

    verifier.verify()?;
    Ok(())
}
