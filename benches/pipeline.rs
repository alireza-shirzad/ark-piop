//! Microbenchmarks for the hot paths that determine end-to-end proving cost.
//!
//! Run with `cargo bench --features test-utils`. Criterion stores previous
//! results in `target/criterion/` and reports deltas on re-run, so a developer
//! can detect regressions locally before pushing. CI uses the same benches in
//! --quick mode as a smoke check.
#![cfg(feature = "test-utils")]

use ark_ff::Zero;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, test_utils::test_prelude,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn mle_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("mle_add");
    for &nv in &[8usize, 10, 12] {
        let size = 1usize << nv;
        let a: Vec<F> = (0..size).map(|i| F::from(i as u64)).collect();
        let b: Vec<F> = (0..size).map(|i| F::from((i * 3) as u64)).collect();
        let poly_a = MLE::from_evaluations_vec(nv, a);
        let poly_b = MLE::from_evaluations_vec(nv, b);
        group.bench_with_input(BenchmarkId::from_parameter(nv), &nv, |bencher, _| {
            bencher.iter(|| {
                let _ = &poly_a + &poly_b;
            });
        });
    }
    group.finish();
}

fn sumcheck_prove_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sumcheck_prove_verify");
    group.sample_size(10);
    for &nv in &[6usize, 8] {
        let size = 1usize << nv;
        group.bench_with_input(BenchmarkId::from_parameter(nv), &nv, |bencher, _| {
            bencher.iter(|| {
                let (mut prover, mut verifier) = test_prelude::<B>().unwrap();
                let evals: Vec<F> = (0..size).map(|i| F::from(i as u64)).collect();
                let poly = MLE::from_evaluations_vec(nv, evals.clone());
                let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
                let sum: F = evals.iter().copied().fold(F::zero(), |a, b| a + b);
                prover.add_mv_sumcheck_claim(tracked.id(), sum).unwrap();
                let proof = prover.build_proof().unwrap();
                verifier.set_proof(proof);
                verifier.track_mv_com_by_id(tracked.id()).unwrap();
                verifier.add_mv_sumcheck_claim(tracked.id(), sum);
                verifier.verify().unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, mle_add, sumcheck_prove_verify);
criterion_main!(benches);
