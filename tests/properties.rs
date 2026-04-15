//! Property-based tests for algebraic invariants in ark-piop.
//!
//! These tests exercise the prover tracker's virtual polynomial algebra
//! (add/sub/mul/scalar operations, degree computation) on randomly-generated
//! inputs to catch edge cases that hand-written tests miss.
#![cfg(feature = "test-utils")]

use ark_ff::Zero;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, test_utils::test_prelude,
};
use proptest::prelude::*;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// Strategy for generating a vector of 2^nv field elements representing
/// the evaluations of a multilinear polynomial.
fn mle_evals_strategy(nv: usize) -> impl Strategy<Value = Vec<F>> {
    let size = 1usize << nv;
    prop::collection::vec(any::<u64>().prop_map(F::from), size..=size)
}

/// Build an MLE from a raw u64 evaluation vector (for tests that prefer
/// small explicit inputs rather than the full u64 range).
fn mle_from_u64s(nv: usize, evals: &[u64]) -> MLE<F> {
    MLE::from_evaluations_vec(nv, evals.iter().copied().map(F::from).collect())
}

// ─── MLE arithmetic identities ────────────────────────────────────────────

proptest! {
    /// `a + b` produces the same evaluations as `b + a`.
    #[test]
    fn mle_add_is_commutative(evals_a in mle_evals_strategy(3), evals_b in mle_evals_strategy(3)) {
        let a = MLE::from_evaluations_vec(3, evals_a);
        let b = MLE::from_evaluations_vec(3, evals_b);
        let ab = &a + &b;
        let ba = &b + &a;
        prop_assert_eq!(ab.evaluations(), ba.evaluations());
    }

    /// `(a + b) + c == a + (b + c)`.
    #[test]
    fn mle_add_is_associative(
        evals_a in mle_evals_strategy(3),
        evals_b in mle_evals_strategy(3),
        evals_c in mle_evals_strategy(3),
    ) {
        let a = MLE::from_evaluations_vec(3, evals_a);
        let b = MLE::from_evaluations_vec(3, evals_b);
        let c = MLE::from_evaluations_vec(3, evals_c);
        let left = &(&a + &b) + &c;
        let right = &a + &(&b + &c);
        prop_assert_eq!(left.evaluations(), right.evaluations());
    }

    /// `a + 0 == a`.
    #[test]
    fn mle_add_zero_is_identity(evals in mle_evals_strategy(3)) {
        let a = MLE::from_evaluations_vec(3, evals);
        let z = MLE::from_evaluations_vec(3, vec![F::zero(); 8]);
        let sum = &a + &z;
        prop_assert_eq!(sum.evaluations(), a.evaluations());
    }

    /// `(a + b) - b == a`.
    #[test]
    fn mle_sub_is_inverse_of_add(
        evals_a in mle_evals_strategy(3),
        evals_b in mle_evals_strategy(3),
    ) {
        let a = MLE::from_evaluations_vec(3, evals_a);
        let b = MLE::from_evaluations_vec(3, evals_b);
        let result = &(&a + &b) - &b;
        prop_assert_eq!(result.evaluations(), a.evaluations());
    }

    /// `c * (a + b) == c*a + c*b`.
    #[test]
    fn mle_scalar_mul_distributes_over_add(
        evals_a in mle_evals_strategy(3),
        evals_b in mle_evals_strategy(3),
        c in any::<u64>().prop_map(F::from),
    ) {
        let a = MLE::from_evaluations_vec(3, evals_a);
        let b = MLE::from_evaluations_vec(3, evals_b);
        let left = &(&a + &b) * &c;
        let right = &(&a * &c) + &(&b * &c);
        prop_assert_eq!(left.evaluations(), right.evaluations());
    }

    /// `is_constant` on a vec of all-equal evals is always true.
    #[test]
    fn mle_is_constant_on_equal_evals(value in any::<u64>().prop_map(F::from), nv in 1usize..=5) {
        let size = 1usize << nv;
        let mle = MLE::from_evaluations_vec(nv, vec![value; size]);
        prop_assert!(mle.is_constant());
    }
}

// ─── Prover tracker algebra identities ────────────────────────────────────
//
// These go through full key generation per iteration, so cap the case count
// to keep the test suite snappy.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// `evaluate(add_polys(a, b), p) == evaluate(a, p) + evaluate(b, p)`
    /// over the evaluation point `p`.
    #[test]
    fn tracker_add_polys_matches_pointwise_sum(
        evals_a in mle_evals_strategy(3),
        evals_b in mle_evals_strategy(3),
        p0 in any::<u64>().prop_map(F::from),
        p1 in any::<u64>().prop_map(F::from),
        p2 in any::<u64>().prop_map(F::from),
    ) {
        let (prover, _verifier) = test_prelude::<B>().unwrap();
        let mut tracker = prover.tracker().borrow_mut().clone();
        let _ = prover;  // drop early

        let a_id = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(3, evals_a));
        let b_id = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(3, evals_b));
        let sum_id = tracker.add_polys(a_id, b_id);

        let pt = vec![p0, p1, p2];
        let ea = tracker.evaluate_mv(a_id, &pt).unwrap();
        let eb = tracker.evaluate_mv(b_id, &pt).unwrap();
        let es = tracker.evaluate_mv(sum_id, &pt).unwrap();
        prop_assert_eq!(es, ea + eb);
    }

    /// `evaluate(mul_polys(a, b), p) == evaluate(a, p) * evaluate(b, p)`.
    #[test]
    fn tracker_mul_polys_matches_pointwise_product(
        evals_a in mle_evals_strategy(3),
        evals_b in mle_evals_strategy(3),
        p0 in any::<u64>().prop_map(F::from),
        p1 in any::<u64>().prop_map(F::from),
        p2 in any::<u64>().prop_map(F::from),
    ) {
        let (prover, _verifier) = test_prelude::<B>().unwrap();
        let mut tracker = prover.tracker().borrow_mut().clone();
        let _ = prover;

        let a_id = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(3, evals_a));
        let b_id = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(3, evals_b));
        let prod_id = tracker.mul_polys(a_id, b_id);

        let pt = vec![p0, p1, p2];
        let ea = tracker.evaluate_mv(a_id, &pt).unwrap();
        let eb = tracker.evaluate_mv(b_id, &pt).unwrap();
        let ep = tracker.evaluate_mv(prod_id, &pt).unwrap();
        prop_assert_eq!(ep, ea * eb);
    }

    /// `evaluate(mul_scalar(a, c), p) == c * evaluate(a, p)`.
    #[test]
    fn tracker_mul_scalar_matches_pointwise_scaling(
        evals in mle_evals_strategy(3),
        c in any::<u64>().prop_map(F::from),
        p0 in any::<u64>().prop_map(F::from),
        p1 in any::<u64>().prop_map(F::from),
        p2 in any::<u64>().prop_map(F::from),
    ) {
        let (prover, _verifier) = test_prelude::<B>().unwrap();
        let mut tracker = prover.tracker().borrow_mut().clone();
        let _ = prover;

        let id = tracker.track_mat_mv_poly(MLE::from_evaluations_vec(3, evals));
        let scaled = tracker.mul_scalar(id, c);

        let pt = vec![p0, p1, p2];
        let e = tracker.evaluate_mv(id, &pt).unwrap();
        let es = tracker.evaluate_mv(scaled, &pt).unwrap();
        prop_assert_eq!(es, c * e);
    }

    /// Degree of a sum equals max of the inputs' degrees, for any two
    /// materialized polynomials (both degree 1 → sum degree 1).
    #[test]
    fn tracker_add_polys_degree_is_max(nv_a in 1usize..=4, nv_b in 1usize..=4) {
        let (prover, _verifier) = test_prelude::<B>().unwrap();
        let mut tracker = prover.tracker().borrow_mut().clone();
        let _ = prover;

        let a = tracker.track_mat_mv_poly(mle_from_u64s(nv_a, &vec![1; 1 << nv_a]));
        let b = tracker.track_mat_mv_poly(mle_from_u64s(nv_b, &vec![1; 1 << nv_b]));
        let sum = tracker.add_polys(a, b);
        prop_assert_eq!(tracker.virt_poly_degree(sum), 1);
    }

    /// Degree of a product equals sum of the inputs' degrees.
    /// Two materialized polys (each degree 1) multiplied → degree 2.
    /// Then (a*b) * c → degree 3.
    #[test]
    fn tracker_mul_polys_degree_is_sum(n in 2usize..=5) {
        let (prover, _verifier) = test_prelude::<B>().unwrap();
        let mut tracker = prover.tracker().borrow_mut().clone();
        let _ = prover;

        let nv = 3;
        let ids: Vec<_> = (0..n)
            .map(|i| {
                tracker.track_mat_mv_poly(mle_from_u64s(nv, &vec![(i as u64) + 1; 1 << nv]))
            })
            .collect();
        let prod = ids.iter().copied().skip(1).fold(ids[0], |acc, id| {
            tracker.mul_polys(acc, id)
        });
        prop_assert_eq!(tracker.virt_poly_degree(prod), n);
    }
}
