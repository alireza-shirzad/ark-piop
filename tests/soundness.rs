//! Soundness tests — the verifier must reject malformed or wrong proofs.
#![cfg(feature = "test-utils")]

use ark_ff::Zero;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkError,
    prover::structs::proof::{PROOF_ENCODING_VERSION, SNARKProof},
    test_utils::test_prelude,
    types::artifact::Artifact,
    verifier::errors::VerifierError,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// Verifying without calling `set_proof` must return `ProofNotReceived`,
/// not panic.
#[test]
fn verify_without_proof_returns_proof_not_received() {
    let (_, verifier) = test_prelude::<B>().unwrap();
    // Note: the public `verify(&self)` clones the verifier internally.
    let err = verifier.verify().expect_err("must fail without proof");
    match err {
        SnarkError::VerifierError(VerifierError::ProofNotReceived) => {}
        other => panic!("expected ProofNotReceived, got: {:?}", other),
    }
}

/// Submitting a sumcheck with a *wrong* claimed sum must fail verification.
#[test]
fn wrong_sumcheck_claim_is_rejected() {
    let (mut prover, mut verifier) = test_prelude::<B>().unwrap();

    let nv = 4usize;
    let size = 1usize << nv;
    let evals: Vec<F> = (0..size).map(|i| F::from(i as u64)).collect();
    let poly = MLE::from_evaluations_vec(nv, evals.clone());

    let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
    let correct_sum: F = evals.iter().copied().fold(F::zero(), |a, b| a + b);
    // The prover must submit the true sum, otherwise build_proof rejects
    // under `honest-prover`.  Build the proof honestly, then feed the
    // verifier a different claimed sum.
    prover
        .add_mv_sumcheck_claim(tracked.id(), correct_sum)
        .unwrap();
    let proof = prover.build_proof().unwrap();

    verifier.set_proof(proof);
    verifier.track_mv_com_by_id(tracked.id()).unwrap();
    // Submit a WRONG claim to the verifier (off by one).
    let wrong_sum = correct_sum + F::from(1u64);
    verifier.add_mv_sumcheck_claim(tracked.id(), wrong_sum);

    let err = verifier
        .verify()
        .expect_err("verifier must reject wrong claim");
    matches!(err, SnarkError::VerifierError(_))
        .then_some(())
        .unwrap_or_else(|| panic!("expected VerifierError, got {:?}", err));
}

/// Submitting a zerocheck claim on a non-zero polynomial must fail.
#[test]
fn nonzero_polynomial_rejected_as_zerocheck() {
    let (mut prover, mut verifier) = test_prelude::<B>().unwrap();

    let nv = 4usize;
    let size = 1usize << nv;
    // A non-zero polynomial
    let evals: Vec<F> = (0..size).map(|i| F::from(i as u64 + 1)).collect();
    let poly = MLE::from_evaluations_vec(nv, evals);
    let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();

    // Under honest-prover, add_mv_zerocheck_claim would reject the nonzero
    // polynomial. Skip this test under that feature since the failure is
    // caught earlier (at claim time).
    let result = prover.add_mv_zerocheck_claim(tracked.id());
    if cfg!(feature = "honest-prover") {
        assert!(
            result.is_err(),
            "honest-prover must reject zerocheck on nonzero poly at add-time"
        );
        return;
    }
    result.unwrap();

    let proof = prover.build_proof().unwrap();
    verifier.set_proof(proof);
    verifier.track_mv_com_by_id(tracked.id()).unwrap();
    verifier.add_mv_zerocheck_claim(tracked.id());

    let err = verifier
        .verify()
        .expect_err("verifier must reject nonzero zerocheck");
    matches!(err, SnarkError::VerifierError(_))
        .then_some(())
        .unwrap_or_else(|| panic!("expected VerifierError, got {:?}", err));
}

/// The serialized proof starts with a one-byte version tag and a round trip
/// through `to_bytes`/`from_bytes` must succeed.
#[test]
fn proof_envelope_version_roundtrip() {
    let (mut prover, _verifier) = test_prelude::<B>().unwrap();
    let nv = 3usize;
    let evals: Vec<F> = (0..(1 << nv)).map(|i| F::from(i as u64)).collect();
    let poly = MLE::from_evaluations_vec(nv, evals.clone());
    let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
    let sum: F = evals.iter().copied().fold(F::zero(), |a, b| a + b);
    prover.add_mv_sumcheck_claim(tracked.id(), sum).unwrap();
    let proof = prover.build_proof().unwrap();

    let bytes = proof.to_bytes().unwrap();
    assert_eq!(
        bytes[0], PROOF_ENCODING_VERSION,
        "first byte of serialized proof must be the version tag"
    );

    let decoded: SNARKProof<B> = SNARKProof::<B>::from_bytes(&bytes).unwrap();
    // Re-encode and check stability.
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
}

/// A buffer with the wrong version byte must return an `Artifact` error
/// mentioning the mismatch, not a silent deserialization failure.
#[test]
fn proof_envelope_rejects_wrong_version() {
    let (mut prover, _verifier) = test_prelude::<B>().unwrap();
    let nv = 3usize;
    let evals: Vec<F> = (0..(1 << nv)).map(|i| F::from(i as u64)).collect();
    let poly = MLE::from_evaluations_vec(nv, evals.clone());
    let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
    let sum: F = evals.iter().copied().fold(F::zero(), |a, b| a + b);
    prover.add_mv_sumcheck_claim(tracked.id(), sum).unwrap();
    let proof = prover.build_proof().unwrap();

    let mut bytes = proof.to_bytes().unwrap();
    bytes[0] = PROOF_ENCODING_VERSION.wrapping_add(1);

    let err = SNARKProof::<B>::from_bytes(&bytes).expect_err("wrong version must fail");
    match err {
        SnarkError::Artifact(msg) => assert!(
            msg.contains("version"),
            "error message must mention version: got {msg}"
        ),
        other => panic!("expected SnarkError::Artifact, got {other:?}"),
    }
}

/// An empty buffer must fail with a descriptive error, not a panic.
#[test]
fn proof_envelope_rejects_empty_buffer() {
    let err = SNARKProof::<B>::from_bytes(&[]).expect_err("empty buffer must fail");
    match err {
        SnarkError::Artifact(_) => {}
        other => panic!("expected SnarkError::Artifact, got {other:?}"),
    }
}
