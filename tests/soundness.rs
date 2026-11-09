//! Soundness tests: the verifier must reject malformed or wrong proofs.
#![cfg(feature = "test-utils")]

use ark_ff::Zero;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, assert_soundness_error},
    prover::structs::proof::{PROOF_ENCODING_VERSION, SNARKProof},
    test_utils::test_prelude,
    types::artifact::Artifact,
    verifier::errors::VerifierError,
};
use ark_serialize::{CanonicalSerialize, Compress};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// Verifying without calling `set_proof` must return `ProofNotReceived`,
/// not panic.
#[test]
fn verify_without_proof_returns_proof_not_received() {
    let (_, verifier) = test_prelude::<B>().unwrap();
    let err = verifier.verify().expect_err("must fail without proof");
    match err {
        SnarkError::VerifierError(VerifierError::ProofNotReceived) => {}
        other => panic!("expected ProofNotReceived, got: {:?}", other),
    }
}

/// Submitting a sumcheck with a wrong claimed sum must fail verification.
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
    // under `honest-prover`. The verifier is fed a different claimed sum.
    prover
        .add_mv_sumcheck_claim(tracked.id(), correct_sum)
        .unwrap();
    let proof = prover.build_proof().unwrap();

    verifier.set_proof(proof);
    verifier.track_mv_com_by_id(tracked.id()).unwrap();
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
    let evals: Vec<F> = (0..size).map(|i| F::from(i as u64 + 1)).collect();
    let poly = MLE::from_evaluations_vec(nv, evals);
    let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();

    // Under `honest-prover` the claim is refused when it is added.
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

/// Version 2 had no LogUp-GKR subproofs and named no lookup protocol. With
/// those fields last, cutting the empty list and the protocol's messages
/// off a current proof gives exactly its version-2 encoding, which must be
/// refused by its tag, and must not decode under the current tag either.
#[test]
fn proof_envelope_rejects_version_2() {
    let (mut prover, _verifier) = test_prelude::<B>().unwrap();
    let nv = 3usize;
    let evals: Vec<F> = (0..(1 << nv)).map(|i| F::from(i as u64)).collect();
    let poly = MLE::from_evaluations_vec(nv, evals.clone());
    let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
    let sum: F = evals.iter().copied().fold(F::zero(), |a, b| a + b);
    prover.add_mv_sumcheck_claim(tracked.id(), sum).unwrap();
    let proof = prover.build_proof().unwrap();
    assert!(proof.logup_gkr_subproofs.is_empty());

    let mut bytes = proof.to_bytes().unwrap();
    let lookup_messages = proof.lookup_messages.serialized_size(Compress::Yes);
    let since_version_2 = bytes.split_off(bytes.len() - 8 - lookup_messages);
    assert_eq!(since_version_2[..8], [0u8; 8]);
    assert!(SNARKProof::<B>::from_bytes(&bytes).is_err());

    bytes[0] = 2;
    let err = SNARKProof::<B>::from_bytes(&bytes).expect_err("version 2 must fail");
    assert!(matches!(err, SnarkError::Artifact(_)), "got {err:?}");
}

/// A proof with a sumcheck claim on a committed column, which gives it a
/// commitment: something that is not encoded the same compressed and
/// uncompressed.
fn proof_with_a_commitment() -> SNARKProof<B> {
    let (mut prover, _verifier) = test_prelude::<B>().unwrap();
    let nv = 3usize;
    let evals: Vec<F> = (0..(1 << nv)).map(|i| F::from(i as u64)).collect();
    let poly = MLE::from_evaluations_vec(nv, evals.clone());
    let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
    let sum: F = evals.iter().copied().fold(F::zero(), |a, b| a + b);
    prover.add_mv_sumcheck_claim(tracked.id(), sum).unwrap();
    prover.build_proof().unwrap()
}

/// The bytes of a proof are a proof and nothing after it. Whatever
/// followed would be ignored by every check of the verifier, and could be
/// what is left of a proof whose fields were made to end early.
#[test]
fn proof_envelope_rejects_trailing_bytes() {
    let bytes = proof_with_a_commitment().to_bytes().unwrap();
    for trailing in [&[0u8][..], &[0xff; 9], &bytes[1..]] {
        let longer = [&bytes[..], trailing].concat();
        let err = SNARKProof::<B>::from_bytes(&longer).expect_err("trailing bytes must fail");
        match err {
            SnarkError::Artifact(msg) => assert!(
                msg.contains(&format!("{} bytes", trailing.len())),
                "error message must count the trailing bytes: got {msg}"
            ),
            other => panic!("expected SnarkError::Artifact, got {other:?}"),
        }
    }
}

/// A payload written uncompressed is still read, as the same proof, and
/// nothing may follow it either.
#[test]
fn proof_envelope_reads_an_uncompressed_payload_whole() {
    let proof = proof_with_a_commitment();
    let bytes = proof.to_bytes().unwrap();
    let mut uncompressed = vec![PROOF_ENCODING_VERSION];
    proof.serialize_uncompressed(&mut uncompressed).unwrap();
    assert!(uncompressed.len() > bytes.len());

    let decoded = SNARKProof::<B>::from_bytes(&uncompressed).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);

    uncompressed.push(0);
    let err = SNARKProof::<B>::from_bytes(&uncompressed).expect_err("trailing bytes must fail");
    assert!(matches!(err, SnarkError::Artifact(_)), "got {err:?}");
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

/// A nozerocheck claim built the same way on both sides.
#[derive(Clone, Copy)]
enum NonZero {
    Col(usize),
    Diff(usize, usize),
    Prod(usize, usize),
}

/// Commits `cols`, claims each of `claims` nonzero everywhere, and verifies.
fn prove_nonzero(cols: &[Vec<F>], claims: &[NonZero]) -> Result<(), SnarkError> {
    let (mut prover, mut verifier) = test_prelude::<B>()?;
    let nv = cols[0].len().trailing_zeros() as usize;
    let polys = cols
        .iter()
        .map(|col| prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(nv, col.clone())))
        .collect::<Result<Vec<_>, _>>()?;
    for claim in claims {
        let poly = match *claim {
            NonZero::Col(i) => polys[i].clone(),
            NonZero::Diff(i, j) => &polys[i] - &polys[j],
            NonZero::Prod(i, j) => &polys[i] * &polys[j],
        };
        prover.add_mv_nozerocheck_claim(poly.id())?;
    }
    let proof = prover.build_proof()?;

    verifier.set_proof(proof);
    let oracles = polys
        .iter()
        .map(|poly| verifier.track_mv_com_by_id(poly.id()))
        .collect::<Result<Vec<_>, _>>()?;
    for claim in claims {
        let oracle = match *claim {
            NonZero::Col(i) => oracles[i].clone(),
            NonZero::Diff(i, j) => &oracles[i] - &oracles[j],
            NonZero::Prod(i, j) => &oracles[i] * &oracles[j],
        };
        verifier.add_mv_nozerocheck_claim(oracle.id());
    }
    verifier.verify()
}

fn col(f: impl Fn(u64) -> u64) -> Vec<F> {
    (0..16u64).map(|i| F::from(f(i))).collect()
}

/// Columns: `i+1`, `2i+3`, `1/(i+1)`, `i` (zero at 0), `i mod 2`,
/// `1 - i mod 2`.
fn nonzero_cols() -> Vec<Vec<F>> {
    let mut inverse = col(|i| i + 1);
    ark_ff::batch_inversion(&mut inverse);
    vec![
        col(|i| i + 1),
        col(|i| 2 * i + 3),
        inverse,
        col(|i| i),
        col(|i| i % 2),
        col(|i| 1 - i % 2),
    ]
}

/// Covers each way a claim enters the product: a committed column as it
/// is, a difference and a product through committed copies, and a product
/// that is the constant 1 through its public value.
#[test]
fn nonzero_claims_of_every_shape_verify() {
    let claims = [
        NonZero::Col(0),
        NonZero::Diff(1, 0),
        NonZero::Prod(0, 1),
        NonZero::Prod(0, 2),
    ];
    prove_nonzero(&nonzero_cols(), &claims).unwrap();
}

#[test]
fn nonzero_claim_on_a_column_with_a_zero_is_rejected() {
    let claims = [NonZero::Col(0), NonZero::Col(3)];
    assert_soundness_error(prove_nonzero(&nonzero_cols(), &claims).unwrap_err());
}

#[test]
fn nonzero_claim_on_a_difference_with_a_zero_is_rejected() {
    // (2i+3) - (i+1) is nonzero; (i+1) - (i+1) is zero everywhere.
    let claims = [NonZero::Diff(1, 0), NonZero::Diff(0, 0)];
    assert_soundness_error(prove_nonzero(&nonzero_cols(), &claims).unwrap_err());
}

/// `(i mod 2)·(1 - i mod 2)` is the constant zero, so its copy is sent as a
/// public constant, which the verifier must check itself.
#[test]
fn nonzero_claim_on_a_product_that_is_constant_zero_is_rejected() {
    let claims = [NonZero::Col(0), NonZero::Prod(4, 5)];
    assert_soundness_error(prove_nonzero(&nonzero_cols(), &claims).unwrap_err());
}
