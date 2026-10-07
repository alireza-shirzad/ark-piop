//! What the verifier accepts and rejects around the proof-wide plumbing,
//! with an honest prover on the other side of every test.

use std::collections::BTreeMap;

use ark_ff::{Field, One, Zero};
use ark_serialize::{CanonicalSerialize, Compress};

use crate::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    piop::logup_gkr::{FractionInstance, GkrClaims, GkrShape, Numerator},
    prover::structs::proof::{PROOF_ENCODING_VERSION, SNARKProof},
    test_utils::prelude_with_vars,
    types::{SumcheckSubproof, TrackerID, artifact::Artifact},
    verifier::{ArgVerifier, errors::VerifierError},
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// No column here has more than 2^8 rows.
const SRS_NV: usize = 10;

fn mle(evals: &[F]) -> MLE<F> {
    MLE::from_evaluations_vec(evals.len().trailing_zeros() as usize, evals.to_vec())
}

fn column(nv: usize, seed: u64) -> Vec<F> {
    (0..1u64 << nv).map(|i| F::from(seed * i + seed)).collect()
}

fn sum(evals: &[F]) -> F {
    evals.iter().fold(F::zero(), |acc, v| acc + v)
}

fn assert_check_failed<T>(res: SnarkResult<T>) {
    match res.map(drop) {
        Err(SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))) => {}
        other => panic!("expected a failed verifier check, got {other:?}"),
    }
}

/// How the narrow column of a [`RawClaimCase`] is built.
#[derive(Clone, Copy)]
enum Narrow {
    Committed,
    /// The product of two commitments, the shape of a claim on `eq · column`.
    Product,
}

/// `(narrow nv, wide nv, narrow kind, buckets)` for [`RawClaimCase`]. The
/// plans with one bucket put both claims in the same sumcheck, the others
/// give the narrow claim a sumcheck of its own.
const RAW_CLAIM_PLANS: [(usize, usize, Narrow, usize); 5] = [
    (5, 6, Narrow::Committed, 1),
    (0, 6, Narrow::Committed, 1),
    (2, 8, Narrow::Committed, 2),
    (5, 6, Narrow::Product, 1),
    (2, 8, Narrow::Product, 2),
];

/// An honest proof for a raw claim on a `narrow` column and an ordinary
/// claim on a `wide` one. The wide column is the widest commitment, so the
/// narrow one sits below the proof's global nv.
struct RawClaimCase {
    proof: SNARKProof<B>,
    verifier: ArgVerifier<B>,
    /// The commitments the narrow column is made of.
    narrow_parts: Vec<TrackerID>,
    narrow: TrackerID,
    narrow_sum: F,
    wide: TrackerID,
    wide_sum: F,
    /// `2^(wide nv - narrow nv)`: what an ordinary claim on the narrow
    /// column is scaled by in the proof's claim map.
    global_scale: F,
}

impl RawClaimCase {
    fn new(narrow_nv: usize, wide_nv: usize, kind: Narrow) -> Self {
        let (mut prover, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
        let mut commit = |evals: &[F]| prover.track_and_commit_mat_mv_poly(&mle(evals)).unwrap();
        let mut narrow_evals = column(narrow_nv, 3);
        let mut narrow_poly = commit(&narrow_evals);
        let mut narrow_parts = vec![narrow_poly.id()];
        if let Narrow::Product = kind {
            let factor_evals = column(narrow_nv, 7);
            let factor = commit(&factor_evals);
            narrow_parts.push(factor.id());
            narrow_poly = &narrow_poly * &factor;
            for (eval, factor) in narrow_evals.iter_mut().zip(&factor_evals) {
                *eval *= factor;
            }
        }
        let wide_evals = column(wide_nv, 5);
        let wide = commit(&wide_evals).id();
        let narrow = narrow_poly.id();
        let (narrow_sum, wide_sum) = (sum(&narrow_evals), sum(&wide_evals));
        prover
            .add_mv_sumcheck_claim_raw(narrow, narrow_sum)
            .unwrap();
        prover.add_mv_sumcheck_claim(wide, wide_sum).unwrap();
        assert_eq!(
            prover.tracker().borrow().sumcheck_claims_snapshot(),
            [(narrow, narrow_sum, true), (wide, wide_sum, false)]
        );
        Self {
            proof: prover.build_proof().unwrap(),
            verifier,
            narrow_parts,
            narrow,
            narrow_sum,
            wide,
            wide_sum,
            global_scale: F::from(2u64).pow([(wide_nv - narrow_nv) as u64]),
        }
    }

    fn claim_map(&self) -> &BTreeMap<TrackerID, F> {
        self.proof.sc_subproof.as_ref().unwrap().sumcheck_claims()
    }

    /// The proof with `value` as the claim-map entry of the narrow column.
    fn proof_with_map_entry(&self, value: F) -> SNARKProof<B> {
        let mut proof = self.proof.clone();
        let subproof = proof.sc_subproof.as_ref().unwrap();
        let mut claims = subproof.sumcheck_claims().clone();
        claims.insert(self.narrow, value);
        proof.sc_subproof = Some(SumcheckSubproof::new(subproof.buckets().to_vec(), claims));
        proof
    }

    /// Mirrors the statement with `raw_sum` as the verifier's own value of
    /// the narrow sum, and verifies `proof`.
    fn verify(&self, proof: SNARKProof<B>, raw_sum: F) -> SnarkResult<()> {
        let mut verifier = self.verifier.fork();
        verifier.set_proof(proof);
        let parts = self
            .narrow_parts
            .iter()
            .map(|id| verifier.track_mv_com_by_id(*id))
            .collect::<SnarkResult<Vec<_>>>()?;
        let narrow = match parts.as_slice() {
            [column] => column.id(),
            [column, factor] => (column * factor).id(),
            _ => unreachable!(),
        };
        assert_eq!(narrow, self.narrow);
        verifier.track_mv_com_by_id(self.wide)?;
        verifier.add_mv_sumcheck_claim_raw(narrow, raw_sum);
        verifier.add_mv_sumcheck_claim(self.wide, self.wide_sum);
        assert_eq!(
            verifier.tracker().borrow().sumcheck_claims_snapshot(),
            [(narrow, raw_sum, true), (self.wide, self.wide_sum, false)]
        );
        verifier.verify()
    }
}

#[test]
fn raw_claim_below_the_global_nv_verifies() {
    for (narrow_nv, wide_nv, kind, buckets) in RAW_CLAIM_PLANS {
        let case = RawClaimCase::new(narrow_nv, wide_nv, kind);
        let subproof = case.proof.sc_subproof.as_ref().unwrap();
        assert_eq!(subproof.buckets().len(), buckets);
        // Only the ordinary claim is sent.
        assert!(case.claim_map().contains_key(&case.wide));
        assert!(!case.claim_map().contains_key(&case.narrow));
        case.verify(case.proof.clone(), case.narrow_sum).unwrap();
    }
}

/// Whatever the proof's claim map says about a raw claim, the verifier
/// scales its own value its own way. An entry equal to that value is the
/// interesting one: an ordinary claim that matches its entry is taken to be
/// in the proof's global frame and divided down instead of lifted.
#[test]
fn claim_map_entry_for_a_raw_claim_is_ignored() {
    for (narrow_nv, wide_nv, kind, _) in RAW_CLAIM_PLANS {
        let case = RawClaimCase::new(narrow_nv, wide_nv, kind);
        let entries = [
            case.narrow_sum,
            case.narrow_sum * case.global_scale,
            F::from(0xdead_beefu64),
            F::zero(),
        ];
        for entry in entries {
            case.verify(case.proof_with_map_entry(entry), case.narrow_sum)
                .unwrap();
        }
    }
}

/// A wrong raw value fails with and without a claim-map entry backing it.
/// `sum · 2^(wide nv - narrow nv)` with a matching entry is exactly what an
/// ordinary claim on the narrow column looks like, so it is the value a
/// verifier that consulted the map would let through.
#[test]
fn wrong_raw_claim_is_rejected() {
    for (narrow_nv, wide_nv, kind, _) in RAW_CLAIM_PLANS {
        let case = RawClaimCase::new(narrow_nv, wide_nv, kind);
        let wrong_sums = [
            case.narrow_sum + F::one(),
            case.narrow_sum * case.global_scale,
            F::zero(),
        ];
        for wrong in wrong_sums {
            assert_check_failed(case.verify(case.proof.clone(), wrong));
            assert_check_failed(case.verify(case.proof_with_map_entry(wrong), wrong));
        }
    }
}

/// An honest proof carrying two LogUp-GKR batches of different layouts with
/// a commitment and an ordinary claim between them, so that everything
/// after the first batch depends on both transcripts having absorbed it.
struct GkrCase {
    proof: SNARKProof<B>,
    verifier: ArgVerifier<B>,
    shapes: [Vec<GkrShape>; 2],
    claims: [GkrClaims<F>; 2],
    column: TrackerID,
    column_sum: F,
}

impl GkrCase {
    fn new() -> Self {
        let (mut prover, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
        let unit = FractionInstance {
            num: Numerator::One,
            den: column(3, 5),
        };
        let weighted = FractionInstance {
            num: Numerator::Values(column(2, 2)),
            den: column(2, 9),
        };
        let unit_shape = GkrShape {
            n_vars: 3,
            numerator_is_one: true,
        };
        let weighted_shape = GkrShape {
            n_vars: 2,
            numerator_is_one: false,
        };

        let first = prover
            .prove_logup_gkr(vec![unit, weighted.clone()])
            .unwrap();
        let column_evals = column(4, 3);
        let column = prover
            .track_and_commit_mat_mv_poly(&mle(&column_evals))
            .unwrap()
            .id();
        let column_sum = sum(&column_evals);
        prover.add_mv_sumcheck_claim(column, column_sum).unwrap();
        let second = prover.prove_logup_gkr(vec![weighted]).unwrap();

        Self {
            proof: prover.build_proof().unwrap(),
            verifier,
            shapes: [vec![unit_shape, weighted_shape], vec![weighted_shape]],
            claims: [first, second],
            column,
            column_sum,
        }
    }

    /// Mirrors the statement on a fresh verifier, running only the first
    /// `batches` of the two batches, and returns the verifier before its
    /// final `verify`.
    fn mirror(&self, proof: &SNARKProof<B>, batches: usize) -> SnarkResult<ArgVerifier<B>> {
        let mut verifier = self.verifier.fork();
        verifier.set_proof_ref(proof);
        if batches > 0 {
            assert_eq!(verifier.verify_logup_gkr(&self.shapes[0])?, self.claims[0]);
        }
        verifier.track_mv_com_by_id(self.column)?;
        verifier.add_mv_sumcheck_claim(self.column, self.column_sum);
        if batches > 1 {
            assert_eq!(verifier.verify_logup_gkr(&self.shapes[1])?, self.claims[1]);
        }
        Ok(verifier)
    }
}

#[test]
fn gkr_batches_agree_between_prover_and_verifier() {
    let case = GkrCase::new();
    assert_eq!(case.proof.logup_gkr_subproofs.len(), 2);
    case.mirror(&case.proof, 2).unwrap().verify().unwrap();
}

#[test]
fn missing_gkr_subproof_is_an_error_not_a_panic() {
    let case = GkrCase::new();

    let mut unset = case.verifier.fork();
    assert!(matches!(
        unset.verify_logup_gkr(&case.shapes[0]),
        Err(SnarkError::VerifierError(VerifierError::ProofNotReceived))
    ));

    // One batch more than the proof holds.
    let mut verifier = case.mirror(&case.proof, 2).unwrap();
    assert_check_failed(verifier.verify_logup_gkr(&case.shapes[1]));

    // The proof lost its second batch, or both.
    let mut proof = case.proof.clone();
    proof.logup_gkr_subproofs.pop();
    assert_check_failed(case.mirror(&proof, 2));
    proof.logup_gkr_subproofs.clear();
    assert_check_failed(case.mirror(&proof, 1));
}

/// Every subproof has to be verified by somebody: a statement that runs
/// fewer batches than the proof carries does not verify.
#[test]
fn unconsumed_gkr_subproof_fails_verification() {
    let case = GkrCase::new();
    for batches in [0, 1] {
        let verifier = case.mirror(&case.proof, batches).unwrap();
        assert_check_failed(verifier.verify());
    }

    // An extra subproof behind the ones the statement runs.
    let mut padded = case.proof.clone();
    padded
        .logup_gkr_subproofs
        .push(case.proof.logup_gkr_subproofs[1].clone());
    assert_check_failed(case.mirror(&padded, 2).unwrap().verify());
}

/// The count of verified subproofs belongs to one proof: handing the
/// verifier a proof again starts it over.
#[test]
fn setting_a_proof_resets_the_gkr_subproof_count() {
    let case = GkrCase::new();
    let mut verifier = case.mirror(&case.proof, 2).unwrap();
    verifier.verify().unwrap();
    verifier.set_proof_ref(&case.proof);
    assert_check_failed(verifier.verify());
}

#[test]
fn proof_with_gkr_subproofs_roundtrips_and_verifies() {
    let case = GkrCase::new();
    let bytes = case.proof.to_bytes().unwrap();
    assert_eq!(bytes[0], PROOF_ENCODING_VERSION);

    let decoded = SNARKProof::<B>::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.logup_gkr_subproofs, case.proof.logup_gkr_subproofs);
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
    case.mirror(&decoded, 2).unwrap().verify().unwrap();
}

#[test]
fn size_breakdown_accounts_for_the_gkr_subproofs() {
    let case = GkrCase::new();
    let breakdown = case.proof.size_breakdown().unwrap();
    assert_eq!(breakdown.size, case.proof.to_bytes().unwrap().len());
    assert_eq!(
        breakdown.parts["logup_gkr_subproofs"].size,
        case.proof
            .logup_gkr_subproofs
            .serialized_size(Compress::Yes)
    );
    // The one byte left over is the version tag.
    let parts: usize = breakdown.parts.values().map(|part| part.size).sum();
    assert_eq!(parts + 1, breakdown.size);
}
