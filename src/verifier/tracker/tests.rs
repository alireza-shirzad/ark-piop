//! What the verifier accepts and rejects around the proof-wide plumbing,
//! with an honest prover on the other side of every test.

use std::collections::BTreeMap;

use ark_ff::{Field, One, Zero};

use crate::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::structs::proof::SNARKProof,
    test_utils::prelude_with_vars,
    types::{SumcheckSubproof, TrackerID},
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

fn assert_check_failed(res: SnarkResult<()>) {
    match res {
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
