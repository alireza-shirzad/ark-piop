//! What the verifier accepts and rejects around the proof-wide plumbing:
//! raw sumcheck claims, LogUp-GKR subproofs and the shape of the bucket
//! sumchecks.

use std::{collections::BTreeMap, sync::Arc};

use ark_ff::{Field, One, Zero};
use ark_serialize::{CanonicalSerialize, Compress};

use crate::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::{mat_poly::mle::MLE, virt_poly::hp_interface::VPAuxInfo},
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::{
        logup_gkr::{FractionInstance, GkrClaims, GkrShape, Numerator},
        structs::SumcheckProof,
    },
    prover::structs::proof::{PROOF_ENCODING_VERSION, SNARKProof},
    test_utils::prelude_with_vars,
    types::{
        CommitmentBinding, PCSOpeningProof, SumcheckBucketProof, SumcheckSubproof, TrackerID,
        artifact::Artifact, claim::TrackerSumcheckClaim,
    },
    verifier::{ArgVerifier, errors::VerifierError, structs::oracle::Oracle},
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

/// Setting a proof puts the count of verified subproofs back to zero, by
/// reference or by value, whatever else would make a second `verify` on a
/// used verifier fail.
#[test]
fn setting_a_proof_puts_the_gkr_subproof_count_back_to_zero() {
    let case = GkrCase::new();
    let consumed = |verifier: &ArgVerifier<B>| {
        verifier
            .tracker()
            .borrow()
            .state
            .logup_gkr_subproofs_consumed
    };
    for by_value in [false, true] {
        let mut verifier = case.mirror(&case.proof, 2).unwrap();
        assert_eq!(consumed(&verifier), 2);
        if by_value {
            verifier.set_proof(case.proof.clone());
        } else {
            verifier.set_proof_ref(&case.proof);
        }
        assert_eq!(consumed(&verifier), 0);
    }
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

/// A prover that runs the bucket sumcheck over fewer variables than the
/// claimed column has. It holds only the half of the column where the top
/// variable is 0, under the commitment to the whole column, and proves that
/// half's sum, which the verifier is told is the sum of the column. Every
/// message is consistent with the transcript; only the round count is off.
#[test]
fn sumcheck_over_a_subcube_is_rejected() {
    let (mut prover, mut verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
    let nv = 4;
    let evals = column(nv, 3);
    let half = &evals[..1 << (nv - 1)];
    assert_ne!(sum(half), sum(&evals));

    let commitment = <B as SnarkBackend>::MvPCS::commit(
        prover.mv_pcs_prover_param().as_ref(),
        &Arc::new(mle(&evals)),
    )
    .unwrap();
    let column = prover
        .track_mat_mv_poly_with_commitment(&mle(half), commitment, CommitmentBinding::ProofEmitted)
        .unwrap()
        .id();
    prover.add_mv_sumcheck_claim(column, sum(half)).unwrap();
    let proof = prover.build_proof().unwrap();
    let buckets = proof.sc_subproof.as_ref().unwrap().buckets();
    assert_eq!(buckets[0].num_vars(), nv - 1);
    assert_eq!(buckets[0].sc_proof().proofs.len(), nv - 1);

    verifier.set_proof(proof);
    verifier.track_mv_com_by_id(column).unwrap();
    verifier.add_mv_sumcheck_claim(column, sum(half));
    assert_check_failed(verifier.verify());
}

/// A bucket's sumcheck as the proof carries it.
type Bucket = (SumcheckProof<F>, VPAuxInfo<F>);

/// `proof` with its sumcheck buckets rewritten by `edit`.
fn with_buckets(proof: &SNARKProof<B>, edit: impl FnOnce(&mut Vec<Bucket>)) -> SNARKProof<B> {
    let mut proof = proof.clone();
    let subproof = proof.sc_subproof.as_ref().unwrap();
    let mut buckets: Vec<Bucket> = subproof
        .buckets()
        .iter()
        .map(|bucket| (bucket.sc_proof().clone(), bucket.sc_aux_info().clone()))
        .collect();
    edit(&mut buckets);
    let buckets = buckets
        .into_iter()
        .map(|(sc_proof, aux_info)| SumcheckBucketProof::new(sc_proof, aux_info))
        .collect();
    proof.sc_subproof = Some(SumcheckSubproof::new(
        buckets,
        subproof.sumcheck_claims().clone(),
    ));
    proof
}

/// A proof whose bucket sumchecks do not have the verifier's shape is
/// refused with an error, whichever part of the shape is off.
#[test]
fn malformed_bucket_sumcheck_is_an_error_not_a_panic() {
    let case = RawClaimCase::new(2, 8, Narrow::Committed);
    let verify = |proof| case.verify(proof, case.narrow_sum);
    let reject = |edit: &dyn Fn(&mut Vec<Bucket>)| {
        assert_check_failed(verify(with_buckets(&case.proof, edit)));
    };
    verify(with_buckets(&case.proof, |_| {})).unwrap();

    for bucket in [0, 1] {
        // A round short: in the messages, in the declared count, in both.
        reject(&|buckets| {
            buckets[bucket].0.proofs.pop();
        });
        reject(&|buckets| buckets[bucket].1.num_variables -= 1);
        reject(&|buckets| {
            buckets[bucket].0.proofs.pop();
            buckets[bucket].0.point.pop();
            buckets[bucket].1.num_variables -= 1;
        });
        // A round more declared than sent, and sent than declared.
        reject(&|buckets| buckets[bucket].1.num_variables += 1);
        reject(&|buckets| {
            let last = buckets[bucket].0.proofs.last().unwrap().clone();
            buckets[bucket].0.proofs.push(last);
        });
        // Round messages too short for the reads at 0 and 1, and for the
        // declared degree.
        reject(&|buckets| {
            buckets[bucket].1.max_degree = 0;
            for msg in &mut buckets[bucket].0.proofs {
                msg.evaluations.truncate(1);
            }
        });
        reject(&|buckets| {
            buckets[bucket].0.proofs[0].evaluations.pop();
        });
    }

    // A bucket missing, a bucket too many, none at all.
    reject(&|buckets| {
        buckets.pop();
    });
    reject(&|buckets| {
        buckets.remove(0);
    });
    reject(&|buckets| buckets.push(buckets[1].clone()));
    reject(&|buckets| buckets.clear());
    let mut bare = case.proof.clone();
    bare.sc_subproof = None;
    assert_check_failed(verify(bare));
}

/// A bucket's sumcheck may not declare a higher degree than the verifier's
/// own polynomial has: the round polynomials would not be that
/// polynomial's, and the degree is what a round costs to check. The
/// product case has a degree above one to stay under, too.
#[test]
fn bucket_sumcheck_of_a_higher_degree_than_its_polynomial_is_rejected() {
    for kind in [Narrow::Committed, Narrow::Product] {
        let case = RawClaimCase::new(2, 8, kind);
        let verify = |proof| case.verify(proof, case.narrow_sum);
        verify(with_buckets(&case.proof, |_| {})).unwrap();
        let declared: Vec<usize> = case
            .proof
            .sc_subproof
            .as_ref()
            .unwrap()
            .buckets()
            .iter()
            .map(|bucket| bucket.sc_aux_info().max_degree)
            .collect();

        for bucket in 0..declared.len() {
            for raised in [declared[bucket] + 1, 64, 1 << 20, usize::MAX] {
                // The messages are padded to the declared degree where that
                // can be done, so that the shape is right and only the
                // degree is not.
                let proof = with_buckets(&case.proof, |buckets| {
                    buckets[bucket].1.max_degree = raised;
                    if raised <= 64 {
                        for msg in &mut buckets[bucket].0.proofs {
                            msg.evaluations.resize(raised + 1, F::zero());
                        }
                    }
                });
                match verify(proof) {
                    Err(SnarkError::VerifierError(VerifierError::VerifierCheckFailed(reason)))
                        if reason.contains("declares degree") => {}
                    other => panic!("degree {raised} in bucket {bucket}: got {other:?}"),
                }
            }
            // A lower degree than the polynomial's is no proof of it, but
            // that is for the sumcheck to find.
            if declared[bucket] > 1 {
                let proof = with_buckets(&case.proof, |buckets| {
                    buckets[bucket].1.max_degree -= 1;
                    for msg in &mut buckets[bucket].0.proofs {
                        msg.evaluations.pop();
                    }
                });
                assert!(verify(proof).is_err());
            }
        }
    }
}

/// A claim on a polynomial whose every term has a zero coefficient: its
/// terms are dropped on the way to the sumcheck, which must still run over
/// the bucket's hypercube. `(zero claim nv, nv of an ordinary claim next
/// to it)`: alone in the proof, the widest claim of a shared bucket, a
/// narrower one, and with a bucket to itself.
#[test]
fn claim_on_a_zero_polynomial_gets_a_sumcheck_of_its_bucket_size() {
    let plans: [(usize, Option<usize>, usize); 6] = [
        (3, None, 1),
        (1, None, 1),
        (5, Some(4), 1),
        (7, Some(8), 1),
        (3, Some(8), 2),
        (8, Some(3), 2),
    ];
    for (zero_nv, other_nv, buckets) in plans {
        let run = |claimed: F| -> SnarkResult<()> {
            let (mut prover, mut verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
            let committed = prover
                .track_and_commit_mat_mv_poly(&mle(&column(zero_nv, 3)))
                .unwrap();
            let zero = committed.mul_scalar_poly(F::zero());
            let mut ids = vec![committed.id()];
            let other_sum = other_nv.map(|nv| {
                let evals = column(nv, 5);
                let other = prover.track_and_commit_mat_mv_poly(&mle(&evals)).unwrap();
                prover
                    .add_mv_sumcheck_claim(other.id(), sum(&evals))
                    .unwrap();
                ids.push(other.id());
                sum(&evals)
            });
            if cfg!(feature = "honest-prover") && !claimed.is_zero() {
                assert!(prover.add_mv_sumcheck_claim(zero.id(), claimed).is_err());
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed("refused by the honest prover".to_string()),
                ));
            }
            prover.add_mv_sumcheck_claim(zero.id(), claimed).unwrap();
            let proof = prover.build_proof()?;
            let proof_buckets = proof.sc_subproof.as_ref().unwrap().buckets();
            assert_eq!(proof_buckets.len(), buckets);
            assert!(
                proof_buckets
                    .iter()
                    .all(|bucket| bucket.sc_aux_info().max_degree >= 1)
            );

            verifier.set_proof(proof);
            let committed = verifier.track_mv_com_by_id(ids[0])?;
            let zero = committed.mul_scalar_oracle(F::zero());
            if let Some(other_sum) = other_sum {
                let other = verifier.track_mv_com_by_id(ids[1])?;
                verifier.add_mv_sumcheck_claim(other.id(), other_sum);
            }
            verifier.add_mv_sumcheck_claim(zero.id(), claimed);
            verifier.verify()
        };
        run(F::zero()).unwrap();
        assert_check_failed(run(F::one()));
    }
}

/// Lookup and keyed-sum claims are reduced by `ArgVerifier::verify` before
/// the tracker verifies. The tracker's own `verify` cannot reduce them and
/// must not pass over them.
#[test]
fn tracker_verify_refuses_claims_that_were_not_reduced() {
    use crate::piop::keyed_sumcheck::KeyedSumcheckVerifierInput;

    let (mut prover, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
    let evals = column(4, 3);
    let column = prover
        .track_and_commit_mat_mv_poly(&mle(&evals))
        .unwrap()
        .id();
    prover.add_mv_sumcheck_claim(column, sum(&evals)).unwrap();
    let proof = prover.build_proof().unwrap();

    let mirror = || {
        let mut verifier = verifier.fork();
        verifier.set_proof_ref(&proof);
        let oracle = verifier.track_mv_com_by_id(column).unwrap();
        verifier.add_mv_sumcheck_claim(column, sum(&evals));
        (verifier, oracle)
    };
    let tracker_verify = |verifier: ArgVerifier<B>| verifier.tracker().borrow_mut().verify();

    tracker_verify(mirror().0).unwrap();

    let (mut with_lookup, _) = mirror();
    with_lookup.add_mv_lookup_claim(column, column).unwrap();
    assert_check_failed(tracker_verify(with_lookup));

    let (mut with_keyed_sum, oracle) = mirror();
    with_keyed_sum
        .add_mv_keyed_sum_claim(KeyedSumcheckVerifierInput {
            fxs: vec![oracle.clone()],
            gxs: vec![oracle],
            mfxs: vec![None],
            mgxs: vec![None],
        })
        .unwrap();
    assert_check_failed(tracker_verify(with_keyed_sum));
}

/// A raw claim is lifted to its bucket by `2^(bucket nv - own nv)`, and the
/// sizes behind that exponent are the proof's to declare. The factor is
/// exact however large the exponent.
#[test]
fn raw_claim_is_lifted_by_an_exact_power_of_two() {
    let (_, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
    let tracker = verifier.tracker();
    let mut tracker = tracker.borrow_mut();
    let id = tracker.track_base_oracle(Oracle::new_constant(3, F::from(5u64)));
    for target_nv in [3usize, 4, 66, 67, 131, 200] {
        let claims = &mut tracker.state.mv_pcs_substate.sum_check_claims;
        *claims = vec![
            TrackerSumcheckClaim::new_raw(id, F::from(40u64)),
            TrackerSumcheckClaim::new(id, F::from(40u64)),
        ];
        tracker
            .equalize_sumcheck_claims(target_nv, target_nv)
            .unwrap();
        let lifted = F::from(40u64) * F::from(2u64).pow([target_nv as u64 - 3]);
        assert_eq!(
            tracker.sumcheck_claims_snapshot(),
            [(id, lifted, true), (id, lifted, false)]
        );
    }
}

/// The proof declares a committed constant far larger than any column can
/// be. Whatever the claims on it turn into, the verifier answers with an
/// error.
#[test]
fn constant_of_an_absurd_declared_size_is_an_error_not_a_panic() {
    let case = RawClaimCase::new(0, 6, Narrow::Committed);
    let constants = &case.proof.mv_pcs_subproof.constant_map;
    assert!(constants.contains_key(&case.narrow));
    for num_vars in [63, 64, 65, 100, 127, 128, 144, 300, u32::MAX] {
        let mut proof = case.proof.clone();
        proof
            .mv_pcs_subproof
            .constant_num_vars
            .insert(case.narrow, num_vars);
        assert_check_failed(case.verify(proof, case.narrow_sum));
    }
}

/// Columns of three sizes, two of them claimed only through their sum, so
/// that what the proof says they evaluate to is checked by nothing but the
/// openings: the sumcheck sees `a(r) + b(r)`.
struct OpeningCase {
    proof: SNARKProof<B>,
    verifier: ArgVerifier<B>,
    /// `a`, `b` of one size and the wider `c`.
    columns: [TrackerID; 3],
    pair_sum: F,
    wide_sum: F,
}

impl OpeningCase {
    fn new(pair_nv: usize, wide_nv: usize) -> Self {
        let (mut prover, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
        let tables = [column(pair_nv, 3), column(pair_nv, 7), column(wide_nv, 5)];
        let polys = tables
            .each_ref()
            .map(|table| prover.track_and_commit_mat_mv_poly(&mle(table)).unwrap());
        let pair = &polys[0] + &polys[1];
        let (pair_sum, wide_sum) = (sum(&tables[0]) + sum(&tables[1]), sum(&tables[2]));
        prover.add_mv_sumcheck_claim(pair.id(), pair_sum).unwrap();
        prover
            .add_mv_sumcheck_claim(polys[2].id(), wide_sum)
            .unwrap();
        Self {
            proof: prover.build_proof().unwrap(),
            verifier,
            columns: polys.map(|poly| poly.id()),
            pair_sum,
            wide_sum,
        }
    }

    fn verify(&self, proof: &SNARKProof<B>) -> SnarkResult<()> {
        let mut verifier = self.verifier.fork();
        verifier.set_proof_ref(proof);
        let [a, b, c] = self
            .columns
            .map(|id| verifier.track_mv_com_by_id(id).unwrap());
        verifier.add_mv_sumcheck_claim((&a + &b).id(), self.pair_sum);
        verifier.add_mv_sumcheck_claim(c.id(), self.wide_sum);
        verifier.verify()
    }

    /// The proof with what it claims `a` and `b` evaluate to moved by
    /// opposite amounts, wherever both are evaluated.
    fn with_cancelling_evaluations(&self) -> SNARKProof<B> {
        let mut proof = self.proof.clone();
        let subproof = &mut proof.mv_pcs_subproof;
        let [a, b] = [0, 1].map(|i| subproof.comitment_map[&self.columns[i]]);
        assert_ne!(a, b);
        let points: Vec<_> = subproof.query_map[&a].keys().copied().collect();
        assert!(!points.is_empty());
        for point in points {
            *subproof
                .query_map
                .get_mut(&a)
                .unwrap()
                .get_mut(&point)
                .unwrap() += F::one();
            *subproof
                .query_map
                .get_mut(&b)
                .unwrap()
                .get_mut(&point)
                .unwrap() -= F::one();
        }
        proof
    }
}

/// The openings failed, not a check before them.
fn assert_openings_rejected(res: SnarkResult<()>) {
    match res {
        Err(SnarkError::PCSErrors(_)) => {}
        Err(SnarkError::VerifierError(VerifierError::VerifierCheckFailed(reason)))
            if reason.contains("opening proof") => {}
        other => panic!("expected the openings to be rejected, got {other:?}"),
    }
}

#[test]
fn commitments_of_mixed_sizes_are_opened_and_checked() {
    for (pair_nv, wide_nv) in [(3, 5), (5, 3), (4, 4), (1, 6)] {
        let case = OpeningCase::new(pair_nv, wide_nv);
        assert!(matches!(
            case.proof.mv_pcs_subproof.opening_proof,
            PCSOpeningProof::BatchProof(_)
        ));
        case.verify(&case.proof).unwrap();
    }
}

/// Evaluations that are false and still satisfy every sumcheck: the
/// verifier has to take the openings' word for it, and they refuse.
#[test]
fn false_evaluations_that_cancel_in_the_sumcheck_are_rejected() {
    for (pair_nv, wide_nv) in [(3, 5), (5, 3), (4, 4)] {
        let case = OpeningCase::new(pair_nv, wide_nv);
        assert_openings_rejected(case.verify(&case.with_cancelling_evaluations()));
    }
}

#[test]
fn tampered_batch_opening_is_rejected() {
    let case = OpeningCase::new(3, 5);
    let edit = |edit: &dyn Fn(&mut <<B as SnarkBackend>::MvPCS as PCS<F>>::BatchProof)| {
        let mut proof = case.proof.clone();
        match &mut proof.mv_pcs_subproof.opening_proof {
            PCSOpeningProof::BatchProof(batch) => edit(batch),
            other => panic!("expected a batch opening, got {other:?}"),
        }
        proof
    };
    let generator = <ark_bn254::G1Affine as ark_ec::AffineRepr>::generator();
    let forged = [
        edit(&|batch| batch.g_prime_proof.proofs[0] = generator),
        edit(&|batch| {
            batch.g_prime_proof.proofs.pop();
        }),
        edit(&|batch| {
            let message = &mut batch.sum_check_proof.proofs[0].evaluations;
            message[0] += F::one();
            message[1] -= F::one();
        }),
        edit(&|batch| batch.sum_check_proof.point[0] += F::one()),
    ];
    for proof in &forged {
        assert_openings_rejected(case.verify(proof));
    }

    // An opening proof of another kind than the claims call for.
    let mut none = case.proof.clone();
    none.mv_pcs_subproof.opening_proof = PCSOpeningProof::Empty;
    assert_check_failed(case.verify(&none));
}

/// A proof with one commitment opens it alone, also when the claim on it
/// is over more variables than it has.
#[test]
fn single_opening_is_checked() {
    for (nv, tampered_fails) in [(4, true), (1, true)] {
        let (mut prover, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
        let table = column(nv, 3);
        let poly = prover.track_and_commit_mat_mv_poly(&mle(&table)).unwrap();
        let squared: F = table.iter().map(|v| *v * v).sum();
        let product = &poly * &poly;
        prover.add_mv_sumcheck_claim(product.id(), squared).unwrap();
        let proof = prover.build_proof().unwrap();
        assert!(matches!(
            proof.mv_pcs_subproof.opening_proof,
            PCSOpeningProof::SingleProof(_)
        ));

        let verify = |proof: &SNARKProof<B>| {
            let mut verifier = verifier.fork();
            verifier.set_proof_ref(proof);
            let oracle = verifier.track_mv_com_by_id(poly.id()).unwrap();
            verifier.add_mv_sumcheck_claim((&oracle * &oracle).id(), squared);
            verifier.verify()
        };
        verify(&proof).unwrap();

        let mut tampered = proof.clone();
        match &mut tampered.mv_pcs_subproof.opening_proof {
            PCSOpeningProof::SingleProof(single) => {
                single.proofs[0] = <ark_bn254::G1Affine as ark_ec::AffineRepr>::generator()
            }
            other => panic!("expected a single opening, got {other:?}"),
        }
        assert_eq!(verify(&tampered).is_err(), tampered_fails);
        assert_openings_rejected(verify(&tampered));
    }
}

/// A statement about a polynomial the verifier holds the commitment of,
/// `table`, and a column the proof commits to.
struct ExternalCase {
    proof: SNARKProof<B>,
    verifier: ArgVerifier<B>,
    column: TrackerID,
    sum: F,
}

impl ExternalCase {
    /// The prover runs with `prover_table` as the table and commits to it
    /// again as its column, which gives both one commitment id in the
    /// proof. The sums it claims are that polynomial's.
    fn new(prover_table: &[F]) -> (Self, <<B as SnarkBackend>::MvPCS as PCS<F>>::Commitment) {
        let (mut prover, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
        let poly = mle(prover_table);
        // A commitment made outside the proof, under the same keys.
        let (pk, _) = crate::setup::KeyGenerator::<B>::new()
            .with_num_mv_vars(SRS_NV)
            .gen_keys()
            .unwrap();
        let commitment = <<B as SnarkBackend>::MvPCS as PCS<F>>::commit(
            pk.mv_pcs_param.as_ref(),
            &Arc::new(poly.clone()),
        )
        .unwrap();

        let table = prover
            .track_mat_mv_poly_with_commitment(
                &poly,
                commitment.clone(),
                CommitmentBinding::External,
            )
            .unwrap();
        let column = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
        let sum = sum(prover_table);
        prover.add_mv_sumcheck_claim(table.id(), sum).unwrap();
        prover.add_mv_sumcheck_claim(column.id(), sum).unwrap();
        let proof = prover.build_proof().unwrap();
        let ids = &proof.mv_pcs_subproof.comitment_map;
        assert_eq!(ids[&table.id()], ids[&column.id()]);
        (
            Self {
                proof,
                verifier,
                column: column.id(),
                sum,
            },
            commitment,
        )
    }

    /// Verifies against `table`, the commitment the verifier holds.
    fn verify(&self, table: <<B as SnarkBackend>::MvPCS as PCS<F>>::Commitment) -> SnarkResult<()> {
        let mut verifier = self.verifier.fork();
        verifier.set_proof_ref(&self.proof);
        let table = verifier
            .track_mat_mv_com_with_binding(table, CommitmentBinding::External)
            .unwrap();
        let column = verifier.track_mv_com_by_id(self.column).unwrap();
        verifier.add_mv_sumcheck_claim(table.id(), self.sum);
        verifier.add_mv_sumcheck_claim(column.id(), self.sum);
        verifier.verify()
    }
}

/// The proof's commitment map says which commitments share their
/// evaluations. A prover that proves a sum of its own polynomial and maps
/// the verifier's table onto it would have the table's evaluations opened
/// against its own commitment, were one id allowed to stand for both.
#[test]
fn verifier_held_commitment_is_not_opened_as_one_of_the_proofs() {
    let (true_table, other) = (column(4, 3), column(4, 11));

    // The column is the table: one id for both is what an honest proof has.
    let (honest, commitment) = ExternalCase::new(&true_table);
    honest.verify(commitment.clone()).unwrap();

    // The proof is about `other`, the verifier's table is `true_table`.
    let (forged, _) = ExternalCase::new(&other);
    assert_ne!(sum(&other), sum(&true_table));
    assert_check_failed(forged.verify(commitment));
}

/// An ordinary claim's sum is over the polynomial's own hypercube. The
/// proof's claim map holds every sum lifted to the widest commitment, and
/// a verifier that scaled a claim by whether its sum is the map's entry
/// took an honest proof of the true sum for one of the lifted sum as well.
#[test]
fn ordinary_claim_is_not_proved_for_the_sum_lifted_to_the_widest_commitment() {
    for (narrow_nv, wide_nv) in [(3, 5), (2, 8), (4, 4)] {
        let (mut prover, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
        let (narrow_table, wide_table) = (column(narrow_nv, 3), column(wide_nv, 5));
        let mut commit = |table: &[F]| {
            prover
                .track_and_commit_mat_mv_poly(&mle(table))
                .unwrap()
                .id()
        };
        let (narrow, wide) = (commit(&narrow_table), commit(&wide_table));
        let (narrow_sum, wide_sum) = (sum(&narrow_table), sum(&wide_table));
        prover.add_mv_sumcheck_claim(narrow, narrow_sum).unwrap();
        prover.add_mv_sumcheck_claim(wide, wide_sum).unwrap();
        let proof = prover.build_proof().unwrap();

        let verify = |claimed: F| {
            let mut verifier = verifier.fork();
            verifier.set_proof_ref(&proof);
            verifier.track_mv_com_by_id(narrow).unwrap();
            verifier.track_mv_com_by_id(wide).unwrap();
            verifier.add_mv_sumcheck_claim(narrow, claimed);
            verifier.add_mv_sumcheck_claim(wide, wide_sum);
            verifier.verify()
        };
        verify(narrow_sum).unwrap();

        let lifted = narrow_sum * F::from(2u64).pow([(wide_nv - narrow_nv) as u64]);
        let map = proof.sc_subproof.as_ref().unwrap().sumcheck_claims();
        assert_eq!(map[&narrow], lifted);
        if wide_nv > narrow_nv {
            assert!(verify(lifted).is_err(), "sizes ({narrow_nv}, {wide_nv})");
        }
    }
}

/// A sum the verifier reads from the proof is a message of the prover, and
/// the weights its claim is batched under must come after it. A prover
/// that can learn the weights first, here by batching unit sums on a copy
/// of itself, picks one value for two different sums that the batched
/// claim cannot tell from the true ones, and a check that the two sums are
/// equal passes.
#[test]
fn sums_read_from_the_proof_are_bound_before_their_claims_are_batched() {
    let (mut prover, verifier) = prelude_with_vars::<B>(SRS_NV).unwrap();
    let tables = [column(4, 3), column(4, 7)];
    let ids = tables.each_ref().map(|table| {
        prover
            .track_and_commit_mat_mv_poly(&mle(table))
            .unwrap()
            .id()
    });
    let sums = tables.each_ref().map(|table| sum(table));
    assert_ne!(sums[0], sums[1]);

    // The verifier's side of a statement "the two sums are equal": it
    // reads both from the proof, claims them and compares.
    let verify = |proof: &SNARKProof<B>| -> SnarkResult<[F; 2]> {
        let mut verifier = verifier.fork();
        verifier.set_proof_ref(proof);
        let mut read = [F::zero(); 2];
        for (id, sum) in ids.iter().zip(&mut read) {
            verifier.track_mv_com_by_id(*id)?;
            *sum = verifier.prover_claimed_sum(*id)?;
            verifier.add_mv_sumcheck_claim(*id, *sum);
        }
        verifier.verify()?;
        Ok(read)
    };

    // The weight of each claim, as far as a copy of the prover gives it
    // away: the batched sum of a unit sum for one claim and zero for the
    // other. No honest prover claims those.
    let weights = (!cfg!(feature = "honest-prover")).then(|| {
        [[1u64, 0], [0, 1]].map(|unit| {
            let mut probe = prover.deep_copy();
            for (id, sum) in ids.iter().zip(unit) {
                probe.add_mv_sumcheck_claim(*id, F::from(sum)).unwrap();
            }
            let tracker = probe.tracker();
            let mut tracker = tracker.borrow_mut();
            crate::tracker_core::pipeline::batch_s_check_claims(&mut *tracker).unwrap();
            tracker.sumcheck_claims_snapshot()[0].1
        })
    });

    for (id, sum) in ids.iter().zip(sums) {
        prover.add_mv_sumcheck_claim(*id, sum).unwrap();
    }
    let proof = prover.build_proof().unwrap();
    assert_eq!(verify(&proof).unwrap(), sums);

    let Some([w0, w1]) = weights else { return };
    let shared = (w0 * sums[0] + w1 * sums[1]) / (w0 + w1);
    let mut forged = proof.clone();
    let subproof = forged.sc_subproof.as_ref().unwrap();
    let mut claims = subproof.sumcheck_claims().clone();
    for id in ids {
        claims.insert(id, shared);
    }
    forged.sc_subproof = Some(SumcheckSubproof::new(subproof.buckets().to_vec(), claims));
    match verify(&forged) {
        Ok(read) => panic!("two different sums were accepted as {read:?}"),
        Err(err) => assert_check_failed::<()>(Err(err)),
    }
}
