//! The keyed-sum reduction from inside the crate: provers that cheat while
//! staying consistent with the transcript, the layout of the GKR batch, and
//! the two sides staying in step.

use std::collections::BTreeMap;

use ark_ff::{One, Zero};
use ark_serialize::{CanonicalSerialize, Compress};

use super::{
    KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput,
    reduction::{
        ColumnEvals, InstancePlan, KeyedSumRelation, KeyedTerm, Operand, Party, ProvingParty, Side,
        plan_instances, prove_keyed_sums, reduce_keyed_sums, verify_keyed_sums,
    },
};
use crate::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    piop::{
        PIOP,
        logup_gkr::{
            GkrClaims,
            tests::{Deviation, Fault, naive_prove_batch},
        },
    },
    prover::{
        ArgProver,
        structs::{polynomial::TrackedPoly, proof::SNARKProof},
        tracker::ProverTracker,
    },
    test_utils::prelude_with_vars,
    types::{SumcheckSubproof, TrackerID, artifact::Artifact},
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// No column here has more than 2^8 rows.
const SRS_NV: usize = 10;

fn setup() -> (ArgProver<B>, ArgVerifier<B>) {
    prelude_with_vars::<B>(SRS_NV).unwrap()
}

fn fv(vals: impl IntoIterator<Item = u64>) -> Vec<F> {
    vals.into_iter().map(F::from).collect()
}

fn mle(evals: &[F]) -> MLE<F> {
    assert!(evals.len().is_power_of_two());
    MLE::from_evaluations_vec(evals.len().trailing_zeros() as usize, evals.to_vec())
}

fn commit(prover: &mut ArgProver<B>, evals: &[F]) -> TrackedPoly<B> {
    prover.track_and_commit_mat_mv_poly(&mle(evals)).unwrap()
}

/// An in-table column of `2^nv` rows for a table `0..modulus`, different
/// for every `seed`.
fn in_table(nv: usize, modulus: u64, seed: u64) -> Vec<F> {
    fv((0..1u64 << nv).map(|i| (i * 3 + seed * 5 + i * i * seed) % modulus))
}

/// What the table side of a keyed sum must weigh each of its rows with for
/// the sum to balance `entries`, columns with optional weights: each term
/// ranges over the larger of the two, the smaller one repeating.
fn tally(table: &[F], entries: &[(&[F], Option<&[F]>)]) -> Vec<F> {
    let mut weights = vec![F::zero(); table.len()];
    for (col, mult) in entries {
        let rows = col.len().max(mult.map_or(0, <[F]>::len));
        for row in 0..rows {
            let weight = mult.map_or(F::one(), |m| m[row % m.len()]);
            if let Some(at) = table.iter().position(|v| *v == col[row % col.len()]) {
                weights[at] += weight;
            }
        }
    }
    weights
}

fn assert_verifier_error(err: SnarkError) {
    assert!(
        matches!(err, SnarkError::VerifierError(_)),
        "expected VerifierError, got {err:?}"
    );
}

/// A false statement put to an honest prover: with `honest-prover` the
/// prover refuses it, otherwise the verifier must.
fn assert_false_statement_rejected<T>(res: SnarkResult<T>) {
    let err = res
        .map(drop)
        .expect_err("a false statement must be rejected");
    if cfg!(feature = "honest-prover") {
        assert!(
            matches!(err, SnarkError::ProverError(_)),
            "expected the honest prover to refuse, got {err:?}"
        );
    } else {
        assert_verifier_error(err);
    }
}

/// The two sides hold the same position in the id sequence, the same
/// pending sumcheck claims and the same transcript. The transcript is probed
/// on copies.
fn assert_in_sync(prover: &ArgProver<B>, verifier: &ArgVerifier<B>) {
    let prover_tracker = prover.tracker().borrow().clone();
    let verifier = verifier.fork();
    assert_eq!(
        prover_tracker.sumcheck_claims_snapshot(),
        verifier.tracker().borrow().sumcheck_claims_snapshot(),
        "prover and verifier hold different sumcheck claims"
    );
    let mut prover = ArgProver::new_from_tracker(prover_tracker);
    let mut verifier = verifier;
    assert_eq!(prover.peek_next_id(), verifier.peek_next_id());
    assert_eq!(
        prover.get_and_append_challenge(b"parity probe").unwrap(),
        verifier.get_and_append_challenge(b"parity probe").unwrap(),
        "prover and verifier transcripts have diverged"
    );
}

/// An entry of a keyed sum by column index: `(column, multiplicity)`.
type Entry = (usize, Option<usize>);
/// The `f` and `g` entries of one relation.
type Sides = (Vec<Entry>, Vec<Entry>);

/// Where the verifier stopped.
#[derive(Debug)]
enum Rejected {
    /// In the reduction: the GKR subproof or the comparison of the roots.
    Reduction(SnarkError),
    /// After it, in the sumchecks and openings the input claims went into.
    Claims(SnarkError),
}

/// A statement over committed columns, through the crate-internal entry
/// points: the columns are named by id on both sides, whatever their size,
/// and the relations are reduced in one batch.
struct Session {
    prover: ArgProver<B>,
    verifier: ArgVerifier<B>,
    ids: Vec<TrackerID>,
    /// Ordinary sumcheck claims, made before the relations: the factors of
    /// the summed product and its sum.
    summed: Vec<(Vec<TrackerID>, F)>,
    relations: Vec<KeyedSumRelation<F>>,
}

impl Session {
    fn new(columns: &[Vec<F>], summed: &[&[usize]], relations: &[Sides]) -> Self {
        let (mut prover, verifier) = setup();
        let handles: Vec<TrackedPoly<B>> = columns
            .iter()
            .map(|evals| commit(&mut prover, evals))
            .collect();
        let ids: Vec<TrackerID> = handles.iter().map(TrackedPoly::id).collect();
        let summed: Vec<(Vec<TrackerID>, F)> = summed
            .iter()
            .map(|factors| {
                let rows = columns[factors[0]].len();
                let product = |row| factors.iter().map(|f| columns[*f][row]).product::<F>();
                let product_sum = (0..rows).map(product).sum();
                let poly = factors[1..]
                    .iter()
                    .fold(handles[factors[0]].clone(), |acc, f| &acc * &handles[*f]);
                prover
                    .add_mv_sumcheck_claim(poly.id(), product_sum)
                    .unwrap();
                (factors.iter().map(|f| ids[*f]).collect(), product_sum)
            })
            .collect();
        let terms = |entries: &[Entry]| -> Vec<KeyedTerm<F>> {
            entries
                .iter()
                .map(|(col, _)| KeyedTerm::Poly(ids[*col]))
                .collect()
        };
        let mults = |entries: &[Entry]| -> Vec<Option<KeyedTerm<F>>> {
            entries
                .iter()
                .map(|(_, mult)| mult.map(|mult| KeyedTerm::Poly(ids[mult])))
                .collect()
        };
        let relations = relations
            .iter()
            .map(|(f, g)| KeyedSumRelation {
                fxs: terms(f),
                mfxs: mults(f),
                gxs: terms(g),
                mgxs: mults(g),
            })
            .collect();
        Self {
            prover,
            verifier,
            ids,
            summed,
            relations,
        }
    }

    /// The honest prover, or with `evals` a prover that runs the GKR on
    /// tables of its own choosing in place of some committed columns.
    fn prove_with(&mut self, evals: ColumnEvals<F>) -> SnarkResult<()> {
        prove_keyed_sums(&mut self.prover, &self.relations, evals)
    }

    /// A prover that leaves the GKR protocol once, at `deviation`, and is
    /// otherwise consistent with everything it has sent.
    fn prove_deviating(&mut self, deviation: Deviation) -> SnarkResult<()> {
        struct Deviating {
            honest: ProvingParty<F>,
            deviation: Deviation,
        }
        impl Party<ProverTracker<B>> for Deviating {
            fn run(
                &mut self,
                tracker: &mut ProverTracker<B>,
                plan: &[InstancePlan<F>],
                run: std::ops::Range<usize>,
                gamma: F,
            ) -> SnarkResult<GkrClaims<F>> {
                let instances = self.honest.instances(tracker, plan, run, gamma)?;
                let fault = Fault {
                    deviation: self.deviation,
                    patch_until: 0,
                };
                Ok(tracker
                    .prove_logup_gkr_with(|tr| naive_prove_batch(&instances, tr, Some(fault))))
            }

            fn reject(&self, reason: String) -> SnarkError {
                Party::<ProverTracker<B>>::reject(&self.honest, reason)
            }
        }
        let mut party = Deviating {
            honest: ProvingParty {
                evals: ColumnEvals::new(),
            },
            deviation,
        };
        let tracker = self.prover.tracker();
        let mut tracker = tracker.borrow_mut();
        reduce_keyed_sums(&mut *tracker, &mut party, &self.relations).map(drop)
    }

    fn plan(&self) -> Vec<InstancePlan<F>> {
        plan_instances(&*self.prover.tracker().borrow(), &self.relations).unwrap()
    }

    /// Verifies `proof` on a copy of the verifier, so that several proofs
    /// can be put to the same statement.
    fn verify(&self, proof: &SNARKProof<B>) -> Result<(), Rejected> {
        let mut verifier = self.verifier.fork();
        verifier.set_proof_ref(proof);
        let reduction = || -> SnarkResult<()> {
            for id in &self.ids {
                verifier.track_mv_com_by_id(*id)?;
            }
            let oracle = |verifier: &mut ArgVerifier<B>, id| verifier.track_mv_com_by_id(id);
            for (factors, sum) in &self.summed {
                let mut poly = oracle(&mut verifier, factors[0])?;
                for factor in &factors[1..] {
                    poly = &poly * &oracle(&mut verifier, *factor)?;
                }
                verifier.add_mv_sumcheck_claim(poly.id(), *sum);
            }
            verify_keyed_sums(&mut verifier, &self.relations)
        }();
        reduction.map_err(Rejected::Reduction)?;
        verifier.verify().map_err(Rejected::Claims)
    }

    fn prove_and_verify(mut self) -> Result<(), Rejected> {
        self.prove_with(ColumnEvals::new()).unwrap();
        let proof = self.prover.build_proof().unwrap();
        self.verify(&proof)
    }
}

/// A prover whose GKR run is about other tables than the committed ones,
/// or bends a message, satisfies the GKR verifier and the comparison of
/// the roots. What must stop it is the input claims: under `honest-prover`
/// its own tracker refuses the false sums, otherwise the verifier rejects
/// the sumchecks they went into. Returns the proof it got that far with.
fn assert_stopped_by_the_input_claims(
    mut session: Session,
    cheat: impl FnOnce(&mut Session) -> SnarkResult<()>,
) -> Option<SNARKProof<B>> {
    let cheated = cheat(&mut session);
    if cfg!(feature = "honest-prover") {
        let err = cheated.expect_err("the prover claimed a false sum to itself");
        assert!(matches!(err, SnarkError::ProverError(_)), "got {err:?}");
        return None;
    }
    cheated.unwrap();
    let proof = session.prover.build_proof().unwrap();
    match session.verify(&proof) {
        Err(Rejected::Claims(err)) => assert_verifier_error(err),
        other => panic!("expected the input claims to fail, got {other:?}"),
    }
    Some(proof)
}

/// A lookup `subs ⊆ table` as a session: column 0 is the table, column 1
/// its multiplicities for `counted`, the rest `committed`.
fn lookup_session(table: &[F], counted: &[Vec<F>], committed: &[Vec<F>]) -> Session {
    let counted: Vec<(&[F], Option<&[F]>)> = counted.iter().map(|sub| (&sub[..], None)).collect();
    let mut columns = vec![table.to_vec(), tally(table, &counted)];
    columns.extend_from_slice(committed);
    let f = (2..columns.len()).map(|sub| (sub, None)).collect();
    Session::new(&columns, &[], &[(f, vec![(0, Some(1))])])
}

// ─── Cheating provers ────────────────────────────────────────────────────

/// The committed sub column has a value outside the table. The prover runs
/// the GKR on a column that has not, with the multiplicities to match, so
/// every GKR check passes and the two sides balance.
#[test]
fn gkr_on_fake_leaves_with_true_column_claim_is_rejected() {
    let table = fv(0..8);
    for (sub_nv, n_subs, fake_at) in [(3, 1, 0), (5, 1, 0), (2, 1, 0), (3, 3, 0), (3, 3, 2)] {
        let fake: Vec<Vec<F>> = (0..n_subs).map(|s| in_table(sub_nv, 8, s)).collect();
        let mut committed = fake.clone();
        committed[fake_at][1] = F::from(9u64);

        // The same statement about the fake columns is true.
        lookup_session(&table, &fake, &fake)
            .prove_and_verify()
            .unwrap();
        // An honest prover on the committed columns fails at the roots.
        match lookup_session(&table, &fake, &committed).prove_and_verify() {
            Err(Rejected::Reduction(err)) => assert_verifier_error(err),
            other => panic!("expected the roots to differ, got {other:?}"),
        }

        let session = lookup_session(&table, &fake, &committed);
        let evals = BTreeMap::from([(session.ids[2 + fake_at], fake[fake_at].clone())]);
        assert_stopped_by_the_input_claims(session, |session| session.prove_with(evals));
    }
}

/// The committed multiplicities are wrong and the prover runs the GKR on
/// the right ones: on the table side, and for a weighted column whose
/// weights have fewer rows than it.
#[test]
fn gkr_on_fake_numerators_with_true_multiplicity_claim_is_rejected() {
    let table = fv(0..8);
    let sub = fv([1, 1, 2, 3, 5, 5, 5, 7]);

    let right = tally(&table, &[(&sub, None)]);
    let mut wrong = right.clone();
    wrong[1] -= F::one();
    wrong[2] += F::one();
    let session = |multiplicity: &[F]| {
        let columns = [table.clone(), multiplicity.to_vec(), sub.clone()];
        Session::new(&columns, &[], &[(vec![(2, None)], vec![(0, Some(1))])])
    };
    session(&right).prove_and_verify().unwrap();
    let cheater = session(&wrong);
    let evals = BTreeMap::from([(cheater.ids[1], right)]);
    assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));

    let weights = fv([2, 3]);
    let mut wrong = weights.clone();
    wrong[1] += F::one();
    let counts = tally(&table, &[(&sub, Some(&weights))]);
    let session = |weights: &[F]| {
        let columns = [table.clone(), counts.clone(), sub.clone(), weights.to_vec()];
        Session::new(&columns, &[], &[(vec![(2, Some(3))], vec![(0, Some(1))])])
    };
    session(&weights).prove_and_verify().unwrap();
    let cheater = session(&wrong);
    let evals = BTreeMap::from([(cheater.ids[3], weights)]);
    assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
}

/// The masks of the last iteration are the GKR's claims on the input
/// layers, and nothing inside the GKR checks them. The prover moves one of
/// them along a direction that keeps its layer check true and carries on
/// honestly from there. A unit-numerator instance sends two values there,
/// the others four.
#[test]
fn tampered_last_mask_of_a_gkr_subproof_is_rejected() {
    let table = fv(0..8);
    for sub_nv in [3, 2] {
        let sub = in_table(sub_nv, 8, 1);
        for (instance, mask_len) in [(0, 2), (1, 4)] {
            let subs = std::slice::from_ref(&sub);
            let session = lookup_session(&table, subs, subs);
            // Every instance reaches its input layer in the last iteration.
            let deviation = Deviation::Mask {
                iteration: 2,
                instance,
                delta: F::from(5u64),
            };
            let proof = assert_stopped_by_the_input_claims(session, |session| {
                session.prove_deviating(deviation)
            });
            if let Some(proof) = proof {
                let masks = proof.logup_gkr_subproofs[0].masks.last().unwrap();
                assert_eq!(masks[instance].len(), mask_len);
            }
        }
    }
}

/// An instance without variables never enters an iteration: its root is
/// its input claim, numerator and denominator both.
#[test]
fn tampered_root_of_an_nv0_values_instance_is_rejected() {
    let table = fv(0..8);
    // Key 7 with weight 3, one row each.
    let session = |key: u64, weight: u64, counts: &[F]| {
        let columns = [table.clone(), counts.to_vec(), fv([key]), fv([weight])];
        Session::new(&columns, &[], &[(vec![(2, Some(3))], vec![(0, Some(1))])])
    };
    let counts = |key: usize, weight: u64| {
        let mut counts = vec![F::zero(); 8];
        counts[key] = F::from(weight);
        counts
    };
    let honest = session(7, 3, &counts(7, 3));
    assert_eq!(honest.plan()[0].n_vars(), 0);
    assert!(honest.plan()[0].mults.is_some());
    honest.prove_and_verify().unwrap();

    // The root sent as an equal fraction: both claims are off.
    assert_stopped_by_the_input_claims(session(7, 3, &counts(7, 3)), |session| {
        session.prove_deviating(Deviation::ScaleRoot {
            instance: 0,
            scale: F::from(2u64),
        })
    });

    // Only the numerator is off: the table counts 2, the committed weight
    // is 3 and the GKR runs on 2.
    let cheater = session(7, 3, &counts(7, 2));
    let evals = BTreeMap::from([(cheater.ids[3], fv([2]))]);
    assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));

    // Only the denominator is off: the table counts key 6, the committed
    // key is 7 and the GKR runs on 6.
    let cheater = session(7, 3, &counts(6, 3));
    let evals = BTreeMap::from([(cheater.ids[2], fv([6]))]);
    assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
}

#[test]
fn relation_with_an_nv0_instance_of_each_kind_verifies() {
    let table = fv(0..8);
    let session = |unit_key: u64, key: u64, weight: u64| {
        let mut counts = vec![F::zero(); 8];
        counts[7] = F::one();
        counts[5] = F::from(3u64);
        let columns = [
            table.clone(),
            counts,
            fv([unit_key]),
            fv([key]),
            fv([weight]),
        ];
        let f = vec![(2, None), (3, Some(4))];
        Session::new(&columns, &[], &[(f, vec![(0, Some(1))])])
    };
    let honest = session(7, 5, 3);
    let kinds: Vec<(usize, bool)> = honest
        .plan()
        .iter()
        .map(|instance| (instance.n_vars(), instance.mults.is_none()))
        .collect();
    assert_eq!(kinds, [(0, true), (0, false), (3, false)]);
    honest.prove_and_verify().unwrap();

    for (unit_key, key, weight) in [(6, 5, 3), (7, 4, 3), (7, 5, 2)] {
        match session(unit_key, key, weight).prove_and_verify() {
            Err(Rejected::Reduction(err)) => assert_verifier_error(err),
            other => panic!("expected the roots to differ, got {other:?}"),
        }
    }
}

/// Whether an instance has numerators of its own follows the statement: a
/// multiplicity that is named is claimed, even when all its values are 1.
#[test]
fn named_all_ones_multiplicity_is_still_a_values_instance() {
    let table = fv(0..8);
    let sub = in_table(3, 8, 1);
    let columns = [
        table.clone(),
        tally(&table, &[(&sub, None)]),
        sub,
        fv([1; 8]),
    ];
    let mut session = Session::new(&columns, &[], &[(vec![(2, Some(3))], vec![(0, Some(1))])]);
    assert!(session.plan()[0].mults.is_some());
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    assert_eq!(proof.logup_gkr_subproofs[0].masks[2][0].len(), 4);
    session.verify(&proof).unwrap();
}

/// The lookup `sub ⊆ table`, 8 rows each and with the multiplicities of
/// `counted`, next to a sum over two columns of `2^wide_nv` rows: the
/// lookup's columns sit below the proof's widest commitment.
fn narrow_lookup_session(table: &[F], sub: &[F], counted: &[F], wide_nv: usize) -> Session {
    let columns = [
        table.to_vec(),
        tally(table, &[(counted, None)]),
        sub.to_vec(),
        fv((0..1u64 << wide_nv).map(|i| i * i + 1)),
        fv((0..1u64 << wide_nv).map(|i| 3 * i + 2)),
    ];
    Session::new(
        &columns,
        &[&[3, 4]],
        &[(vec![(2, None)], vec![(0, Some(1))])],
    )
}

fn with_claim_map_entry(proof: &SNARKProof<B>, id: TrackerID, value: F) -> SNARKProof<B> {
    let mut proof = proof.clone();
    let subproof = proof.sc_subproof.as_ref().unwrap();
    let mut claims = subproof.sumcheck_claims().clone();
    claims.insert(id, value);
    proof.sc_subproof = Some(SumcheckSubproof::new(subproof.buckets().to_vec(), claims));
    proof
}

/// The claim map of a proof is not bound by the transcript. Whatever it
/// says about an input claim of the reduction, the verifier uses its own
/// value. `(wide nv, buckets)`: one sumcheck for everything, and one for
/// the lookup alone.
#[test]
fn raw_claim_ignores_proof_map() {
    let table = fv(0..8);
    let sub = fv([1, 1, 2, 3, 5, 5, 5, 7]);
    for (wide_nv, buckets) in [(4, 1), (8, 2)] {
        let mut session = narrow_lookup_session(&table, &sub, &sub, wide_nv);
        session.prove_with(ColumnEvals::new()).unwrap();
        let claims = session.prover.tracker().borrow().sumcheck_claims_snapshot();
        let raw: Vec<(TrackerID, F)> = claims
            .iter()
            .filter(|(_, _, raw)| *raw)
            .map(|(id, sum, _)| (*id, *sum))
            .collect();
        // The sub, the table and the multiplicities.
        assert_eq!(raw.len(), 3);
        assert_eq!(claims.len(), 4);

        let proof = session.prover.build_proof().unwrap();
        let subproof = proof.sc_subproof.as_ref().unwrap();
        assert_eq!(subproof.buckets().len(), buckets);
        for (id, _) in &raw {
            assert!(!subproof.sumcheck_claims().contains_key(id));
        }
        session.verify(&proof).unwrap();

        let global_scale = F::from(1u64 << (wide_nv - 3));
        for (id, sum) in raw {
            for entry in [sum, sum * global_scale, sum + F::one(), F::zero()] {
                session
                    .verify(&with_claim_map_entry(&proof, id, entry))
                    .unwrap();
            }
        }
    }
}

/// Were the verifier to take the claim map's word for an input claim, it
/// would rescale the claim as the map implies and end up checking the
/// column times `2^(G - nv)`, `G` being the widest commitment. The prover
/// here has a sub column that is in the table only after that scaling. It
/// runs the GKR on the scaled column, proves the true sum in the sumcheck
/// and writes into the map what the verifier would need to read.
#[test]
fn scaled_column_attack_through_the_proof_map_is_rejected() {
    let sub = fv([1, 1, 2, 3, 5, 5, 5, 7]);
    for (wide_nv, buckets) in [(4, 1), (8, 2)] {
        let scale = F::from(1u64 << (wide_nv - 3));
        let table: Vec<F> = (0..8u64).map(|j| F::from(j) * scale).collect();
        let scaled: Vec<F> = sub.iter().map(|v| *v * scale).collect();

        narrow_lookup_session(&table, &scaled, &scaled, wide_nv)
            .prove_and_verify()
            .unwrap();

        let mut session = narrow_lookup_session(&table, &sub, &scaled, wide_nv);
        let evals = BTreeMap::from([(session.ids[2], scaled)]);
        let cheated = session.prove_with(evals);
        if cfg!(feature = "honest-prover") {
            assert!(matches!(cheated, Err(SnarkError::ProverError(_))));
            continue;
        }
        cheated.unwrap();

        // The first input claim is the sub column's; its value is the
        // scaled column at the GKR's point.
        let tracker = session.prover.tracker();
        let (claimed, value, _) = tracker.borrow().sumcheck_claims_snapshot()[1];
        let true_sum = value / scale;
        tracker.borrow_mut().set_sumcheck_claim(claimed, true_sum);

        let proof = session.prover.build_proof().unwrap();
        assert_eq!(proof.sc_subproof.as_ref().unwrap().buckets().len(), buckets);
        let entries = [value, true_sum, value * scale, true_sum * scale];
        let forged = entries.map(|entry| with_claim_map_entry(&proof, claimed, entry));
        for proof in std::iter::once(&proof).chain(&forged) {
            match session.verify(proof) {
                Err(Rejected::Claims(err)) => assert_verifier_error(err),
                other => panic!("expected the input claims to fail, got {other:?}"),
            }
        }
    }
}

/// Two relations in one batch, each false, with errors that cancel over the
/// batch: the sides are compared per relation.
#[test]
fn relations_whose_errors_cancel_over_the_batch_are_rejected() {
    let a = fv(0..8);
    let b = fv((0..8).map(|i| i + 100));
    let columns = [a, b];
    let entry = |column: usize| vec![(column, None)];

    // As one relation the four columns balance.
    let together = (vec![(0, None), (1, None)], vec![(1, None), (0, None)]);
    Session::new(&columns, &[&[0]], &[together])
        .prove_and_verify()
        .unwrap();

    let apart = [(entry(0), entry(1)), (entry(1), entry(0))];
    match Session::new(&columns, &[&[0]], &apart).prove_and_verify() {
        Err(Rejected::Reduction(err)) => assert_verifier_error(err),
        other => panic!("expected the roots to differ, got {other:?}"),
    }

    // A true relation does not vouch for a false one next to it.
    let mixed = [(entry(0), entry(0)), (entry(0), entry(1))];
    match Session::new(&columns, &[&[0]], &mixed).prove_and_verify() {
        Err(Rejected::Reduction(err)) => assert_verifier_error(err),
        other => panic!("expected the roots to differ, got {other:?}"),
    }
}

// ─── Layout of the batch ─────────────────────────────────────────────────

/// `add_mv_lookup_claim` for every sub against one committed table, with
/// nothing else in the proof. Returns the proof when it is accepted.
fn lookup_e2e(table: &[F], subs: &[Vec<F>]) -> SnarkResult<SNARKProof<B>> {
    let (mut prover, mut verifier) = setup();
    let table = commit(&mut prover, table).id();
    let mut ids = vec![table];
    for sub in subs {
        let sub = commit(&mut prover, sub).id();
        prover.add_mv_lookup_claim(table, sub)?;
        ids.push(sub);
    }
    let proof = prover.build_proof()?;
    verifier.set_proof_ref(&proof);
    for id in &ids {
        verifier.track_mv_com_by_id(*id)?;
    }
    for sub in &ids[1..] {
        verifier.add_mv_lookup_claim(table, *sub)?;
    }
    verifier.verify()?;
    assert_in_sync(&prover, &verifier);
    Ok(proof)
}

/// `S` sub columns of one size are stacked into one instance per binary
/// digit of `S`, next to the table's. A value outside the table is caught
/// wherever in the stacks its column sits.
#[test]
fn same_size_columns_are_stacked_by_binary_decomposition() {
    let table = fv(0..16);
    for n_subs in [1usize, 2, 3, 5, 8, 13] {
        let subs: Vec<Vec<F>> = (0..n_subs).map(|s| in_table(3, 16, s as u64)).collect();
        let proof = lookup_e2e(&table, &subs).unwrap();
        assert_eq!(proof.logup_gkr_subproofs.len(), 1);
        assert_eq!(
            proof.logup_gkr_subproofs[0].roots.len(),
            n_subs.count_ones() as usize + 1
        );

        // The first and the last column of the largest stack, and the
        // first and the last of the smallest.
        let largest = 1 << n_subs.ilog2();
        let smallest = 1 << n_subs.trailing_zeros();
        for at in [0, largest - 1, n_subs - smallest, n_subs - 1] {
            let mut subs = subs.clone();
            subs[at][5] = F::from(16u64);
            assert_false_statement_rejected(lookup_e2e(&table, &subs));
        }
    }
}

/// A column of a keyed sum with its optional multiplicity.
type KeyedCol = (Vec<F>, Option<Vec<F>>);

/// `KeyedSumcheck` on committed columns, with both sides compared right
/// after the PIOP as well as at the end. Returns the instances the prover
/// laid out and the proof.
fn keyed_e2e(
    fs: &[KeyedCol],
    gs: &[KeyedCol],
) -> SnarkResult<(Vec<InstancePlan<F>>, SNARKProof<B>)> {
    let (mut prover, mut verifier) = setup();
    let mut ids = Vec::new();
    let mut side = |prover: &mut ArgProver<B>, cols: &[KeyedCol]| {
        let mut handles = (Vec::new(), Vec::new());
        for (col, mult) in cols {
            let col = commit(prover, col);
            let mult = mult.as_ref().map(|mult| commit(prover, mult));
            ids.push((col.id(), mult.as_ref().map(TrackedPoly::id)));
            handles.0.push(col);
            handles.1.push(mult);
        }
        handles
    };
    let (fxs, mfxs) = side(&mut prover, fs);
    let (gxs, mgxs) = side(&mut prover, gs);
    let relation = KeyedSumRelation {
        fxs: fxs.iter().map(KeyedTerm::from).collect(),
        mfxs: mfxs.iter().map(|m| m.as_ref().map(Into::into)).collect(),
        gxs: gxs.iter().map(KeyedTerm::from).collect(),
        mgxs: mgxs.iter().map(|m| m.as_ref().map(Into::into)).collect(),
    };
    let plan = plan_instances(&*prover.tracker().borrow(), &[relation]).unwrap();
    KeyedSumcheck::<B>::prove(
        &mut prover,
        KeyedSumcheckProverInput {
            fxs,
            gxs,
            mfxs,
            mgxs,
        },
    )?;
    let after_piop = ArgProver::new_from_tracker(prover.tracker().borrow().clone());
    let proof = prover.build_proof()?;

    verifier.set_proof_ref(&proof);
    let mut side = |ids: &[(TrackerID, Option<TrackerID>)]| -> SnarkResult<_> {
        let mut oracles = (Vec::new(), Vec::new());
        for (col, mult) in ids {
            oracles.0.push(verifier.track_mv_com_by_id(*col)?);
            let mult = mult.map(|mult| verifier.track_mv_com_by_id(mult));
            oracles.1.push(mult.transpose()?);
        }
        Ok(oracles)
    };
    let (fxs, mfxs) = side(&ids[..fs.len()])?;
    let (gxs, mgxs) = side(&ids[fs.len()..])?;
    KeyedSumcheck::<B>::verify(
        &mut verifier,
        KeyedSumcheckVerifierInput {
            fxs,
            gxs,
            mfxs,
            mgxs,
        },
    )?;
    assert_in_sync(&after_piop, &verifier);
    verifier.verify()?;
    assert_in_sync(&prover, &verifier);
    Ok((plan, proof))
}

/// `(side, claim nv, stack log, unit numerators, constant column, constant
/// multiplicity)` of every instance.
fn layout(plan: &[InstancePlan<F>]) -> Vec<(Side, usize, usize, bool, bool, bool)> {
    let constant = |operand: &Operand<F>| matches!(operand, Operand::Constant(_));
    plan.iter()
        .map(|instance| {
            (
                instance.side,
                instance.claim_nv,
                instance.stack_log,
                instance.mults.is_none(),
                constant(&instance.cols),
                instance.mults.as_ref().is_some_and(constant),
            )
        })
        .collect()
}

/// The table side of a keyed sum that balances `fs` against `table`.
fn table_side(table: &[F], fs: &[KeyedCol]) -> Vec<KeyedCol> {
    let entries: Vec<(&[F], Option<&[F]>)> = fs
        .iter()
        .map(|(col, mult)| (&col[..], mult.as_deref()))
        .collect();
    vec![(table.to_vec(), Some(tally(table, &entries)))]
}

/// One side holding columns of several sizes, with and without
/// multiplicities, interleaved: entries are stacked only with entries of
/// the same sizes and kind, and a group sits where its first entry was.
#[test]
fn mixed_signatures_on_one_side_are_grouped_in_order_of_appearance() {
    let table = fv(0..16);
    let fs: Vec<KeyedCol> = vec![
        (in_table(3, 16, 1), None),
        (in_table(5, 16, 2), None),
        (in_table(3, 16, 3), Some(fv(1..9))),
        (in_table(3, 16, 4), None),
        (in_table(3, 16, 5), Some(fv([2, 5]))),
        (in_table(5, 16, 6), None),
        (in_table(3, 16, 7), Some(fv(3..11))),
        (in_table(2, 16, 8), Some(fv([4, 9, 2, 6]))),
        (in_table(3, 16, 9), None),
    ];
    let (plan, proof) = keyed_e2e(&fs, &table_side(&table, &fs)).unwrap();
    assert_eq!(
        layout(&plan),
        [
            // Three unit columns of 8 rows: a pair and a single.
            (Side::F, 3, 1, true, false, false),
            (Side::F, 3, 0, true, false, false),
            (Side::F, 5, 1, true, false, false),
            (Side::F, 3, 1, false, false, false),
            (Side::F, 3, 0, false, false, false),
            (Side::F, 2, 0, false, false, false),
            (Side::G, 4, 0, false, false, false),
        ]
    );
    assert_eq!(proof.logup_gkr_subproofs[0].roots.len(), plan.len());

    // One value outside the table, or one weight off, in every group.
    let bad_value = |fs: &mut Vec<KeyedCol>, at: usize| fs[at].0[1] = F::from(16u64);
    let bad_weight = |fs: &mut Vec<KeyedCol>, at: usize| {
        fs[at].1.as_mut().unwrap()[1] += F::one();
    };
    let g = table_side(&table, &fs);
    for at in [0, 3, 8, 1, 5, 2, 6, 4, 7] {
        let mut fs = fs.clone();
        bad_value(&mut fs, at);
        assert_false_statement_rejected(keyed_e2e(&fs, &g));
    }
    for at in [2, 6, 4, 7] {
        let mut fs = fs.clone();
        bad_weight(&mut fs, at);
        assert_false_statement_rejected(keyed_e2e(&fs, &g));
    }
}

/// A constant column or multiplicity is an instance of its own, in place,
/// and is checked against the GKR's claim in the clear; the columns around
/// it are still stacked with each other.
#[test]
fn constant_entries_stand_alone_among_stacked_ones() {
    let table = fv(0..16);
    let fs = |constant: u64, weighted_constant: u64, constant_weight: u64| -> Vec<KeyedCol> {
        vec![
            (in_table(3, 16, 1), None),
            (fv([constant; 8]), None),
            (in_table(3, 16, 2), None),
            (fv([weighted_constant; 8]), Some(fv(1..9))),
            (in_table(3, 16, 3), Some(fv([constant_weight; 8]))),
            (in_table(3, 16, 4), None),
            (fv([constant; 4]), Some(fv([constant_weight; 4]))),
        ]
    };
    let honest = fs(7, 11, 4);
    let g = table_side(&table, &honest);
    let (plan, proof) = keyed_e2e(&honest, &g).unwrap();
    assert_eq!(
        layout(&plan),
        [
            (Side::F, 3, 1, true, false, false),
            (Side::F, 3, 0, true, false, false),
            (Side::F, 3, 0, true, true, false),
            (Side::F, 3, 0, false, true, false),
            (Side::F, 3, 0, false, false, true),
            (Side::F, 2, 0, false, true, true),
            (Side::G, 4, 0, false, false, false),
        ]
    );
    assert_eq!(proof.logup_gkr_subproofs[0].roots.len(), plan.len());

    for (constant, weighted_constant, constant_weight) in [(16, 11, 4), (7, 16, 4), (7, 11, 5)] {
        let fs = fs(constant, weighted_constant, constant_weight);
        assert_false_statement_rejected(keyed_e2e(&fs, &g));
    }
}

/// A constant operand has no tracker claim: the verifier compares the
/// GKR's claim with the constant its own statement names. A proof about
/// other constants, sound in itself, is not a proof of that statement.
#[test]
fn constant_operands_are_checked_against_the_gkr_claims() {
    let table = fv(0..16);
    let keys = in_table(3, 16, 1);
    let weights = fv(1..9);
    // One constant column, one constant multiplicity.
    let relation = |session: &Session, constant: u64, constant_weight: u64| {
        let value = |v: u64| KeyedTerm::Constant {
            value: F::from(v),
            nv: 3,
        };
        KeyedSumRelation {
            fxs: vec![value(constant), KeyedTerm::Poly(session.ids[2])],
            mfxs: vec![
                Some(KeyedTerm::Poly(session.ids[3])),
                Some(value(constant_weight)),
            ],
            gxs: vec![KeyedTerm::Poly(session.ids[0])],
            mgxs: vec![Some(KeyedTerm::Poly(session.ids[1]))],
        }
    };
    let counts = tally(
        &table,
        &[(&fv([7; 8]), Some(&weights)), (&keys, Some(&fv([4; 8])))],
    );
    let columns = [table, counts, keys, weights];
    let mut session = Session::new(&columns, &[], &[]);
    session.relations = vec![relation(&session, 7, 4)];
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    session.verify(&proof).unwrap();

    for (constant, constant_weight) in [(8, 4), (7, 5)] {
        session.relations = vec![relation(&session, constant, constant_weight)];
        match session.verify(&proof) {
            Err(Rejected::Reduction(err)) => assert_verifier_error(err),
            other => panic!("expected the constant to be compared, got {other:?}"),
        }
    }
}

/// A product of a one-row polynomial and an `n`-variable one has `n`
/// variables in the tracker whatever the order of its factors, but its
/// handle does not: the verifier's keeps the left factor's size. The sizes
/// of the instances are the tracker's.
#[test]
fn products_with_a_one_row_factor_take_their_size_from_the_tracker() {
    let table = fv((0..16).map(|i| 3 * i));
    let run = |scalar: u64, committed_scalar: bool| -> SnarkResult<()> {
        let (mut prover, mut verifier) = setup();
        let cols: Vec<Vec<F>> = (0..4).map(|s| in_table(3, 16, s)).collect();
        let scaled: Vec<Vec<F>> = cols
            .iter()
            .map(|col| col.iter().map(|v| *v * F::from(3u64)).collect())
            .collect();
        let scaled: Vec<(&[F], Option<&[F]>)> = scaled.iter().map(|col| (&col[..], None)).collect();

        let table_p = commit(&mut prover, &table);
        let cols_p: Vec<TrackedPoly<B>> = cols.iter().map(|c| commit(&mut prover, c)).collect();
        // A committed one-row polynomial is a constant handle; a tracked
        // one is a polynomial like any other.
        let scalar_p = if committed_scalar {
            commit(&mut prover, &fv([scalar]))
        } else {
            prover.track_mat_mv_poly(mle(&fv([scalar])))
        };
        let products_p = [
            &scalar_p * &cols_p[0],
            &cols_p[1] * &scalar_p,
            &scalar_p * &cols_p[2],
            &cols_p[3] * &scalar_p,
        ];
        let mut ids = vec![table_p.id()];
        ids.extend(cols_p.iter().map(TrackedPoly::id));
        if committed_scalar {
            ids.push(scalar_p.id());
        }
        // Two products through a lookup, two as columns of a keyed sum
        // whose other side is again the table.
        let [lookup_a, lookup_b, keyed_a, keyed_b] = products_p;
        prover.add_mv_lookup_claim(table_p.id(), lookup_a.id())?;
        prover.add_mv_lookup_claim(table_p.id(), lookup_b.id())?;
        let keyed_counts = tally(&table, &scaled[2..]);
        let keyed_counts_p = commit(&mut prover, &keyed_counts);
        ids.push(keyed_counts_p.id());
        KeyedSumcheck::<B>::prove(
            &mut prover,
            KeyedSumcheckProverInput {
                fxs: vec![table_p.clone()],
                mfxs: vec![Some(keyed_counts_p)],
                gxs: vec![keyed_a, keyed_b],
                mgxs: vec![None, None],
            },
        )?;
        let proof = prover.build_proof()?;

        verifier.set_proof_ref(&proof);
        let n_committed = if committed_scalar { 6 } else { 5 };
        let mut oracles: Vec<TrackedOracle<B>> = Vec::new();
        for id in &ids[..n_committed] {
            oracles.push(verifier.track_mv_com_by_id(*id)?);
        }
        let scalar_v = if committed_scalar {
            oracles[5].clone()
        } else {
            verifier.track_base_oracle(Oracle::new_multivariate(0, move |_| Ok(F::from(scalar))))
        };
        let (table_v, cols_v) = (&oracles[0], &oracles[1..5]);
        let [lookup_a, lookup_b, keyed_a, keyed_b] = [
            &scalar_v * &cols_v[0],
            &cols_v[1] * &scalar_v,
            &scalar_v * &cols_v[2],
            &cols_v[3] * &scalar_v,
        ];
        // The verifier's handles disagree with each other and with the
        // tracker, which has three variables for all four.
        assert_eq!((lookup_a.log_size(), lookup_b.log_size()), (0, 3));
        for product in [&lookup_a, &lookup_b, &keyed_a, &keyed_b] {
            let nv = verifier.tracker().borrow().oracle_log_size(product.id());
            assert_eq!(nv, Some(3));
        }
        verifier.add_mv_lookup_claim(table_v.id(), lookup_a.id())?;
        verifier.add_mv_lookup_claim(table_v.id(), lookup_b.id())?;
        let keyed_counts_v = verifier.track_mv_com_by_id(*ids.last().unwrap())?;
        KeyedSumcheck::<B>::verify(
            &mut verifier,
            KeyedSumcheckVerifierInput {
                fxs: vec![table_v.clone()],
                mfxs: vec![Some(keyed_counts_v)],
                gxs: vec![keyed_a, keyed_b],
                mgxs: vec![None, None],
            },
        )?;
        verifier.verify()?;
        assert_in_sync(&prover, &verifier);
        Ok(())
    };
    for committed_scalar in [true, false] {
        run(3, committed_scalar).unwrap();
        // Times 5 the columns leave the table.
        assert_false_statement_rejected(run(5, committed_scalar));
    }
}

// ─── Honest-prover check ─────────────────────────────────────────────────

/// A column and its multiplicity of different sizes: the verdict of the
/// protocol, and under `honest-prover` that of the prover's own check, is
/// the one of the sum taken over the larger of the two with the smaller one
/// repeating.
#[test]
fn honest_check_agrees_with_protocol_on_mixed_col_mult_nv() {
    let table = fv(0..8);
    // `(column rows, weight rows)` on the `f` side.
    for (col_rows, weight_rows) in [(1, 8), (8, 32), (32, 8), (2, 16), (16, 1), (8, 8)] {
        let col = fv((0..col_rows).map(|i| (i * 3 + 1) % 8));
        let weights = fv((0..weight_rows).map(|i| i + 1));
        let fs = vec![(col, Some(weights))];
        let truth = table_side(&table, &fs);
        // What a check that pairs rows without repeating would balance.
        let rows = col_rows.min(weight_rows) as usize;
        let truncated = table_side(
            &table,
            &[(
                fs[0].0[..rows].to_vec(),
                Some(fs[0].1.as_ref().unwrap()[..rows].to_vec()),
            )],
        );

        for (gs, holds) in [(&truth, true), (&truncated, col_rows == weight_rows)] {
            #[cfg(feature = "honest-prover")]
            {
                let (mut prover, _) = setup();
                let mut handles = |cols: &[KeyedCol]| {
                    let col = commit(&mut prover, &cols[0].0);
                    let mult = commit(&mut prover, cols[0].1.as_ref().unwrap());
                    (vec![col], vec![Some(mult)])
                };
                let (fxs, mfxs) = handles(&fs);
                let (gxs, mgxs) = handles(gs);
                let input = KeyedSumcheckProverInput {
                    fxs,
                    gxs,
                    mfxs,
                    mgxs,
                };
                let checked = KeyedSumcheck::<B>::honest_prover_check_helper(&input);
                assert_eq!(checked.is_ok(), holds, "{col_rows} x {weight_rows}");
            }
            let proved = keyed_e2e(&fs, gs);
            if holds {
                proved.unwrap();
            } else {
                assert_false_statement_rejected(proved);
            }
        }
    }
}

// ─── Proof plumbing ──────────────────────────────────────────────────────

#[test]
fn proof_with_a_lookup_carries_its_gkr_subproof_through_a_roundtrip() {
    let table = fv(0..16);
    let subs: Vec<Vec<F>> = (0..3).map(|s| in_table(5, 16, s)).collect();
    let mut session = lookup_session(&table, &subs, &subs);
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    assert_eq!(proof.logup_gkr_subproofs.len(), 1);
    assert!(!proof.logup_gkr_subproofs[0].masks.is_empty());

    let bytes = proof.to_bytes().unwrap();
    let decoded = SNARKProof::<B>::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.logup_gkr_subproofs, proof.logup_gkr_subproofs);
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
    session.verify(&decoded).unwrap();

    let breakdown = proof.size_breakdown().unwrap();
    assert_eq!(breakdown.size, bytes.len());
    assert_eq!(
        breakdown.parts["logup_gkr_subproofs"].size,
        proof.logup_gkr_subproofs.serialized_size(Compress::Yes)
    );
    // The one byte left over is the version tag.
    let parts: usize = breakdown.parts.values().map(|part| part.size).sum();
    assert_eq!(parts + 1, breakdown.size);
}

/// The prover's instances are the columns side by side, entry `i` of a
/// stack in the rows `i·2^claim_nv ..`, a column narrower than its
/// multiplicity repeated, and `gamma` taken off the columns only.
#[test]
fn stacked_instance_lays_its_entries_out_by_row_then_entry() {
    use crate::piop::logup_gkr::Numerator;

    let cols: Vec<Vec<F>> = (0..3).map(|s| in_table(1, 16, s + 1)).collect();
    let mults: Vec<Vec<F>> = (0..3).map(|s| fv((0..4).map(|i| 10 * s + i))).collect();
    let columns: Vec<Vec<F>> = cols.iter().chain(&mults).cloned().collect();
    let f = (0..3).map(|i| (i, Some(i + 3))).collect();
    let session = Session::new(&columns, &[], &[(f, vec![(0, Some(3))])]);
    let plan = session.plan();
    assert_eq!(plan[0].stack_log, 1);
    assert_eq!((plan[0].claim_nv, plan[0].n_vars()), (2, 3));

    let gamma = F::from(1000u64);
    let mut party = ProvingParty {
        evals: ColumnEvals::new(),
    };
    let tracker = session.prover.tracker();
    let instances = party
        .instances(&mut tracker.borrow_mut(), &plan, 0..plan.len(), gamma)
        .unwrap();
    assert!(party.evals.is_empty());

    let expected_den: Vec<F> = (0..8).map(|j| cols[j >> 2][j & 1] - gamma).collect();
    let expected_num: Vec<F> = (0..8).map(|j| mults[j >> 2][j & 3]).collect();
    assert_eq!(instances[0].den, expected_den);
    match &instances[0].num {
        Numerator::Values(num) => assert_eq!(*num, expected_num),
        Numerator::One => panic!("the stack has multiplicities"),
    }
    assert_eq!(instances[1].den.len(), 4);
}
