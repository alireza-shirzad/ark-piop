//! The keyed-sum reduction from inside the crate: provers that cheat while
//! staying consistent with the transcript, the layout of the GKR batch, and
//! the two sides staying in step.

use std::collections::BTreeMap;

use ark_ff::{One, Zero};
use ark_poly::Polynomial;
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
    setup::KeyGenerator,
    test_utils::prelude_with_vars,
    tracker_core::TrackerCore,
    types::{SharedArgConfig, SumcheckSubproof, TrackerID, artifact::Artifact},
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
        tracker::VerifierTracker,
    },
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// No column here has more than 2^8 rows.
const SRS_NV: usize = 10;

fn setup() -> (ArgProver<B>, ArgVerifier<B>) {
    prelude_with_vars::<B>(SRS_NV).unwrap()
}

/// [`setup`] with the GKR runs of each side limited to its own budget. An
/// honest pair is given the same one.
fn setup_with_budgets(prover: usize, verifier: usize) -> (ArgProver<B>, ArgVerifier<B>) {
    let config = |logup_gkr_run_budget| SharedArgConfig {
        logup_gkr_run_budget,
        ..SharedArgConfig::default()
    };
    let (pk, vk) = KeyGenerator::<B>::new()
        .with_num_mv_vars(SRS_NV)
        .gen_keys()
        .unwrap();
    let prover = ProverTracker::new_from_pk_with_config(pk, config(prover));
    let verifier = VerifierTracker::new_from_vk_with_config(vk, config(verifier));
    (
        ArgProver::new_from_tracker(prover),
        ArgVerifier::new_from_tracker(verifier),
    )
}

fn fv(vals: impl IntoIterator<Item = u64>) -> Vec<F> {
    vals.into_iter().map(F::from).collect()
}

fn sum(evals: &[F]) -> F {
    evals.iter().fold(F::zero(), |acc, v| acc + v)
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

/// The two sides hold the same position in the id sequence, polynomials of
/// the same size under every id, the same pending sumcheck claims on
/// polynomials of the same degree, and the same transcript. The transcript
/// is probed on copies.
fn assert_in_sync(prover: &ArgProver<B>, verifier: &ArgVerifier<B>) {
    let prover_tracker = prover.tracker().borrow().clone();
    let verifier = verifier.fork();
    let claims = prover_tracker.sumcheck_claims_snapshot();
    assert_eq!(
        claims,
        verifier.tracker().borrow().sumcheck_claims_snapshot(),
        "prover and verifier hold different sumcheck claims"
    );
    // The sumcheck buckets are planned from the sizes and degrees of the
    // claimed polynomials, and products are ordered by the ids of their
    // factors: equally many ids is not enough.
    let next = TrackerCore::peek_next_id(&prover_tracker);
    {
        let verifier_tracker = verifier.tracker();
        let verifier_tracker = verifier_tracker.borrow();
        for (id, _, _) in &claims {
            assert_eq!(
                TrackerCore::virt_poly_degree(&prover_tracker, *id),
                TrackerCore::virt_poly_degree(&*verifier_tracker, *id),
                "prover and verifier give claimed polynomial {id} different degrees"
            );
        }
        for id in (0..next.to_int()).map(TrackerID::from_usize) {
            assert_eq!(
                TrackerCore::poly_nv(&prover_tracker, id),
                TrackerCore::poly_nv(&*verifier_tracker, id),
                "prover and verifier hold polynomials of different sizes under {id}"
            );
        }
    }
    let mut prover = ArgProver::new_from_tracker(prover_tracker);
    let mut verifier = verifier;
    assert_eq!(next, verifier.peek_next_id());
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
        Self::on(setup(), columns, summed, relations)
    }

    /// A session whose sides cut their GKR batches by the given budgets.
    fn with_budgets(
        (prover, verifier): (usize, usize),
        columns: &[Vec<F>],
        relations: &[Sides],
    ) -> Self {
        let parties = setup_with_budgets(prover, verifier);
        Self::on(parties, columns, &[], relations)
    }

    fn on(
        (mut prover, verifier): (ArgProver<B>, ArgVerifier<B>),
        columns: &[Vec<F>],
        summed: &[&[usize]],
        relations: &[Sides],
    ) -> Self {
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

    /// Mirrors the statement and the reduction of `proof` on a copy of the
    /// verifier, so that several proofs can be put to the same statement.
    /// Returns the copy as the reduction left it.
    fn verify_reduction(&self, proof: &SNARKProof<B>) -> SnarkResult<ArgVerifier<B>> {
        let mut verifier = self.verifier.fork();
        verifier.set_proof_ref(proof);
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
        verify_keyed_sums(&mut verifier, &self.relations)?;
        Ok(verifier)
    }

    fn verify(&self, proof: &SNARKProof<B>) -> Result<(), Rejected> {
        let verifier = self.verify_reduction(proof).map_err(Rejected::Reduction)?;
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

// ─── Runs of bounded size ────────────────────────────────────────────────

/// What the run budget counts for an instance: 3 field elements per
/// fraction when the numerators are 1, 4 otherwise.
fn weighted_sizes(plan: &[InstancePlan<F>]) -> Vec<usize> {
    plan.iter()
        .map(|instance| (if instance.mults.is_none() { 3 } else { 4 }) << instance.n_vars())
        .collect()
}

/// How many instances each GKR subproof of `proof` covers.
fn run_lengths(proof: &SNARKProof<B>) -> Vec<usize> {
    proof
        .logup_gkr_subproofs
        .iter()
        .map(|subproof| subproof.roots.len())
        .collect()
}

fn assert_rejected_in_the_reduction(res: Result<(), Rejected>) {
    match res {
        Err(Rejected::Reduction(err)) => assert_verifier_error(err),
        other => panic!("expected the reduction to fail, got {other:?}"),
    }
}

/// The columns of [`mixed_relations`], whose keyed sums all hold.
struct MixedColumns {
    table: Vec<F>,
    a: Vec<F>,
    b: Vec<F>,
    c: Vec<F>,
    c_weights: Vec<F>,
    d: Vec<F>,
    p: Vec<F>,
    q: Vec<F>,
}

impl MixedColumns {
    fn new() -> Self {
        Self {
            table: fv(0..16),
            a: in_table(3, 16, 1),
            b: in_table(5, 16, 2),
            c: in_table(3, 16, 3),
            c_weights: fv((0..8).map(|i| 2 * i + 1)),
            d: in_table(2, 16, 4),
            p: fv((0..32).map(|i| i + 100)),
            q: fv((0..32).map(|i| (i * 13 + 5) % 32 + 100)),
        }
    }

    /// Three relations of mixed sizes and kinds: `a`, `b` and the weighted
    /// `c` looked up in the table, `d` looked up in the table, and `q` a
    /// permutation of `p`. `counts_abc` and `counts_d` are what the table
    /// side of the first two counts.
    ///
    /// Their instances, in order, with their weighted sizes: `a` 24, `b`
    /// 96, `c` 32, the table 64, `d` 12, the table 64, `p` 96, `q` 96.
    fn session(&self, budgets: (usize, usize), counts_abc: &[F], counts_d: &[F]) -> Session {
        let columns = [
            self.table.clone(),
            counts_abc.to_vec(),
            self.a.clone(),
            self.b.clone(),
            self.c.clone(),
            self.c_weights.clone(),
            counts_d.to_vec(),
            self.d.clone(),
            self.p.clone(),
            self.q.clone(),
        ];
        let relations = [
            (vec![(2, None), (3, None), (4, Some(5))], vec![(0, Some(1))]),
            (vec![(7, None)], vec![(0, Some(6))]),
            (vec![(8, None)], vec![(9, None)]),
        ];
        Session::with_budgets(budgets, &columns, &relations)
    }

    fn counts_abc(&self) -> Vec<F> {
        let entries: [(&[F], Option<&[F]>); 3] = [
            (&self.a, None),
            (&self.b, None),
            (&self.c, Some(&self.c_weights)),
        ];
        tally(&self.table, &entries)
    }

    fn counts_d(&self) -> Vec<F> {
        tally(&self.table, &[(&self.d, None)])
    }

    /// The session of an honest prover on these columns.
    fn honest(&self, budgets: (usize, usize)) -> Session {
        self.session(budgets, &self.counts_abc(), &self.counts_d())
    }
}

/// A batch above the budget is proved in several GKR runs, each a subproof
/// with a point of its own: instances fill a run in order until the next
/// one would not fit. The relations are still compared as wholes, and every
/// run's claims are tied to the columns.
#[test]
fn gkr_batch_split_small_budget() {
    let columns = MixedColumns::new();
    let unsplit = SharedArgConfig::default().logup_gkr_run_budget;

    let mut session = columns.honest((100, 100));
    assert_eq!(
        weighted_sizes(&session.plan()),
        [24, 96, 32, 64, 12, 64, 96, 96]
    );
    session.prove_with(ColumnEvals::new()).unwrap();
    let after_reduction = ArgProver::new_from_tracker(session.prover.tracker().borrow().clone());
    let proof = session.prover.build_proof().unwrap();
    // `c` and the first table fill a run exactly; `d` shares one with the
    // second table.
    assert_eq!(run_lengths(&proof), [1, 1, 2, 2, 1, 1]);
    let verifier = session.verify_reduction(&proof).unwrap();
    assert_in_sync(&after_reduction, &verifier);
    verifier.verify().unwrap();

    // One element less and `c` no longer fits beside its table, which then
    // takes `d` in.
    for (budget, runs) in [
        (unsplit, vec![8]),
        (96, vec![1, 1, 2, 2, 1, 1]),
        (95, vec![1, 1, 1, 2, 1, 1, 1]),
    ] {
        let mut session = columns.honest((budget, budget));
        session.prove_with(ColumnEvals::new()).unwrap();
        let proof = session.prover.build_proof().unwrap();
        assert_eq!(run_lengths(&proof), runs);
        session.verify(&proof).unwrap();
    }

    // A value outside the table in the first run, whose relation is closed
    // by the table two runs later.
    let mut bad = MixedColumns::new();
    bad.a[5] = F::from(16u64);
    let session = bad.session((100, 100), &columns.counts_abc(), &columns.counts_d());
    assert_rejected_in_the_reduction(session.prove_and_verify());

    // A miscounted table in the run it shares with `d`.
    let mut counts_d = columns.counts_d();
    counts_d[3] += F::one();
    let session = columns.session((100, 100), &columns.counts_abc(), &counts_d);
    assert_rejected_in_the_reduction(session.prove_and_verify());

    // The last instance of the last run is not a permutation of `p`, which
    // sits in the run before.
    let mut bad = MixedColumns::new();
    bad.q[31] = bad.q[30];
    assert_rejected_in_the_reduction(bad.honest((100, 100)).prove_and_verify());
}

/// The input claims of every run are pushed, each at its run's point. A
/// committed column is not what the table counts and the prover runs the
/// GKR on one that is: a column alone in the first run, and a column and a
/// multiplicity of the fourth.
#[test]
fn gkr_on_fake_leaves_in_any_run_is_rejected() {
    let columns = MixedColumns::new();
    for column in [2, 7, 6] {
        let mut committed = MixedColumns::new();
        let mut counts_d = columns.counts_d();
        let fake = match column {
            2 => {
                committed.a[1] = F::from(16u64);
                columns.a.clone()
            }
            7 => {
                committed.d[1] = F::from(16u64);
                columns.d.clone()
            }
            _ => {
                counts_d[3] += F::one();
                columns.counts_d()
            }
        };
        let session = committed.session((100, 100), &columns.counts_abc(), &counts_d);
        let evals = BTreeMap::from([(session.ids[column], fake)]);
        assert_stopped_by_the_input_claims(session, |session| session.prove_with(evals));
    }
}

/// Two relations, each false and each side a run of its own, whose errors
/// cancel over the batch.
#[test]
fn relations_whose_errors_cancel_across_runs_are_rejected() {
    let columns = [fv(0..32), fv((0..32).map(|i| i + 100))];
    let entry = |column: usize| vec![(column, None)];
    let budgets = (100, 100);

    let together = (vec![(0, None), (1, None)], vec![(1, None), (0, None)]);
    let mut session = Session::with_budgets(budgets, &columns, &[together]);
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    assert_eq!(run_lengths(&proof), [1, 1]);
    session.verify(&proof).unwrap();

    let apart = [(entry(0), entry(1)), (entry(1), entry(0))];
    let mut session = Session::with_budgets(budgets, &columns, &apart);
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    assert_eq!(run_lengths(&proof), [1, 1, 1, 1]);
    assert_rejected_in_the_reduction(session.verify(&proof));
}

/// An instance above the budget is proved in a run of its own, between the
/// runs its neighbours are packed into, down to a budget nothing fits in.
#[test]
fn gkr_single_instance_over_budget() {
    let table = fv(0..8);
    let small = fv([3, 1, 4, 1]);
    let small_permuted = fv([1, 1, 3, 4]);
    let session = |budget: usize, big: &[F]| {
        let columns = [
            small.clone(),
            small_permuted.clone(),
            big.to_vec(),
            table.clone(),
            tally(&table, &[(&in_table(5, 8, 1), None)]),
        ];
        let relations = [
            (vec![(0, None)], vec![(1, None)]),
            (vec![(2, None)], vec![(3, Some(4))]),
            (vec![(1, None)], vec![(0, None)]),
        ];
        Session::with_budgets((budget, budget), &columns, &relations)
    };
    let big = in_table(5, 8, 1);
    let mut outside = big.clone();
    outside[17] = F::from(8u64);

    assert_eq!(
        weighted_sizes(&session(40, &big).plan()),
        [12, 12, 96, 32, 12, 12]
    );
    for (budget, runs) in [
        (40, vec![2, 1, 1, 2]),
        // The table's run has room for one more instance, which parts the
        // two sides of the last relation.
        (44, vec![2, 1, 2, 1]),
        (95, vec![2, 1, 3]),
        // Every instance is above the budget.
        (11, vec![1; 6]),
        (0, vec![1; 6]),
        (usize::MAX, vec![6]),
    ] {
        let mut honest = session(budget, &big);
        honest.prove_with(ColumnEvals::new()).unwrap();
        let after_reduction = ArgProver::new_from_tracker(honest.prover.tracker().borrow().clone());
        let proof = honest.prover.build_proof().unwrap();
        assert_eq!(run_lengths(&proof), runs, "budget {budget}");
        let verifier = honest.verify_reduction(&proof).unwrap();
        assert_in_sync(&after_reduction, &verifier);
        verifier.verify().unwrap();

        assert_rejected_in_the_reduction(session(budget, &outside).prove_and_verify());
    }
}

/// The cut into runs is part of the statement the verifier checks: a proof
/// cut by another budget than the verifier's is rejected at the first run
/// that differs, whichever side has the finer cut. Budgets that give the
/// same cut are the same statement.
#[test]
fn gkr_budget_mismatch_between_prover_and_verifier_is_rejected() {
    let columns = MixedColumns::new();
    let unsplit = SharedArgConfig::default().logup_gkr_run_budget;
    let run = |budgets: (usize, usize)| {
        let mut session = columns.honest(budgets);
        session.prove_with(ColumnEvals::new()).unwrap();
        let proof = session.prover.build_proof().unwrap();
        session.verify(&proof)
    };

    for budgets in [
        (100, unsplit),
        (unsplit, 100),
        // The first two runs are the same on both sides.
        (100, 95),
        (95, 100),
        (0, 100),
        (100, 0),
    ] {
        assert_rejected_in_the_reduction(run(budgets));
    }
    run((100, 96)).unwrap();
    run((unsplit, usize::MAX)).unwrap();
}

/// The budget cuts the batch the lookup claims and the deferred keyed sums
/// are reduced in like any other: a stack of two sub columns, a wider sub
/// column, the table, and the two sides of a permutation, with weighted
/// sizes 48, 96, 64, 96 and 96.
#[test]
fn lookups_and_deferred_keyed_sums_are_reduced_in_runs_under_a_small_budget() {
    let table = fv(0..16);
    let subs = [in_table(3, 16, 1), in_table(3, 16, 2), in_table(5, 16, 3)];
    let p = fv((0..32).map(|i| i + 100));
    let q = fv((0..32).map(|i| (i * 13 + 5) % 32 + 100));

    let run = |budget: usize, subs: &[Vec<F>; 3], q: &[F]| -> SnarkResult<Vec<usize>> {
        let (mut prover, mut verifier) = setup_with_budgets(budget, budget);
        let mut columns = vec![&table[..]];
        columns.extend(subs.iter().map(|sub| &sub[..]));
        columns.extend([&p[..], q]);
        let handles: Vec<TrackedPoly<B>> =
            columns.iter().map(|col| commit(&mut prover, col)).collect();
        for sub in &handles[1..4] {
            prover.add_mv_lookup_claim(handles[0].id(), sub.id())?;
        }
        prover.add_mv_keyed_sum_claim(KeyedSumcheckProverInput {
            fxs: vec![handles[4].clone()],
            gxs: vec![handles[5].clone()],
            mfxs: vec![None],
            mgxs: vec![None],
        })?;
        let mut reduced = ArgProver::new_from_tracker(prover.tracker().borrow().clone());
        reduced.reduce_lookup_claims()?;
        let proof = prover.build_proof()?;

        verifier.set_proof_ref(&proof);
        let oracles = handles
            .iter()
            .map(|handle| verifier.track_mv_com_by_id(handle.id()))
            .collect::<SnarkResult<Vec<_>>>()?;
        for sub in &oracles[1..4] {
            verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())?;
        }
        verifier.add_mv_keyed_sum_claim(KeyedSumcheckVerifierInput {
            fxs: vec![oracles[4].clone()],
            gxs: vec![oracles[5].clone()],
            mfxs: vec![None],
            mgxs: vec![None],
        })?;
        verifier.reduce_lookup_claims()?;
        assert_in_sync(&reduced, &verifier);
        verifier.verify()?;
        Ok(run_lengths(&proof))
    };

    let unsplit = SharedArgConfig::default().logup_gkr_run_budget;
    for (budget, runs) in [
        (unsplit, vec![5]),
        // The table fits beside one side of the permutation, exactly.
        (160, vec![2, 2, 1]),
        (150, vec![2, 1, 1, 1]),
        (0, vec![1; 5]),
    ] {
        assert_eq!(run(budget, &subs, &q).unwrap(), runs, "budget {budget}");

        // A value outside the table in the stack and in the wide column,
        // whose table is one or two runs away, and a `q` that repeats a row.
        for bad_sub in [1, 2] {
            let mut subs = subs.clone();
            subs[bad_sub][5] = F::from(16u64);
            assert_false_statement_rejected(run(budget, &subs, &q));
        }
        let mut bad_q = q.clone();
        bad_q[31] = bad_q[30];
        assert_false_statement_rejected(run(budget, &subs, &bad_q));
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

// ─── Parity ──────────────────────────────────────────────────────────────

/// Lookups into three tables, two of them with several sub columns of
/// mixed sizes, interleaved with ordinary claims and with keyed sums proved
/// on the spot. After each side has reduced its lookup claims, and before
/// either compiles anything, both hold the same ids, claims and transcript.
#[test]
fn both_sides_are_in_step_after_reducing_their_lookup_claims() {
    let table_a = fv(0..16);
    let table_b = fv((0..8).map(|i| i * 9));
    let subs_a: Vec<Vec<F>> = vec![
        in_table(4, 16, 1),
        in_table(6, 16, 2),
        in_table(4, 16, 3),
        in_table(2, 16, 4),
        in_table(4, 16, 5),
    ];
    let subs_b: Vec<Vec<F>> = vec![
        fv((0..8).map(|i| ((i * 3) % 8) * 9)),
        fv((0..8).map(|i| ((i * 5) % 8) * 9)),
    ];
    let data_c = fv((0..32).map(|i| if i < 25 { i } else { 900 + i }));
    let act_c = fv((0..32).map(|i| u64::from(i < 25)));
    let summed = fv((0..16).map(|i| i * i));
    let perm_f = fv(0..32);
    let perm_g = fv((0..32).map(|i| (i * 13 + 5) % 32));
    let weighted_f = fv((0..8).map(|i| i + 100));
    let weights = fv(1..9);

    let (mut prover, mut verifier) = setup();
    let mut committed = Vec::new();
    let mut commit_all = |prover: &mut ArgProver<B>, cols: &[&Vec<F>]| -> Vec<TrackedPoly<B>> {
        let handles: Vec<_> = cols.iter().map(|col| commit(prover, col)).collect();
        committed.extend(handles.iter().map(TrackedPoly::id));
        handles
    };
    let cols: Vec<&Vec<F>> = [&table_a, &table_b, &data_c, &act_c, &summed]
        .into_iter()
        .chain(&subs_a)
        .chain(&subs_b)
        .chain([&perm_f, &perm_g, &weighted_f, &weights])
        .collect();
    let handles = commit_all(&mut prover, &cols);
    let (table_a_p, table_b_p, data_p, act_p, summed_p) = (
        &handles[0],
        &handles[1],
        &handles[2],
        &handles[3],
        &handles[4],
    );
    let (subs_a_p, subs_b_p, rest_p) = (&handles[5..10], &handles[10..12], &handles[12..]);
    let table_c_p = prover.track_mat_mv_poly(mle(&fv(0..32)));
    let sub_c_p = data_p * act_p;

    prover
        .add_mv_sumcheck_claim(summed_p.id(), sum(&summed))
        .unwrap();
    for sub in &subs_a_p[..3] {
        prover
            .add_mv_lookup_claim(table_a_p.id(), sub.id())
            .unwrap();
    }
    KeyedSumcheck::<B>::prove(
        &mut prover,
        KeyedSumcheckProverInput {
            fxs: vec![rest_p[0].clone()],
            gxs: vec![rest_p[1].clone()],
            mfxs: vec![None],
            mgxs: vec![None],
        },
    )
    .unwrap();
    let after_first_piop = ArgProver::new_from_tracker(prover.tracker().borrow().clone());
    for sub in subs_b_p {
        prover
            .add_mv_lookup_claim(table_b_p.id(), sub.id())
            .unwrap();
    }
    prover
        .add_mv_lookup_claim(table_c_p.id(), sub_c_p.id())
        .unwrap();
    for sub in &subs_a_p[3..] {
        prover
            .add_mv_lookup_claim(table_a_p.id(), sub.id())
            .unwrap();
    }
    KeyedSumcheck::<B>::prove(
        &mut prover,
        KeyedSumcheckProverInput {
            fxs: vec![rest_p[2].clone()],
            gxs: vec![rest_p[2].clone()],
            mfxs: vec![Some(rest_p[3].clone())],
            mgxs: vec![Some(rest_p[3].clone())],
        },
    )
    .unwrap();
    let after_second_piop = ArgProver::new_from_tracker(prover.tracker().borrow().clone());

    // The proof comes from a copy, so that the prover itself stops right
    // after its reduction.
    let proof = ArgProver::new_from_tracker(prover.tracker().borrow().clone())
        .build_proof()
        .unwrap();
    prover.reduce_lookup_claims().unwrap();
    // Three tables: one batch, with the sub columns of each in stacks.
    assert_eq!(proof.logup_gkr_subproofs.len(), 3);
    assert_eq!(proof.logup_gkr_subproofs[2].roots.len(), 5 + 2 + 2);

    verifier.set_proof_ref(&proof);
    let oracles: Vec<TrackedOracle<B>> = committed
        .iter()
        .map(|id| verifier.track_mv_com_by_id(*id).unwrap())
        .collect();
    let (table_a_v, table_b_v, data_v, act_v, summed_v) = (
        &oracles[0],
        &oracles[1],
        &oracles[2],
        &oracles[3],
        &oracles[4],
    );
    let (subs_a_v, subs_b_v, rest_v) = (&oracles[5..10], &oracles[10..12], &oracles[12..]);
    let table_c = mle(&fv(0..32));
    let table_c_v = verifier
        .track_base_oracle(Oracle::new_multivariate(5, move |point: Vec<F>| {
            Ok(table_c.evaluate(&point[..5].to_vec()))
        }));
    let sub_c_v = data_v * act_v;

    verifier.add_mv_sumcheck_claim(summed_v.id(), sum(&summed));
    for sub in &subs_a_v[..3] {
        verifier
            .add_mv_lookup_claim(table_a_v.id(), sub.id())
            .unwrap();
    }
    KeyedSumcheck::<B>::verify(
        &mut verifier,
        KeyedSumcheckVerifierInput {
            fxs: vec![rest_v[0].clone()],
            gxs: vec![rest_v[1].clone()],
            mfxs: vec![None],
            mgxs: vec![None],
        },
    )
    .unwrap();
    assert_in_sync(&after_first_piop, &verifier);
    for sub in subs_b_v {
        verifier
            .add_mv_lookup_claim(table_b_v.id(), sub.id())
            .unwrap();
    }
    verifier
        .add_mv_lookup_claim(table_c_v.id(), sub_c_v.id())
        .unwrap();
    for sub in &subs_a_v[3..] {
        verifier
            .add_mv_lookup_claim(table_a_v.id(), sub.id())
            .unwrap();
    }
    KeyedSumcheck::<B>::verify(
        &mut verifier,
        KeyedSumcheckVerifierInput {
            fxs: vec![rest_v[2].clone()],
            gxs: vec![rest_v[2].clone()],
            mfxs: vec![Some(rest_v[3].clone())],
            mgxs: vec![Some(rest_v[3].clone())],
        },
    )
    .unwrap();
    assert_in_sync(&after_second_piop, &verifier);

    verifier.reduce_lookup_claims().unwrap();
    assert_in_sync(&prover, &verifier);
    verifier.verify().unwrap();
}

/// Keyed sums claimed for later, between lookup claims. Claiming them moves
/// neither side; the reduction then takes them after the lookup groups, in
/// the order they were claimed, and leaves both sides with the same ids,
/// claims and transcript.
#[test]
fn both_sides_are_in_step_after_reducing_their_deferred_keyed_sums() {
    let table = fv(0..16);
    let subs = [in_table(4, 16, 1), in_table(6, 16, 2)];
    let perm_f = fv(0..32);
    let perm_g = fv((0..32).map(|i| (i * 13 + 5) % 32));
    let keys = fv((0..8).map(|i| i + 100));
    let weights = fv(1..9);

    let (mut prover, mut verifier) = setup();
    let cols = [
        &table, &subs[0], &subs[1], &perm_f, &perm_g, &keys, &weights,
    ];
    let handles: Vec<TrackedPoly<B>> = cols.iter().map(|col| commit(&mut prover, col)).collect();
    let ids: Vec<TrackerID> = handles.iter().map(TrackedPoly::id).collect();
    let permutation = |h: &[TrackedPoly<B>]| KeyedSumcheckProverInput {
        fxs: vec![h[3].clone()],
        gxs: vec![h[4].clone()],
        mfxs: vec![None],
        mgxs: vec![None],
    };
    let weighted = |h: &[TrackedPoly<B>]| KeyedSumcheckProverInput {
        fxs: vec![h[5].clone()],
        gxs: vec![h[5].clone()],
        mfxs: vec![Some(h[6].clone())],
        mgxs: vec![Some(h[6].clone())],
    };

    let before_claims = ArgProver::new_from_tracker(prover.tracker().borrow().clone());
    prover
        .add_mv_keyed_sum_claim(permutation(&handles))
        .unwrap();
    prover.add_mv_lookup_claim(ids[0], ids[1]).unwrap();
    prover.add_mv_keyed_sum_claim(weighted(&handles)).unwrap();
    prover.add_mv_lookup_claim(ids[0], ids[2]).unwrap();
    let after_claims = ArgProver::new_from_tracker(prover.tracker().borrow().clone());

    let proof = ArgProver::new_from_tracker(prover.tracker().borrow().clone())
        .build_proof()
        .unwrap();
    prover.reduce_lookup_claims().unwrap();
    assert_eq!(run_lengths(&proof), [3 + 2 + 2]);
    // The last masks come in instance order, two values where the
    // numerators are 1 and four otherwise: the two subs and their table,
    // then the permutation, then the weighted keys.
    let last_masks: Vec<usize> = proof.logup_gkr_subproofs[0]
        .masks
        .last()
        .unwrap()
        .iter()
        .map(Vec::len)
        .collect();
    assert_eq!(last_masks, [2, 2, 4, 2, 2, 4, 4]);

    verifier.set_proof_ref(&proof);
    let oracles: Vec<TrackedOracle<B>> = ids
        .iter()
        .map(|id| verifier.track_mv_com_by_id(*id).unwrap())
        .collect();
    assert_in_sync(&before_claims, &verifier);
    verifier
        .add_mv_keyed_sum_claim(KeyedSumcheckVerifierInput {
            fxs: vec![oracles[3].clone()],
            gxs: vec![oracles[4].clone()],
            mfxs: vec![None],
            mgxs: vec![None],
        })
        .unwrap();
    verifier.add_mv_lookup_claim(ids[0], ids[1]).unwrap();
    verifier
        .add_mv_keyed_sum_claim(KeyedSumcheckVerifierInput {
            fxs: vec![oracles[5].clone()],
            gxs: vec![oracles[5].clone()],
            mfxs: vec![Some(oracles[6].clone())],
            mgxs: vec![Some(oracles[6].clone())],
        })
        .unwrap();
    verifier.add_mv_lookup_claim(ids[0], ids[2]).unwrap();
    assert_in_sync(&after_claims, &verifier);

    verifier.reduce_lookup_claims().unwrap();
    assert_in_sync(&prover, &verifier);
    verifier.verify().unwrap();
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

// ─── Claims of every kind of instance ────────────────────────────────────

/// Weighted columns of one size share a stacked instance: one claim on the
/// weighted sum of their columns and one on that of their multiplicities.
/// A committed column or weight is off in either entry of the stack and the
/// prover runs the GKR on what the table counts.
#[test]
fn gkr_on_fake_leaves_of_a_stacked_weighted_instance_is_rejected() {
    let table = fv(0..8);
    // Columns 2 and 4 with the weights 3 and 5.
    let entries = [
        in_table(3, 8, 1),
        fv(1..9),
        in_table(3, 8, 2),
        fv((0..8).map(|i| 3 * i + 2)),
    ];
    let counts = tally(
        &table,
        &[
            (&entries[0], Some(&entries[1])),
            (&entries[2], Some(&entries[3])),
        ],
    );
    let session = |entries: &[Vec<F>; 4]| {
        let mut columns = vec![table.clone(), counts.clone()];
        columns.extend_from_slice(entries);
        let f = vec![(2, Some(3)), (4, Some(5))];
        Session::new(&columns, &[], &[(f, vec![(0, Some(1))])])
    };
    let honest = session(&entries);
    let stacked = &honest.plan()[0];
    assert_eq!((stacked.claim_nv, stacked.stack_log), (3, 1));
    assert!(stacked.mults.is_some());
    honest.prove_and_verify().unwrap();

    for fake_at in 0..4 {
        let mut committed = entries.clone();
        committed[fake_at][5] += F::from(8u64);
        let cheater = session(&committed);
        let evals = BTreeMap::from([(cheater.ids[2 + fake_at], entries[fake_at].clone())]);
        assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
    }
}

/// The table side is claimed like any other: the committed table lacks a
/// value of the sub column and the prover runs the GKR on a table that has
/// it, with the committed multiplicities counting that one.
#[test]
fn gkr_on_a_fake_table_with_true_column_claim_is_rejected() {
    let table = fv(0..8);
    let mut sub = in_table(3, 8, 1);
    sub[4] = F::from(9u64);
    let mut fake_table = table.clone();
    fake_table[0] = F::from(9u64);

    let columns = [table, tally(&fake_table, &[(&sub, None)]), sub];
    let session = Session::new(&columns, &[], &[(vec![(2, None)], vec![(0, Some(1))])]);
    let evals = BTreeMap::from([(session.ids[0], fake_table)]);
    assert_stopped_by_the_input_claims(session, |session| session.prove_with(evals));
}

/// A unit-numerator instance without variables has its root denominator as
/// its only claim: the committed key is 6, the table counts 7 and the GKR
/// runs on 7.
#[test]
fn tampered_root_of_an_nv0_unit_instance_is_rejected() {
    let table = fv(0..8);
    let session = |key: u64| {
        let columns = [table.clone(), tally(&table, &[(&fv([7]), None)]), fv([key])];
        Session::new(&columns, &[], &[(vec![(2, None)], vec![(0, Some(1))])])
    };
    let honest = session(7);
    assert_eq!(honest.plan()[0].n_vars(), 0);
    assert!(honest.plan()[0].mults.is_none());
    honest.prove_and_verify().unwrap();

    let cheater = session(6);
    let evals = BTreeMap::from([(cheater.ids[2], fv([7]))]);
    assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
}

/// An entry with one constant operand still has a claim on the other one:
/// a constant column with committed weights that are off, and a committed
/// column that leaves the table under a constant weight. The prover runs
/// the GKR on what the table counts.
#[test]
fn gkr_on_fake_leaves_beside_a_constant_operand_is_rejected() {
    let table = fv(0..16);
    let keys = in_table(3, 16, 1);
    let weights = fv(1..9);
    let counts = tally(
        &table,
        &[(&fv([7; 8]), Some(&weights)), (&keys, Some(&fv([4; 8])))],
    );
    let session = |keys: &[F], weights: &[F]| {
        let columns = [
            table.clone(),
            counts.clone(),
            keys.to_vec(),
            weights.to_vec(),
        ];
        let mut session = Session::new(&columns, &[], &[]);
        let constant = |v: u64| KeyedTerm::Constant {
            value: F::from(v),
            nv: 3,
        };
        session.relations = vec![KeyedSumRelation {
            fxs: vec![constant(7), KeyedTerm::Poly(session.ids[2])],
            mfxs: vec![Some(KeyedTerm::Poly(session.ids[3])), Some(constant(4))],
            gxs: vec![KeyedTerm::Poly(session.ids[0])],
            mgxs: vec![Some(KeyedTerm::Poly(session.ids[1]))],
        }];
        session
    };
    session(&keys, &weights).prove_and_verify().unwrap();

    let mut bad_weights = weights.clone();
    bad_weights[2] += F::one();
    let cheater = session(&keys, &bad_weights);
    let evals = BTreeMap::from([(cheater.ids[3], weights.clone())]);
    assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));

    let mut bad_keys = keys.clone();
    bad_keys[2] = F::from(16u64);
    let cheater = session(&bad_keys, &weights);
    let evals = BTreeMap::from([(cheater.ids[2], keys.clone())]);
    assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
}

/// An input claim is a sum over the hypercube the tracker holds for the
/// claimed polynomial. Were the instance narrower than its column, the
/// claim would bind another statement than the one the GKR ran on, so the
/// schedule refuses it.
#[test]
fn input_claim_on_a_polynomial_of_another_size_than_its_instance_is_refused() {
    use super::reduction::{VerifyingParty, push_input_claims};

    let (mut prover, verifier) = setup();
    let column = commit(&mut prover, &in_table(3, 8, 1)).id();
    let proof = prover.build_proof().unwrap();
    let instance = |nv: usize| InstancePlan {
        relation: 0,
        side: Side::F,
        claim_nv: nv,
        stack_log: 0,
        cols: Operand::Polys {
            ids: vec![column],
            nv,
        },
        mults: None,
    };
    let claims = |nv: usize| GkrClaims {
        point: fv(2..2 + nv as u64),
        roots: vec![[F::one(), F::one()]],
        inputs: vec![[F::one(), F::from(5u64)]],
    };
    let push = |nv: usize| {
        let mut verifier = verifier.fork();
        verifier.set_proof_ref(&proof);
        verifier.track_mv_com_by_id(column).unwrap();
        let tracker = verifier.tracker();
        let mut tracker = tracker.borrow_mut();
        let pushed = push_input_claims(
            &mut *tracker,
            &VerifyingParty,
            &[instance(nv)],
            F::from(7u64),
            &claims(nv),
        );
        pushed.map(|()| tracker.sumcheck_claims_snapshot().len())
    };
    // The column has three variables.
    assert_eq!(push(3).unwrap(), 1);
    assert_verifier_error(push(2).unwrap_err());
}

/// The multiplicities of a lookup are in the transcript before `gamma` is
/// drawn. A prover that sees `gamma` first balances any sub column against
/// the table with one field-valued multiplicity, and everything it then
/// proves about its commitments is true. This one is consistent with a
/// verifier that would draw `gamma` before absorbing the multiplicities.
#[test]
fn multiplicities_chosen_after_gamma_are_rejected() {
    use super::reduction::push_input_claims;
    use ark_ff::Field;

    let table = fv(0..8);
    // The lookup reduced by hand: the multiplicities committed before or
    // after `gamma`, then the one GKR run and its input claims.
    let run = |sub: &[F], gamma_first: bool| -> SnarkResult<()> {
        let (mut prover, mut verifier) = setup();
        let table_id = commit(&mut prover, &table).id();
        let sub_id = commit(&mut prover, sub).id();
        let (gamma, counts_id) = if gamma_first {
            let gamma = prover.get_and_append_challenge(b"gamma")?;
            let sub_side: F = sub.iter().map(|v| (*v - gamma).inverse().unwrap()).sum();
            let mut counts = vec![F::zero(); table.len()];
            counts[0] = sub_side * (table[0] - gamma);
            (gamma, commit(&mut prover, &counts).id())
        } else {
            let counts = commit(&mut prover, &tally(&table, &[(sub, None)])).id();
            (prover.get_and_append_challenge(b"gamma")?, counts)
        };
        let relation = KeyedSumRelation {
            fxs: vec![KeyedTerm::Poly(sub_id)],
            mfxs: vec![None],
            gxs: vec![KeyedTerm::Poly(table_id)],
            mgxs: vec![Some(KeyedTerm::Poly(counts_id))],
        };
        {
            let tracker = prover.tracker();
            let mut tracker = tracker.borrow_mut();
            let plan = plan_instances(&*tracker, &[relation]).unwrap();
            let mut party = ProvingParty {
                evals: ColumnEvals::new(),
            };
            let claims = party.run(&mut *tracker, &plan, 0..plan.len(), gamma)?;
            // The two sides balance under this `gamma`.
            let ([p_f, q_f], [p_g, q_g]) = (claims.roots[0], claims.roots[1]);
            assert_eq!(p_f * q_g, p_g * q_f);
            push_input_claims(&mut *tracker, &party, &plan, gamma, &claims)?;
        }
        let proof = prover.build_proof()?;

        verifier.set_proof_ref(&proof);
        verifier.track_mv_com_by_id(table_id)?;
        verifier.track_mv_com_by_id(sub_id)?;
        verifier.add_mv_lookup_claim(table_id, sub_id)?;
        verifier.verify()
    };

    let inside = in_table(3, 8, 1);
    let mut outside = inside.clone();
    outside[2] = F::from(100u64);
    assert_verifier_error(run(&outside, true).unwrap_err());
    // Done by hand in the verifier's order, the reduction is the real one.
    run(&inside, false).unwrap();
}

/// A stack counts towards the run budget with all its entries: four
/// columns of 8 rows are one instance of 32 fractions, which does not fit
/// in a run with its table.
#[test]
fn gkr_run_budget_counts_a_stack_at_its_full_height() {
    let table = fv(0..8);
    let subs: Vec<Vec<F>> = (0..4).map(|s| in_table(3, 8, s)).collect();
    let counted: Vec<(&[F], Option<&[F]>)> = subs.iter().map(|sub| (&sub[..], None)).collect();
    let mut columns = vec![table.clone(), tally(&table, &counted)];
    columns.extend(subs.iter().cloned());
    let f: Vec<Entry> = (2..6).map(|sub| (sub, None)).collect();
    let relations = [(f, vec![(0, Some(1))])];

    let mut session = Session::with_budgets((100, 100), &columns, &relations);
    assert_eq!(session.plan()[0].stack_log, 2);
    assert_eq!(weighted_sizes(&session.plan()), [96, 32]);
    session.prove_with(ColumnEvals::new()).unwrap();
    let after_reduction = ArgProver::new_from_tracker(session.prover.tracker().borrow().clone());
    let proof = session.prover.build_proof().unwrap();
    assert_eq!(run_lengths(&proof), [1, 1]);
    let verifier = session.verify_reduction(&proof).unwrap();
    assert_in_sync(&after_reduction, &verifier);
    verifier.verify().unwrap();
}

/// Three weighted columns of one size are a stack of two and a stack of
/// one; each stack takes its own multiplicities, the single one included.
#[test]
fn every_stack_of_a_weighted_group_takes_its_own_multiplicities() {
    let table = fv(0..16);
    let fs: Vec<KeyedCol> = (0..3)
        .map(|s| {
            let weights = fv((0..8).map(|i| 10 * s + i + 1));
            (in_table(3, 16, s), Some(weights))
        })
        .collect();
    let g = table_side(&table, &fs);
    let (plan, _) = keyed_e2e(&fs, &g).unwrap();
    assert_eq!(
        layout(&plan)[..2],
        [
            (Side::F, 3, 1, false, false, false),
            (Side::F, 3, 0, false, false, false),
        ]
    );
    for at in 0..3 {
        let mut fs = fs.clone();
        fs[at].1.as_mut().unwrap()[1] += F::one();
        assert_false_statement_rejected(keyed_e2e(&fs, &g));
    }
}

/// A constant multiplicity of 1 is still a multiplicity: its term runs over
/// the constant's rows when it has more than the column, and the instance
/// keeps numerators of its own.
#[test]
fn constant_one_multiplicity_wider_than_its_column_is_a_values_instance() {
    let table = fv(0..8);
    let col = fv([1, 3, 3, 6]);
    // Eight rows of weight 1 over a column of four: every row counts twice.
    let counts = tally(&table, &[(&col, Some(&fv([1; 8])))]);
    let columns = [table, counts, col];
    let mut session = Session::new(&columns, &[], &[]);
    session.relations = vec![KeyedSumRelation {
        fxs: vec![KeyedTerm::Poly(session.ids[2])],
        mfxs: vec![Some(KeyedTerm::Constant {
            value: F::one(),
            nv: 3,
        })],
        gxs: vec![KeyedTerm::Poly(session.ids[0])],
        mgxs: vec![Some(KeyedTerm::Poly(session.ids[1]))],
    }];
    let plan = session.plan();
    assert_eq!((plan[0].claim_nv, plan[0].stack_log), (3, 0));
    assert!(!plan[0].shape().numerator_is_one);
    session.prove_and_verify().unwrap();
}

/// An id neither side tracks is refused when the batch is laid out, before
/// any tracker call that would panic on it.
#[test]
fn keyed_sum_naming_an_untracked_polynomial_is_refused() {
    let columns = [fv(0..8), fv(0..8)];
    let session = Session::new(&columns, &[], &[(vec![(0, None)], vec![(1, None)])]);
    let unknown = KeyedTerm::Poly(TrackerID::from_usize(900));
    let relation = KeyedSumRelation {
        fxs: vec![unknown],
        mfxs: vec![None],
        gxs: vec![KeyedTerm::Poly(session.ids[1])],
        mgxs: vec![None],
    };
    assert!(plan_instances(&*session.prover.tracker().borrow(), &[relation]).is_err());
}

/// A weighted column that stands alone on the `f` side has a claim on the
/// column and one on the weights, each over its own rows: weights of the
/// column's size, a column narrower than its weights, and weights of a
/// single row. `(column rows, weight rows)`; the committed column or the
/// committed weights are off and the prover runs the GKR on what the table
/// counts.
#[test]
fn gkr_on_fake_leaves_of_a_weighted_entry_is_rejected() {
    let table = fv(0..8);
    for (col_rows, weight_rows) in [(8, 8), (4, 8), (8, 1)] {
        let col = fv((0..col_rows).map(|i| (i * 3 + 1) % 8));
        let weights = fv((0..weight_rows).map(|i| i + 2));
        let counts = tally(&table, &[(&col, Some(&weights))]);
        let session = |col: &[F], weights: &[F]| {
            let columns = [
                table.clone(),
                counts.clone(),
                col.to_vec(),
                weights.to_vec(),
            ];
            Session::new(&columns, &[], &[(vec![(2, Some(3))], vec![(0, Some(1))])])
        };
        session(&col, &weights).prove_and_verify().unwrap();

        let mut bad_col = col.clone();
        bad_col[0] += F::from(8u64);
        let cheater = session(&bad_col, &weights);
        let evals = BTreeMap::from([(cheater.ids[2], col.clone())]);
        assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));

        let mut bad_weights = weights.clone();
        bad_weights[0] += F::one();
        let cheater = session(&col, &bad_weights);
        let evals = BTreeMap::from([(cheater.ids[3], weights.clone())]);
        assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
    }
}

/// Lookup groups are reduced in the order their tables were first claimed
/// in, on both sides, also when a table committed later is claimed first.
#[test]
fn lookup_groups_are_reduced_in_the_order_of_their_first_claim() {
    let tables = [fv(0..8), fv((0..8).map(|i| i + 100))];
    let subs = [in_table(3, 8, 1), fv((0..16).map(|i| (i * 5) % 8 + 100))];
    let (mut prover, mut verifier) = setup();
    let ids = [&tables[0], &tables[1], &subs[0], &subs[1]].map(|col| commit(&mut prover, col).id());

    prover.add_mv_lookup_claim(ids[1], ids[3]).unwrap();
    prover.add_mv_lookup_claim(ids[0], ids[2]).unwrap();
    let proof = prover.build_proof().unwrap();

    verifier.set_proof_ref(&proof);
    for id in ids {
        verifier.track_mv_com_by_id(id).unwrap();
    }
    verifier.add_mv_lookup_claim(ids[1], ids[3]).unwrap();
    verifier.add_mv_lookup_claim(ids[0], ids[2]).unwrap();
    verifier.verify().unwrap();
    assert_in_sync(&prover, &verifier);
}

/// Both sides give the same id to the same polynomial, not only equally
/// many ids: later stages order products by the ids of their factors. The
/// `eq` polynomials of a run are the ids its claims do not reveal; with
/// columns of several sizes there is one per size, and each has its size on
/// both sides.
#[test]
fn both_sides_hold_polynomials_of_the_same_size_under_every_id() {
    let unsplit = SharedArgConfig::default().logup_gkr_run_budget;
    for budget in [unsplit, 100] {
        let mut session = MixedColumns::new().honest((budget, budget));
        session.prove_with(ColumnEvals::new()).unwrap();
        let after_reduction =
            ArgProver::new_from_tracker(session.prover.tracker().borrow().clone());
        let proof = session.prover.build_proof().unwrap();
        let verifier = session.verify_reduction(&proof).unwrap();
        // More than one size, or the order of the `eq`s would not show.
        let sizes: std::collections::BTreeSet<usize> = session
            .plan()
            .iter()
            .map(|instance| instance.claim_nv)
            .collect();
        assert!(sizes.len() > 2);
        assert_in_sync(&after_reduction, &verifier);
    }
}
