//! The keyed-sum reduction from inside the crate: provers that cheat while
//! staying consistent with the transcript, the layout of the GKR batch, and
//! the two sides staying in step.

use std::{collections::BTreeMap, sync::Arc};

use ark_ff::{One, Zero};
use ark_poly::Polynomial;
use ark_serialize::{CanonicalSerialize, Compress};
use indexmap::IndexMap;

use super::{
    KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput,
    reduction::{
        Batch, ColumnEvals, InstancePlan, KeyedSumRelation, KeyedTerm, Operand, Party,
        ProvingParty, Reduction, Side, check_batch_sums, plan_instances, prove_keyed_sums,
        reduce_keyed_sums, verify_keyed_sums,
    },
};
use crate::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::{
        PIOP,
        logup_gkr::{
            FractionInstance, GkrClaims, GkrShape, Numerator, proof_len,
            tests::{Deviation, Fault, naive_prove_batch},
        },
        lookup_check::multiplicities_by_sorting,
    },
    prover::{
        ArgProver,
        structs::{polynomial::TrackedPoly, proof::SNARKProof},
        tracker::ProverTracker,
    },
    setup::KeyGenerator,
    test_utils::prelude_with_vars,
    tracker_core::TrackerCore,
    types::{CommitmentBinding, SharedArgConfig, SumcheckSubproof, TrackerID, artifact::Artifact},
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
                batch: &Batch<F>,
                run: usize,
            ) -> SnarkResult<GkrClaims<F>> {
                let instances = self.honest.instances(tracker, batch, run)?;
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

    /// The instances of the batch as the GKR is told about them.
    fn shape(&self) -> Vec<GkrShape> {
        self.plan().iter().map(InstancePlan::shape).collect()
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

/// The masks of the input layers are the GKR's claims on them, and nothing
/// inside the GKR checks them. The prover moves one of them along a
/// direction that keeps its layer check true and carries on honestly from
/// there. A unit-numerator instance sends two values there, the others
/// four.
#[test]
fn tampered_last_mask_of_a_gkr_subproof_is_rejected() {
    let table = fv(0..8);
    // Three iterations, of 0, 1 and 2 rounds of two coefficients, and four
    // values per layer for the table. The sub column sends four per layer
    // but its last.
    for (sub_nv, messages) in [(3, 6 + 12 + 10), (2, 6 + 12 + 6)] {
        let sub = in_table(sub_nv, 8, 1);
        for instance in [0, 1] {
            let subs = std::slice::from_ref(&sub);
            let session = lookup_session(&table, subs, subs);
            let shape = session.shape();
            assert_eq!((shape[0].n_vars, shape[0].numerator_is_one), (sub_nv, true));
            assert_eq!((shape[1].n_vars, shape[1].numerator_is_one), (3, false));
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
                assert_eq!(proof.logup_gkr_subproofs[0].messages.len(), messages);
            }
        }
    }
}

/// The root of an instance is not sent: the verifier works it out from the
/// instance's first layer. For two fractions that layer is the input, and
/// a prover can send another pair of fractions with the same sum. The roots
/// then balance as they should, and the forged pair is the GKR's claim on
/// the input, which nothing inside the GKR checks.
#[test]
fn forged_first_layer_of_a_two_row_instance_is_rejected() {
    let table = fv(0..8);
    let keys = fv([5, 2]);
    // Without weights the instance has unit numerators and its first layer
    // is the two denominators; with weights it is two whole fractions.
    for weights in [None, Some(fv([3, 4]))] {
        let entries = [(&keys[..], weights.as_deref())];
        let mut columns = vec![table.clone(), tally(&table, &entries), keys.clone()];
        columns.extend(weights.clone());
        let f = vec![(2, weights.as_ref().map(|_| 3))];
        let session = || Session::new(&columns, &[], &[(f.clone(), vec![(0, Some(1))])]);
        let shape = session().shape();
        assert_eq!(
            (shape[0].n_vars, shape[0].numerator_is_one),
            (1, weights.is_none())
        );
        session().prove_and_verify().unwrap();

        // The instance joins in the last of the table's three iterations.
        let deviation = Deviation::Mask {
            iteration: 2,
            instance: 0,
            delta: F::from(5u64),
        };
        assert_stopped_by_the_input_claims(session(), |session| session.prove_deviating(deviation));
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
    // Four values on each of the three layers of both instances; without
    // numerators of its own the first would send two less.
    assert_eq!(proof.logup_gkr_subproofs[0].messages.len(), 6 + 12 + 12);
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
/// the lookups alone. For one lookup, and for two whose columns share their
/// instances.
#[test]
fn raw_claim_ignores_proof_map() {
    let table = fv(0..8);
    let sub = fv([1, 1, 2, 3, 5, 5, 5, 7]);
    let one_lookup = |wide_nv: usize| narrow_lookup_session(&table, &sub, &sub, wide_nv);
    let two_lookups = |wide_nv: usize| {
        let subs = two_lookup_subs();
        let mut columns = two_lookup_columns(&subs, &subs);
        columns.push(fv((0..1u64 << wide_nv).map(|i| i * i + 1)));
        columns.push(fv((0..1u64 << wide_nv).map(|i| 3 * i + 2)));
        Session::new(&columns, &[&[8, 9]], &two_lookup_relations(false))
    };
    let sessions: [&dyn Fn(usize) -> Session; 2] = [&one_lookup, &two_lookups];
    for (session, (wide_nv, buckets)) in sessions
        .into_iter()
        .flat_map(|session| [(session, (4, 1)), (session, (8, 2))])
    {
        let mut session = session(wide_nv);
        session.prove_with(ColumnEvals::new()).unwrap();
        let claims = session.prover.tracker().borrow().sumcheck_claims_snapshot();
        let raw: Vec<(TrackerID, F)> = claims
            .iter()
            .filter(|(_, _, raw)| *raw)
            .map(|(id, sum, _)| (*id, *sum))
            .collect();
        // The sub columns, the tables and the multiplicities, each kind in
        // one instance.
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

/// The sum of an instance's fractions, as one fraction.
fn root(instance: &FractionInstance<F>) -> [F; 2] {
    let mut sum = [F::zero(), F::one()];
    for (row, den) in instance.den.iter().enumerate() {
        let num = match &instance.num {
            Numerator::One => F::one(),
            Numerator::Values(values) => values[row],
        };
        sum = [sum[0] * den + num * sum[1], sum[1] * den];
    }
    sum
}

/// Whether the verifier's comparison of the two sides holds for `plan` when
/// the prover's instances are built under `gammas`, one per relation.
fn balances_under(session: &Session, plan: &[InstancePlan<F>], gammas: &[F]) -> bool {
    let batch = Batch {
        plan: plan.to_vec(),
        gammas: gammas.to_vec(),
        runs: vec![(0..plan.len()).collect()],
    };
    let mut party = ProvingParty {
        evals: ColumnEvals::new(),
    };
    let tracker = session.prover.tracker();
    let instances = party
        .instances(&mut tracker.borrow_mut(), &batch, 0)
        .unwrap();
    let reduction = Reduction {
        plan: batch.plan,
        roots: instances.iter().map(root).collect(),
    };
    check_batch_sums(&reduction).is_ok()
}

/// Two relations in one batch, each false, with errors that cancel: what
/// the first has on its `f` side and lacks on its `g` side, the second has
/// the other way round. Their entries share the instances of the batch and
/// the two sides are compared once, over all of them. What tells the
/// relations apart is that each has a `gamma` of its own: under one for
/// both, the two sides are the same sum.
#[test]
fn relations_whose_errors_cancel_over_the_batch_are_rejected() {
    let a = fv(0..8);
    let b = fv((0..8).map(|i| i + 100));
    let columns = [a, b];
    let entry = |column: usize| vec![(column, None)];
    let [gamma, other_gamma] = [F::from(1000u64), F::from(2000u64)];

    // As one relation the four columns balance.
    let together = [(vec![(0, None), (1, None)], vec![(1, None), (0, None)])];
    let mut merged = Session::new(&columns, &[&[0]], &together);
    let merged_plan = merged.plan();
    assert!(balances_under(&merged, &merged_plan, &[gamma]));
    merged.prove_with(ColumnEvals::new()).unwrap();
    let merged_proof = merged.prover.build_proof().unwrap();
    merged.verify(&merged_proof).unwrap();

    // As two relations they are laid out as before, column for column: all
    // that differs is the relation of every second entry.
    let apart = [(entry(0), entry(1)), (entry(1), entry(0))];
    let session = Session::new(&columns, &[&[0]], &apart);
    let plan = session.plan();
    assert_eq!(
        layout(&plan),
        [
            (Side::F, 3, 1, true, false, false),
            (Side::G, 3, 1, true, false, false),
        ]
    );
    for (instance, merged_instance) in plan.iter().zip(&merged_plan) {
        assert_eq!(instance.cols, merged_instance.cols);
        assert_eq!(instance.relations, [0, 1]);
        assert_eq!(merged_instance.relations, [0, 0]);
    }
    // So with one gamma for both relations the comparison would hold. With
    // one each it does not.
    assert!(balances_under(&session, &plan, &[gamma, gamma]));
    assert!(!balances_under(&session, &plan, &[gamma, other_gamma]));
    let apart_relations = session.relations.clone();
    assert_eq!(session.ids, merged.ids);
    assert_rejected_in_the_reduction(session.prove_and_verify());

    // Nor is the proof of the one relation a proof of the two: they have
    // the same instances and differ in their gammas alone.
    merged.relations = apart_relations;
    assert_rejected_in_the_reduction(merged.verify(&merged_proof));

    // A true relation does not vouch for a false one next to it.
    let mixed = [(entry(0), entry(0)), (entry(0), entry(1))];
    assert_rejected_in_the_reduction(Session::new(&columns, &[&[0]], &mixed).prove_and_verify());
}

// ─── Instances shared by relations ───────────────────────────────────────

/// Two sub columns of 8 rows for each of the tables `0..8` and `100..108`.
fn two_lookup_subs() -> [Vec<F>; 4] {
    let second = |seed| {
        in_table(3, 8, seed)
            .iter()
            .map(|v| *v + F::from(100u64))
            .collect()
    };
    [in_table(3, 8, 1), in_table(3, 8, 2), second(3), second(4)]
}

/// The columns of [`two_lookups`]: the first table and its multiplicities,
/// the second and its own, then `committed`. Each table counts whatever of
/// `counted` is in it, whichever table it is meant for.
fn two_lookup_columns(counted: &[Vec<F>; 4], committed: &[Vec<F>; 4]) -> Vec<Vec<F>> {
    let tables = [fv(0..8), fv((0..8).map(|i| i + 100))];
    let counted: Vec<(&[F], Option<&[F]>)> = counted.iter().map(|sub| (&sub[..], None)).collect();
    let mut columns = Vec::new();
    for table in tables {
        columns.push(table.clone());
        columns.push(tally(&table, &counted));
    }
    columns.extend_from_slice(committed);
    columns
}

/// The first two sub columns looked up in the first table and the last two
/// in the second: as two relations, or `merged` into one keyed sum of all
/// four against both tables.
fn two_lookup_relations(merged: bool) -> Vec<Sides> {
    let subs =
        |range: std::ops::Range<usize>| -> Vec<Entry> { range.map(|sub| (sub, None)).collect() };
    if merged {
        vec![(subs(4..8), vec![(0, Some(1)), (2, Some(3))])]
    } else {
        vec![
            (subs(4..6), vec![(0, Some(1))]),
            (subs(6..8), vec![(2, Some(3))]),
        ]
    }
}

fn two_lookups(columns: &[Vec<F>], merged: bool) -> Session {
    Session::new(columns, &[], &two_lookup_relations(merged))
}

/// The sub columns of two lookups share a stack, and so do the two tables.
/// A value outside its table is caught at every position of the stack. So
/// is a value of the other table, which that table counts: the two lookups
/// together balance then, and as one keyed sum they are a true statement,
/// laid out in the same instances.
#[test]
fn value_out_of_its_table_is_rejected_at_every_position_of_a_stack_of_two_relations() {
    let subs = two_lookup_subs();
    let [gamma, other_gamma] = [F::from(1000u64), F::from(2000u64)];
    let honest = two_lookups(&two_lookup_columns(&subs, &subs), false);
    let plan = honest.plan();
    assert_eq!(
        layout(&plan),
        [
            (Side::F, 3, 2, true, false, false),
            (Side::G, 3, 1, false, false, false),
        ]
    );
    assert_eq!(plan[0].relations, [0, 0, 1, 1]);
    assert_eq!(plan[1].relations, [0, 1]);
    assert!(balances_under(&honest, &plan, &[gamma, other_gamma]));
    honest.prove_and_verify().unwrap();

    for at in 0..4 {
        let mut neither = subs.clone();
        neither[at][5] = F::from(999u64);
        let columns = two_lookup_columns(&neither, &neither);
        assert_rejected_in_the_reduction(two_lookups(&columns, false).prove_and_verify());

        let mut other_table = subs.clone();
        other_table[at][5] = F::from(if at < 2 { 103u64 } else { 3 });
        let columns = two_lookup_columns(&other_table, &other_table);
        let merged = two_lookups(&columns, true);
        assert_eq!(layout(&merged.plan()), layout(&plan));
        merged.prove_and_verify().unwrap();
        let session = two_lookups(&columns, false);
        assert_eq!(session.plan(), plan);
        assert!(balances_under(&session, &plan, &[gamma, gamma]));
        assert!(!balances_under(&session, &plan, &[gamma, other_gamma]));
        assert_rejected_in_the_reduction(session.prove_and_verify());
    }
}

/// A stack of two relations has one claim on its columns, with the gammas
/// of its entries weighted as the columns are. A committed sub column is
/// out of its table at any position of the stack, or a committed
/// multiplicity of either table is off, and the prover runs the GKR on
/// columns that balance; or it bends the last mask of either stack.
#[test]
fn gkr_on_fake_leaves_of_a_stack_of_two_relations_is_rejected() {
    let subs = two_lookup_subs();
    for at in 0..4 {
        let mut committed = subs.clone();
        committed[at][5] = F::from(999u64);
        let cheater = two_lookups(&two_lookup_columns(&subs, &committed), false);
        let evals = BTreeMap::from([(cheater.ids[4 + at], subs[at].clone())]);
        assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
    }

    let honest = two_lookup_columns(&subs, &subs);
    for multiplicity in [1, 3] {
        let mut committed = honest.clone();
        committed[multiplicity][2] += F::one();
        let cheater = two_lookups(&committed, false);
        let evals = BTreeMap::from([(cheater.ids[multiplicity], honest[multiplicity].clone())]);
        assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
    }

    // Four sub columns of 8 rows have five layers, and the two tables join
    // in the second iteration.
    for instance in [0, 1] {
        let session = two_lookups(&honest, false);
        assert_eq!(session.shape(), gkr_shape(&[(5, true), (4, false)]));
        let deviation = Deviation::Mask {
            iteration: 4,
            instance,
            delta: F::from(5u64),
        };
        assert_stopped_by_the_input_claims(session, |session| session.prove_deviating(deviation));
    }
}

/// One-row columns of two relations make an instance of two rows, whose
/// first layer is its input, and a third one is left an instance without
/// variables, whose root is. Their claims are on polynomials without
/// variables, each with the gamma of its own relation. With and without
/// weights.
#[test]
fn one_row_entries_of_different_relations_are_claimed_with_their_own_gammas() {
    let table = fv(0..8);
    let (keys, weights) = ([5, 2, 7], [3, 4, 6]);
    for weighted in [false, true] {
        // Column 0 is the table, 1 to 3 what it counts for each relation, 4
        // to 6 are the keys and 7 to 9 their weights.
        let session = |keys: [u64; 3], counted: [u64; 3]| {
            let mut columns = vec![table.clone()];
            for (key, weight) in counted.iter().zip(weights) {
                let weight = fv([if weighted { weight } else { 1 }]);
                columns.push(tally(&table, &[(&fv([*key]), Some(&weight))]));
            }
            columns.extend(keys.map(|key| fv([key])));
            columns.extend(weights.map(|weight| fv([weight])));
            let relations: Vec<Sides> = (0..3)
                .map(|r| {
                    let f = vec![(4 + r, weighted.then_some(7 + r))];
                    (f, vec![(0, Some(1 + r))])
                })
                .collect();
            Session::new(&columns, &[], &relations)
        };
        let honest = session(keys, keys);
        let plan = honest.plan();
        assert_eq!(
            layout(&plan),
            [
                (Side::F, 0, 1, !weighted, false, false),
                (Side::F, 0, 0, !weighted, false, false),
                (Side::G, 3, 1, false, false, false),
                (Side::G, 3, 0, false, false, false),
            ]
        );
        assert_eq!(plan[0].relations, [0, 1]);
        assert_eq!(plan[1].relations, [2]);
        honest.prove_and_verify().unwrap();

        for at in 0..3 {
            // The committed key is not the one its table counts.
            let mut committed = keys;
            committed[at] = 6;
            assert_rejected_in_the_reduction(session(committed, keys).prove_and_verify());
            // The prover runs the GKR on the one it counts.
            let cheater = session(committed, keys);
            let evals = BTreeMap::from([(cheater.ids[4 + at], fv([keys[at]]))]);
            assert_stopped_by_the_input_claims(cheater, |session| session.prove_with(evals));
        }

        // Another pair of fractions with the same sum, sent as the first
        // layer of the two-row instance in the last of the four iterations
        // of the tables.
        let deviation = Deviation::Mask {
            iteration: 3,
            instance: 0,
            delta: F::from(5u64),
        };
        assert_stopped_by_the_input_claims(session(keys, keys), |session| {
            session.prove_deviating(deviation)
        });
        // The root of the instance without variables sent as an equal
        // fraction. A numerator that has to be 1 leaves no other.
        if weighted {
            let deviation = Deviation::ScaleRoot {
                instance: 1,
                scale: F::from(2u64),
            };
            assert_stopped_by_the_input_claims(session(keys, keys), |session| {
                session.prove_deviating(deviation)
            });
        }
    }
}

/// The comparison of the two sides is one of sums of fractions: the roots
/// of each side are added whatever their order, a zero denominator is
/// refused rather than multiplied through, and an empty batch balances.
#[test]
fn batch_sums_are_compared_as_fractions_and_refuse_a_zero_denominator() {
    let instance = |side: Side| InstancePlan::<F> {
        side,
        claim_nv: 0,
        stack_log: 0,
        relations: vec![0],
        cols: Operand::Constant(F::zero()),
        mults: None,
    };
    let check = |roots: &[(Side, [u64; 2])]| {
        check_batch_sums(&Reduction {
            plan: roots.iter().map(|(side, _)| instance(*side)).collect(),
            roots: roots
                .iter()
                .map(|(_, [p, q])| [F::from(*p), F::from(*q)])
                .collect(),
        })
    };
    use Side::{F as Left, G as Right};
    check(&[]).unwrap();
    // 1/2 + 1/3 = 5/6 = 2/6 + 3/6.
    check(&[(Left, [1, 2]), (Left, [1, 3]), (Right, [5, 6])]).unwrap();
    check(&[
        (Right, [2, 6]),
        (Left, [1, 2]),
        (Right, [3, 6]),
        (Left, [2, 6]),
    ])
    .unwrap();
    assert!(check(&[(Left, [1, 2]), (Left, [1, 3]), (Right, [5, 7])]).is_err());
    assert!(check(&[(Left, [1, 2]), (Left, [1, 3])]).is_err());
    assert!(check(&[(Right, [5, 6])]).is_err());
    // Cross-multiplied, a zero denominator would balance anything.
    assert!(check(&[(Left, [1, 0]), (Right, [5, 6])]).is_err());
    assert!(check(&[(Left, [5, 6]), (Right, [1, 0])]).is_err());
    assert!(check(&[(Left, [0, 0]), (Right, [0, 0])]).is_err());
}

// ─── Runs of bounded size ────────────────────────────────────────────────

/// What the run budget counts for an instance: 3 field elements per
/// fraction when the numerators are 1, 4 otherwise.
fn weighted_sizes(plan: &[InstancePlan<F>]) -> Vec<usize> {
    plan.iter()
        .map(|instance| (if instance.mults.is_none() { 3 } else { 4 }) << instance.n_vars())
        .collect()
}

/// The statement of a GKR batch from `(variables, numerators are one)` per
/// instance.
fn gkr_shape(batch: &[(usize, bool)]) -> Vec<GkrShape> {
    batch
        .iter()
        .map(|&(n_vars, numerator_is_one)| GkrShape {
            n_vars,
            numerator_is_one,
        })
        .collect()
}

/// Asserts that the GKR subproofs of `proof` are the runs `runs`, in order,
/// each given by the positions of its instances in the batch `shape`. A
/// subproof is its messages and nothing else, and how many it has follows
/// from the instances it covers.
fn assert_runs(proof: &SNARKProof<B>, shape: &[GkrShape], runs: &[Vec<usize>]) {
    let mut covered = runs.concat();
    covered.sort_unstable();
    let all: Vec<usize> = (0..shape.len()).collect();
    assert_eq!(covered, all, "every instance is in one run");
    let expected: Vec<Option<usize>> = runs
        .iter()
        .map(|run| {
            let run_shape: Vec<GkrShape> = run.iter().map(|index| shape[*index]).collect();
            proof_len(&run_shape)
        })
        .collect();
    let sent: Vec<Option<usize>> = proof
        .logup_gkr_subproofs
        .iter()
        .map(|subproof| Some(subproof.messages.len()))
        .collect();
    assert_eq!(sent, expected, "the subproofs are not the runs {runs:?}");
}

/// [`assert_runs`] for a batch proved in one run.
fn assert_one_run(proof: &SNARKProof<B>, shape: &[GkrShape]) {
    assert_runs(proof, shape, &[(0..shape.len()).collect()]);
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
    /// stacked with `p` 192, `c` 32, the table of the first relation stacked
    /// with that of the second 128, `d` 12, `q` 96.
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
/// with a point of its own: an instance joins the first run that has room
/// for it. The two sides are still compared over the whole batch, and every
/// run's claims are tied to the columns.
#[test]
fn gkr_batch_split_small_budget() {
    let columns = MixedColumns::new();
    let unsplit = SharedArgConfig::default().logup_gkr_run_budget;

    let mut session = columns.honest((100, 100));
    let plan = session.plan();
    assert_eq!(weighted_sizes(&plan), [24, 192, 32, 128, 12, 96]);
    // Both stacks hold entries of two relations.
    assert_eq!(plan[1].relations, [0, 2]);
    assert_eq!(plan[3].relations, [0, 1]);
    let shape = session.shape();
    session.prove_with(ColumnEvals::new()).unwrap();
    let after_reduction = ArgProver::new_from_tracker(session.prover.tracker().borrow().clone());
    let proof = session.prover.build_proof().unwrap();
    // The stacks are above the budget, each a run of its own. `a`, `c` and
    // `d` share the run opened before them, which has no room for `q`.
    assert_runs(&proof, &shape, &[vec![0, 2, 4], vec![1], vec![3], vec![5]]);
    let verifier = session.verify_reduction(&proof).unwrap();
    assert_in_sync(&after_reduction, &verifier);
    verifier.verify().unwrap();

    for (budget, runs) in [
        (unsplit, vec![vec![0, 1, 2, 3, 4, 5]]),
        // `d` fills the first run to the last element.
        (196, vec![vec![0, 2, 3, 4], vec![1], vec![5]]),
        // One less and it opens a run, which `q` then joins.
        (195, vec![vec![0, 2, 3], vec![1], vec![4, 5]]),
    ] {
        let mut session = columns.honest((budget, budget));
        session.prove_with(ColumnEvals::new()).unwrap();
        let after_reduction =
            ArgProver::new_from_tracker(session.prover.tracker().borrow().clone());
        let proof = session.prover.build_proof().unwrap();
        assert_runs(&proof, &shape, &runs);
        let verifier = session.verify_reduction(&proof).unwrap();
        assert_in_sync(&after_reduction, &verifier);
        verifier.verify().unwrap();
    }

    // A value outside the table in the first run, whose table is in a
    // stack two runs later.
    let mut bad = MixedColumns::new();
    bad.a[5] = F::from(16u64);
    let session = bad.session((100, 100), &columns.counts_abc(), &columns.counts_d());
    assert_rejected_in_the_reduction(session.prove_and_verify());

    // The same in the stack `b` shares with a column of another relation.
    let mut bad = MixedColumns::new();
    bad.b[5] = F::from(16u64);
    let session = bad.session((100, 100), &columns.counts_abc(), &columns.counts_d());
    assert_rejected_in_the_reduction(session.prove_and_verify());

    // A miscounted table of the second relation, stacked with that of the
    // first, two runs after `d`.
    let mut counts_d = columns.counts_d();
    counts_d[3] += F::one();
    let session = columns.session((100, 100), &columns.counts_abc(), &counts_d);
    assert_rejected_in_the_reduction(session.prove_and_verify());

    // The last run is not a permutation of `p`, which sits in the stack of
    // the second run.
    let mut bad = MixedColumns::new();
    bad.q[31] = bad.q[30];
    assert_rejected_in_the_reduction(bad.honest((100, 100)).prove_and_verify());
}

/// The input claims of every run are pushed, each at its run's point. A
/// committed column is not what the other side counts and the prover runs
/// the GKR on one that is: two columns of the first run, a multiplicity in
/// the stack of tables, either column of the stack two relations share, and
/// the column of the last run.
#[test]
fn gkr_on_fake_leaves_in_any_run_is_rejected() {
    let columns = MixedColumns::new();
    for column in [2, 7, 6, 3, 8, 9] {
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
            6 => {
                counts_d[3] += F::one();
                columns.counts_d()
            }
            3 => {
                committed.b[1] = F::from(16u64);
                columns.b.clone()
            }
            8 => {
                committed.p[1] = F::from(999u64);
                columns.p.clone()
            }
            _ => {
                committed.q[1] = F::from(999u64);
                columns.q.clone()
            }
        };
        let session = committed.session((100, 100), &columns.counts_abc(), &counts_d);
        let evals = BTreeMap::from([(session.ids[column], fake)]);
        assert_stopped_by_the_input_claims(session, |session| session.prove_with(evals));
    }
}

/// Two relations, each false, whose errors cancel over the batch. Each
/// side is one stack of both relations and a run of its own.
#[test]
fn relations_whose_errors_cancel_across_runs_are_rejected() {
    let columns = [fv(0..32), fv((0..32).map(|i| i + 100))];
    let entry = |column: usize| vec![(column, None)];
    let budgets = (100, 100);
    let runs = [vec![0], vec![1]];

    let together = (vec![(0, None), (1, None)], vec![(1, None), (0, None)]);
    let mut session = Session::with_budgets(budgets, &columns, &[together]);
    let shape = session.shape();
    assert_eq!(shape, gkr_shape(&[(6, true), (6, true)]));
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    assert_runs(&proof, &shape, &runs);
    session.verify(&proof).unwrap();

    let apart = [(entry(0), entry(1)), (entry(1), entry(0))];
    let mut session = Session::with_budgets(budgets, &columns, &apart);
    assert_eq!(session.shape(), shape);
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    assert_runs(&proof, &shape, &runs);
    assert_rejected_in_the_reduction(session.verify(&proof));
}

/// An instance above the budget is proved in a run of its own and closes
/// no other: an instance after it still joins a run before it that has
/// room. Down to a budget nothing fits in.
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

    // The two sides of the permutations, each a stack of the first relation
    // and the last, then the big column and its table.
    let plan = session(40, &big).plan();
    assert_eq!(weighted_sizes(&plan), [24, 24, 96, 32]);
    assert_eq!(plan[0].relations, [0, 2]);
    assert_eq!(plan[1].relations, [0, 2]);
    for (budget, runs) in [
        (56, vec![vec![0, 1], vec![2], vec![3]]),
        (79, vec![vec![0, 1], vec![2], vec![3]]),
        // The table fits beside the stacks, past the big column that
        // stands between them.
        (80, vec![vec![0, 1, 3], vec![2]]),
        (95, vec![vec![0, 1, 3], vec![2]]),
        // The big column is within the budget and still alone.
        (96, vec![vec![0, 1, 3], vec![2]]),
        (152, vec![vec![0, 1, 2], vec![3]]),
        // Every instance is above the budget.
        (23, vec![vec![0], vec![1], vec![2], vec![3]]),
        (0, vec![vec![0], vec![1], vec![2], vec![3]]),
        (usize::MAX, vec![vec![0, 1, 2, 3]]),
    ] {
        let mut honest = session(budget, &big);
        let shape = honest.shape();
        honest.prove_with(ColumnEvals::new()).unwrap();
        let after_reduction = ArgProver::new_from_tracker(honest.prover.tracker().borrow().clone());
        let proof = honest.prover.build_proof().unwrap();
        assert_runs(&proof, &shape, &runs);
        let verifier = honest.verify_reduction(&proof).unwrap();
        assert_in_sync(&after_reduction, &verifier);
        verifier.verify().unwrap();

        assert_rejected_in_the_reduction(session(budget, &outside).prove_and_verify());
    }
}

/// An instance above the budget closes no run opened after it either: two
/// instances that fit together only past it share a run.
#[test]
fn gkr_runs_opened_after_an_over_budget_instance_still_take_instances() {
    let table = fv(0..8);
    let subs = [
        in_table(5, 8, 1),
        in_table(6, 8, 2),
        in_table(4, 8, 3),
        in_table(3, 8, 4),
    ];
    let counted: Vec<(&[F], Option<&[F]>)> = subs.iter().map(|sub| (&sub[..], None)).collect();
    let mut columns = vec![table.clone(), tally(&table, &counted)];
    columns.extend_from_slice(&subs);
    let relations = [((2..6).map(|sub| (sub, None)).collect(), vec![(0, Some(1))])];
    let mut session = Session::with_budgets((100, 100), &columns, &relations);
    assert_eq!(weighted_sizes(&session.plan()), [96, 192, 48, 24, 32]);
    let shape = session.shape();
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    // The 2^6 column is alone above the budget. The 2^4 column fits beside
    // nothing before it, and the 2^3 column fits beside it and nowhere else.
    assert_runs(&proof, &shape, &[vec![0], vec![1], vec![2, 3], vec![4]]);
    session.verify(&proof).unwrap();
}

/// With room in several runs, an instance joins the earliest of them.
#[test]
fn gkr_instance_joins_the_first_of_the_runs_with_room() {
    let table = fv(0..8);
    let subs = [in_table(4, 8, 1), in_table(5, 8, 2), in_table(3, 8, 3)];
    let counted: Vec<(&[F], Option<&[F]>)> = subs.iter().map(|sub| (&sub[..], None)).collect();
    let mut columns = vec![table.clone(), tally(&table, &counted)];
    columns.extend_from_slice(&subs);
    let relations = [((2..5).map(|sub| (sub, None)).collect(), vec![(0, Some(1))])];
    let mut session = Session::with_budgets((130, 130), &columns, &relations);
    assert_eq!(weighted_sizes(&session.plan()), [48, 96, 24, 32]);
    let shape = session.shape();
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();
    // The 2^3 column has room beside either of the columns before it, and
    // so has the table after it.
    assert_runs(&proof, &shape, &[vec![0, 2, 3], vec![1]]);
    session.verify(&proof).unwrap();
}

/// The split into runs is part of the statement the verifier checks: a
/// proof split by another budget than the verifier's is rejected at the
/// first run that differs, whichever side has the finer split. Budgets that
/// give the same runs are the same statement.
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
        // `d` in the first run or in a later one.
        (196, 195),
        (195, 196),
        // `q` in the first run or in the last.
        (100, 164),
        (164, 100),
        (0, 100),
        (100, 0),
    ] {
        assert_rejected_in_the_reduction(run(budgets));
    }
    run((100, 163)).unwrap();
    run((100, 68)).unwrap();
    run((unsplit, usize::MAX)).unwrap();
}

/// The lookup claims and the deferred keyed sums are reduced in one batch,
/// which the budget splits like any other: a stack of two sub columns, the
/// wider sub column stacked with one side of a permutation, the table, and
/// the other side of the permutation, with weighted sizes 48, 192, 64 and
/// 96.
#[test]
fn lookups_and_deferred_keyed_sums_are_reduced_in_runs_under_a_small_budget() {
    let table = fv(0..16);
    let subs = [in_table(3, 16, 1), in_table(3, 16, 2), in_table(5, 16, 3)];
    let p = fv((0..32).map(|i| i + 100));
    let q = fv((0..32).map(|i| (i * 13 + 5) % 32 + 100));
    let shape = gkr_shape(&[(4, true), (6, true), (4, false), (5, true)]);
    // Were the wide sub column and its neighbour of the permutation not in
    // one instance, the batch would have five and a longer proof.
    let apart = gkr_shape(&[(4, true), (5, true), (4, false), (5, true), (5, true)]);
    assert!(proof_len(&shape) < proof_len(&apart));

    let run = |budget: usize, subs: &[Vec<F>; 3], q: &[F]| -> SnarkResult<SNARKProof<B>> {
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
        Ok(proof)
    };

    let unsplit = SharedArgConfig::default().logup_gkr_run_budget;
    for (budget, runs) in [
        (unsplit, vec![vec![0, 1, 2, 3]]),
        // The table has no room beside the two stacks, by one element.
        (303, vec![vec![0, 1], vec![2, 3]]),
        // The stack of the two relations opens a run and the instances
        // after it go back to the first.
        (239, vec![vec![0, 2, 3], vec![1]]),
        (200, vec![vec![0, 2], vec![1], vec![3]]),
        (0, vec![vec![0], vec![1], vec![2], vec![3]]),
    ] {
        let proof = run(budget, &subs, &q).unwrap();
        assert_runs(&proof, &shape, &runs);

        // A value outside the table in either stack, whichever run its
        // table is in, and a `q` that repeats a row.
        for bad_sub in [0, 1, 2] {
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
        // A stack of 2^s columns of 8 rows for every binary digit s of
        // `n_subs`, the largest first, and the table.
        let mut batch: Vec<(usize, bool)> = (0..usize::BITS as usize)
            .rev()
            .filter(|s| n_subs >> s & 1 == 1)
            .map(|s| (3 + s, true))
            .collect();
        batch.push((4, false));
        assert_eq!(batch.len(), n_subs.count_ones() as usize + 1);
        assert_one_run(&proof, &gkr_shape(&batch));

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

/// Lookups into three tables of one size through the public claims. Sub
/// columns of one size share stacks whichever table they are looked up in,
/// and the tables share theirs: six instances where the lookups one by one
/// would have eight. A value outside its table, be it a value of the next
/// table, is caught wherever its column sits.
#[test]
fn lookups_into_tables_of_one_size_share_their_instances() {
    let tables: Vec<Vec<F>> = (0..3).map(|t| fv((0..16).map(|i| i + 100 * t))).collect();
    // `(table, variables)` of every sub column, in the order of the claims.
    let sizes = [
        (0, 3),
        (0, 3),
        (0, 3),
        (1, 3),
        (1, 5),
        (1, 3),
        (2, 3),
        (2, 3),
    ];
    let subs: Vec<Vec<F>> = (0..)
        .zip(sizes)
        .map(|(seed, (table, nv))| {
            let offset = F::from(100 * table as u64);
            in_table(nv, 16, seed).iter().map(|v| *v + offset).collect()
        })
        .collect();

    let run = |subs: &[Vec<F>]| -> SnarkResult<SNARKProof<B>> {
        let (mut prover, mut verifier) = setup();
        let table_ids: Vec<TrackerID> =
            tables.iter().map(|t| commit(&mut prover, t).id()).collect();
        let sub_ids: Vec<TrackerID> = subs.iter().map(|s| commit(&mut prover, s).id()).collect();
        for ((table, _), sub) in sizes.iter().zip(&sub_ids) {
            prover.add_mv_lookup_claim(table_ids[*table], *sub)?;
        }
        let mut reduced = ArgProver::new_from_tracker(prover.tracker().borrow().clone());
        reduced.reduce_lookup_claims()?;
        let proof = prover.build_proof()?;

        verifier.set_proof_ref(&proof);
        for id in table_ids.iter().chain(&sub_ids) {
            verifier.track_mv_com_by_id(*id)?;
        }
        for ((table, _), sub) in sizes.iter().zip(&sub_ids) {
            verifier.add_mv_lookup_claim(table_ids[*table], *sub)?;
        }
        verifier.reduce_lookup_claims()?;
        assert_in_sync(&reduced, &verifier);
        verifier.verify()?;
        Ok(proof)
    };

    let proof = run(&subs).unwrap();
    // Seven sub columns of 8 rows in stacks of four, two and one, the
    // first two of which span two tables each; three tables in a stack of
    // two and one of one; and the sub column of 32 rows.
    let shape = gkr_shape(&[
        (5, true),
        (4, true),
        (3, true),
        (5, false),
        (4, false),
        (5, true),
    ]);
    assert_one_run(&proof, &shape);
    // Table by table: a stack of two and one of one, a table; a stack of
    // two, the wide column, a table; a stack of two, a table.
    let one_by_one = gkr_shape(&[
        (4, true),
        (3, true),
        (4, false),
        (4, true),
        (5, true),
        (4, false),
        (4, true),
        (4, false),
    ]);
    assert!(proof_len(&shape) < proof_len(&one_by_one));

    for (at, (table, _)) in sizes.iter().enumerate() {
        for outside in [999, 100 * ((table + 1) % 3) as u64 + 3] {
            let mut subs = subs.clone();
            subs[at][5] = F::from(outside);
            assert_false_statement_rejected(run(&subs));
        }
    }
}

/// How long the multiplicity of a lookup is, is up to the prover: the
/// verifier has its size from the commitment. Whatever it is, the table
/// side is the table with the multiplicity repeated along it, or the
/// multiplicity with the table repeated along it. A longer or a shorter
/// one therefore proves the same lookup, in an instance of another shape
/// that the table shares with no other, and proves no other lookup.
#[test]
fn multiplicities_of_another_size_than_their_tables_prove_the_same_lookups() {
    let tables = [fv(0..8), fv(100..108)];
    // The second sub column holds every value of its table once.
    let subs = [in_table(3, 8, 1), fv((0..8).map(|i| 100 + (i * 3) % 8))];
    let counts = tally(&tables[0], &[(&subs[0], None)]);
    let session = |subs: &[Vec<F>; 2], first: &[F], second: &[F]| {
        let columns = [
            tables[0].clone(),
            first.to_vec(),
            tables[1].clone(),
            second.to_vec(),
            subs[0].clone(),
            subs[1].clone(),
        ];
        let relations = [
            (vec![(4, None)], vec![(0, Some(1))]),
            (vec![(5, None)], vec![(2, Some(3))]),
        ];
        Session::new(&columns, &[], &relations)
    };
    let unit = (Side::F, 3, 1, true, false, false);

    // As long as their tables, which then share a stack.
    let same = session(&subs, &counts, &fv([1; 8]));
    assert_eq!(
        layout(&same.plan()),
        [unit, (Side::G, 3, 1, false, false, false)]
    );
    same.prove_and_verify().unwrap();

    // Twice as long for the first table, the counts in either half or half
    // of them in each, and half as long for the second.
    let zeros = vec![F::zero(); 8];
    let halved: Vec<F> = counts.iter().map(|c| *c / F::from(2u64)).collect();
    let long = [
        [&counts[..], &zeros[..]].concat(),
        [&zeros[..], &counts[..]].concat(),
        [&halved[..], &halved[..]].concat(),
    ];
    let short = fv([1; 4]);
    for long in &long {
        let other = session(&subs, long, &short);
        assert_eq!(
            layout(&other.plan()),
            [
                unit,
                (Side::G, 4, 0, false, false, false),
                (Side::G, 3, 0, false, false, false)
            ]
        );
        other.prove_and_verify().unwrap();

        // A count too many in the half the table is repeated into.
        let mut miscounted = long.clone();
        miscounted[11] += F::one();
        let session = session(&subs, &miscounted, &short);
        assert_rejected_in_the_reduction(session.prove_and_verify());
    }
    assert_rejected_in_the_reduction(
        session(&subs, &long[0], &fv([1, 1, 1, 2])).prove_and_verify(),
    );

    // A value of the other table in either sub column.
    for (sub, value) in [(0, 100u64), (1, 0)] {
        let mut subs = subs.clone();
        subs[sub][5] = F::from(value);
        let session = session(&subs, &long[0], &short);
        assert_rejected_in_the_reduction(session.prove_and_verify());
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
    let shape: Vec<GkrShape> = plan.iter().map(InstancePlan::shape).collect();
    assert_one_run(&proof, &shape);

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
    let shape: Vec<GkrShape> = plan.iter().map(InstancePlan::shape).collect();
    assert_one_run(&proof, &shape);

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

/// An entry with a constant operand stands alone and is still an entry of
/// its relation: what is taken off the constant is that relation's `gamma`,
/// not the first one's.
#[test]
fn constant_entry_has_the_gamma_of_its_relation() {
    let table = fv(0..16);
    let keys = in_table(3, 16, 1);
    let weights = fv(1..9);
    let counts = tally(&table, &[(&fv([7; 8]), Some(&weights)), (&keys, None)]);
    let columns = [table, counts, keys, weights, fv(0..8), fv((0..8).rev())];
    // A permutation, then a lookup of a constant column and a committed
    // one.
    let session = |constant: u64| {
        let mut session = Session::new(&columns, &[], &[(vec![(4, None)], vec![(5, None)])]);
        session.relations.push(KeyedSumRelation {
            fxs: vec![
                KeyedTerm::Constant {
                    value: F::from(constant),
                    nv: 3,
                },
                KeyedTerm::Poly(session.ids[2]),
            ],
            mfxs: vec![Some(KeyedTerm::Poly(session.ids[3])), None],
            gxs: vec![KeyedTerm::Poly(session.ids[0])],
            mgxs: vec![Some(KeyedTerm::Poly(session.ids[1]))],
        });
        session
    };
    let honest = session(7);
    let plan = honest.plan();
    assert_eq!(
        layout(&plan),
        [
            (Side::F, 3, 1, true, false, false),
            (Side::G, 3, 0, true, false, false),
            (Side::F, 3, 0, false, true, false),
            (Side::G, 4, 0, false, false, false),
        ]
    );
    assert_eq!(plan[0].relations, [0, 1]);
    assert_eq!(plan[2].relations, [1]);
    honest.prove_and_verify().unwrap();

    assert_rejected_in_the_reduction(session(16).prove_and_verify());
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
    // The first table has a pair and a single of 16 rows, a column of 64
    // and one of 4; the second a pair of 8 rows; the third one column.
    assert_eq!(proof.logup_gkr_subproofs.len(), 3);
    let batch = [
        (5, true),
        (4, true),
        (6, true),
        (2, true),
        (4, false),
        (4, true),
        (3, false),
        (5, true),
        (5, false),
    ];
    assert_eq!(
        Some(proof.logup_gkr_subproofs[2].messages.len()),
        proof_len(&gkr_shape(&batch))
    );

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
    // One batch: the two subs and their table, then the permutation, then
    // the weighted keys, with numerators of their own where a multiplicity
    // is named.
    let shape = gkr_shape(&[
        (4, true),
        (6, true),
        (4, false),
        (5, true),
        (5, true),
        (3, false),
        (3, false),
    ]);
    assert_eq!(shape.len(), 3 + 2 + 2);
    assert_one_run(&proof, &shape);
    // The subproof opens with the first layer of every instance in instance
    // order, four values each at these sizes, and a first layer gives its
    // instance's root. Each relation balances on the roots at its own
    // places and on no others.
    let roots: Vec<[F; 2]> = proof.logup_gkr_subproofs[0].messages[..4 * shape.len()]
        .chunks(4)
        .map(|mask| [mask[0] * mask[3] + mask[1] * mask[2], mask[2] * mask[3]])
        .collect();
    let total = |roots: &[[F; 2]]| roots.iter().map(|[p, q]| *p / q).sum::<F>();
    assert_eq!(total(&roots[..2]), total(&roots[2..3]));
    assert_eq!(total(&roots[3..4]), total(&roots[4..5]));
    assert_eq!(total(&roots[5..6]), total(&roots[6..]));
    assert_ne!(total(&roots[..1]), total(&roots[2..3]));
    assert_ne!(total(&roots[2..3]), total(&roots[3..4]));
    assert_ne!(total(&roots[4..5]), total(&roots[5..6]));

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

// ─── Fast paths of the prover ────────────────────────────────────────────

/// The evaluations of `id` with every factor expanded to field elements
/// first, whatever it is stored as.
fn expanded_evaluations(tracker: &ProverTracker<B>, id: TrackerID) -> Vec<F> {
    if let Some(column) = tracker.mat_mv_poly(id) {
        return column.evaluations();
    }
    let mut evals = vec![F::zero(); 1 << tracker.poly_nv(id)];
    for (coeff, product) in tracker.virt_poly(id).unwrap() {
        let factors: Vec<Vec<F>> = product
            .iter()
            .map(|factor| tracker.mat_mv_poly(*factor).unwrap().evaluations())
            .collect();
        for (row, eval) in evals.iter_mut().enumerate() {
            *eval += factors
                .iter()
                .fold(*coeff, |term, factor| term * factor[row % factor.len()]);
        }
    }
    evals
}

/// What [`ArgProver::reduce_lookup_claims`] does, by the slow routes: every
/// column expanded factor by factor and the multiplicities found by sorting.
fn reduce_lookup_claims_the_slow_way(prover: &mut ArgProver<B>) {
    let claims = prover.tracker().borrow_mut().take_lookup_claims();
    let mut by_super: IndexMap<TrackerID, Vec<TrackerID>> = IndexMap::new();
    for claim in claims {
        by_super
            .entry(claim.super_poly())
            .or_default()
            .push(claim.sub_poly());
    }

    let mut evals = ColumnEvals::new();
    for id in by_super
        .iter()
        .flat_map(|(table, subs)| subs.iter().chain([table]))
    {
        let column = expanded_evaluations(&prover.tracker().borrow(), *id);
        evals.insert(*id, column);
    }

    let mut relations = Vec::new();
    for (table, subs) in by_super {
        let included: Vec<&[F]> = subs.iter().map(|id| &evals[id][..]).collect();
        let counts = multiplicities_by_sorting(&included, &evals[&table]);
        let multiplicity = Arc::new(mle(&counts));
        let commitment = <B as SnarkBackend>::MvPCS::commit(
            prover.mv_pcs_prover_param().as_ref(),
            &multiplicity,
        )
        .unwrap();
        let multiplicity = prover
            .tracker()
            .borrow_mut()
            .track_mat_mv_p_with_commitment(
                &multiplicity,
                commitment,
                CommitmentBinding::ProofEmitted,
                false,
            )
            .unwrap();
        evals.insert(multiplicity, counts);
        relations.push(KeyedSumRelation {
            mfxs: vec![None; subs.len()],
            fxs: subs.into_iter().map(KeyedTerm::Poly).collect(),
            gxs: vec![KeyedTerm::Poly(table)],
            mgxs: vec![Some(KeyedTerm::Poly(multiplicity))],
        });
    }
    prove_keyed_sums(prover, &relations, evals).unwrap();
}

/// The columns of [`fast_path_lookups`], in the order they are committed.
fn fast_path_columns() -> Vec<Vec<F>> {
    let rows = 1u64 << 8;
    let below_20 = |nv: usize, seed: u64| in_table(nv, 20, seed);
    vec![
        // 0: small integers with gaps, 1: a table with repeats, 2: a table
        // that is not small integers.
        fv((0..rows).map(|i| i * 200)),
        fv((0..32).map(|i| (i * 7) % 20)),
        (0..16u64).map(|i| -F::from(i + 1)).collect(),
        // 3, 4: activators.
        fv((0..rows).map(|i| u64::from(i % 3 != 0))),
        fv((0..rows).map(|i| u64::from(i % 5 < 2))),
        // 5, 6: limbs out of the first table, 7: one out of the second.
        fv((0..rows).map(|i| ((i * 37 + 11) % 256) * 200)),
        fv((0..rows).map(|i| ((i * 101) % 256) * 200)),
        below_20(8, 1),
        // 8, 9: wider and narrower than the second table.
        below_20(7, 3),
        below_20(3, 4),
        // 10: out of the third table.
        (0..64u64).map(|i| -F::from((i * 5) % 16 + 1)).collect(),
    ]
}

/// A batch of lookups over the columns `ids` in which the prover takes
/// every shortcut it has: columns that are products of small integers and
/// activators, sums of scaled activators, plain columns of every width,
/// tables it can count into and one it has to sort. Returns the claims as
/// `(table, sub)`.
fn fast_path_lookups<T: TrackerCore<F = F>>(
    tracker: &mut T,
    ids: &[TrackerID],
) -> Vec<(TrackerID, TrackerID)> {
    let (gaps, repeats, large) = (ids[0], ids[1], ids[2]);
    let (act, other_act) = (ids[3], ids[4]);
    let mut lookups = Vec::new();
    for limb in [ids[5], ids[6]] {
        lookups.push((gaps, tracker.mul_polys(limb, act)));
    }
    lookups.push((repeats, tracker.mul_polys(ids[7], other_act)));
    // 200·act + 400·other_act, and a limb where one activator is on and
    // the other off.
    let scaled = tracker.mul_scalar(act, F::from(200u64));
    let other_scaled = tracker.mul_scalar(other_act, F::from(400u64));
    lookups.push((gaps, tracker.add_polys(scaled, other_scaled)));
    let gated = tracker.mul_polys(ids[5], act);
    let both = tracker.mul_polys(gated, other_act);
    lookups.push((gaps, tracker.sub_polys(gated, both)));
    for plain in [ids[8], ids[9], ids[7]] {
        lookups.push((repeats, plain));
    }
    lookups.push((large, ids[10]));
    lookups
}

/// The shortcuts the prover takes to its columns and multiplicities leave
/// no trace: the proof is, byte for byte, the one it gets by the slow
/// routes.
#[test]
fn proof_by_the_fast_paths_is_the_proof_by_the_slow_ones() {
    let columns = fast_path_columns();
    let state = |reduce: fn(&mut ArgProver<B>)| {
        let (mut prover, verifier) = setup();
        let ids: Vec<TrackerID> = columns
            .iter()
            .map(|column| commit(&mut prover, column).id())
            .collect();
        let lookups = fast_path_lookups(&mut *prover.tracker().borrow_mut(), &ids);
        for (table, sub) in lookups {
            prover.add_mv_lookup_claim(table, sub).unwrap();
        }
        reduce(&mut prover);
        let proof = prover.tracker().borrow_mut().compile_proof().unwrap();
        (proof, ids, prover, verifier)
    };
    let (proof, ids, prover, mut verifier) = state(|prover| prover.reduce_lookup_claims().unwrap());
    let (slow_proof, ..) = state(reduce_lookup_claims_the_slow_way);

    // The statement is one the shortcuts apply to.
    let tags: Vec<&str> = ids
        .iter()
        .map(|id| {
            let tracker = prover.tracker();
            let tracker = tracker.borrow();
            tracker.mat_mv_poly(*id).unwrap().storage().kind_tag()
        })
        .collect();
    assert_eq!(
        tags,
        [
            "u32", "u8", "field", "bit", "bit", "u32", "u32", "u8", "u8", "u8", "field"
        ]
    );
    assert_eq!(proof.logup_gkr_subproofs.len(), 1);

    let bytes = |proof: &SNARKProof<B>| {
        let mut bytes = Vec::new();
        proof.serialize_with_mode(&mut bytes, Compress::No).unwrap();
        bytes
    };
    assert_eq!(bytes(&proof), bytes(&slow_proof));

    verifier.set_proof_ref(&proof);
    for id in &ids {
        verifier.track_mv_com_by_id(*id).unwrap();
    }
    let lookups = fast_path_lookups(&mut *verifier.tracker().borrow_mut(), &ids);
    for (table, sub) in lookups {
        verifier.add_mv_lookup_claim(table, sub).unwrap();
    }
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
    assert!(!proof.logup_gkr_subproofs[0].messages.is_empty());

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
/// multiplicity repeated, and the `gamma` of each entry's relation taken
/// off its column only. A column is kept for as long as a later run reads
/// it.
#[test]
fn stacked_instance_lays_its_entries_out_by_row_then_entry() {
    let cols: Vec<Vec<F>> = (0..3).map(|s| in_table(1, 16, s + 1)).collect();
    let mults: Vec<Vec<F>> = (0..3).map(|s| fv((0..4).map(|i| 10 * s + i))).collect();
    let columns: Vec<Vec<F>> = cols.iter().chain(&mults).cloned().collect();
    // One entry of the first relation and two of the second, with the same
    // column on the other side of each.
    let relations = [
        (vec![(0, Some(3))], vec![(0, Some(3))]),
        (vec![(1, Some(4)), (2, Some(5))], vec![(0, Some(3))]),
    ];
    let session = Session::new(&columns, &[], &relations);
    let plan = session.plan();
    // The other sides are a stack too.
    assert_eq!(plan.len(), 3);
    assert_eq!((plan[0].stack_log, plan[1].stack_log), (1, 0));
    assert_eq!((plan[0].claim_nv, plan[0].n_vars()), (2, 3));
    assert_eq!(plan[0].relations, [0, 1]);
    assert_eq!(plan[1].relations, [1]);
    assert_eq!((plan[2].side, &plan[2].relations), (Side::G, &vec![0, 1]));

    let gammas = fv([1000, 2000]);
    let batch = Batch {
        plan,
        gammas: gammas.clone(),
        runs: vec![vec![0], vec![1, 2]],
    };
    let mut party = ProvingParty {
        evals: ColumnEvals::new(),
    };
    let tracker = session.prover.tracker();
    let stack = party
        .instances(&mut tracker.borrow_mut(), &batch, 0)
        .unwrap();
    // The other sides read the first entry's polynomials in the next run.
    let kept: Vec<TrackerID> = party.evals.keys().copied().collect();
    assert_eq!(kept, [session.ids[0], session.ids[3]]);

    let expected_den: Vec<F> = (0..8)
        .map(|j| cols[j >> 2][j & 1] - gammas[j >> 2])
        .collect();
    let expected_num: Vec<F> = (0..8).map(|j| mults[j >> 2][j & 3]).collect();
    assert_eq!(stack.len(), 1);
    assert_eq!(stack[0].den, expected_den);
    match &stack[0].num {
        Numerator::Values(num) => assert_eq!(*num, expected_num),
        Numerator::One => panic!("the stack has multiplicities"),
    }

    let rest = party
        .instances(&mut tracker.borrow_mut(), &batch, 1)
        .unwrap();
    assert!(party.evals.is_empty());
    let single_den: Vec<F> = (0..4).map(|j| cols[2][j & 1] - gammas[1]).collect();
    assert_eq!(rest[0].den, single_den);
    let other_side_den: Vec<F> = (0..8).map(|j| cols[0][j & 1] - gammas[j >> 2]).collect();
    assert_eq!(rest[1].den, other_side_den);
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
        side: Side::F,
        claim_nv: nv,
        stack_log: 0,
        relations: vec![0],
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
        let batch = Batch {
            plan: vec![instance(nv)],
            gammas: fv([7]),
            runs: vec![vec![0]],
        };
        let pushed = push_input_claims(&mut *tracker, &VerifyingParty, &batch, 0, &claims(nv));
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
            let batch = Batch {
                runs: vec![(0..plan.len()).collect()],
                plan,
                gammas: vec![gamma],
            };
            let mut party = ProvingParty {
                evals: ColumnEvals::new(),
            };
            let claims = party.run(&mut *tracker, &batch, 0)?;
            // The two sides balance under this `gamma`.
            let ([p_f, q_f], [p_g, q_g]) = (claims.roots[0], claims.roots[1]);
            assert_eq!(p_f * q_g, p_g * q_f);
            push_input_claims(&mut *tracker, &party, &batch, 0, &claims)?;
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

/// Each relation has a `gamma` of its own, drawn in the order of the
/// relations once the multiplicities of all of them are committed. Two
/// lookups reduced by hand in that order are the real reduction. With the
/// two gammas exchanged, or the first drawn before the second table's
/// multiplicities are committed, they are not.
#[test]
fn gammas_are_drawn_per_relation_in_order_after_every_multiplicity() {
    use super::reduction::push_input_claims;

    #[derive(Clone, Copy)]
    enum Order {
        AsTheVerifier,
        Exchanged,
        BetweenTheMultiplicities,
    }
    let columns = {
        let subs = two_lookup_subs();
        two_lookup_columns(&subs, &subs)
    };
    let run = |order: Order| -> SnarkResult<()> {
        let (mut prover, mut verifier) = setup();
        let mut commit_column = |at: usize| commit(&mut prover, &columns[at]).id();
        let tables = [0, 2].map(&mut commit_column);
        let subs = [4, 5, 6, 7].map(&mut commit_column);
        let (first_counts, first_gamma) = match order {
            Order::BetweenTheMultiplicities => {
                let counts = commit(&mut prover, &columns[1]).id();
                (counts, Some(prover.get_and_append_challenge(b"gamma")?))
            }
            _ => (commit(&mut prover, &columns[1]).id(), None),
        };
        let counts = [first_counts, commit(&mut prover, &columns[3]).id()];
        let first_gamma = match first_gamma {
            Some(gamma) => gamma,
            None => prover.get_and_append_challenge(b"gamma")?,
        };
        let mut gammas = vec![first_gamma, prover.get_and_append_challenge(b"gamma")?];
        if matches!(order, Order::Exchanged) {
            gammas.swap(0, 1);
        }
        let relations: Vec<KeyedSumRelation<F>> = (0..2)
            .map(|r| KeyedSumRelation {
                fxs: subs[2 * r..2 * r + 2]
                    .iter()
                    .map(|sub| KeyedTerm::Poly(*sub))
                    .collect(),
                mfxs: vec![None; 2],
                gxs: vec![KeyedTerm::Poly(tables[r])],
                mgxs: vec![Some(KeyedTerm::Poly(counts[r]))],
            })
            .collect();
        {
            let tracker = prover.tracker();
            let mut tracker = tracker.borrow_mut();
            let plan = plan_instances(&*tracker, &relations).unwrap();
            // Both instances hold entries of both relations.
            assert_eq!(plan[0].relations, [0, 0, 1, 1]);
            assert_eq!(plan[1].relations, [0, 1]);
            let batch = Batch {
                runs: vec![(0..plan.len()).collect()],
                plan,
                gammas,
            };
            let mut party = ProvingParty {
                evals: ColumnEvals::new(),
            };
            let claims = party.run(&mut *tracker, &batch, 0)?;
            push_input_claims(&mut *tracker, &party, &batch, 0, &claims)?;
        }
        let proof = prover.build_proof()?;

        verifier.set_proof_ref(&proof);
        for id in tables.iter().chain(&subs) {
            verifier.track_mv_com_by_id(*id)?;
        }
        for (r, sub) in subs.iter().enumerate() {
            verifier.add_mv_lookup_claim(tables[r / 2], *sub)?;
        }
        verifier.verify()
    };

    run(Order::AsTheVerifier).unwrap();
    assert_verifier_error(run(Order::Exchanged).unwrap_err());
    assert_verifier_error(run(Order::BetweenTheMultiplicities).unwrap_err());
}

/// A relation without entries has no column to take a `gamma` off and
/// draws none. A batch of nothing else leaves the transcript as it was, and
/// one among others does not move theirs.
#[test]
fn relation_without_entries_draws_no_gamma() {
    let empty = || KeyedSumRelation::<F> {
        fxs: Vec::new(),
        mfxs: Vec::new(),
        gxs: Vec::new(),
        mgxs: Vec::new(),
    };
    let columns = [fv(0..8), fv((0..8).rev())];
    let next_challenge = |session: &Session| {
        let tracker = session.prover.tracker().borrow().clone();
        let mut prover = ArgProver::new_from_tracker(tracker);
        prover.get_and_append_challenge(b"probe").unwrap()
    };

    let mut session = Session::new(&columns, &[], &[]);
    let untouched = next_challenge(&session);
    session.relations = vec![empty(), empty()];
    session.prove_with(ColumnEvals::new()).unwrap();
    assert_eq!(next_challenge(&session), untouched);

    let permutation = (vec![(0, None)], vec![(1, None)]);
    let both = [permutation.clone(), permutation];
    let mut plain = Session::new(&columns, &[], &both);
    let mut padded = Session::new(&columns, &[], &both);
    padded.relations.insert(1, empty());
    assert_eq!(padded.plan()[0].relations, [0, 2]);
    plain.prove_with(ColumnEvals::new()).unwrap();
    padded.prove_with(ColumnEvals::new()).unwrap();
    assert_ne!(next_challenge(&plain), untouched);
    assert_eq!(next_challenge(&padded), next_challenge(&plain));
    let proof = padded.prover.build_proof().unwrap();
    padded.verify(&proof).unwrap();
}

/// A relation with entries on one side only says that side sums to zero as
/// a rational function, and has a `gamma` like any other: columns whose
/// fractions cancel at one point, zero included, do not satisfy it. Weights
/// that cancel key by key do.
#[test]
fn relation_with_one_side_has_a_gamma_of_its_own() {
    let minus = |v: u64| -F::from(v);
    // 1/(1 - X) + 1/(-1 - X) is zero at X = 0 and nowhere else.
    let columns = [vec![F::one(), minus(1)]];
    for sides in [(vec![(0, None)], vec![]), (vec![], vec![(0, None)])] {
        let session = Session::new(&columns, &[], &[sides]);
        assert_rejected_in_the_reduction(session.prove_and_verify());
    }

    // The same beside a relation that holds.
    let columns = [vec![F::one(), minus(1)], fv(0..8), fv((0..8).rev())];
    let relations = [
        (vec![(1, None)], vec![(2, None)]),
        (vec![(0, None)], vec![]),
    ];
    let session = Session::new(&columns, &[], &relations);
    assert_rejected_in_the_reduction(session.prove_and_verify());

    // Weights that cancel on every key: the one side is zero whatever
    // `gamma` is.
    let columns = [
        fv([5, 5, 7, 7]),
        vec![F::one(), minus(1), F::from(2u64), minus(2)],
    ];
    for sides in [(vec![(0, Some(1))], vec![]), (vec![], vec![(0, Some(1))])] {
        Session::new(&columns, &[], &[sides])
            .prove_and_verify()
            .unwrap();
    }
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
    let shape = session.shape();
    session.prove_with(ColumnEvals::new()).unwrap();
    let after_reduction = ArgProver::new_from_tracker(session.prover.tracker().borrow().clone());
    let proof = session.prover.build_proof().unwrap();
    assert_runs(&proof, &shape, &[vec![0], vec![1]]);
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

/// A window activator over every row, or over none, is a constant. The
/// claims it ends up in have the degree on both sides that a constant
/// factor gives them, like those under a window that is neither.
#[test]
fn claims_under_a_constant_window_activator_have_one_degree_on_both_sides() {
    for active in [0, 8, 5] {
        let (mut prover, mut verifier) = setup();
        let table = commit(&mut prover, &fv(0..8));
        let data = commit(&mut prover, &in_table(3, 8, 1));
        let activator = prover.get_or_build_contig_one_poly(3, active).unwrap();
        let sub = &data * &activator;
        prover.add_mv_lookup_claim(table.id(), sub.id()).unwrap();
        let mut reduced = ArgProver::new_from_tracker(prover.tracker().borrow().clone());
        reduced.reduce_lookup_claims().unwrap();
        let proof = prover.build_proof().unwrap();

        verifier.set_proof_ref(&proof);
        let table = verifier.track_mv_com_by_id(table.id()).unwrap();
        let data = verifier.track_mv_com_by_id(data.id()).unwrap();
        let activator = verifier.get_or_build_contig_one_poly(3, active).unwrap();
        let sub = &data * &activator;
        verifier.add_mv_lookup_claim(table.id(), sub.id()).unwrap();
        verifier.reduce_lookup_claims().unwrap();
        assert_in_sync(&reduced, &verifier);
        verifier.verify().unwrap();
    }
}

// ─── A verdict that stays ────────────────────────────────────────────────

/// A false lookup by a prover that is honest about everything else: the GKR
/// and every input claim are true statements about the committed columns,
/// and only the sums of the two sides differ. They are compared once, in
/// the reduction, which leaves nothing false behind for the sumchecks to
/// find; a verifier asked a second time must still know.
#[test]
fn rejected_lookup_stays_rejected_on_a_second_verify() {
    let table = fv(0..8);
    let mut sub = in_table(3, 8, 1);
    sub[4] = F::from(9u64);
    let (mut prover, mut verifier) = setup();
    let table_id = commit(&mut prover, &table).id();
    let sub_id = commit(&mut prover, &sub).id();
    let counts_id = commit(&mut prover, &tally(&table, &[(&sub, None)])).id();
    let relation = KeyedSumRelation {
        fxs: vec![KeyedTerm::Poly(sub_id)],
        mfxs: vec![None],
        gxs: vec![KeyedTerm::Poly(table_id)],
        mgxs: vec![Some(KeyedTerm::Poly(counts_id))],
    };
    prove_keyed_sums(&mut prover, &[relation], ColumnEvals::new()).unwrap();
    let proof = prover.build_proof().unwrap();

    verifier.set_proof_ref(&proof);
    verifier.track_mv_com_by_id(table_id).unwrap();
    verifier.track_mv_com_by_id(sub_id).unwrap();
    verifier.add_mv_lookup_claim(table_id, sub_id).unwrap();
    assert_verifier_error(verifier.verify().unwrap_err());
    assert_verifier_error(verifier.verify().unwrap_err());
    // Handing it the proof again does not take the reduction back.
    verifier.set_proof_ref(&proof);
    assert_verifier_error(verifier.verify().unwrap_err());
}

/// The same when the keyed sum is checked on the spot and the caller goes
/// on to `verify` although the check failed.
#[test]
fn rejected_keyed_sum_fails_the_verify_that_follows() {
    let columns = [fv(0..8), fv([0, 1, 2, 3, 4, 5, 6, 6])];
    let mut session = Session::new(&columns, &[], &[(vec![(0, None)], vec![(1, None)])]);
    session.prove_with(ColumnEvals::new()).unwrap();
    let proof = session.prover.build_proof().unwrap();

    let mut verifier = session.verifier.fork();
    verifier.set_proof_ref(&proof);
    for id in &session.ids {
        verifier.track_mv_com_by_id(*id).unwrap();
    }
    assert_verifier_error(verify_keyed_sums(&mut verifier, &session.relations).unwrap_err());
    assert_verifier_error(verifier.verify().unwrap_err());
}

/// The reduction can fail before it reaches the GKR: here the proof is from
/// a prover that never made the lookup, so the multiplicity commitment the
/// verifier asks for is not there. The claim is not forgotten with it.
#[test]
fn lookup_that_could_not_be_reduced_fails_every_later_verify() {
    let table = fv(0..8);
    let mut sub = in_table(3, 8, 1);
    sub[4] = F::from(9u64);
    let (mut prover, mut verifier) = setup();
    let table_id = commit(&mut prover, &table).id();
    let sub_id = commit(&mut prover, &sub).id();
    prover.add_mv_sumcheck_claim(sub_id, sum(&sub)).unwrap();
    let proof = prover.build_proof().unwrap();

    verifier.set_proof_ref(&proof);
    verifier.track_mv_com_by_id(table_id).unwrap();
    verifier.track_mv_com_by_id(sub_id).unwrap();
    verifier.add_mv_sumcheck_claim(sub_id, sum(&sub));
    verifier.add_mv_lookup_claim(table_id, sub_id).unwrap();
    assert_verifier_error(verifier.verify().unwrap_err());
    assert_verifier_error(verifier.verify().unwrap_err());
}
