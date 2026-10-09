//! Lookup and keyed-sumcheck behaviour through the public API.
//!
//! Each test states a relation and checks only whether it is accepted or
//! rejected, never how the proof is laid out, so the suite keeps its meaning
//! when the protocol underneath the claims changes. There are two such
//! protocols to choose from, and every test runs under both
//! ([`under_each_protocol`]); the few that look at what a proof carries say
//! what that is under each.
#![cfg(feature = "test-utils")]

use std::cell::Cell;

use ark_ff::{One, Zero};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    piop::{
        PIOP,
        keyed_sumcheck::{KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput},
        lookup_check::{
            HintedLookupCheckPIOP, HintedLookupCheckProverInput, HintedLookupCheckVerifierInput,
            LookupCheckPIOP, LookupCheckProverInput, LookupCheckVerifierInput,
        },
    },
    prover::{
        ArgProver,
        structs::{
            polynomial::TrackedPoly,
            proof::{PROOF_ENCODING_VERSION, SNARKProof},
        },
    },
    setup::KeyGenerator,
    types::{
        LOOKUP_PROTOCOL_ENV, LookupMessages, LookupProtocol, SharedArgConfig, TrackerID,
        artifact::Artifact,
    },
    verifier::{
        ArgVerifier,
        errors::VerifierError,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_poly::Polynomial;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// Every column here has at most 2^8 rows; the 2^10 SRS loads in
/// milliseconds, where `test_prelude` re-reads the 2^19 one on every call.
const SRS_NV: usize = 10;

const PROTOCOLS: [LookupProtocol; 2] = [LookupProtocol::LogUp, LookupProtocol::LogUpGkr];

thread_local! {
    /// The lookup protocol the test of this thread is running under.
    static PROTOCOL: Cell<Option<LookupProtocol>> = const { Cell::new(None) };
}

/// Runs `test` once under each lookup protocol. [`setup`] configures both
/// sides for the protocol of the run, so a statement is put to both
/// protocols by the same code; `test` is told which one it is under for
/// the few things that differ between them. The protocol is printed, to
/// show in a failure which run it was.
fn under_each_protocol(test: impl Fn(LookupProtocol)) {
    for protocol in PROTOCOLS {
        println!("under {protocol}");
        PROTOCOL.set(Some(protocol));
        test(protocol);
    }
    PROTOCOL.set(None);
}

/// The term sums a LogUp proof carries; a LogUp-GKR proof has none.
fn logup_sums(proof: &SNARKProof<B>) -> &[F] {
    match &proof.lookup_messages {
        LookupMessages::LogUp { sums } => sums,
        LookupMessages::LogUpGkr => &[],
    }
}

/// A prover and a verifier for the protocol of the run. Their
/// configuration is explicit: the environment does not choose for them.
fn setup() -> (ArgProver<B>, ArgVerifier<B>) {
    let protocol = PROTOCOL
        .get()
        .expect("a test of this suite runs under_each_protocol");
    setup_under(protocol, protocol)
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

fn commit(prover: &mut ArgProver<B>, evals: &[F]) -> SnarkResult<TrackedPoly<B>> {
    prover.track_and_commit_mat_mv_poly(&mle(evals))
}

/// Tracks the prover's commitments on the verifier, in commit order (the
/// order in which both transcripts absorbed them).
fn track_all(
    verifier: &mut ArgVerifier<B>,
    ids: &[TrackerID],
) -> SnarkResult<Vec<TrackedOracle<B>>> {
    ids.iter()
        .map(|id| verifier.track_mv_com_by_id(*id))
        .collect()
}

/// The two sides hold the same position in the tracker-id sequence and the
/// same transcript. Probed on copies so the real trackers stay untouched.
fn assert_prover_verifier_in_sync(prover: &ArgProver<B>, verifier: &ArgVerifier<B>) {
    let mut prover = prover.deep_copy();
    let mut verifier = verifier.deep_copy();
    assert_eq!(
        prover.peek_next_id(),
        verifier.peek_next_id(),
        "prover and verifier disagree on the next tracker id"
    );
    assert_eq!(
        prover.get_and_append_challenge(b"parity probe").unwrap(),
        verifier.get_and_append_challenge(b"parity probe").unwrap(),
        "prover and verifier transcripts have diverged"
    );
}

/// Runs a whole statement: `prove` commits and claims and returns what the
/// verifier needs to mirror it; `verify` mirrors it. Both sides must end in
/// sync whenever the statement is accepted.
fn prove_and_verify<S>(
    prove: impl FnOnce(&mut ArgProver<B>) -> SnarkResult<S>,
    verify: impl FnOnce(&mut ArgVerifier<B>, S) -> SnarkResult<()>,
) -> SnarkResult<()> {
    proof_of_accepted(prove, verify).map(drop)
}

/// [`prove_and_verify`], handing back the proof that was accepted.
fn proof_of_accepted<S>(
    prove: impl FnOnce(&mut ArgProver<B>) -> SnarkResult<S>,
    verify: impl FnOnce(&mut ArgVerifier<B>, S) -> SnarkResult<()>,
) -> SnarkResult<SNARKProof<B>> {
    let (mut prover, mut verifier) = setup();
    let statement = prove(&mut prover)?;
    let proof = prover.build_proof()?;
    verifier.set_proof_ref(&proof);
    verify(&mut verifier, statement)?;
    verifier.verify()?;
    assert_prover_verifier_in_sync(&prover, &verifier);
    Ok(proof)
}

fn assert_accepted(res: SnarkResult<()>) {
    if let Err(err) = res {
        panic!("a true statement must be accepted, got {err:?}");
    }
}

/// A false statement. Under `honest-prover` the prover itself refuses it,
/// at claim time or while proving; otherwise the proof is built and it is
/// the verifier that must reject.
fn assert_rejected(res: SnarkResult<()>) {
    let err = res.expect_err("a false statement must not be accepted");
    if cfg!(feature = "honest-prover") {
        assert!(
            matches!(err, SnarkError::ProverError(_)),
            "expected the honest prover to refuse, got {err:?}"
        );
    } else {
        assert_verifier_error(err);
    }
}

/// The prover was honest about its own statement but the verifier checked a
/// different one: a verifier error in both feature modes.
fn assert_rejected_by_verifier(res: SnarkResult<()>) {
    assert_verifier_error(
        res.expect_err("the verifier must reject a statement that was not proved"),
    );
}

fn assert_verifier_error(err: SnarkError) {
    assert!(
        matches!(err, SnarkError::VerifierError(_)),
        "expected VerifierError, got {err:?}"
    );
}

/// `add_mv_lookup_claim` with a committed table and committed subs, and
/// nothing else in the proof.
fn lookup_e2e(table: &[F], subs: &[Vec<F>]) -> SnarkResult<()> {
    prove_and_verify(
        |prover| {
            let table = commit(prover, table)?;
            let mut ids = vec![table.id()];
            for sub in subs {
                let sub = commit(prover, sub)?;
                prover.add_mv_lookup_claim(table.id(), sub.id())?;
                ids.push(sub.id());
            }
            Ok(ids)
        },
        |verifier, ids| {
            let oracles = track_all(verifier, &ids)?;
            for sub in &oracles[1..] {
                verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())?;
            }
            Ok(())
        },
    )
}

/// `HintedLookupCheckPIOP` with a multiplicity column chosen by the caller.
fn hinted_e2e(table: &[F], subs: &[Vec<F>], multiplicity: &[F]) -> SnarkResult<()> {
    prove_and_verify(
        |prover| {
            let super_col = commit(prover, table)?;
            let included_cols = subs
                .iter()
                .map(|sub| commit(prover, sub))
                .collect::<SnarkResult<Vec<_>>>()?;
            let super_col_multiplicity = commit(prover, multiplicity)?;
            let mut ids = vec![super_col.id()];
            ids.extend(included_cols.iter().map(TrackedPoly::id));
            ids.push(super_col_multiplicity.id());
            HintedLookupCheckPIOP::<B>::prove(
                prover,
                HintedLookupCheckProverInput {
                    included_cols,
                    super_col,
                    super_col_multiplicity,
                },
            )?;
            Ok(ids)
        },
        |verifier, ids| {
            let mut oracles = track_all(verifier, &ids)?;
            let super_col_multiplicity = oracles.pop().unwrap();
            let super_tracked_col_oracle = oracles.remove(0);
            HintedLookupCheckPIOP::<B>::verify(
                verifier,
                HintedLookupCheckVerifierInput {
                    included_tracked_col_oracles: oracles,
                    super_tracked_col_oracle,
                    super_col_multiplicity,
                },
            )
        },
    )
}

/// `LookupCheckPIOP`, which commits the multiplicity column itself.
fn lookup_piop_e2e(table: &[F], subs: &[Vec<F>]) -> SnarkResult<()> {
    prove_and_verify(
        |prover| {
            let super_col = commit(prover, table)?;
            let included_cols = subs
                .iter()
                .map(|sub| commit(prover, sub))
                .collect::<SnarkResult<Vec<_>>>()?;
            let mut ids = vec![super_col.id()];
            ids.extend(included_cols.iter().map(TrackedPoly::id));
            LookupCheckPIOP::<B>::prove(
                prover,
                LookupCheckProverInput {
                    included_cols,
                    super_col,
                },
            )?;
            Ok(ids)
        },
        |verifier, ids| {
            let mut oracles = track_all(verifier, &ids)?;
            let super_tracked_col_oracle = oracles.remove(0);
            LookupCheckPIOP::<B>::verify(
                verifier,
                LookupCheckVerifierInput {
                    included_tracked_col_oracles: oracles,
                    super_tracked_col_oracle,
                },
            )?;
            Ok(())
        },
    )
}

/// A column of a keyed sum with its optional multiplicity.
type KeyedCol = (Vec<F>, Option<Vec<F>>);
/// One side of a keyed sum: its columns and their multiplicities.
type KeyedSide<T> = (Vec<T>, Vec<Option<T>>);

fn commit_keyed_side(
    prover: &mut ArgProver<B>,
    side: &[KeyedCol],
) -> SnarkResult<KeyedSide<TrackedPoly<B>>> {
    let mut cols = Vec::new();
    let mut mults = Vec::new();
    for (col, mult) in side {
        cols.push(commit(prover, col)?);
        mults.push(mult.as_ref().map(|m| commit(prover, m)).transpose()?);
    }
    Ok((cols, mults))
}

fn keyed_side_ids(
    cols: &[TrackedPoly<B>],
    mults: &[Option<TrackedPoly<B>>],
) -> Vec<(TrackerID, Option<TrackerID>)> {
    cols.iter()
        .zip(mults)
        .map(|(col, mult)| (col.id(), mult.as_ref().map(TrackedPoly::id)))
        .collect()
}

fn track_keyed_side(
    verifier: &mut ArgVerifier<B>,
    ids: &[(TrackerID, Option<TrackerID>)],
) -> SnarkResult<KeyedSide<TrackedOracle<B>>> {
    let mut cols = Vec::new();
    let mut mults = Vec::new();
    for (col, mult) in ids {
        cols.push(verifier.track_mv_com_by_id(*col)?);
        mults.push(mult.map(|id| verifier.track_mv_com_by_id(id)).transpose()?);
    }
    Ok((cols, mults))
}

/// `KeyedSumcheck` driven directly on committed columns. The two sides are
/// compared right after the PIOP call as well as at the end.
fn keyed_e2e(fs: &[KeyedCol], gs: &[KeyedCol]) -> SnarkResult<()> {
    prove_and_verify(
        |prover| {
            let (fxs, mfxs) = commit_keyed_side(prover, fs)?;
            let (gxs, mgxs) = commit_keyed_side(prover, gs)?;
            let ids = (keyed_side_ids(&fxs, &mfxs), keyed_side_ids(&gxs, &mgxs));
            KeyedSumcheck::<B>::prove(
                prover,
                KeyedSumcheckProverInput {
                    fxs,
                    gxs,
                    mfxs,
                    mgxs,
                },
            )?;
            Ok((ids, prover.deep_copy()))
        },
        |verifier, ((f_ids, g_ids), prover_after_piop)| {
            let (fxs, mfxs) = track_keyed_side(verifier, &f_ids)?;
            let (gxs, mgxs) = track_keyed_side(verifier, &g_ids)?;
            KeyedSumcheck::<B>::verify(
                verifier,
                KeyedSumcheckVerifierInput {
                    fxs,
                    gxs,
                    mfxs,
                    mgxs,
                },
            )?;
            assert_prover_verifier_in_sync(&prover_after_piop, verifier);
            Ok(())
        },
    )
}

/// One keyed-sum relation: its `f` side and its `g` side.
type KeyedRelation<'a> = (&'a [KeyedCol], &'a [KeyedCol]);
/// The ids of one side's columns and multiplicities.
type KeyedSideIds = Vec<(TrackerID, Option<TrackerID>)>;

/// Keyed sums claimed with `add_mv_keyed_sum_claim` and discharged when the
/// proof is built. All `relations` are committed; the prover claims those at
/// `claimed`, in that order, and the verifier those at `mirrored`. Making
/// the claims moves neither side.
fn deferred_keyed_e2e_mirroring(
    relations: &[KeyedRelation],
    claimed: &[usize],
    mirrored: &[usize],
) -> SnarkResult<SNARKProof<B>> {
    proof_of_accepted(
        |prover| {
            let mut ids: Vec<(KeyedSideIds, KeyedSideIds)> = Vec::new();
            let mut inputs = Vec::new();
            for (fs, gs) in relations {
                let (fxs, mfxs) = commit_keyed_side(prover, fs)?;
                let (gxs, mgxs) = commit_keyed_side(prover, gs)?;
                ids.push((keyed_side_ids(&fxs, &mfxs), keyed_side_ids(&gxs, &mgxs)));
                inputs.push(Some(KeyedSumcheckProverInput {
                    fxs,
                    gxs,
                    mfxs,
                    mgxs,
                }));
            }
            let position = |prover: &ArgProver<B>| {
                let mut copy = prover.deep_copy();
                let challenge = copy.get_and_append_challenge(b"parity probe").unwrap();
                (copy.peek_next_id(), challenge)
            };
            let before_claims = position(prover);
            for relation in claimed {
                let input = inputs[*relation]
                    .take()
                    .expect("a relation is claimed once");
                prover.add_mv_keyed_sum_claim(input)?;
            }
            assert_eq!(position(prover), before_claims);
            Ok((ids, prover.deep_copy()))
        },
        |verifier, (ids, prover_after_claims)| {
            let mut inputs = Vec::new();
            for (f_ids, g_ids) in &ids {
                let (fxs, mfxs) = track_keyed_side(verifier, f_ids)?;
                let (gxs, mgxs) = track_keyed_side(verifier, g_ids)?;
                inputs.push(Some(KeyedSumcheckVerifierInput {
                    fxs,
                    gxs,
                    mfxs,
                    mgxs,
                }));
            }
            for relation in mirrored {
                let input = inputs[*relation]
                    .take()
                    .expect("a relation is mirrored once");
                verifier.add_mv_keyed_sum_claim(input)?;
            }
            assert_prover_verifier_in_sync(&prover_after_claims, verifier);
            Ok(())
        },
    )
}

/// [`deferred_keyed_e2e_mirroring`] with every relation claimed and a
/// verifier that mirrors the prover.
fn deferred_keyed_e2e(relations: &[KeyedRelation]) -> SnarkResult<()> {
    let all: Vec<usize> = (0..relations.len()).collect();
    deferred_keyed_e2e_mirroring(relations, &all, &all).map(drop)
}

/// Prover side of a transparent range table `0..2^nv`: tracked, never
/// committed.
fn range_table(nv: usize) -> MLE<F> {
    mle(&fv(0..1u64 << nv))
}

/// Verifier side of [`range_table`]: the table's MLE `sum_i 2^i x_i`, read
/// from the low `nv` coordinates of the query point. Slicing (rather than
/// zipping) makes a point shorter than `nv` a panic, as it is for the
/// closures downstream gadgets register.
fn range_oracle(nv: usize) -> Oracle<F> {
    Oracle::new_multivariate(nv, move |x: Vec<F>| {
        let mut acc = F::zero();
        let mut weight = F::one();
        for xi in &x[..nv] {
            acc += weight * xi;
            weight += weight;
        }
        Ok(acc)
    })
}

/// A range check the way downstream sign gadgets issue it: `data * activator`
/// (a virtual product of two commitments) looked up in a transparent range
/// table that only the prover materialises.
fn transparent_range_e2e(table_nv: usize, data: &[F], activator: &[F]) -> SnarkResult<()> {
    prove_and_verify(
        |prover| {
            let data = commit(prover, data)?;
            let activator = commit(prover, activator)?;
            let table = prover.track_mat_mv_poly(range_table(table_nv));
            let sub = &data * &activator;
            prover.add_mv_lookup_claim(table.id(), sub.id())?;
            Ok([data.id(), activator.id()])
        },
        |verifier, ids| {
            let oracles = track_all(verifier, &ids)?;
            let table = verifier.track_base_oracle(range_oracle(table_nv));
            let sub = &oracles[0] * &oracles[1];
            verifier.add_mv_lookup_claim(table.id(), sub.id())
        },
    )
}

/// A 0/1 column with the first `active` of `2^nv` rows set.
fn prefix_activator(nv: usize, active: usize) -> Vec<F> {
    fv((0..1usize << nv).map(|i| u64::from(i < active)))
}

#[test]
fn lookup_value_outside_table_is_rejected() {
    under_each_protocol(|_| {
        let table = fv(0..64);
        let good = fv((0..64).map(|i| (i * 7) % 64));
        assert_accepted(lookup_e2e(&table, std::slice::from_ref(&good)));

        let mut bad = good.clone();
        bad[13] = F::from(1000u64);
        assert_rejected(lookup_e2e(&table, &[bad]));

        // One past the table's largest value, in the last row of the second sub.
        let mut bad = good.clone();
        bad[63] = F::from(64u64);
        assert_rejected(lookup_e2e(&table, &[good, bad]));
    });
}

#[test]
fn lookup_sub_smaller_than_table() {
    under_each_protocol(|_| {
        let table = fv(0..256);
        assert_accepted(lookup_e2e(&table, &[fv((0..16).map(|i| i * 16 + 3))]));

        let mut bad = fv((0..16).map(|i| i * 16 + 3));
        bad[5] = F::from(256u64);
        assert_rejected(lookup_e2e(&table, &[bad]));
    });
}

#[test]
fn lookup_sub_larger_than_table() {
    under_each_protocol(|_| {
        let table = fv(0..16);
        assert_accepted(lookup_e2e(&table, &[fv((0..256).map(|i| (i * 5) % 16))]));

        let mut bad = fv((0..256).map(|i| (i * 5) % 16));
        bad[200] = F::from(16u64);
        assert_rejected(lookup_e2e(&table, &[bad]));
    });
}

#[test]
fn lookup_three_subs_table_with_duplicates() {
    under_each_protocol(|_| {
        // Every table value occurs four times; an odd number of subs of one size.
        let table = fv((0..64).map(|i| i % 16));
        let subs = [
            fv((0..64).map(|i| (i * 7) % 16)),
            fv((0..64).map(|i| (i * 3) % 8)),
            fv((0..64).map(|i| i % 5)),
        ];
        assert_accepted(lookup_e2e(&table, &subs));

        let mut bad = subs.clone();
        bad[2][40] = F::from(16u64);
        assert_rejected(lookup_e2e(&table, &bad));
    });
}

/// Subs of three different sizes against one table, on both sides of the
/// table's own size.
#[test]
fn lookup_subs_of_mixed_sizes_one_table() {
    under_each_protocol(|_| {
        let table = fv(0..32);
        let subs = [
            fv((0..8).map(|i| i * 4)),
            fv((0..128).map(|i| (i * 11) % 32)),
            fv((0..32).map(|i| 31 - i)),
            fv((0..128).map(|i| i % 3)),
        ];
        assert_accepted(lookup_e2e(&table, &subs));

        let mut bad = subs.clone();
        bad[0][7] = F::from(32u64);
        assert_rejected(lookup_e2e(&table, &bad));
    });
}

/// The same claim made twice, and a table looked up in itself.
#[test]
fn lookup_repeated_and_self_claims() {
    under_each_protocol(|_| {
        assert_accepted(prove_and_verify(
            |prover| {
                let table = commit(prover, &fv(0..16))?;
                let sub = commit(prover, &fv((0..16).map(|i| (i * 3) % 8)))?;
                prover.add_mv_lookup_claim(table.id(), sub.id())?;
                prover.add_mv_lookup_claim(table.id(), sub.id())?;
                prover.add_mv_lookup_claim(table.id(), table.id())?;
                Ok([table.id(), sub.id()])
            },
            |verifier, ids| {
                let oracles = track_all(verifier, &ids)?;
                verifier.add_mv_lookup_claim(oracles[0].id(), oracles[1].id())?;
                verifier.add_mv_lookup_claim(oracles[0].id(), oracles[1].id())?;
                verifier.add_mv_lookup_claim(oracles[0].id(), oracles[0].id())
            },
        ));
    });
}

#[test]
fn hinted_lookup_correct_multiplicity_accepts() {
    under_each_protocol(|_| {
        // Every even table value is hit twice, odd values never.
        let table = fv(0..64);
        let sub = fv((0..64).map(|i| (i * 2) % 64));
        let multiplicity = fv((0..64).map(|i| if i % 2 == 0 { 2 } else { 0 }));
        assert_accepted(hinted_e2e(&table, &[sub], &multiplicity));

        // Two subs of different sizes feeding one multiplicity column.
        let subs = [fv((0..64).map(|i| i % 16)), fv(0..16)];
        let multiplicity = fv((0..64).map(|i| if i < 16 { 5 } else { 0 }));
        assert_accepted(hinted_e2e(&table, &subs, &multiplicity));
    });
}

#[test]
fn hinted_lookup_wrong_multiplicity_is_rejected() {
    under_each_protocol(|_| {
        let table = fv(0..64);
        let sub = fv((0..64).map(|i| (i * 2) % 64));
        let multiplicity = fv((0..64).map(|i| if i % 2 == 0 { 2 } else { 0 }));

        let mut one_more = multiplicity.clone();
        one_more[4] += F::one();
        assert_rejected(hinted_e2e(&table, std::slice::from_ref(&sub), &one_more));

        // Same total, so a check on the multiplicity sum alone would pass.
        let mut moved = multiplicity;
        moved[4] += F::one();
        moved[6] -= F::one();
        assert_rejected(hinted_e2e(&table, &[sub], &moved));
    });
}

#[test]
fn lookup_check_piop_accepts_and_rejects() {
    under_each_protocol(|_| {
        let table = fv(0..16);
        assert_accepted(lookup_piop_e2e(&table, &[fv((0..32).map(|i| (i * 3) % 8))]));

        // Every table entry is hit exactly once, so the multiplicity column the
        // PIOP commits is constant and travels as a committed constant.
        assert_accepted(lookup_piop_e2e(
            &table,
            &[fv((0..16).map(|i| (i * 5 + 3) % 16))],
        ));
        // Likewise with two subs: the constant is 2.
        assert_accepted(lookup_piop_e2e(
            &table,
            &[
                fv((0..16).map(|i| 15 - i)),
                fv((0..16).map(|i| (i * 7) % 16)),
            ],
        ));

        let mut bad = fv((0..16).map(|i| (i * 5 + 3) % 16));
        bad[9] = F::from(16u64);
        assert_rejected(lookup_piop_e2e(&table, &[bad]));
    });
}

#[test]
fn keyed_sumcheck_multiplicities_both_sides_mixed_nv() {
    under_each_protocol(|_| {
        let f = fv(0..32);
        let mf = fv((0..32).map(|i| (i % 3) + 1));
        let g = fv((0..128).map(|i| i % 32));
        let mg = fv((0..128).map(|i| if i < 32 { (i % 3) + 1 } else { 0 }));
        assert_accepted(keyed_e2e(
            &[(f.clone(), Some(mf.clone()))],
            &[(g.clone(), Some(mg.clone()))],
        ));

        // A second, smaller f column with unit multiplicity, balanced on the g
        // side by one more unit on its eight values.
        let small = fv(0..8);
        let mg_with_small = fv((0..128).map(|i| match i {
            0..8 => (i % 3) + 2,
            8..32 => (i % 3) + 1,
            _ => 0,
        }));
        assert_accepted(keyed_e2e(
            &[(f.clone(), Some(mf.clone())), (small, None)],
            &[(g.clone(), Some(mg_with_small))],
        ));

        let mut wrong_mf = mf;
        wrong_mf[0] += F::one();
        assert_rejected(keyed_e2e(&[(f, Some(wrong_mf))], &[(g, Some(mg))]));
    });
}

#[test]
fn keyed_sumcheck_permutation_and_non_permutation() {
    under_each_protocol(|_| {
        let f = fv(0..64);
        let g = fv((0..64).map(|i| (i * 5 + 3) % 64));
        assert_accepted(keyed_e2e(&[(f.clone(), None)], &[(g.clone(), None)]));

        let mut not_a_permutation = g.clone();
        not_a_permutation[9] = F::from(99u64);
        assert_rejected(keyed_e2e(
            &[(f.clone(), None)],
            &[(not_a_permutation, None)],
        ));

        // Two columns a side: only the union of each side has to match.
        let low = fv(0..32);
        let high = fv(32..64);
        let evens = fv((0..32).map(|i| 2 * i));
        let odds = fv((0..32).map(|i| 2 * i + 1));
        assert_accepted(keyed_e2e(
            &[(low.clone(), None), (high.clone(), None)],
            &[(odds.clone(), None), (evens.clone(), None)],
        ));
        // One column against two half-size ones.
        assert_accepted(keyed_e2e(
            &[(f, None)],
            &[(evens.clone(), None), (odds, None)],
        ));
        // Both sides hold 64 values, but 0..32 twice is not 0..64.
        assert_rejected(keyed_e2e(
            &[(low.clone(), None), (low, None)],
            &[(evens, None), (high, None)],
        ));
    });
}

/// Columns and multiplicities that were committed as constants reach the
/// keyed sum as constant handles, not as tracked polynomials.
#[test]
fn keyed_sumcheck_constant_columns_and_multiplicities() {
    under_each_protocol(|_| {
        // `n` copies of the key 7, credited to row 7 of a table.
        let counts = |n: u64| fv((0..16).map(|i| if i == 7 { n } else { 0 }));
        assert_accepted(keyed_e2e(
            &[(fv([7; 8]), None)],
            &[(fv(0..16), Some(counts(8)))],
        ));
        assert_rejected(keyed_e2e(
            &[(fv([7; 8]), None)],
            &[(fv(0..16), Some(counts(7)))],
        ));

        // Constant columns on both sides, of equal and of different sizes.
        assert_accepted(keyed_e2e(&[(fv([7; 8]), None)], &[(fv([7; 8]), None)]));
        assert_accepted(keyed_e2e(
            &[(fv([7; 8]), None), (fv([7; 8]), None)],
            &[(fv([7; 16]), None)],
        ));
        assert_rejected(keyed_e2e(&[(fv([7; 8]), None)], &[(fv([6; 8]), None)]));

        // Constant multiplicities.
        let f = fv(0..8);
        let g = fv((0..8).map(|i| 7 - i));
        assert_accepted(keyed_e2e(
            &[(f.clone(), Some(fv([3; 8])))],
            &[(g.clone(), Some(fv([3; 8])))],
        ));
        assert_rejected(keyed_e2e(
            &[(f, Some(fv([3; 8])))],
            &[(g, Some(fv([4; 8])))],
        ));
    });
}

/// A constant column under a constant multiplicity, and under weights with
/// fewer rows than it has. The term runs over the larger of the two: the
/// column's value is counted once per row of that, with the weight the row
/// has as the weights repeat.
#[test]
fn keyed_sumcheck_constant_column_under_constant_and_narrower_multiplicities() {
    under_each_protocol(|_| {
        let table = |sevens: u64| {
            let counts = fv((0..16).map(|i| if i == 7 { sevens } else { 0 }));
            [(fv(0..16), Some(counts))]
        };
        // `rows` sevens, weighed 3 on each of `weight_rows` rows.
        for (rows, weight_rows) in [(8, 8), (8, 16), (16, 8), (1, 4), (4, 1)] {
            let column = [(fv(vec![7; rows]), Some(fv(vec![3; weight_rows])))];
            let weight = 3 * rows.max(weight_rows) as u64;
            assert_accepted(keyed_e2e(&column, &table(weight)));
            for other in [3 * rows as u64 - 1, 3 * weight_rows as u64 + 1, 2 * weight] {
                assert_rejected(keyed_e2e(&column, &table(other)));
            }
        }

        // 16 sevens under 8 weights that add up to 36, each used twice.
        let column = [(fv([7; 16]), Some(fv(1..9)))];
        assert_accepted(keyed_e2e(&column, &table(72)));
        assert_rejected(keyed_e2e(&column, &table(36)));
    });
}

/// As `lookup_constant_sub_wider_than_every_commitment`, through the PIOP.
#[test]
fn keyed_sumcheck_constant_column_wider_than_every_commitment() {
    under_each_protocol(|_| {
        let counts = fv((0..16).map(|i| if i == 7 { 32 } else { 0 }));
        assert_accepted(keyed_e2e(
            &[(fv([7; 32]), None)],
            &[(fv(0..16), Some(counts))],
        ));
    });
}

/// A multiplicity with more rows than its column, and the other way round:
/// each term of the sum ranges over the larger of the two, the smaller one
/// repeating.
#[test]
fn keyed_sum_column_and_multiplicity_of_different_nv() {
    under_each_protocol(|_| {
        // One key, eight weights adding up to 28.
        let counts = |n: u64| fv((0..16).map(|i| if i == 7 { n } else { 0 }));
        assert_accepted(keyed_e2e(
            &[(fv([7]), Some(fv(0..8)))],
            &[(fv(0..16), Some(counts(28)))],
        ));
        assert_rejected(keyed_e2e(
            &[(fv([7]), Some(fv(0..8)))],
            &[(fv(0..16), Some(counts(27)))],
        ));

        // Keys 0..8 repeating under 32 weights.
        let per_key =
            fv((0..8).map(|key| (0..32u64).filter(|i| i % 8 == key).map(|i| i + 1).sum()));
        assert_accepted(keyed_e2e(
            &[(fv(0..8), Some(fv((0..32).map(|i| i + 1))))],
            &[(fv(0..8), Some(per_key))],
        ));

        // 32 keys, each of 0..8 four times, under 8 repeating weights.
        assert_accepted(keyed_e2e(
            &[(fv((0..32).map(|i| i % 8)), Some(fv((0..8).map(|i| i + 1))))],
            &[(fv(0..8), Some(fv((0..8).map(|key| 4 * (key + 1)))))],
        ));
    });
}

#[test]
fn lookup_sub_virtual_product() {
    under_each_protocol(|_| {
        let table = fv(0..16);
        let activator = prefix_activator(5, 20);
        // Active rows hold table values. Inactive rows hold values far outside
        // the table: the activator, not the data, is what makes them harmless.
        let data = fv((0..32).map(|i| if i < 20 { (i * 3) % 16 } else { 1000 + i }));
        let run = |data: &[F]| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &table)?;
                    let data = commit(prover, data)?;
                    let activator = commit(prover, &activator)?;
                    let sub = &data * &activator;
                    prover.add_mv_lookup_claim(table.id(), sub.id())?;
                    Ok([table.id(), data.id(), activator.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    let sub = &oracles[1] * &oracles[2];
                    verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())
                },
            )
        };
        assert_accepted(run(&data));

        let mut bad = data.clone();
        bad[19] = F::from(16u64);
        assert_rejected(run(&bad));
    });
}

/// A constant data chunk is committed as a constant, so `data * activator`
/// reaches the lookup as a scalar multiple of the activator; an all-zero
/// chunk (the high limbs of small integers) makes that scalar zero.
#[test]
fn lookup_sub_committed_constant_times_activator() {
    under_each_protocol(|_| {
        let run = |chunk: u64| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &fv(0..16))?;
                    let data = commit(prover, &fv([chunk; 32]))?;
                    assert!(data.is_constant());
                    let activator = commit(prover, &prefix_activator(5, 11))?;
                    let sub = &data * &activator;
                    prover.add_mv_lookup_claim(table.id(), sub.id())?;
                    Ok([table.id(), data.id(), activator.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    let sub = &oracles[1] * &oracles[2];
                    verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())
                },
            )
        };
        assert_accepted(run(0));
        assert_accepted(run(7));
        assert_rejected(run(16));
    });
}

/// As above with the sub far wider than the table, so that the claim on the
/// all-zero sub is the only one of its size in the proof.
#[test]
fn lookup_sub_zero_constant_times_activator_far_wider_than_the_table() {
    under_each_protocol(|_| {
        let run = |chunk: u64| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &fv(0..4))?;
                    let data = commit(prover, &fv([chunk; 256]))?;
                    assert!(data.is_constant());
                    let activator = commit(prover, &prefix_activator(8, 201))?;
                    let sub = &data * &activator;
                    prover.add_mv_lookup_claim(table.id(), sub.id())?;
                    Ok([table.id(), data.id(), activator.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    let sub = &oracles[1] * &oracles[2];
                    verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())
                },
            )
        };
        assert_accepted(run(0));
        assert_accepted(run(3));
        assert_rejected(run(4));
    });
}

/// A window activator that covers every row, or none, is a constant: the
/// output of a filter that kept everything or nothing. Both sides have to
/// count it as one when they plan the sumchecks, or they split the claims
/// differently. The two plain claims put the plan where one degree more or
/// less on the sub decides it.
#[test]
fn lookup_sub_under_a_window_activator_that_is_constant() {
    under_each_protocol(|_| {
        let run = |active: usize, data_modulus: u64| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &fv(0..8))?;
                    let data = commit(prover, &fv((0..8).map(|i| (i * 3 + 1) % data_modulus)))?;
                    let activator = prover.get_or_build_contig_one_poly(3, active)?;
                    let sub = &data * &activator;
                    prover.add_mv_lookup_claim(table.id(), sub.id())?;

                    let narrow = fv(0..8);
                    let narrow_poly = commit(prover, &narrow)?;
                    prover.add_mv_sumcheck_claim(narrow_poly.id(), sum(&narrow))?;

                    let wide = fv((0..16).map(|i| i + 2));
                    let wide_poly = commit(prover, &wide)?;
                    let square = &wide_poly * &wide_poly;
                    let square_sum = sum(&wide.iter().map(|v| *v * v).collect::<Vec<F>>());
                    prover.add_mv_sumcheck_claim(square.id(), square_sum)?;

                    let ids = [table.id(), data.id(), narrow_poly.id(), wide_poly.id()];
                    Ok((ids, sum(&narrow), square_sum))
                },
                |verifier, (ids, narrow_sum, square_sum)| {
                    // In the prover's order: the activator and the product take
                    // their ids between the commitments.
                    let lookup = track_all(verifier, &ids[..2])?;
                    let activator = verifier.get_or_build_contig_one_poly(3, active)?;
                    let sub = &lookup[1] * &activator;
                    verifier.add_mv_lookup_claim(lookup[0].id(), sub.id())?;

                    let narrow = verifier.track_mv_com_by_id(ids[2])?;
                    verifier.add_mv_sumcheck_claim(narrow.id(), narrow_sum);
                    let wide = verifier.track_mv_com_by_id(ids[3])?;
                    let square = &wide * &wide;
                    verifier.add_mv_sumcheck_claim(square.id(), square_sum);
                    Ok(())
                },
            )
        };
        for active in [0, 8, 5] {
            assert_accepted(run(active, 8));
        }
        // Rows 1 and 4 leave the table; an empty window hides them.
        assert_accepted(run(0, 11));
        assert_rejected(run(8, 11));
        assert_rejected(run(5, 11));
    });
}

/// `sub ⊆ 0..16` for a sub with `rows` copies of `chunk`, committed as a
/// constant. `derived` multiplies it by an all-ones activator, itself a
/// committed constant, so the sub is a folded constant that only gets a
/// tracker id when the claim asks for one. `sibling` commits one more
/// column with as many rows as the sub, as the other columns of a real table
/// would be.
fn constant_sub_e2e(chunk: u64, rows: usize, derived: bool, sibling: bool) -> SnarkResult<()> {
    prove_and_verify(
        |prover| {
            let table = commit(prover, &fv(0..16))?;
            let data = commit(prover, &fv(vec![chunk; rows]))?;
            assert!(data.is_constant());
            let mut ids = vec![table.id(), data.id()];
            let sub = if derived {
                let activator = commit(prover, &fv(vec![1; rows]))?;
                ids.push(activator.id());
                &data * &activator
            } else {
                data
            };
            assert!(sub.is_constant());
            if sibling {
                ids.push(commit(prover, &fv(0..rows as u64))?.id());
            }
            prover.add_mv_lookup_claim(table.id(), sub.id())?;
            Ok(ids)
        },
        |verifier, ids| {
            let oracles = track_all(verifier, &ids)?;
            let sub = if derived {
                &oracles[1] * &oracles[2]
            } else {
                oracles[1].clone()
            };
            verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())
        },
    )
}

/// A constant chunk without an activator: the sub is a committed constant.
#[test]
fn lookup_sub_bare_committed_constant() {
    under_each_protocol(|_| {
        for (rows, sibling) in [(8, false), (16, false), (64, true)] {
            assert_accepted(constant_sub_e2e(0, rows, false, sibling));
            assert_accepted(constant_sub_e2e(7, rows, false, sibling));
            assert_rejected(constant_sub_e2e(16, rows, false, sibling));
        }
    });
}

/// A constant chunk times a constant activator folds to a constant that was
/// never committed; asking for its id tracks it on both sides.
#[test]
fn lookup_sub_derived_constant() {
    under_each_protocol(|_| {
        for (rows, sibling) in [(8, false), (16, false), (64, true)] {
            assert_accepted(constant_sub_e2e(0, rows, true, sibling));
            assert_accepted(constant_sub_e2e(7, rows, true, sibling));
            assert_rejected(constant_sub_e2e(16, rows, true, sibling));
        }
    });
}

/// A scalar times a constant column folds to a constant with the column's
/// rows on both sides, whichever factor comes first: its size decides how
/// often its value is looked up, or counted in a keyed sum.
#[test]
fn scalar_times_constant_column_keeps_the_rows_of_the_column() {
    under_each_protocol(|_| {
        let lookup = |scalar_first: bool, scalar: u64| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &fv(0..16))?;
                    let column = commit(prover, &fv([3; 8]))?;
                    assert!(column.is_constant());
                    let scalar = prover.track_mat_mv_cnst_poly(0, F::from(scalar));
                    let sub = if scalar_first {
                        &scalar * &column
                    } else {
                        &column * &scalar
                    };
                    assert!(sub.is_constant());
                    prover.add_mv_lookup_claim(table.id(), sub.id())?;
                    Ok([table.id(), column.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    let scalar = verifier.track_mat_mv_cnst_oracle(0, F::from(scalar));
                    let sub = if scalar_first {
                        &scalar * &oracles[1]
                    } else {
                        &oracles[1] * &scalar
                    };
                    verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())
                },
            )
        };
        // The same product as a column of a keyed sum, where it stays a
        // constant handle: 8 rows of 6 against a table that counts `count`.
        let keyed = |scalar_first: bool, count: u64| {
            let mut counts = vec![F::zero(); 16];
            counts[6] = F::from(count);
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &fv(0..16))?;
                    let counts = commit(prover, &counts)?;
                    let column = commit(prover, &fv([3; 8]))?;
                    let scalar = prover.track_mat_mv_cnst_poly(0, F::from(2u64));
                    let product = if scalar_first {
                        &scalar * &column
                    } else {
                        &column * &scalar
                    };
                    let ids = [table.id(), counts.id(), column.id()];
                    KeyedSumcheck::<B>::prove(
                        prover,
                        KeyedSumcheckProverInput {
                            fxs: vec![product],
                            mfxs: vec![None],
                            gxs: vec![table],
                            mgxs: vec![Some(counts)],
                        },
                    )?;
                    Ok(ids)
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    let scalar = verifier.track_mat_mv_cnst_oracle(0, F::from(2u64));
                    let product = if scalar_first {
                        &scalar * &oracles[2]
                    } else {
                        &oracles[2] * &scalar
                    };
                    KeyedSumcheck::<B>::verify(
                        verifier,
                        KeyedSumcheckVerifierInput {
                            fxs: vec![product],
                            mfxs: vec![None],
                            gxs: vec![oracles[0].clone()],
                            mgxs: vec![Some(oracles[1].clone())],
                        },
                    )
                },
            )
        };
        for scalar_first in [true, false] {
            assert_accepted(lookup(scalar_first, 2));
            assert_rejected(lookup(scalar_first, 7));
            assert_accepted(keyed(scalar_first, 8));
            // One row of 6 is what a product of the scalar's size would be.
            assert_rejected(keyed(scalar_first, 1));
        }
    });
}

/// The constant sub is the largest column of the whole proof: the table and
/// its multiplicity have 16 rows and nothing else is committed.
#[test]
fn lookup_constant_sub_wider_than_every_commitment() {
    under_each_protocol(|_| {
        assert_accepted(constant_sub_e2e(7, 32, false, false));
        assert_accepted(constant_sub_e2e(7, 64, true, false));
        assert_rejected(constant_sub_e2e(16, 32, false, false));
    });
}

/// Two sub columns of one size whose tables are held at different sizes: a
/// committed constant, which is one value, or a column whose rows repeat
/// and are held once, beside a column held row by row. Neighbours of one
/// size share a helper under LogUp, and it is that of both columns
/// whichever comes first.
#[test]
fn lookup_neighbouring_subs_held_at_different_sizes() {
    under_each_protocol(|_| {
        let table = fv(0..16);
        let dense = fv((0..8).map(|i| (i * 5 + 1) % 16));
        let constant = fv([7; 8]);
        for subs in [[&constant, &dense], [&dense, &constant]] {
            let subs = subs.map(Vec::clone);
            assert_accepted(lookup_e2e(&table, &subs));
            let mut outside = subs.clone();
            outside[0][7] = F::from(16u64);
            assert_rejected(lookup_e2e(&table, &outside));
            let mut outside = subs;
            outside[1][7] = F::from(16u64);
            assert_rejected(lookup_e2e(&table, &outside));
        }

        // Four rows that stand for eight, known to both sides.
        let run = |repeating_first: bool, repeated: &[F]| {
            let repeating = || MLE::from_evaluations_vec(3, repeated.to_vec());
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &table)?;
                    let dense = commit(prover, &dense)?;
                    let repeating = prover.track_mat_mv_poly(repeating());
                    assert_eq!(repeating.log_size(), dense.log_size());
                    let subs = if repeating_first {
                        [repeating.id(), dense.id()]
                    } else {
                        [dense.id(), repeating.id()]
                    };
                    for sub in subs {
                        prover.add_mv_lookup_claim(table.id(), sub)?;
                    }
                    Ok(([table.id(), dense.id()], subs))
                },
                |verifier, (ids, subs)| {
                    let oracles = track_all(verifier, &ids)?;
                    let repeating = repeating();
                    verifier.track_base_oracle(Oracle::new_multivariate(3, move |x: Vec<F>| {
                        Ok(repeating.evaluate(&x[..3].to_vec()))
                    }));
                    for sub in subs {
                        verifier.add_mv_lookup_claim(oracles[0].id(), sub)?;
                    }
                    Ok(())
                },
            )
        };
        for repeating_first in [true, false] {
            assert_accepted(run(repeating_first, &fv([3, 9, 3, 15])));
            assert_rejected(run(repeating_first, &fv([3, 9, 3, 16])));
        }
    });
}

/// `(a + 4·b + 16) · activator`: several terms, a scalar on a term and a
/// constant term, all under one activator.
#[test]
fn lookup_sub_multiterm_virtual() {
    under_each_protocol(|_| {
        let table = fv(0..32);
        let a = fv((0..16).map(|i| i % 4));
        let b = fv((0..16).map(|i| (i / 4) % 4));
        let activator = prefix_activator(4, 13);
        let run = |a: &[F]| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &table)?;
                    let a = commit(prover, a)?;
                    let b = commit(prover, &b)?;
                    let activator = commit(prover, &activator)?;
                    let folded =
                        (&a + &b.mul_scalar_poly(F::from(4u64))).add_scalar_poly(F::from(16u64));
                    let sub = &folded * &activator;
                    prover.add_mv_lookup_claim(table.id(), sub.id())?;
                    Ok([table.id(), a.id(), b.id(), activator.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    let folded = (&oracles[1] + &oracles[2].mul_scalar_oracle(F::from(4u64)))
                        .add_scalar_oracle(F::from(16u64));
                    let sub = &folded * &oracles[3];
                    verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())
                },
            )
        };
        assert_accepted(run(&a));

        let mut bad = a.clone();
        bad[12] = F::from(40u64);
        assert_rejected(run(&bad));
    });
}

#[test]
fn lookup_transparent_table_sub_larger() {
    under_each_protocol(|_| {
        let activator = prefix_activator(6, 50);
        // Inactive rows are zero, as in the limb columns of a sign check.
        let data = fv((0..64).map(|i| if i < 50 { (i * 7) % 16 } else { 0 }));
        assert_accepted(transparent_range_e2e(4, &data, &activator));

        let mut bad = data;
        bad[49] = F::from(16u64);
        assert_rejected(transparent_range_e2e(4, &bad, &activator));
    });
}

#[test]
fn lookup_transparent_table_sub_smaller() {
    under_each_protocol(|_| {
        let activator = prefix_activator(3, 6);
        let data = fv((0..8).map(|i| if i < 6 { i * 9 + 2 } else { 0 }));
        assert_accepted(transparent_range_e2e(6, &data, &activator));

        let mut bad = data;
        bad[0] = F::from(64u64);
        assert_rejected(transparent_range_e2e(6, &bad, &activator));
    });
}

/// The AND-table lookup of a bitwise gadget: the table depends on challenges
/// drawn after the columns are committed, exists only on the prover, and is
/// tracked after those challenges on both sides.
#[test]
fn lookup_table_tracked_after_challenge() {
    under_each_protocol(|_| {
        const BITS: usize = 2;
        let label: &'static [u8] = b"and fold";
        // Row `a + 4·b` of the table holds `r0·a + r1·b + r2·(a & b)`.
        let and_table = |rs: [F; 3]| -> Vec<F> {
            (0..1u64 << (2 * BITS))
                .map(|idx| {
                    let (a, b) = (idx % (1 << BITS), idx >> BITS);
                    rs[0] * F::from(a) + rs[1] * F::from(b) + rs[2] * F::from(a & b)
                })
                .collect()
        };
        // The same table as a multilinear polynomial in the bits of a and b.
        let and_table_oracle = |rs: [F; 3]| {
            Oracle::new_multivariate(2 * BITS, move |x: Vec<F>| {
                let mut acc = F::zero();
                let mut weight = F::one();
                for i in 0..BITS {
                    acc +=
                        weight * (rs[0] * x[i] + rs[1] * x[BITS + i] + rs[2] * x[i] * x[BITS + i]);
                    weight += weight;
                }
                Ok(acc)
            })
        };
        let a: Vec<u64> = (0..32).map(|i| i % 4).collect();
        let b: Vec<u64> = (0..32).map(|i| (i / 4) % 4).collect();
        let and: Vec<u64> = a.iter().zip(&b).map(|(a, b)| a & b).collect();
        let activator = prefix_activator(5, 27);
        let run = |and: &[u64]| {
            prove_and_verify(
                |prover| {
                    let a = commit(prover, &fv(a.iter().copied()))?;
                    let b = commit(prover, &fv(b.iter().copied()))?;
                    let and = commit(prover, &fv(and.iter().copied()))?;
                    let activator = commit(prover, &activator)?;
                    let rs = [
                        prover.get_and_append_challenge(label)?,
                        prover.get_and_append_challenge(label)?,
                        prover.get_and_append_challenge(label)?,
                    ];
                    let folded = &(&a.mul_scalar_poly(rs[0]) + &b.mul_scalar_poly(rs[1]))
                        + &and.mul_scalar_poly(rs[2]);
                    let sub = &folded * &activator;
                    let table = prover.track_mat_mv_poly(mle(&and_table(rs)));
                    prover.add_mv_lookup_claim(table.id(), sub.id())?;
                    Ok([a.id(), b.id(), and.id(), activator.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    let rs = [
                        verifier.get_and_append_challenge(label)?,
                        verifier.get_and_append_challenge(label)?,
                        verifier.get_and_append_challenge(label)?,
                    ];
                    let folded = &(&oracles[0].mul_scalar_oracle(rs[0])
                        + &oracles[1].mul_scalar_oracle(rs[1]))
                        + &oracles[2].mul_scalar_oracle(rs[2]);
                    let sub = &folded * &oracles[3];
                    let table = verifier.track_base_oracle(and_table_oracle(rs));
                    verifier.add_mv_lookup_claim(table.id(), sub.id())
                },
            )
        };
        assert_accepted(run(&and));

        // An inactive row may hold anything: it folds to the table's zero row.
        let mut garbage_in_inactive_row = and.clone();
        garbage_in_inactive_row[30] = 3;
        assert_accepted(run(&garbage_in_inactive_row));

        // An active row may not: 3 & 1 is 1.
        let mut bad = and;
        assert_eq!((a[7], b[7], bad[7]), (3, 1, 1));
        bad[7] = 2;
        assert_rejected(run(&bad));
    });
}

/// A one-row table and a one-row sub, next to an ordinary claim on a real
/// column.
#[test]
fn lookup_nv0_table_and_sub() {
    under_each_protocol(|_| {
        let other = fv(0..8);
        let run = |sub: u64| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &fv([7]))?;
                    let sub = commit(prover, &fv([sub]))?;
                    let other_p = commit(prover, &other)?;
                    prover.add_mv_sumcheck_claim(other_p.id(), sum(&other))?;
                    prover.add_mv_lookup_claim(table.id(), sub.id())?;
                    Ok([table.id(), sub.id(), other_p.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    verifier.add_mv_sumcheck_claim(oracles[2].id(), sum(&other));
                    verifier.add_mv_lookup_claim(oracles[0].id(), oracles[1].id())
                },
            )
        };
        assert_accepted(run(7));
        assert_rejected(run(8));
    });
}

/// The same lookup as the whole statement: every polynomial is a constant.
#[test]
#[ignore = "limitation of the sumcheck, not of the lookup: a proof whose only claims are on \
            polynomials without variables cannot be built; build_proof returns a PolyIOP error \
            (\"Attempt to prove a constant\") for a true statement"]
fn lookup_nv0_only_statement() {
    under_each_protocol(|_| {
        assert_accepted(lookup_e2e(&fv([7]), &[fv([7])]));
        assert_rejected(lookup_e2e(&fv([7]), &[fv([8])]));
    });
}

/// A one-row sub in a real table, and a real sub in a one-row table.
#[test]
fn lookup_nv0_against_larger_columns() {
    under_each_protocol(|_| {
        assert_accepted(lookup_e2e(&fv(0..16), &[fv([7])]));
        assert_rejected(lookup_e2e(&fv(0..16), &[fv([16])]));

        let mut bad = fv([7; 8]);
        bad[3] = F::from(6u64);
        assert_rejected(lookup_e2e(&fv([7]), &[bad]));
    });
}

/// A table that is itself a committed constant.
#[test]
fn lookup_constant_table() {
    under_each_protocol(|_| {
        assert_accepted(lookup_e2e(&fv([7; 32]), &[fv([7; 8])]));
        assert_rejected(lookup_e2e(&fv([7; 32]), &[fv([6; 8])]));
        assert_rejected(lookup_e2e(&fv([7; 8]), &[fv([7, 7, 7, 7, 7, 7, 7, 6])]));
    });
}

/// The lookup is the whole statement: the proof carries no sumcheck or
/// zerocheck claim of the caller's own, and the table is not even committed.
#[test]
fn lookup_only_statement() {
    under_each_protocol(|_| {
        assert_accepted(lookup_e2e(&fv(0..8), &[fv((0..8).map(|i| 7 - i))]));
        assert_accepted(transparent_range_e2e(
            3,
            &fv((0..8).map(|i| 7 - i)),
            &fv([1; 8]),
        ));
    });
}

/// Lookup claims against three tables, interleaved with ordinary claims and
/// with keyed sumchecks proved on the spot.
#[test]
fn several_super_groups_plus_direct_keyed_sumcheck() {
    under_each_protocol(|_| {
        struct Statement {
            ids: Vec<TrackerID>,
            summed: F,
            after_permutation: ArgProver<B>,
            after_weighted: ArgProver<B>,
        }
        let summed = fv((0..16).map(|i| i * i));
        let table_a = fv(0..16);
        let table_b = fv((0..64).map(|i| (i % 32) * 3));
        let sub_a1 = fv((0..16).map(|i| (i * 3) % 16));
        let sub_a2 = fv((0..64).map(|i| i % 11));
        let sub_b1 = fv((0..8).map(|i| i * 9));
        let data_c = fv((0..32).map(|i| if i < 25 { i } else { 0 }));
        let act_c = prefix_activator(5, 25);
        let perm_f = fv(0..32);
        let perm_g = fv((0..32).map(|i| (i * 13 + 5) % 32));
        let weighted_f = fv((0..8).map(|i| i + 100));
        let weighted_mf = fv((0..8).map(|i| i + 1));
        let weighted_g = fv((0..32).map(|i| (i % 8) + 100));
        let weighted_mg = fv((0..32).map(|i| if i < 8 { i + 1 } else { 0 }));

        assert_accepted(prove_and_verify(
            |prover| {
                let cols = [
                    &summed,
                    &table_a,
                    &table_b,
                    &sub_a1,
                    &sub_a2,
                    &sub_b1,
                    &data_c,
                    &act_c,
                    &perm_f,
                    &perm_g,
                    &weighted_f,
                    &weighted_mf,
                    &weighted_g,
                    &weighted_mg,
                ]
                .map(|evals| commit(prover, evals))
                .into_iter()
                .collect::<SnarkResult<Vec<_>>>()?;
                let ids = cols.iter().map(TrackedPoly::id).collect();
                let [
                    summed_p,
                    table_a,
                    table_b,
                    sub_a1,
                    sub_a2,
                    sub_b1,
                    data_c,
                    act_c,
                    perm_f,
                    perm_g,
                    weighted_f,
                    weighted_mf,
                    weighted_g,
                    weighted_mg,
                ]: [TrackedPoly<B>; 14] = cols.try_into().unwrap();
                let table_c = prover.track_mat_mv_poly(range_table(5));
                let sub_c1 = &data_c * &act_c;
                // Active rows of data_c count up from zero, as perm_f does.
                let zero = &sub_c1 - &(&perm_f * &act_c);

                prover.add_mv_sumcheck_claim(summed_p.id(), sum(&summed))?;
                prover.add_mv_lookup_claim(table_a.id(), sub_a1.id())?;
                KeyedSumcheck::<B>::prove(
                    prover,
                    KeyedSumcheckProverInput {
                        fxs: vec![perm_f],
                        gxs: vec![perm_g],
                        mfxs: vec![None],
                        mgxs: vec![None],
                    },
                )?;
                let after_permutation = prover.deep_copy();
                prover.add_mv_lookup_claim(table_b.id(), sub_b1.id())?;
                prover.add_mv_lookup_claim(table_a.id(), sub_a2.id())?;
                prover.add_mv_zerocheck_claim(zero.id())?;
                KeyedSumcheck::<B>::prove(
                    prover,
                    KeyedSumcheckProverInput {
                        fxs: vec![weighted_f],
                        gxs: vec![weighted_g],
                        mfxs: vec![Some(weighted_mf)],
                        mgxs: vec![Some(weighted_mg)],
                    },
                )?;
                let after_weighted = prover.deep_copy();
                prover.add_mv_lookup_claim(table_c.id(), sub_c1.id())?;
                Ok(Statement {
                    ids,
                    summed: sum(&summed),
                    after_permutation,
                    after_weighted,
                })
            },
            |verifier, statement| {
                let [
                    summed,
                    table_a,
                    table_b,
                    sub_a1,
                    sub_a2,
                    sub_b1,
                    data_c,
                    act_c,
                    perm_f,
                    perm_g,
                    weighted_f,
                    weighted_mf,
                    weighted_g,
                    weighted_mg,
                ]: [TrackedOracle<B>; 14] =
                    track_all(verifier, &statement.ids)?.try_into().unwrap();
                let table_c = verifier.track_base_oracle(range_oracle(5));
                let sub_c1 = &data_c * &act_c;
                let zero = &sub_c1 - &(&perm_f * &act_c);

                verifier.add_mv_sumcheck_claim(summed.id(), statement.summed);
                verifier.add_mv_lookup_claim(table_a.id(), sub_a1.id())?;
                KeyedSumcheck::<B>::verify(
                    verifier,
                    KeyedSumcheckVerifierInput {
                        fxs: vec![perm_f],
                        gxs: vec![perm_g],
                        mfxs: vec![None],
                        mgxs: vec![None],
                    },
                )?;
                assert_prover_verifier_in_sync(&statement.after_permutation, verifier);
                verifier.add_mv_lookup_claim(table_b.id(), sub_b1.id())?;
                verifier.add_mv_lookup_claim(table_a.id(), sub_a2.id())?;
                verifier.add_mv_zerocheck_claim(zero.id());
                KeyedSumcheck::<B>::verify(
                    verifier,
                    KeyedSumcheckVerifierInput {
                        fxs: vec![weighted_f],
                        gxs: vec![weighted_g],
                        mfxs: vec![Some(weighted_mf)],
                        mgxs: vec![Some(weighted_mg)],
                    },
                )?;
                assert_prover_verifier_in_sync(&statement.after_weighted, verifier);
                verifier.add_mv_lookup_claim(table_c.id(), sub_c1.id())
            },
        ));
    });
}

/// Two hinted lookups, each false, whose errors cancel when all four sides
/// are added up: `sub_a` holds one value that only `table_b` has and the
/// multiplicity of `table_b` counts it, and the other way round. Each
/// relation has to balance on its own.
#[test]
fn two_relations_with_cancelling_errors_are_rejected() {
    under_each_protocol(|_| {
        let table_a = fv(0..8);
        let table_b = fv(8..16);
        let counts_a = [1, 3, 1, 3, 1, 3, 1, 3];
        let counts_b = [3, 1, 3, 1, 3, 1, 3, 1];
        let repeat = |table: std::ops::Range<u64>, counts: [usize; 8]| -> Vec<u64> {
            table
                .zip(counts)
                .flat_map(|(value, count)| std::iter::repeat_n(value, count))
                .collect()
        };
        // The multiplicities claim the counts above, but one 7 of sub_a has been
        // swapped for the 8 that sub_b is missing.
        let mut sub_a = repeat(0..8, counts_a);
        let mut sub_b = repeat(8..16, counts_b);
        assert_eq!((sub_a[15], sub_b[0]), (7, 8));
        (sub_a[15], sub_b[0]) = (8, 7);
        let (sub_a, sub_b) = (fv(sub_a), fv(sub_b));
        let multiplicity_a = fv(counts_a.map(|c| c as u64));
        let multiplicity_b = fv(counts_b.map(|c| c as u64));

        assert_rejected(prove_and_verify(
            |prover| {
                let cols = [
                    &table_a,
                    &sub_a,
                    &table_b,
                    &sub_b,
                    &multiplicity_a,
                    &multiplicity_b,
                ]
                .map(|evals| commit(prover, evals))
                .into_iter()
                .collect::<SnarkResult<Vec<_>>>()?;
                let ids: Vec<TrackerID> = cols.iter().map(TrackedPoly::id).collect();
                let [table_a, sub_a, table_b, sub_b, m_a, m_b]: [TrackedPoly<B>; 6] =
                    cols.try_into().unwrap();
                HintedLookupCheckPIOP::<B>::prove(
                    prover,
                    HintedLookupCheckProverInput {
                        included_cols: vec![sub_a],
                        super_col: table_a,
                        super_col_multiplicity: m_a,
                    },
                )?;
                HintedLookupCheckPIOP::<B>::prove(
                    prover,
                    HintedLookupCheckProverInput {
                        included_cols: vec![sub_b],
                        super_col: table_b,
                        super_col_multiplicity: m_b,
                    },
                )?;
                Ok(ids)
            },
            |verifier, ids| {
                let [table_a, sub_a, table_b, sub_b, m_a, m_b]: [TrackedOracle<B>; 6] =
                    track_all(verifier, &ids)?.try_into().unwrap();
                // Both relations are checked before either verdict is read, so
                // a verifier that only compares totals gets to see them cancel.
                let first = HintedLookupCheckPIOP::<B>::verify(
                    verifier,
                    HintedLookupCheckVerifierInput {
                        included_tracked_col_oracles: vec![sub_a],
                        super_tracked_col_oracle: table_a,
                        super_col_multiplicity: m_a,
                    },
                );
                let second = HintedLookupCheckPIOP::<B>::verify(
                    verifier,
                    HintedLookupCheckVerifierInput {
                        included_tracked_col_oracles: vec![sub_b],
                        super_tracked_col_oracle: table_b,
                        super_col_multiplicity: m_b,
                    },
                );
                first.and(second)
            },
        ));
    });
}

/// Two lookup groups whose subs each hold a value found only in the other
/// group's table. The union of the subs is inside the union of the tables,
/// so only a per-table check tells this apart from a true statement.
#[test]
fn lookup_groups_do_not_share_tables() {
    under_each_protocol(|_| {
        let run = |sub_a: &[F], sub_b: &[F]| {
            prove_and_verify(
                |prover| {
                    let table_a = commit(prover, &fv(0..8))?;
                    let table_b = commit(prover, &fv(8..16))?;
                    let sub_a = commit(prover, sub_a)?;
                    let sub_b = commit(prover, sub_b)?;
                    prover.add_mv_lookup_claim(table_a.id(), sub_a.id())?;
                    prover.add_mv_lookup_claim(table_b.id(), sub_b.id())?;
                    Ok([table_a.id(), table_b.id(), sub_a.id(), sub_b.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    verifier.add_mv_lookup_claim(oracles[0].id(), oracles[2].id())?;
                    verifier.add_mv_lookup_claim(oracles[1].id(), oracles[3].id())
                },
            )
        };
        assert_accepted(run(
            &fv([0, 1, 2, 3, 4, 5, 6, 7]),
            &fv([8, 9, 10, 11, 12, 13, 14, 15]),
        ));
        assert_rejected(run(
            &fv([0, 1, 2, 3, 4, 5, 6, 8]),
            &fv([7, 9, 10, 11, 12, 13, 14, 15]),
        ));
    });
}

/// The prover proves `good ⊆ table`; the verifier is told `other ⊆ table`.
/// `other` is committed in the same proof, is opened through a sumcheck
/// claim of its own, and really is inside the table: only the binding of
/// the lookup to the column it was proved for can reject this.
#[test]
fn verifier_statement_swap_column_is_rejected() {
    under_each_protocol(|_| {
        let table = fv(0..16);
        let good = fv((0..16).map(|i| (i * 3) % 16));
        let other = fv((0..16).map(|i| (i * 5) % 8));
        let run = |swap: bool| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &table)?;
                    let good = commit(prover, &good)?;
                    let other_p = commit(prover, &other)?;
                    prover.add_mv_sumcheck_claim(other_p.id(), sum(&other))?;
                    prover.add_mv_lookup_claim(table.id(), good.id())?;
                    Ok([table.id(), good.id(), other_p.id()])
                },
                |verifier, ids| {
                    let oracles = track_all(verifier, &ids)?;
                    verifier.add_mv_sumcheck_claim(oracles[2].id(), sum(&other));
                    let sub = if swap { &oracles[2] } else { &oracles[1] };
                    verifier.add_mv_lookup_claim(oracles[0].id(), sub.id())
                },
            )
        };
        assert_accepted(run(false));
        assert_rejected_by_verifier(run(true));
    });
}

/// As above for the multiplicity of a hinted lookup: proved with the true
/// counts, mirrored with another committed column.
#[test]
fn verifier_statement_swap_multiplicity_is_rejected() {
    under_each_protocol(|_| {
        let table = fv(0..16);
        let sub = fv((0..16).map(|i| (i * 2) % 16));
        let good = fv((0..16).map(|i| if i % 2 == 0 { 2 } else { 0 }));
        // Same total as `good`, different rows.
        let other = fv((0..16).map(|i| if i % 2 == 1 { 2 } else { 0 }));
        let run = |swap: bool| {
            prove_and_verify(
                |prover| {
                    let table = commit(prover, &table)?;
                    let sub = commit(prover, &sub)?;
                    let good = commit(prover, &good)?;
                    let other_p = commit(prover, &other)?;
                    let ids = [table.id(), sub.id(), good.id(), other_p.id()];
                    prover.add_mv_sumcheck_claim(other_p.id(), sum(&other))?;
                    HintedLookupCheckPIOP::<B>::prove(
                        prover,
                        HintedLookupCheckProverInput {
                            included_cols: vec![sub],
                            super_col: table,
                            super_col_multiplicity: good,
                        },
                    )?;
                    Ok(ids)
                },
                |verifier, ids| {
                    let [table, sub, good, other_o]: [TrackedOracle<B>; 4] =
                        track_all(verifier, &ids)?.try_into().unwrap();
                    verifier.add_mv_sumcheck_claim(other_o.id(), sum(&other));
                    HintedLookupCheckPIOP::<B>::verify(
                        verifier,
                        HintedLookupCheckVerifierInput {
                            included_tracked_col_oracles: vec![sub],
                            super_tracked_col_oracle: table,
                            super_col_multiplicity: if swap { other_o } else { good },
                        },
                    )
                },
            )
        };
        assert_accepted(run(false));
        assert_rejected_by_verifier(run(true));
    });
}

/// The prover makes two lookup claims against two tables; the verifier
/// mirrors the first `mirrored` of them, and a third one when asked for more.
fn mirrored_lookup_claims_e2e(mirrored: usize) -> SnarkResult<()> {
    prove_and_verify(
        |prover| {
            let table_a = commit(prover, &fv(0..16))?;
            let table_b = commit(prover, &fv(0..8))?;
            let sub_a = commit(prover, &fv((0..16).map(|i| (i * 3) % 16)))?;
            let sub_b = commit(prover, &fv((0..16).map(|i| (i * 3) % 8)))?;
            let unclaimed = commit(prover, &fv((0..16).map(|i| (i * 5) % 8)))?;
            prover.add_mv_lookup_claim(table_a.id(), sub_a.id())?;
            prover.add_mv_lookup_claim(table_b.id(), sub_b.id())?;
            Ok([&table_a, &table_b, &sub_a, &sub_b, &unclaimed].map(TrackedPoly::id))
        },
        |verifier, ids| {
            let oracles = track_all(verifier, &ids)?;
            let claims = [(0, 2), (1, 3), (1, 4)];
            for (table, sub) in &claims[..mirrored] {
                verifier.add_mv_lookup_claim(oracles[*table].id(), oracles[*sub].id())?;
            }
            Ok(())
        },
    )
}

/// A verifier that checks fewer lookups than the proof contains is checking
/// a different statement, even though what it does check is true.
#[test]
fn verifier_missing_lookup_claim_is_rejected() {
    under_each_protocol(|_| {
        assert_accepted(mirrored_lookup_claims_e2e(2));
        assert_rejected_by_verifier(mirrored_lookup_claims_e2e(1));
        assert_rejected_by_verifier(mirrored_lookup_claims_e2e(0));
    });
}

/// The extra claim is true, but the prover never proved it.
#[test]
fn verifier_extra_lookup_claim_is_rejected() {
    under_each_protocol(|_| {
        assert_rejected_by_verifier(mirrored_lookup_claims_e2e(3));
    });
}

/// The column behind the ordinary claim of [`proof_with_lookups`].
fn summed_column() -> Vec<F> {
    fv((0..32).map(|i| 3 * i + 1))
}

/// A proof with two lookup groups, a virtual sub and an ordinary claim, the
/// verifier it is meant for and the ids of its input commitments.
fn proof_with_lookups() -> (SNARKProof<B>, ArgVerifier<B>, [TrackerID; 6]) {
    let (mut prover, verifier) = setup();
    let cols = [
        fv(0..16),
        fv((0..64).map(|i| i % 4)),
        fv((0..32).map(|i| (i * 7) % 16)),
        prefix_activator(5, 17),
        fv((0..8).map(|i| i % 4)),
        summed_column(),
    ]
    .map(|evals| commit(&mut prover, &evals).unwrap());
    let ids = cols.each_ref().map(TrackedPoly::id);
    let [table_a, table_b, data, activator, sub_b, summed] = cols;
    let sub_a = &data * &activator;
    prover
        .add_mv_lookup_claim(table_a.id(), sub_a.id())
        .unwrap();
    prover
        .add_mv_lookup_claim(table_b.id(), sub_b.id())
        .unwrap();
    prover
        .add_mv_sumcheck_claim(summed.id(), sum(&summed_column()))
        .unwrap();
    (prover.build_proof().unwrap(), verifier, ids)
}

/// Mirrors the statement of [`proof_with_lookups`] and verifies.
fn verify_proof_with_lookups(
    verifier: &mut ArgVerifier<B>,
    ids: &[TrackerID; 6],
) -> SnarkResult<()> {
    let [table_a, table_b, data, activator, sub_b, summed]: [TrackedOracle<B>; 6] =
        track_all(verifier, ids)?.try_into().unwrap();
    let sub_a = &data * &activator;
    verifier.add_mv_lookup_claim(table_a.id(), sub_a.id())?;
    verifier.add_mv_lookup_claim(table_b.id(), sub_b.id())?;
    verifier.add_mv_sumcheck_claim(summed.id(), sum(&summed_column()));
    verifier.verify()
}

#[test]
fn snark_proof_with_lookup_roundtrips_and_verifies() {
    under_each_protocol(|protocol| {
        let (proof, mut verifier, ids) = proof_with_lookups();
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(bytes[0], PROOF_ENCODING_VERSION);

        let decoded = SNARKProof::<B>::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
        match protocol {
            // Both tables are reduced in one batch.
            LookupProtocol::LogUpGkr => assert_eq!(proof.logup_gkr_subproofs.len(), 1),
            // A sum for the virtual sub column, one for the other and one
            // for each table.
            LookupProtocol::LogUp => {
                assert!(proof.logup_gkr_subproofs.is_empty());
                assert_eq!(logup_sums(&proof).len(), 4);
            }
        }
        assert_eq!(decoded.logup_gkr_subproofs, proof.logup_gkr_subproofs);
        assert_eq!(decoded.lookup_messages, proof.lookup_messages);
        verifier.set_proof(decoded);
        assert_accepted(verify_proof_with_lookups(&mut verifier, &ids));
    });
}

/// The version tag is the one of proofs whose claimed sums are bound
/// before their claims are batched, and a proof tagged with the version
/// before it is not decoded.
#[test]
fn snark_proof_tagged_with_the_previous_encoding_version_is_refused() {
    under_each_protocol(|_| {
        let (proof, _, _) = proof_with_lookups();
        let mut bytes = proof.to_bytes().unwrap();
        assert_eq!(bytes[0], 7);
        bytes[0] = 6;
        assert!(SNARKProof::<B>::from_bytes(&bytes).is_err());
    });
}

/// Every byte of a serialized proof belongs to exactly one top-level part of
/// the size breakdown; the one byte left over is the version tag.
#[test]
fn size_breakdown_parts_sum_to_total() {
    under_each_protocol(|_| {
        let (proof, ..) = proof_with_lookups();
        let breakdown = proof
            .size_breakdown()
            .expect("a proof has a size breakdown");
        assert_eq!(breakdown.size, proof.to_bytes().unwrap().len());
        let parts: usize = breakdown.parts.values().map(|part| part.size).sum();
        assert_eq!(parts + 1, breakdown.size);
    });
}

/// A keyed sum whose numerator is `multiplicity · activator`, or the bare
/// activator: rows the activator switches off contribute nothing, whatever
/// their key is. `deferred` claims the sum for the proof's batch instead of
/// proving it on the spot.
fn activator_numerator_semantics(deferred: bool) {
    let activator = prefix_activator(5, 21);
    // Active rows cycle through the keys 100..107. Inactive rows alternate
    // between keys the other side does not have at all and real keys.
    let keys = fv((0..32).map(|i| {
        if i < 21 || i % 2 == 1 {
            100 + i % 7
        } else {
            900 + i
        }
    }));
    let weights = fv((0..32).map(|i| i + 1));
    let g = fv((0..8).map(|i| 100 + i));
    // Per key, the total weight of the first `active` rows holding it; every
    // row weighs 1 when the numerator is the bare activator.
    let totals = |active: u64, weighted: bool| -> Vec<F> {
        let weight = |i: u64| if weighted { i + 1 } else { 1 };
        fv((0..8).map(|key| (0..active).filter(|i| i % 7 == key).map(weight).sum()))
    };
    let run = |totals: &[F], weighted: bool| {
        prove_and_verify(
            |prover| {
                let keys = commit(prover, &keys)?;
                let weights = commit(prover, &weights)?;
                let activator = commit(prover, &activator)?;
                let g = commit(prover, &g)?;
                let totals = commit(prover, totals)?;
                let ids = [keys.id(), weights.id(), activator.id(), g.id(), totals.id()];
                let numerator = if weighted {
                    &weights * &activator
                } else {
                    activator
                };
                let input = KeyedSumcheckProverInput {
                    fxs: vec![keys],
                    gxs: vec![g],
                    mfxs: vec![Some(numerator)],
                    mgxs: vec![Some(totals)],
                };
                if deferred {
                    prover.add_mv_keyed_sum_claim(input)?;
                } else {
                    KeyedSumcheck::<B>::prove(prover, input)?;
                }
                Ok((ids, prover.deep_copy()))
            },
            |verifier, (ids, prover_after_piop)| {
                let [keys, weights, activator, g, totals]: [TrackedOracle<B>; 5] =
                    track_all(verifier, &ids)?.try_into().unwrap();
                let numerator = if weighted {
                    &weights * &activator
                } else {
                    activator
                };
                let input = KeyedSumcheckVerifierInput {
                    fxs: vec![keys],
                    gxs: vec![g],
                    mfxs: vec![Some(numerator)],
                    mgxs: vec![Some(totals)],
                };
                if deferred {
                    verifier.add_mv_keyed_sum_claim(input)?;
                } else {
                    KeyedSumcheck::<B>::verify(verifier, input)?;
                }
                assert_prover_verifier_in_sync(&prover_after_piop, verifier);
                Ok(())
            },
        )
    };
    for weighted in [true, false] {
        assert_accepted(run(&totals(21, weighted), weighted));
        // Row 21 is inactive and holds a real key; it must not count.
        assert_rejected(run(&totals(22, weighted), weighted));
    }
}

#[test]
fn keyed_sum_activator_numerator_semantics() {
    under_each_protocol(|_| {
        activator_numerator_semantics(false);
    });
}

#[test]
fn deferred_keyed_sum_activator_numerator_semantics() {
    under_each_protocol(|_| {
        activator_numerator_semantics(true);
    });
}

// ─── Keyed sums claimed for the proof's batch ────────────────────────────

/// Two lookup groups and two keyed sums, interleaved with each other and
/// with an ordinary claim. Claimed for later, the keyed sums join the lookups
/// in one LogUp-GKR batch; proved on the spot, each is a batch of its own.
#[test]
fn deferred_keyed_sum_claims_share_one_gkr() {
    under_each_protocol(|protocol| {
        let summed = fv((0..16).map(|i| i * i));
        let table_a = fv(0..16);
        let table_b = fv((0..8).map(|i| i * 9));
        let sub_a1 = fv((0..16).map(|i| (i * 3) % 16));
        let sub_a2 = fv((0..64).map(|i| i % 11));
        let sub_b = fv((0..8).map(|i| ((i * 3) % 8) * 9));
        let perm_f = fv(0..32);
        let perm_g = fv((0..32).map(|i| (i * 13 + 5) % 32));
        let weighted_f = fv((0..8).map(|i| i + 100));
        let weighted_mf = fv((0..8).map(|i| i + 1));
        let weighted_g = fv((0..32).map(|i| (i % 8) + 100));
        let weighted_mg = fv((0..32).map(|i| if i < 8 { i + 1 } else { 0 }));
        let cols = [
            &summed,
            &table_a,
            &table_b,
            &sub_a1,
            &sub_a2,
            &sub_b,
            &perm_f,
            &perm_g,
            &weighted_f,
            &weighted_mf,
            &weighted_g,
            &weighted_mg,
        ];

        let run = |deferred: bool| {
            proof_of_accepted(
                |prover| {
                    let handles = cols
                        .iter()
                        .map(|evals| commit(prover, evals))
                        .collect::<SnarkResult<Vec<_>>>()?;
                    let ids: Vec<TrackerID> = handles.iter().map(TrackedPoly::id).collect();
                    let [
                        summed_p,
                        table_a,
                        table_b,
                        sub_a1,
                        sub_a2,
                        sub_b,
                        perm_f,
                        perm_g,
                        weighted_f,
                        weighted_mf,
                        weighted_g,
                        weighted_mg,
                    ]: [TrackedPoly<B>; 12] = handles.try_into().unwrap();
                    let keyed_sum = |prover: &mut ArgProver<B>, input| {
                        if deferred {
                            prover.add_mv_keyed_sum_claim(input)
                        } else {
                            KeyedSumcheck::<B>::prove(prover, input)
                        }
                    };
                    prover.add_mv_lookup_claim(table_a.id(), sub_a1.id())?;
                    keyed_sum(
                        prover,
                        KeyedSumcheckProverInput {
                            fxs: vec![perm_f],
                            gxs: vec![perm_g],
                            mfxs: vec![None],
                            mgxs: vec![None],
                        },
                    )?;
                    prover.add_mv_lookup_claim(table_b.id(), sub_b.id())?;
                    prover.add_mv_sumcheck_claim(summed_p.id(), sum(&summed))?;
                    keyed_sum(
                        prover,
                        KeyedSumcheckProverInput {
                            fxs: vec![weighted_f],
                            gxs: vec![weighted_g],
                            mfxs: vec![Some(weighted_mf)],
                            mgxs: vec![Some(weighted_mg)],
                        },
                    )?;
                    prover.add_mv_lookup_claim(table_a.id(), sub_a2.id())?;
                    Ok(ids)
                },
                |verifier, ids| {
                    let [
                        summed_v,
                        table_a,
                        table_b,
                        sub_a1,
                        sub_a2,
                        sub_b,
                        perm_f,
                        perm_g,
                        weighted_f,
                        weighted_mf,
                        weighted_g,
                        weighted_mg,
                    ]: [TrackedOracle<B>; 12] = track_all(verifier, &ids)?.try_into().unwrap();
                    let keyed_sum = |verifier: &mut ArgVerifier<B>, input| {
                        if deferred {
                            verifier.add_mv_keyed_sum_claim(input)
                        } else {
                            KeyedSumcheck::<B>::verify(verifier, input)
                        }
                    };
                    verifier.add_mv_lookup_claim(table_a.id(), sub_a1.id())?;
                    keyed_sum(
                        verifier,
                        KeyedSumcheckVerifierInput {
                            fxs: vec![perm_f],
                            gxs: vec![perm_g],
                            mfxs: vec![None],
                            mgxs: vec![None],
                        },
                    )?;
                    verifier.add_mv_lookup_claim(table_b.id(), sub_b.id())?;
                    verifier.add_mv_sumcheck_claim(summed_v.id(), sum(&summed));
                    keyed_sum(
                        verifier,
                        KeyedSumcheckVerifierInput {
                            fxs: vec![weighted_f],
                            gxs: vec![weighted_g],
                            mfxs: vec![Some(weighted_mf)],
                            mgxs: vec![Some(weighted_mg)],
                        },
                    )?;
                    verifier.add_mv_lookup_claim(table_a.id(), sub_a2.id())
                },
            )
        };
        let proof = run(true).expect("a true statement must be accepted");
        let on_the_spot = run(false).expect("a true statement must be accepted");
        match protocol {
            LookupProtocol::LogUpGkr => {
                assert_eq!(proof.logup_gkr_subproofs.len(), 1);
                assert_eq!(on_the_spot.logup_gkr_subproofs.len(), 3);
            }
            // LogUp has nothing to share between relations: a helper and a
            // sum for each of the nine columns, none of which has a
            // neighbour to share a helper with, whenever its relation is
            // reduced.
            LookupProtocol::LogUp => {
                assert!(proof.logup_gkr_subproofs.is_empty());
                assert!(on_the_spot.logup_gkr_subproofs.is_empty());
                assert_eq!(logup_sums(&proof).len(), 9);
                assert_eq!(logup_sums(&on_the_spot).len(), 9);
            }
        }
    });
}

/// Keyed sums claimed for later with nothing else in the proof: true ones
/// are accepted and a false one is rejected, alone and among true ones.
#[test]
fn deferred_false_keyed_sum_is_rejected() {
    under_each_protocol(|_| {
        let f = fv(0..32);
        let g = fv((0..32).map(|i| (i * 5 + 3) % 32));
        let mut not_a_permutation = g.clone();
        not_a_permutation[9] = F::from(99u64);
        let keys = fv((0..8).map(|i| i + 100));
        let weights = fv((0..8).map(|i| i + 1));
        let mut wrong_weights = weights.clone();
        wrong_weights[3] += F::one();

        let permutation = [(f.clone(), None)];
        let permuted = [(g, None)];
        let broken = [(not_a_permutation, None)];
        let weighted = [(keys.clone(), Some(weights))];
        let misweighted = [(keys, Some(wrong_weights))];

        assert_accepted(deferred_keyed_e2e(&[(&permutation, &permuted)]));
        assert_accepted(deferred_keyed_e2e(&[
            (&permutation, &permuted),
            (&weighted, &weighted),
            (&permuted, &permutation),
        ]));

        assert_rejected(deferred_keyed_e2e(&[(&permutation, &broken)]));
        assert_rejected(deferred_keyed_e2e(&[(&weighted, &misweighted)]));
        for at in 0..3 {
            let mut relations: Vec<KeyedRelation> = vec![
                (&permutation, &permuted),
                (&weighted, &weighted),
                (&permuted, &permutation),
            ];
            relations[at] = (&weighted, &misweighted);
            assert_rejected(deferred_keyed_e2e(&relations));
        }
    });
}

/// A keyed sum claimed without the check `honest-prover` makes of it: the
/// prover goes on to build its proof whether the relation holds or not,
/// under either feature set, and it is the verifier that turns a false one
/// down. The checked claim of the same relation is refused by an honest
/// prover.
#[test]
fn unchecked_false_keyed_sum_is_proved_and_rejected_by_the_verifier() {
    under_each_protocol(|_| {
        let f = fv(0..32);
        let g = fv((0..32).map(|i| (i * 5 + 3) % 32));
        let mut not_a_permutation = g.clone();
        not_a_permutation[9] = F::from(99u64);
        let keys = fv((0..8).map(|i| i + 100));
        let weights = fv((0..8).map(|i| i + 1));
        let mut wrong_weights = weights.clone();
        wrong_weights[3] += F::one();

        let run = |fs: &[KeyedCol], gs: &[KeyedCol], checked: bool| {
            prove_and_verify(
                |prover| {
                    let (fxs, mfxs) = commit_keyed_side(prover, fs)?;
                    let (gxs, mgxs) = commit_keyed_side(prover, gs)?;
                    let ids = (keyed_side_ids(&fxs, &mfxs), keyed_side_ids(&gxs, &mgxs));
                    let input = KeyedSumcheckProverInput {
                        fxs,
                        gxs,
                        mfxs,
                        mgxs,
                    };
                    match checked {
                        true => prover.add_mv_keyed_sum_claim(input)?,
                        false => prover.add_mv_keyed_sum_claim_unchecked(input)?,
                    }
                    Ok(ids)
                },
                |verifier, (f_ids, g_ids)| {
                    let (fxs, mfxs) = track_keyed_side(verifier, &f_ids)?;
                    let (gxs, mgxs) = track_keyed_side(verifier, &g_ids)?;
                    verifier.add_mv_keyed_sum_claim(KeyedSumcheckVerifierInput {
                        fxs,
                        gxs,
                        mfxs,
                        mgxs,
                    })
                },
            )
        };

        let permutation = [(f, None)];
        let weighted = [(keys.clone(), Some(weights))];
        assert_accepted(run(&permutation, &[(g, None)], false));
        assert_accepted(run(&weighted, &weighted, false));
        for (fs, false_gs) in [
            (&permutation, [(not_a_permutation, None)]),
            (&weighted, [(keys, Some(wrong_weights))]),
        ] {
            assert_rejected_by_verifier(run(fs, &false_gs, false));
            assert_rejected(run(fs, &false_gs, true));
        }
        // An unchecked claim is still one of a shape the verifier takes.
        assert!(matches!(
            run(&permutation, &[], false),
            Err(SnarkError::ProverError(_))
        ));
    });
}

/// Two keyed sums claimed for later, each false, whose four sides balance
/// when added up. Each relation has to balance on its own.
#[test]
fn deferred_keyed_sums_with_cancelling_errors_are_rejected() {
    under_each_protocol(|_| {
        let a = [(fv(0..8), None)];
        let b = [(fv(100..108), None)];
        let both = [a[0].clone(), b[0].clone()];
        let both_swapped = [b[0].clone(), a[0].clone()];

        assert_accepted(deferred_keyed_e2e(&[(&both, &both_swapped)]));
        assert_rejected(deferred_keyed_e2e(&[(&a, &b), (&b, &a)]));

        // The same with weights: each relation credits the other's key.
        let key = |k: u64| fv([k; 4]);
        let weights = |w: u64| Some(fv((0..4).map(|i| w + i)));
        let x = [(key(7), weights(1)), (fv(0..4), None)];
        let x_other = [(key(9), weights(1)), (fv(0..4), None)];
        assert_accepted(deferred_keyed_e2e(&[(&x, &x), (&x_other, &x_other)]));
        assert_rejected(deferred_keyed_e2e(&[(&x, &x_other), (&x_other, &x)]));
    });
}

/// Three true keyed sums of one shape; the prover claims the first two.
fn mirrored_deferred_claims_e2e(mirrored: &[usize]) -> SnarkResult<()> {
    let column = |seed: u64| [(fv((0..16).map(|i| i * seed + 1)), None)];
    let permuted = |seed: u64| [(fv((0..16).map(|i| ((i * 5 + 3) % 16) * seed + 1)), None)];
    let (f0, g0) = (column(3), permuted(3));
    let (f1, g1) = (column(7), permuted(7));
    let (f2, g2) = (column(11), permuted(11));
    let relations: [KeyedRelation; 3] = [(&f0, &g0), (&f1, &g1), (&f2, &g2)];
    deferred_keyed_e2e_mirroring(&relations, &[0, 1], mirrored).map(drop)
}

/// A verifier that mirrors fewer keyed sums than the prover claimed is
/// checking a different statement, even though what it does check is true.
#[test]
fn verifier_missing_deferred_keyed_sum_is_rejected() {
    under_each_protocol(|_| {
        assert_accepted(mirrored_deferred_claims_e2e(&[0, 1]));
        assert_rejected_by_verifier(mirrored_deferred_claims_e2e(&[0]));
        assert_rejected_by_verifier(mirrored_deferred_claims_e2e(&[1]));
        assert_rejected_by_verifier(mirrored_deferred_claims_e2e(&[]));
    });
}

/// The extra keyed sum is true, but the prover never proved it.
#[test]
fn verifier_extra_deferred_keyed_sum_is_rejected() {
    under_each_protocol(|_| {
        assert_rejected_by_verifier(mirrored_deferred_claims_e2e(&[0, 1, 2]));
        assert_rejected_by_verifier(mirrored_deferred_claims_e2e(&[0, 2]));
    });
}

/// Both keyed sums are true and of one shape, so the batch looks the same in
/// either order; its claims are still tied to the columns in the prover's.
#[test]
fn verifier_reordering_deferred_keyed_sums_is_rejected() {
    under_each_protocol(|_| {
        assert_rejected_by_verifier(mirrored_deferred_claims_e2e(&[1, 0]));
    });
}

/// A keyed sum is checked for its shape when it is claimed, on both sides,
/// and a refused claim leaves nothing behind.
#[test]
fn deferred_keyed_sum_claim_checks_its_shape() {
    under_each_protocol(|_| {
        let f = fv(0..16);
        let g = fv((0..16).map(|i| (i * 5 + 3) % 16));
        // `(fxs, mfxs, gxs, mgxs)` lengths.
        let malformed = [(0, 0, 1, 1), (1, 0, 1, 1), (1, 1, 0, 0), (1, 1, 1, 2)];

        assert_accepted(prove_and_verify(
            |prover| {
                let f = commit(prover, &f)?;
                let g = commit(prover, &g)?;
                let ids = [f.id(), g.id()];
                let input = |(fxs, mfxs, gxs, mgxs)| KeyedSumcheckProverInput {
                    fxs: vec![f.clone(); fxs],
                    mfxs: vec![None; mfxs],
                    gxs: vec![g.clone(); gxs],
                    mgxs: vec![None; mgxs],
                };
                for shape in malformed {
                    let err = prover
                        .add_mv_keyed_sum_claim(input(shape))
                        .expect_err("a malformed keyed sum must be refused");
                    assert!(matches!(err, SnarkError::ProverError(_)), "got {err:?}");
                }
                prover.add_mv_keyed_sum_claim(input((1, 1, 1, 1)))?;
                Ok(ids)
            },
            |verifier, ids| {
                let [f, g]: [TrackedOracle<B>; 2] = track_all(verifier, &ids)?.try_into().unwrap();
                let input = |(fxs, mfxs, gxs, mgxs)| KeyedSumcheckVerifierInput {
                    fxs: vec![f.clone(); fxs],
                    mfxs: vec![None; mfxs],
                    gxs: vec![g.clone(); gxs],
                    mgxs: vec![None; mgxs],
                };
                for shape in malformed {
                    let err = verifier
                        .add_mv_keyed_sum_claim(input(shape))
                        .expect_err("a malformed keyed sum must be refused");
                    assert_verifier_error(err);
                }
                verifier.add_mv_keyed_sum_claim(input((1, 1, 1, 1)))
            },
        ));
    });
}

/// Proving the PIOP on the spot refuses the same shapes on both sides, and
/// writes nothing for them: the well-formed relation that follows verifies.
#[test]
fn keyed_sumcheck_checks_its_shape_on_both_sides() {
    under_each_protocol(|_| {
        let f = fv(0..16);
        let g = fv((0..16).map(|i| (i * 5 + 3) % 16));
        // `(fxs, mfxs, gxs, mgxs)` lengths.
        let malformed = [(0, 0, 1, 1), (1, 0, 1, 1), (1, 1, 0, 0), (1, 1, 1, 2)];

        assert_accepted(prove_and_verify(
            |prover| {
                let f = commit(prover, &f)?;
                let g = commit(prover, &g)?;
                let ids = [f.id(), g.id()];
                let input = |(fxs, mfxs, gxs, mgxs)| KeyedSumcheckProverInput {
                    fxs: vec![f.clone(); fxs],
                    mfxs: vec![None; mfxs],
                    gxs: vec![g.clone(); gxs],
                    mgxs: vec![None; mgxs],
                };
                for shape in malformed {
                    let err = KeyedSumcheck::<B>::prove(prover, input(shape))
                        .expect_err("a malformed keyed sum must be refused");
                    assert!(matches!(err, SnarkError::ProverError(_)), "got {err:?}");
                }
                KeyedSumcheck::<B>::prove(prover, input((1, 1, 1, 1)))?;
                Ok(ids)
            },
            |verifier, ids| {
                let [f, g]: [TrackedOracle<B>; 2] = track_all(verifier, &ids)?.try_into().unwrap();
                let input = |(fxs, mfxs, gxs, mgxs)| KeyedSumcheckVerifierInput {
                    fxs: vec![f.clone(); fxs],
                    mfxs: vec![None; mfxs],
                    gxs: vec![g.clone(); gxs],
                    mgxs: vec![None; mgxs],
                };
                for shape in malformed {
                    let err = KeyedSumcheck::<B>::verify(verifier, input(shape))
                        .expect_err("a malformed keyed sum must be refused");
                    assert_verifier_error(err);
                }
                KeyedSumcheck::<B>::verify(verifier, input((1, 1, 1, 1)))
            },
        ));
    });
}

// ─── The lookup protocol as a choice ─────────────────────────────────────

fn other(protocol: LookupProtocol) -> LookupProtocol {
    match protocol {
        LookupProtocol::LogUp => LookupProtocol::LogUpGkr,
        LookupProtocol::LogUpGkr => LookupProtocol::LogUp,
    }
}

/// A prover and a verifier configured for a protocol each, whatever the
/// environment names.
fn setup_under(prover: LookupProtocol, verifier: LookupProtocol) -> (ArgProver<B>, ArgVerifier<B>) {
    let (pk, vk) = KeyGenerator::<B>::new()
        .with_num_mv_vars(SRS_NV)
        .gen_keys()
        .unwrap();
    let config = |lookup_protocol| SharedArgConfig {
        lookup_protocol,
        ..SharedArgConfig::default()
    };
    (
        ArgProver::new_from_pk_with_config(pk, config(prover)).unwrap(),
        ArgVerifier::new_from_vk_with_config(vk, config(verifier)).unwrap(),
    )
}

/// The statement of one sumcheck claim on a committed column: nothing in it
/// is proved by a lookup protocol. Returns the verifier's verdict on the
/// proof as `retag` leaves it.
fn sum_claim_e2e(
    prover: LookupProtocol,
    verifier: LookupProtocol,
    retag: impl FnOnce(&mut SNARKProof<B>),
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = setup_under(prover, verifier);
    let column = summed_column();
    let id = commit(&mut prover, &column)?.id();
    prover.add_mv_sumcheck_claim(id, sum(&column))?;
    let mut proof = prover.build_proof()?;
    retag(&mut proof);
    verifier.set_proof_ref(&proof);
    let oracle = verifier.track_mv_com_by_id(id)?;
    verifier.add_mv_sumcheck_claim(oracle.id(), sum(&column));
    verifier.verify()
}

fn assert_check_failed(res: SnarkResult<()>) {
    let err = res.expect_err("the verifier must refuse the proof");
    assert!(
        matches!(
            err,
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))
        ),
        "expected a failed verifier check, got {err:?}"
    );
}

#[test]
fn lookup_protocol_is_named_logup_or_gkr_in_any_case() {
    for name in ["logup", "LogUp", "LOGUP"] {
        assert_eq!(
            name.parse::<LookupProtocol>().unwrap(),
            LookupProtocol::LogUp
        );
    }
    for name in ["gkr", "Gkr", "GKR"] {
        assert_eq!(
            name.parse::<LookupProtocol>().unwrap(),
            LookupProtocol::LogUpGkr
        );
    }
    for name in ["", " gkr", "logup-gkr", "logupgkr", "0", "plookup"] {
        let err = name.parse::<LookupProtocol>().unwrap_err();
        assert!(matches!(err, SnarkError::SetupError(_)), "got {err:?}");
    }
    assert_eq!(LookupProtocol::default(), LookupProtocol::LogUpGkr);
}

/// What this process's environment makes of a default configuration and of
/// the constructors. It holds under any environment, and prints which of
/// the three outcomes it found for
/// [`environment_names_the_default_lookup_protocol`], which runs it under
/// each.
#[test]
fn default_configuration_follows_the_environment() {
    let keys = || {
        KeyGenerator::<B>::new()
            .with_num_mv_vars(SRS_NV)
            .gen_keys()
            .unwrap()
    };
    let explicit = SharedArgConfig {
        lookup_protocol: LookupProtocol::LogUp,
        ..SharedArgConfig::default()
    };
    let named = std::env::var(LOOKUP_PROTOCOL_ENV).ok();
    let expected = match named.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => Some(LookupProtocol::LogUpGkr),
        Some("logup") => Some(LookupProtocol::LogUp),
        Some("gkr") => Some(LookupProtocol::LogUpGkr),
        Some(_) => None,
    };
    let Some(expected) = expected else {
        // The default cannot say so; everything that builds on it does.
        assert_eq!(
            SharedArgConfig::default().lookup_protocol,
            LookupProtocol::LogUpGkr
        );
        let err = LookupProtocol::from_env().unwrap_err();
        assert!(matches!(err, SnarkError::SetupError(_)), "got {err:?}");
        let (pk, vk) = keys();
        for config in [SharedArgConfig::default(), explicit] {
            let err = ArgProver::<B>::new_from_pk_with_config(pk.clone(), config.clone())
                .map(drop)
                .unwrap_err();
            assert!(matches!(err, SnarkError::SetupError(_)), "got {err:?}");
            let err = ArgVerifier::<B>::new_from_vk_with_config(vk.clone(), config)
                .map(drop)
                .unwrap_err();
            assert!(matches!(err, SnarkError::SetupError(_)), "got {err:?}");
        }
        let default_prover = std::panic::catch_unwind(|| drop(ArgProver::<B>::new_from_pk(pk)));
        let default_verifier = std::panic::catch_unwind(|| drop(ArgVerifier::<B>::new_from_vk(vk)));
        assert!(default_prover.is_err() && default_verifier.is_err());
        println!("lookup protocol of the environment: refused");
        return;
    };
    assert_eq!(LookupProtocol::from_env().unwrap(), named.map(|_| expected));
    assert_eq!(SharedArgConfig::default().lookup_protocol, expected);
    // An explicit configuration is not the environment's to change.
    let (pk, vk) = keys();
    let mut prover = ArgProver::<B>::new_from_pk_with_config(pk.clone(), explicit).unwrap();
    assert_eq!(
        prover.build_proof().unwrap().lookup_messages.protocol(),
        LookupProtocol::LogUp
    );
    // The default constructors are those of a default configuration.
    let mut prover = ArgProver::<B>::new_from_pk(pk);
    let proof = prover.build_proof().unwrap();
    assert_eq!(proof.lookup_messages.protocol(), expected);
    let mut verifier = ArgVerifier::<B>::new_from_vk(vk);
    verifier.set_proof(proof);
    assert_accepted(verifier.verify());
    println!("lookup protocol of the environment: {expected}");
}

/// The environment variable is read by a process once, so each value gets a
/// process of its own: this test binary, running the test above.
#[test]
fn environment_names_the_default_lookup_protocol() {
    let probe = |value: Option<&str>| {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "default_configuration_follows_the_environment",
            "--nocapture",
        ]);
        match value {
            Some(value) => command.env(LOOKUP_PROTOCOL_ENV, value),
            None => command.env_remove(LOOKUP_PROTOCOL_ENV),
        };
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "under {value:?}: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
            .lines()
            .find_map(|line| line.strip_prefix("lookup protocol of the environment: "))
            .unwrap_or_else(|| panic!("under {value:?} the probe did not run: {stdout}"))
            .to_string()
    };
    assert_eq!(probe(None), "LogUp-GKR");
    for value in ["logup", "LogUp", "LOGUP"] {
        assert_eq!(probe(Some(value)), "LogUp");
    }
    for value in ["gkr", "GKR"] {
        assert_eq!(probe(Some(value)), "LogUp-GKR");
    }
    for value in ["", "logup-gkr", "1", "default"] {
        assert_eq!(probe(Some(value)), "refused");
    }
}

/// A proof names the protocol of the prover that made it, and keeps the
/// name through its encoding.
#[test]
fn proof_names_the_lookup_protocol_of_its_prover() {
    for protocol in PROTOCOLS {
        let (mut prover, _) = setup_under(protocol, protocol);
        let proof = prover.build_proof().unwrap();
        assert_eq!(proof.lookup_messages.protocol(), protocol);
        let decoded = SNARKProof::<B>::from_bytes(&proof.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded.lookup_messages, proof.lookup_messages);
    }
}

/// The two sides have to be configured for the same protocol, in a proof
/// without a single lookup as well: the proof would be accepted by a
/// verifier of the prover's protocol, and the other one refuses it.
#[test]
fn verifier_of_another_protocol_refuses_a_proof_without_lookups() {
    for protocol in PROTOCOLS {
        assert_accepted(sum_claim_e2e(protocol, protocol, |_| ()));
        assert_check_failed(sum_claim_e2e(protocol, other(protocol), |_| ()));
    }
}

/// A verifier does not wait for its `verify` to say that a proof was made
/// with another protocol. Whatever it reads off the proof first says so: a
/// commitment the proof has, or one it lacks where a statement laid out
/// for the verifier's protocol would have one.
#[test]
fn verifier_of_another_protocol_refuses_the_proof_at_its_first_read() {
    for protocol in PROTOCOLS {
        let (mut prover, mut verifier) = setup_under(protocol, other(protocol));
        let id = commit(&mut prover, &summed_column()).unwrap().id();
        let proof = prover.build_proof().unwrap();
        verifier.set_proof_ref(&proof);
        let refusal = format!(
            "proof was made with {protocol}, verifier is configured for {}",
            other(protocol)
        );
        for id in [id, TrackerID(id.0 + 1)] {
            match verifier.track_mv_com_by_id(id).map(drop) {
                Err(SnarkError::VerifierError(VerifierError::VerifierCheckFailed(reason))) => {
                    assert_eq!(reason, refusal)
                }
                other => panic!("expected the proof to be refused, got {other:?}"),
            }
        }

        let (_, mut verifier) = setup_under(protocol, protocol);
        verifier.set_proof_ref(&proof);
        verifier.track_mv_com_by_id(id).unwrap();
    }
}

/// The name a proof carries is not what makes a verifier accept it. A proof
/// renamed to the verifier's protocol passes the comparison of the names
/// and fails on the transcript, which opens with the prover's protocol;
/// one renamed away from it fails the comparison.
#[test]
fn proof_renamed_to_another_lookup_protocol_is_rejected() {
    let rename = |to: LookupProtocol| {
        move |proof: &mut SNARKProof<B>| {
            proof.lookup_messages = match to {
                LookupProtocol::LogUp => LookupMessages::LogUp { sums: Vec::new() },
                LookupProtocol::LogUpGkr => LookupMessages::LogUpGkr,
            }
        }
    };
    for protocol in PROTOCOLS {
        assert_check_failed(sum_claim_e2e(protocol, protocol, rename(other(protocol))));
        assert_rejected_by_verifier(sum_claim_e2e(
            protocol,
            other(protocol),
            rename(other(protocol)),
        ));
    }
}

/// The protocol's tag is the last byte of a LogUp-GKR proof. Flipped to
/// LogUp's, the bytes announce sums that are not there; set to anything
/// else, they name no protocol. Neither decodes.
#[test]
fn proof_bytes_with_a_flipped_protocol_tag_do_not_decode() {
    let (mut prover, _) = setup_under(LookupProtocol::LogUpGkr, LookupProtocol::LogUpGkr);
    let bytes = prover.build_proof().unwrap().to_bytes().unwrap();
    let tag = *bytes.last().unwrap();
    assert_eq!(tag, 1);
    assert!(SNARKProof::<B>::from_bytes(&bytes).is_ok());
    for flipped in [tag ^ 1, tag ^ 2, 0xff] {
        let mut bytes = bytes.clone();
        *bytes.last_mut().unwrap() = flipped;
        assert!(SNARKProof::<B>::from_bytes(&bytes).is_err());
    }
}

/// A lookup of two sub columns of one size, a keyed sum with weights and an
/// unrelated sumcheck claim, proved under `prover` and put to a verifier of
/// `verifier` as `tamper` leaves the proof.
fn lookups_e2e(
    prover: LookupProtocol,
    verifier: LookupProtocol,
    tamper: impl FnOnce(&mut SNARKProof<B>),
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = setup_under(prover, verifier);
    let table = fv(0..16);
    let weights = fv((0..8).map(|i| i + 1));
    let keys = fv((0..8).map(|i| 2 * i));
    let mut counts = vec![F::zero(); 16];
    for (key, weight) in keys.iter().zip(&weights) {
        let at = table.iter().position(|v| v == key).unwrap();
        counts[at] += weight;
    }
    let cols = [
        table,
        fv((0..32).map(|i| (i * 5) % 16)),
        fv((0..32).map(|i| (i * 7 + 3) % 16)),
        keys,
        weights,
        counts,
        summed_column(),
    ]
    .map(|evals| commit(&mut prover, &evals).unwrap());
    let ids = cols.each_ref().map(TrackedPoly::id);
    let [table, sub_a, sub_b, keys, weights, counts, summed] = cols;
    prover.add_mv_lookup_claim(table.id(), sub_a.id())?;
    prover.add_mv_lookup_claim(table.id(), sub_b.id())?;
    prover.add_mv_keyed_sum_claim(KeyedSumcheckProverInput {
        fxs: vec![keys],
        mfxs: vec![Some(weights)],
        gxs: vec![table],
        mgxs: vec![Some(counts)],
    })?;
    prover.add_mv_sumcheck_claim(summed.id(), sum(&summed_column()))?;
    let mut proof = prover.build_proof()?;
    tamper(&mut proof);

    verifier.set_proof_ref(&proof);
    let [table, sub_a, sub_b, keys, weights, counts, summed]: [TrackedOracle<B>; 7] =
        track_all(&mut verifier, &ids)?.try_into().unwrap();
    verifier.add_mv_lookup_claim(table.id(), sub_a.id())?;
    verifier.add_mv_lookup_claim(table.id(), sub_b.id())?;
    verifier.add_mv_keyed_sum_claim(KeyedSumcheckVerifierInput {
        fxs: vec![keys],
        mfxs: vec![Some(weights)],
        gxs: vec![table],
        mgxs: vec![Some(counts)],
    })?;
    verifier.add_mv_sumcheck_claim(summed.id(), sum(&summed_column()));
    verifier.verify()
}

/// With lookups in the proof as without: a verifier of the prover's
/// protocol accepts, and one of the other refuses by a check of its own,
/// in both directions, never by running into what the proof lacks.
#[test]
fn verifier_of_another_protocol_refuses_a_proof_with_lookups() {
    for protocol in PROTOCOLS {
        assert_accepted(lookups_e2e(protocol, protocol, |_| ()));
        assert_check_failed(lookups_e2e(protocol, other(protocol), |_| ()));
    }
}

/// A LogUp proof and a LogUp-GKR proof of one statement, each renamed to
/// the other protocol, with the messages of that protocol missing or made
/// up: refused by the verifier it was made for and by the one it now names.
#[test]
fn proof_with_lookups_renamed_to_another_protocol_is_rejected() {
    let as_logup = |proof: &mut SNARKProof<B>| {
        proof.lookup_messages = LookupMessages::LogUp {
            sums: vec![F::one(); 5],
        }
    };
    let as_gkr = |proof: &mut SNARKProof<B>| proof.lookup_messages = LookupMessages::LogUpGkr;
    let (logup, gkr) = (LookupProtocol::LogUp, LookupProtocol::LogUpGkr);
    assert_check_failed(lookups_e2e(gkr, gkr, as_logup));
    assert_rejected_by_verifier(lookups_e2e(gkr, logup, as_logup));
    assert_check_failed(lookups_e2e(logup, logup, as_gkr));
    assert_rejected_by_verifier(lookups_e2e(logup, gkr, as_gkr));
}

/// The tag of a LogUp proof sits before its sums. Set to a byte that names
/// no protocol, the bytes do not decode. Flipped to LogUp-GKR's, they are a
/// proof without sums with the bytes of the sums left over behind it, and
/// the bytes of a proof end where the proof does: they do not decode
/// either. Flipped and cut off behind the tag, they are that proof and
/// nothing else, which is refused by the verifier it was made for, which
/// is told of another protocol, and by a LogUp-GKR verifier, which shares
/// no challenge with its prover.
#[test]
fn logup_proof_with_a_flipped_protocol_tag_is_rejected() {
    let (logup, gkr) = (LookupProtocol::LogUp, LookupProtocol::LogUpGkr);
    let flipped = |proof: &SNARKProof<B>, to: Option<u8>| {
        let mut bytes = proof.to_bytes().unwrap();
        // The two sub columns share a helper: a sum for them, for
        // their table, and for each side of the keyed sum.
        assert_eq!(logup_sums(proof).len(), 4);
        let tag_at = bytes.len() - 1 - 8 - 32 * 4;
        assert_eq!(bytes[tag_at], 0);
        match to {
            Some(to) => bytes[tag_at] = to,
            None => bytes[tag_at] ^= 1,
        }
        (bytes, tag_at)
    };
    let flip = |to: Option<u8>| {
        move |proof: &mut SNARKProof<B>| {
            let (bytes, _) = flipped(proof, to);
            assert!(SNARKProof::<B>::from_bytes(&bytes).is_err());
        }
    };
    for to in [None, Some(2), Some(0xff)] {
        assert_accepted(lookups_e2e(logup, logup, flip(to)));
    }

    let flip_and_cut = |proof: &mut SNARKProof<B>| {
        let (mut bytes, tag_at) = flipped(proof, None);
        bytes.truncate(tag_at + 1);
        *proof = SNARKProof::<B>::from_bytes(&bytes).unwrap();
        assert_eq!(proof.lookup_messages, LookupMessages::LogUpGkr);
    };
    assert_check_failed(lookups_e2e(logup, logup, flip_and_cut));
    assert_rejected_by_verifier(lookups_e2e(logup, gkr, flip_and_cut));
}

fn with_logup_sums(change: impl FnOnce(&mut Vec<F>)) -> impl FnOnce(&mut SNARKProof<B>) {
    |proof| match &mut proof.lookup_messages {
        LookupMessages::LogUp { sums } => change(sums),
        LookupMessages::LogUpGkr => panic!("not a LogUp proof"),
    }
}

/// The sums a LogUp proof sends are in the transcript: any of them changed
/// after the fact, alone or with another one changed the other way so that
/// the two sides of the relation still balance, leaves a proof whose
/// sumcheck is about other sums and other challenges.
#[test]
fn logup_sum_changed_after_the_fact_is_rejected() {
    let logup = LookupProtocol::LogUp;
    for at in 0..4 {
        let bump = with_logup_sums(|sums| sums[at] += F::one());
        assert_rejected_by_verifier(lookups_e2e(logup, logup, bump));
    }
    // The helper of the two sub columns and the table they are looked up
    // in are the two sides of one relation; so are the keys and the table
    // of the keyed sum.
    for (f, g) in [(0, 1), (2, 3)] {
        let shift = with_logup_sums(|sums| {
            sums[f] += F::one();
            sums[g] += F::one();
        });
        assert_rejected_by_verifier(lookups_e2e(logup, logup, shift));
    }
}

/// A proof with fewer sums than the verifier has terms, or with more, is
/// refused with an error: the verifier reads the sums in order and must
/// have read every one of them.
#[test]
fn logup_proof_with_missing_or_extra_sums_is_an_error_not_a_panic() {
    let logup = LookupProtocol::LogUp;
    for kept in 0..4 {
        let cut = with_logup_sums(|sums| sums.truncate(kept));
        assert_check_failed(lookups_e2e(logup, logup, cut));
    }
    let extra = with_logup_sums(|sums| sums.push(F::zero()));
    assert_check_failed(lookups_e2e(logup, logup, extra));
    let repeated = with_logup_sums(|sums| sums.extend_from_within(..));
    assert_check_failed(lookups_e2e(logup, logup, repeated));
    // A LogUp-GKR proof has no place for sums, and a LogUp proof is not
    // read for GKR subproofs: one that carries some anyway is refused.
    let with_subproof = |proof: &mut SNARKProof<B>| {
        proof.logup_gkr_subproofs.push(Default::default());
    };
    assert_check_failed(lookups_e2e(logup, logup, with_subproof));
}
