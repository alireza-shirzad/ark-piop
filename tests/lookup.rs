//! Lookup and keyed-sumcheck behaviour through the public API.
//!
//! Each test states a relation and checks only whether it is accepted or
//! rejected, never how the proof is laid out, so the suite keeps its meaning
//! when the protocol underneath the claims changes.
#![cfg(feature = "test-utils")]

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
    test_utils::prelude_with_vars,
    types::{TrackerID, artifact::Artifact},
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// Every column here has at most 2^8 rows; the 2^10 SRS loads in
/// milliseconds, where `test_prelude` re-reads the 2^19 one on every call.
const SRS_NV: usize = 10;

fn setup() -> (ArgProver<B>, ArgVerifier<B>) {
    prelude_with_vars::<B>(SRS_NV).unwrap()
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
    let (mut prover, mut verifier) = setup();
    let statement = prove(&mut prover)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    verify(&mut verifier, statement)?;
    verifier.verify()?;
    assert_prover_verifier_in_sync(&prover, &verifier);
    Ok(())
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
}

#[test]
fn lookup_sub_smaller_than_table() {
    let table = fv(0..256);
    assert_accepted(lookup_e2e(&table, &[fv((0..16).map(|i| i * 16 + 3))]));

    let mut bad = fv((0..16).map(|i| i * 16 + 3));
    bad[5] = F::from(256u64);
    assert_rejected(lookup_e2e(&table, &[bad]));
}

#[test]
fn lookup_sub_larger_than_table() {
    let table = fv(0..16);
    assert_accepted(lookup_e2e(&table, &[fv((0..256).map(|i| (i * 5) % 16))]));

    let mut bad = fv((0..256).map(|i| (i * 5) % 16));
    bad[200] = F::from(16u64);
    assert_rejected(lookup_e2e(&table, &[bad]));
}

#[test]
fn lookup_three_subs_table_with_duplicates() {
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
}

/// Subs of three different sizes against one table, on both sides of the
/// table's own size.
#[test]
fn lookup_subs_of_mixed_sizes_one_table() {
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
}

/// The same claim made twice, and a table looked up in itself.
#[test]
fn lookup_repeated_and_self_claims() {
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
}

#[test]
fn hinted_lookup_correct_multiplicity_accepts() {
    // Every even table value is hit twice, odd values never.
    let table = fv(0..64);
    let sub = fv((0..64).map(|i| (i * 2) % 64));
    let multiplicity = fv((0..64).map(|i| if i % 2 == 0 { 2 } else { 0 }));
    assert_accepted(hinted_e2e(&table, &[sub], &multiplicity));

    // Two subs of different sizes feeding one multiplicity column.
    let subs = [fv((0..64).map(|i| i % 16)), fv(0..16)];
    let multiplicity = fv((0..64).map(|i| if i < 16 { 5 } else { 0 }));
    assert_accepted(hinted_e2e(&table, &subs, &multiplicity));
}

#[test]
fn hinted_lookup_wrong_multiplicity_is_rejected() {
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
}

#[test]
fn lookup_check_piop_accepts_and_rejects() {
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
}

#[test]
fn keyed_sumcheck_multiplicities_both_sides_mixed_nv() {
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
}

#[test]
fn keyed_sumcheck_permutation_and_non_permutation() {
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
}

/// Columns and multiplicities that were committed as constants reach the
/// keyed sum as constant handles, not as tracked polynomials.
#[test]
fn keyed_sumcheck_constant_columns_and_multiplicities() {
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
}

/// As `lookup_constant_sub_wider_than_every_commitment`, through the PIOP.
#[test]
fn keyed_sumcheck_constant_column_wider_than_every_commitment() {
    let counts = fv((0..16).map(|i| if i == 7 { 32 } else { 0 }));
    assert_accepted(keyed_e2e(
        &[(fv([7; 32]), None)],
        &[(fv(0..16), Some(counts))],
    ));
}

/// A multiplicity with more rows than its column, and the other way round:
/// each term of the sum ranges over the larger of the two, the smaller one
/// repeating.
#[test]
fn keyed_sum_column_and_multiplicity_of_different_nv() {
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
    let per_key = fv((0..8).map(|key| (0..32u64).filter(|i| i % 8 == key).map(|i| i + 1).sum()));
    assert_accepted(keyed_e2e(
        &[(fv(0..8), Some(fv((0..32).map(|i| i + 1))))],
        &[(fv(0..8), Some(per_key))],
    ));

    // 32 keys, each of 0..8 four times, under 8 repeating weights.
    assert_accepted(keyed_e2e(
        &[(fv((0..32).map(|i| i % 8)), Some(fv((0..8).map(|i| i + 1))))],
        &[(fv(0..8), Some(fv((0..8).map(|key| 4 * (key + 1)))))],
    ));
}

#[test]
fn lookup_sub_virtual_product() {
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
}

/// A constant data chunk is committed as a constant, so `data * activator`
/// reaches the lookup as a scalar multiple of the activator; an all-zero
/// chunk (the high limbs of small integers) makes that scalar zero.
#[test]
fn lookup_sub_committed_constant_times_activator() {
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
}

/// As above with the sub far wider than the table, so that the claim on the
/// all-zero sub is the only one of its size in the proof.
#[test]
fn lookup_sub_zero_constant_times_activator_far_wider_than_the_table() {
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
    for (rows, sibling) in [(8, false), (16, false), (64, true)] {
        assert_accepted(constant_sub_e2e(0, rows, false, sibling));
        assert_accepted(constant_sub_e2e(7, rows, false, sibling));
        assert_rejected(constant_sub_e2e(16, rows, false, sibling));
    }
}

/// A constant chunk times a constant activator folds to a constant that was
/// never committed; asking for its id tracks it on both sides.
#[test]
fn lookup_sub_derived_constant() {
    for (rows, sibling) in [(8, false), (16, false), (64, true)] {
        assert_accepted(constant_sub_e2e(0, rows, true, sibling));
        assert_accepted(constant_sub_e2e(7, rows, true, sibling));
        assert_rejected(constant_sub_e2e(16, rows, true, sibling));
    }
}

/// The constant sub is the largest column of the whole proof: the table and
/// its multiplicity have 16 rows and nothing else is committed.
#[test]
fn lookup_constant_sub_wider_than_every_commitment() {
    assert_accepted(constant_sub_e2e(7, 32, false, false));
    assert_accepted(constant_sub_e2e(7, 64, true, false));
    assert_rejected(constant_sub_e2e(16, 32, false, false));
}

/// `(a + 4·b + 16) · activator`: several terms, a scalar on a term and a
/// constant term, all under one activator.
#[test]
fn lookup_sub_multiterm_virtual() {
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
}

#[test]
fn lookup_transparent_table_sub_larger() {
    let activator = prefix_activator(6, 50);
    // Inactive rows are zero, as in the limb columns of a sign check.
    let data = fv((0..64).map(|i| if i < 50 { (i * 7) % 16 } else { 0 }));
    assert_accepted(transparent_range_e2e(4, &data, &activator));

    let mut bad = data;
    bad[49] = F::from(16u64);
    assert_rejected(transparent_range_e2e(4, &bad, &activator));
}

#[test]
fn lookup_transparent_table_sub_smaller() {
    let activator = prefix_activator(3, 6);
    let data = fv((0..8).map(|i| if i < 6 { i * 9 + 2 } else { 0 }));
    assert_accepted(transparent_range_e2e(6, &data, &activator));

    let mut bad = data;
    bad[0] = F::from(64u64);
    assert_rejected(transparent_range_e2e(6, &bad, &activator));
}

/// The AND-table lookup of a bitwise gadget: the table depends on challenges
/// drawn after the columns are committed, exists only on the prover, and is
/// tracked after those challenges on both sides.
#[test]
fn lookup_table_tracked_after_challenge() {
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
                acc += weight * (rs[0] * x[i] + rs[1] * x[BITS + i] + rs[2] * x[i] * x[BITS + i]);
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
}

/// A one-row table and a one-row sub, next to an ordinary claim on a real
/// column.
#[test]
fn lookup_nv0_table_and_sub() {
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
}

/// The same lookup as the whole statement: every polynomial is a constant.
#[test]
#[ignore = "limitation of the sumcheck, not of the lookup: a proof whose only claims are on \
            polynomials without variables cannot be built; build_proof returns a PolyIOP error \
            (\"Attempt to prove a constant\") for a true statement"]
fn lookup_nv0_only_statement() {
    assert_accepted(lookup_e2e(&fv([7]), &[fv([7])]));
    assert_rejected(lookup_e2e(&fv([7]), &[fv([8])]));
}

/// A one-row sub in a real table, and a real sub in a one-row table.
#[test]
fn lookup_nv0_against_larger_columns() {
    assert_accepted(lookup_e2e(&fv(0..16), &[fv([7])]));
    assert_rejected(lookup_e2e(&fv(0..16), &[fv([16])]));

    let mut bad = fv([7; 8]);
    bad[3] = F::from(6u64);
    assert_rejected(lookup_e2e(&fv([7]), &[bad]));
}

/// A table that is itself a committed constant.
#[test]
fn lookup_constant_table() {
    assert_accepted(lookup_e2e(&fv([7; 32]), &[fv([7; 8])]));
    assert_rejected(lookup_e2e(&fv([7; 32]), &[fv([6; 8])]));
    assert_rejected(lookup_e2e(&fv([7; 8]), &[fv([7, 7, 7, 7, 7, 7, 7, 6])]));
}

/// The lookup is the whole statement: the proof carries no sumcheck or
/// zerocheck claim of the caller's own, and the table is not even committed.
#[test]
fn lookup_only_statement() {
    assert_accepted(lookup_e2e(&fv(0..8), &[fv((0..8).map(|i| 7 - i))]));
    assert_accepted(transparent_range_e2e(
        3,
        &fv((0..8).map(|i| 7 - i)),
        &fv([1; 8]),
    ));
}

/// Lookup claims against three tables, interleaved with ordinary claims and
/// with keyed sumchecks proved on the spot.
#[test]
fn several_super_groups_plus_direct_keyed_sumcheck() {
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
            ]: [TrackedOracle<B>; 14] = track_all(verifier, &statement.ids)?.try_into().unwrap();
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
}

/// Two hinted lookups, each false, whose errors cancel when all four sides
/// are added up: `sub_a` holds one value that only `table_b` has and the
/// multiplicity of `table_b` counts it, and the other way round. Each
/// relation has to balance on its own.
#[test]
fn two_relations_with_cancelling_errors_are_rejected() {
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
}

/// Two lookup groups whose subs each hold a value found only in the other
/// group's table. The union of the subs is inside the union of the tables,
/// so only a per-table check tells this apart from a true statement.
#[test]
fn lookup_groups_do_not_share_tables() {
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
}

/// The prover proves `good ⊆ table`; the verifier is told `other ⊆ table`.
/// `other` is committed in the same proof, is opened through a sumcheck
/// claim of its own, and really is inside the table: only the binding of
/// the lookup to the column it was proved for can reject this.
#[test]
fn verifier_statement_swap_column_is_rejected() {
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
}

/// As above for the multiplicity of a hinted lookup: proved with the true
/// counts, mirrored with another committed column.
#[test]
fn verifier_statement_swap_multiplicity_is_rejected() {
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
    assert_accepted(mirrored_lookup_claims_e2e(2));
    assert_rejected_by_verifier(mirrored_lookup_claims_e2e(1));
    assert_rejected_by_verifier(mirrored_lookup_claims_e2e(0));
}

/// The extra claim is true, but the prover never proved it.
#[test]
fn verifier_extra_lookup_claim_is_rejected() {
    assert_rejected_by_verifier(mirrored_lookup_claims_e2e(3));
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
    let (proof, mut verifier, ids) = proof_with_lookups();
    let bytes = proof.to_bytes().unwrap();
    assert_eq!(bytes[0], PROOF_ENCODING_VERSION);

    let decoded = SNARKProof::<B>::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
    // Both tables are reduced in one batch, which the decoded proof keeps.
    assert_eq!(proof.logup_gkr_subproofs.len(), 1);
    assert_eq!(decoded.logup_gkr_subproofs, proof.logup_gkr_subproofs);
    verifier.set_proof(decoded);
    assert_accepted(verify_proof_with_lookups(&mut verifier, &ids));
}

/// Every byte of a serialized proof belongs to exactly one top-level part of
/// the size breakdown; the one byte left over is the version tag.
#[test]
fn size_breakdown_parts_sum_to_total() {
    let (proof, ..) = proof_with_lookups();
    let breakdown = proof
        .size_breakdown()
        .expect("a proof has a size breakdown");
    assert_eq!(breakdown.size, proof.to_bytes().unwrap().len());
    let parts: usize = breakdown.parts.values().map(|part| part.size).sum();
    assert_eq!(parts + 1, breakdown.size);
}

/// A keyed sum whose numerator is `multiplicity · activator`, or the bare
/// activator: rows the activator switches off contribute nothing, whatever
/// their key is.
#[test]
fn keyed_sum_activator_numerator_semantics() {
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
                KeyedSumcheck::<B>::prove(
                    prover,
                    KeyedSumcheckProverInput {
                        fxs: vec![keys],
                        gxs: vec![g],
                        mfxs: vec![Some(numerator)],
                        mgxs: vec![Some(totals)],
                    },
                )?;
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
                KeyedSumcheck::<B>::verify(
                    verifier,
                    KeyedSumcheckVerifierInput {
                        fxs: vec![keys],
                        gxs: vec![g],
                        mfxs: vec![Some(numerator)],
                        mgxs: vec![Some(totals)],
                    },
                )?;
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
