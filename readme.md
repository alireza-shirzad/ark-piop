# ark-piop

A Rust framework for building **Polynomial Interactive Oracle Proof (PIOP)**
arguments on top of the [arkworks](https://github.com/arkworks-rs) ecosystem.

`ark-piop` is a **library**, not a binary. It provides the plumbing — prover
and verifier trackers, polynomial commitment schemes, Fiat-Shamir transcript,
serialization — so that downstream crates can express a proof system as a
composition of these pieces without re-implementing them.

Protocols are expressed by emitting **claims** on tracked polynomials. The
tracker supports five claim kinds:

| Claim            | Meaning                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| **sumcheck**     | `∑_{x ∈ {0,1}^n} p(x) = s` for a declared sum `s`                       |
| **zerocheck**    | `p(x) = 0` for all `x ∈ {0,1}^n`                                        |
| **nozerocheck**  | `p(x) ≠ 0` for all `x ∈ {0,1}^n`                                        |
| **lookup**       | every value in a sub-column appears in a super-column (LogUp)           |
| **evaluation**   | `p(r) = v` at a committed point `r`                                     |

You emit as many claims as you like across the run. When the prover calls
`build_proof()`, **all registered claims are batched into a single proof**
via a shared sumcheck / zerocheck compilation pipeline, and the verifier's
mirrored claims are checked against it in one pass.

> ⚠️ **Research-grade code, not audited.** See [SECURITY.md](SECURITY.md)
> before using for anything real.

## Using it in your project

Add it as a git dependency:

```toml
[dependencies]
ark-piop = { git = "https://github.com/alireza-shirzad/ark-piop" }

[dev-dependencies]
ark-piop = { git = "https://github.com/alireza-shirzad/ark-piop", features = ["test-utils"] }
```

A minimal end-to-end that emits several claim kinds and demonstrates the
**prover/verifier mirror** pattern — every claim the prover emits must be
mirrored on the verifier side against the same tracker ID:

```rust
use ark_ff::Zero;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    test_utils::test_prelude,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

let (mut prover, mut verifier) = test_prelude::<B>().unwrap();

// --- polynomials (4 variables → 16 evaluations each) -------------------
let nv = 4;
let size = 1 << nv;
let evals_a: Vec<F> = (0..size).map(|i| F::from(i as u64)).collect();
let evals_zero: Vec<F> = vec![F::zero(); size];
// super column contains every value in the sub column:
let evals_super: Vec<F> = (0..size).map(|i| F::from((i % 8) as u64)).collect();
let evals_sub:   Vec<F> = (0..size).map(|i| F::from(((i * 3) % 8) as u64)).collect();

let poly_a     = MLE::from_evaluations_vec(nv, evals_a.clone());
let poly_zero  = MLE::from_evaluations_vec(nv, evals_zero);
let poly_super = MLE::from_evaluations_vec(nv, evals_super);
let poly_sub   = MLE::from_evaluations_vec(nv, evals_sub);

// --- prover: track, commit, emit claims --------------------------------
let t_a     = prover.track_and_commit_mat_mv_poly(&poly_a).unwrap();
let t_zero  = prover.track_and_commit_mat_mv_poly(&poly_zero).unwrap();
let t_super = prover.track_and_commit_mat_mv_poly(&poly_super).unwrap();
let t_sub   = prover.track_and_commit_mat_mv_poly(&poly_sub).unwrap();

let sum_a: F = evals_a.iter().copied().fold(F::zero(), |x, y| x + y);

// All claims are registered separately; build_proof batches them.
prover.add_mv_sumcheck_claim(t_a.id(), sum_a).unwrap();
prover.add_mv_zerocheck_claim(t_zero.id()).unwrap();
prover.add_mv_lookup_claim(t_super.id(), t_sub.id()).unwrap();

// Single compilation step: every claim folds into one proof.
let proof = prover.build_proof().unwrap();

// --- verifier: mirror every claim, then verify -------------------------
verifier.set_proof(proof);

// Each tracked commitment the prover registered must be tracked here too,
// in the same order, so tracker IDs line up on both sides.
verifier.track_mv_com_by_id(t_a.id()).unwrap();
verifier.track_mv_com_by_id(t_zero.id()).unwrap();
verifier.track_mv_com_by_id(t_super.id()).unwrap();
verifier.track_mv_com_by_id(t_sub.id()).unwrap();

// Mirror the claims — same IDs, same public inputs (e.g. `sum_a`).
verifier.add_mv_sumcheck_claim(t_a.id(), sum_a);
verifier.add_mv_zerocheck_claim(t_zero.id());
verifier.add_mv_lookup_claim(t_super.id(), t_sub.id()).unwrap();

verifier.verify().unwrap();
```

The key invariant: **the prover and verifier must emit the same claims in
the same order** — tracker IDs are assigned sequentially from a shared
counter, and the final batched proof is only sound if both sides agree on
what each ID refers to. Skip a `track_mv_com_by_id` call on the verifier
and every subsequent ID will be off by one.

A larger worked example exercising zerocheck and lookup claims lives in
[tests/pipeline.rs](tests/pipeline.rs). For a real-world downstream use,
see [truth-table](https://github.com/alireza-shirzad/truth-table) which
builds a database-query proof system on top of this crate.

## Architecture

| Layer          | Modules                                          | Purpose                                                      |
| -------------- | ------------------------------------------------ | ------------------------------------------------------------ |
| Foundation     | `arithmetic`, `transcript`, `structs`, `errors`  | Field math, Fiat-Shamir transcript, shared types             |
| Commitment     | `pcs`                                            | Polynomial commitment schemes (KZG10 univariate, PST13 multivariate) |
| Protocol       | `piop`                                           | `PIOP` trait, sumcheck / zerocheck / nozerocheck / lookup / evaluation sub-protocols |
| Setup          | `setup`                                          | Trusted-setup key generation (proving key + verifying key)   |
| Proving        | `prover`                                         | Prover tracker, proof compilation pipeline                   |
| Verification   | `verifier`                                       | Verifier tracker, proof verification pipeline                |
| I/O            | `artifact`                                       | Canonical serialization of proofs and keys                   |

The central abstraction is the [`SnarkBackend`] trait, which bundles a prime
field with a univariate and a multivariate PCS. Protocol code is generic over
`B: SnarkBackend`, so the same protocol can be instantiated over different
curves or commitment schemes by swapping a single type parameter.

## Typical workflow

1. Pick or define a `SnarkBackend` (e.g. `DefaultSnarkBackend` = BN254 +
   PST13 + KZG10 for testing).
2. Generate keys via `setup::KeyGenerator`.
3. Express your protocol by adding claims (sumcheck / zerocheck / lookup) on
   tracked polynomials through the prover tracker API.
4. Call `prover.build_proof()` — the tracker batches all registered claims
   into a single proof.
5. On the verifier side, mirror the claims against the received proof and
   call `verifier.verify()`.

## Features

- `test-utils` *(optional)* — exposes `test_prelude()` and
  `DefaultSnarkBackend` for downstream tests and benches.
- `parallel` *(default)* — enables rayon-based parallelism in arkworks.
- `honest-prover` — extra debug checks that catch malformed claims on the
  prover side before proof compilation; useful during development, turn off
  in benchmarks.
- `std` *(default)* — standard library support (required).
- `print-trace` — enables `ark-std` timing traces.

## Development

```sh
just test      # run tests with and without honest-prover
just clippy    # lint both feature combinations
just fmt       # format check (nightly rustfmt)
just bench     # run criterion microbenchmarks
just ci        # fmt + clippy + test
```

See [CHANGELOG.md](CHANGELOG.md) for recent changes and
[SECURITY.md](SECURITY.md) for the disclosure policy.
