# Changelog

All notable changes to `ark-piop` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- LogUp-GKR for lookup claims and keyed sums: all of a proof's lookups are
  reduced in one batched GKR argument at `build_proof`, without helper
  commitments (`piop::logup_gkr`).
- `LookupProtocol` and `SharedArgConfig::lookup_protocol` choose between
  LogUp and LogUp-GKR per proof. `ARK_PIOP_LOOKUP_PROTOCOL=logup|gkr` sets
  the protocol of `SharedArgConfig::default()`. LogUp-GKR is the default.
- `ArgProver::new_from_pk_with_config` and
  `ArgVerifier::new_from_vk_with_config`.
- `add_mv_keyed_sum_claim` on the prover and the verifier, to have a keyed
  sum proved with the proof's lookups.
- `SharedArgConfig::logup_gkr_run_budget` bounds the prover memory of one
  GKR run.
- `examples/bench_lookup.rs`, a lookup benchmark harness.

### Changed

- **Proof encoding version 7.** Earlier proofs do not decode, and proofs
  differ from earlier ones under either protocol.
- The multivariate batch opening is over polynomials of mixed sizes, binds
  its claims to the transcript before drawing its challenge, and no longer
  repeats the claimed evaluations in the proof.
- `PST13::open` and `PST13::verify` read as many coordinates of a point as
  the committed polynomial has variables.
- The prover opens commitments in the order of the proof's query map.
- `SNARKProof::from_bytes` rejects trailing bytes.
- `SharedArgConfig` and `SNARKProof` have new fields; the `TrackerCore`
  trait has new required methods.
- `ProverTracker::new_from_pk_with_config` returns a `Result`.
- `VerifierTracker`'s `config` field is no longer public.
- Under LogUp, the per-column sums are sent in the proof and bound to the
  transcript, and constant columns are checked in the clear.

### Fixed

- **`verify()` rejects a proof whose polynomial openings do not hold.** The
  results of both PCS verifications were discarded, the multivariate batch
  check read the evaluations and the point from the proof instead of the
  verifier's own, and it only held for commitments of one size, so a proof
  with false evaluations was accepted.
- A commitment id of the proof's commitment map can no longer stand for two
  different commitments, which let the evaluations of a commitment the
  verifier holds be opened against one of the proof's.
- The univariate batch check verifies one proof per claim.
- A bucket sumcheck that declares a higher degree than the verifier's own
  polynomial has is rejected; the degree was the proof's to choose.
- **A sumcheck claim is checked for the sum it was added with.** The
  verifier took a claim's sum for one of the proof's claim map, which holds
  sums lifted to the widest commitment, whenever the two were equal. An
  honest proof of a sum was thereby also accepted for that sum times a power
  of two. A sum is now in the map's frame only if the verifier read it there
  with `prover_claimed_sum`.
- **Claimed sums are bound to the transcript before their claims are
  batched.** The batching weights did not depend on the sums, so a prover
  could choose sums it reports in the proof after seeing them, and have two
  different sums accepted as equal.
- A lookup whose constant column is wider than every commitment, and one
  whose column and multiplicities differ in size, are now proved.
- Verification fails after a lookup reduction that failed or never ran.

## [0.1.0] - 2026-04-15

Initial release.
