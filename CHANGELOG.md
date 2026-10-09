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

- **Proof encoding version 5.** Earlier proofs do not decode, and proofs
  differ from earlier ones under either protocol.
- `SNARKProof::from_bytes` rejects trailing bytes.
- `SharedArgConfig` and `SNARKProof` have new fields; the `TrackerCore`
  trait has new required methods.
- `ProverTracker::new_from_pk_with_config` returns a `Result`.
- `VerifierTracker`'s `config` field is no longer public.
- Under LogUp, the per-column sums are sent in the proof and bound to the
  transcript, and constant columns are checked in the clear.

### Fixed

- A lookup whose constant column is wider than every commitment, and one
  whose column and multiplicities differ in size, are now proved.
- Verification fails after a lookup reduction that failed or never ran.

## [0.1.0] - 2026-04-15

Initial release.
