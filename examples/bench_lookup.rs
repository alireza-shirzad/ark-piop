//! Measures what lookup claims add to a proof, one configuration per process
//! (so that peak RSS belongs to that configuration alone).
//!
//! Run with:
//!     cargo run --release --example bench_lookup --features test-utils -- \
//!         [--header] [--reps N] [--protocol P] \
//!         <shape> <table_log> <sub_log> <n_subs> <mode>
//!
//! Protocols (`--protocol`), for both sides:
//!   gkr       LogUp-GKR.
//!   logup     LogUp with committed helpers.
//! Without the option the protocol is that of a default configuration: the
//! one `ARK_PIOP_LOOKUP_PROTOCOL` names, and LogUp-GKR when it is not set.
//! The option decides when both are given.
//!
//! Shapes:
//!   material  the table `0..2^table_log` is committed; every sub is a
//!             committed column of `2^sub_log` random table values.
//!   tt        the shape of a downstream range check: the table
//!             `0..2^table_log` is transparent (an uncommitted polynomial on
//!             the prover, a closure on the verifier); every sub is the
//!             virtual product of a committed limb column and a committed
//!             0/1 activator. Inactive rows of a limb column are zero, and
//!             `ACT_GROUP` subs (default 16) share one activator, as the
//!             limbs of the checked columns of one table do.
//!
//! Modes:
//!   lookup    one `add_mv_lookup_claim` per sub.
//!   control   the same commitments with one ordinary sumcheck claim per
//!             committed column and no lookup, so `lookup - control` is the
//!             cost of the lookups themselves.
//!
//! Prints one tab-separated line, which ends in the protocol the proofs
//! were made with; `--header` prints the column names first (alone, when no
//! configuration is given). `build_proof_ms` and `verify_ms`
//! are minima over the repetitions; a repetition whose `build_proof` took
//! 30 s or more is the last one. Input commitments are computed once, outside
//! the timed region. The verifier checks every proof.
//!
//! Environment: `SRS_NV` (default 19) and `SRS_DIR` (default
//! `<cwd>/../artifacts/srs`) select the SRS; `RAYON_NUM_THREADS` the threads.

use ark_ff::{One, Zero};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    pcs::PCS,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    setup::KeyGenerator,
    types::{CommitmentBinding, LookupProtocol, SharedArgConfig, TrackerID, artifact::Artifact},
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use std::{process::exit, sync::Arc, time::Instant};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;
type Commitment = <<B as SnarkBackend>::MvPCS as PCS<F>>::Commitment;

const COLUMNS: &str = "shape\ttable_log\tsub_log\tn_subs\tthreads\tmode\tbuild_proof_ms\tverify_ms\t\
                       proof_bytes\tmv_commitments\tgkr_bytes\tpeak_rss_mb\tprotocol";
/// A slower `build_proof` is measured once.
const REPEAT_BELOW_MS: f64 = 30_000.0;

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Material,
    Tt,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Lookup,
    Control,
}

struct Config {
    shape: Shape,
    table_log: usize,
    sub_log: usize,
    n_subs: usize,
    mode: Mode,
    reps: usize,
    protocol: LookupProtocol,
}

/// A committed input column. The commitment is computed once and handed to
/// every repetition's prover, which tracks its own copy of the polynomial.
struct Column {
    poly: Arc<MLE<F>>,
    commitment: Commitment,
    sum: F,
}

struct Inputs {
    /// material: the table. tt: the activators.
    shared: Vec<Column>,
    /// material: the subs. tt: the limb columns.
    data: Vec<Column>,
    /// tt: limb column `i` belongs to activator `i / group`.
    group: usize,
}

fn usage() -> ! {
    eprintln!(
        "usage: bench_lookup [--header] [--reps N] [--protocol <logup|gkr>] <material|tt> \
         <table_log> <sub_log> <n_subs> <lookup|control>\n\
         without --protocol, the lookup protocol is the one ARK_PIOP_LOOKUP_PROTOCOL names, and \
         gkr when it is not set"
    );
    exit(2)
}

fn parse_args() -> (bool, Option<Config>) {
    let mut header = false;
    let mut reps = 3;
    let mut protocol = None;
    let mut positional = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--header" => header = true,
            "--reps" => {
                reps = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|&n: &usize| n > 0)
                    .unwrap_or_else(|| usage())
            }
            "--protocol" => {
                protocol = Some(
                    args.next()
                        .and_then(|v| v.parse::<LookupProtocol>().ok())
                        .unwrap_or_else(|| usage()),
                )
            }
            _ => positional.push(arg),
        }
    }
    if header && positional.is_empty() {
        return (true, None);
    }
    let [shape, table_log, sub_log, n_subs, mode] = positional.as_slice() else {
        usage()
    };
    let number = |s: &String| s.parse::<usize>().unwrap_or_else(|_| usage());
    let config = Config {
        shape: match shape.as_str() {
            "material" => Shape::Material,
            "tt" => Shape::Tt,
            _ => usage(),
        },
        table_log: number(table_log),
        sub_log: number(sub_log),
        n_subs: number(n_subs),
        mode: match mode.as_str() {
            "lookup" => Mode::Lookup,
            "control" => Mode::Control,
            _ => usage(),
        },
        reps,
        protocol: protocol.unwrap_or_else(|| SharedArgConfig::default().lookup_protocol),
    };
    if config.n_subs == 0 {
        usage()
    }
    (header, Some(config))
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn threads() -> usize {
    #[cfg(feature = "parallel")]
    {
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}

/// A field of `/proc/self/status`, in MiB; 0 where there is no procfs.
fn status_mb(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let line = status.lines().find(|line| line.starts_with(field))?;
            line.split_whitespace().nth(1)?.parse::<u64>().ok()
        })
        .map_or(0, |kb| kb / 1024)
}

fn ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1e3
}

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}

/// Commits a column of small integers. It is built the way callers build
/// theirs, as field elements, and then stored the way the tracker stores it.
fn column(prover: &ArgProver<B>, nv: usize, values: Vec<u64>) -> Column {
    let sum = F::from(values.iter().sum::<u64>());
    let evals = values.into_iter().map(F::from).collect();
    let poly = Arc::new(MLE::from_evaluations_vec(nv, evals).compressed());
    let commitment = <B as SnarkBackend>::MvPCS::commit(prover.mv_pcs_prover_param(), &poly)
        .expect("commit an input column");
    Column {
        poly,
        commitment,
        sum,
    }
}

fn build_inputs(config: &Config, prover: &ArgProver<B>) -> Inputs {
    let table_size = 1u64 << config.table_log;
    let rows = 1usize << config.sub_log;
    let mut state = 0x1234_5678u64 + config.n_subs as u64;
    match config.shape {
        Shape::Material => Inputs {
            shared: vec![column(prover, config.table_log, (0..table_size).collect())],
            data: (0..config.n_subs)
                .map(|_| {
                    let values = (0..rows).map(|_| lcg(&mut state) % table_size).collect();
                    column(prover, config.sub_log, values)
                })
                .collect(),
            group: config.n_subs,
        },
        Shape::Tt => {
            let group = env_usize("ACT_GROUP").filter(|&g| g > 0).unwrap_or(16);
            // About three rows in four are active.
            let activators: Vec<Vec<u64>> = (0..config.n_subs.div_ceil(group))
                .map(|_| {
                    (0..rows)
                        .map(|_| u64::from(!lcg(&mut state).is_multiple_of(4)))
                        .collect()
                })
                .collect();
            let data = (0..config.n_subs)
                .map(|i| {
                    let values = activators[i / group]
                        .iter()
                        .map(|active| active * (lcg(&mut state) % table_size))
                        .collect();
                    column(prover, config.sub_log, values)
                })
                .collect();
            let shared = activators
                .into_iter()
                .map(|values| column(prover, config.sub_log, values))
                .collect();
            Inputs {
                shared,
                data,
                group,
            }
        }
    }
}

/// The range table's multilinear extension `sum_i 2^i x_i`, read from the
/// low `nv` coordinates of the query point.
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

fn track(prover: &mut ArgProver<B>, columns: &[Column]) -> Vec<TrackedPoly<B>> {
    columns
        .iter()
        .map(|column| {
            prover
                .track_mat_mv_poly_with_commitment(
                    &column.poly,
                    column.commitment,
                    CommitmentBinding::ProofEmitted,
                )
                .expect("track an input column")
        })
        .collect()
}

fn mirror(verifier: &mut ArgVerifier<B>, ids: &[TrackerID]) -> Vec<TrackedOracle<B>> {
    ids.iter()
        .map(|id| {
            verifier
                .track_mv_com_by_id(*id)
                .expect("the proof carries every input commitment")
        })
        .collect()
}

struct Measurement {
    build_proof_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    mv_commitments: usize,
    gkr_bytes: usize,
}

fn run_once(
    config: &Config,
    inputs: &Inputs,
    mut prover: ArgProver<B>,
    mut verifier: ArgVerifier<B>,
) -> Measurement {
    let shared = track(&mut prover, &inputs.shared);
    let data = track(&mut prover, &inputs.data);
    let ids = |polys: &[TrackedPoly<B>]| polys.iter().map(TrackedPoly::id).collect::<Vec<_>>();
    let (shared_ids, data_ids) = (ids(&shared), ids(&data));
    match (config.mode, config.shape) {
        (Mode::Control, _) => {
            for (poly, column) in shared.iter().zip(&inputs.shared) {
                prover.add_mv_sumcheck_claim(poly.id(), column.sum).unwrap();
            }
            for (poly, column) in data.iter().zip(&inputs.data) {
                prover.add_mv_sumcheck_claim(poly.id(), column.sum).unwrap();
            }
        }
        (Mode::Lookup, Shape::Material) => {
            for sub in &data {
                prover
                    .add_mv_lookup_claim(shared[0].id(), sub.id())
                    .unwrap();
            }
        }
        (Mode::Lookup, Shape::Tt) => {
            let table_evals = (0..1u64 << config.table_log).map(F::from).collect();
            let table =
                prover.track_mat_mv_poly(MLE::from_evaluations_vec(config.table_log, table_evals));
            for (i, limb) in data.iter().enumerate() {
                let sub = limb * &shared[i / inputs.group];
                prover.add_mv_lookup_claim(table.id(), sub.id()).unwrap();
            }
        }
    }
    // The handles share ownership of the tracker with `prover`.
    drop((shared, data));

    let start = Instant::now();
    let proof = prover.build_proof().expect("build_proof");
    let build_proof_ms = ms(start);
    let mv_commitments = prover.commitment_counts().0;
    drop(prover);
    let proof_bytes = proof.to_bytes().expect("serialize the proof").len();
    let gkr_bytes = proof
        .size_breakdown()
        .and_then(|breakdown| breakdown.parts.get("logup_gkr_subproofs").map(|p| p.size))
        .unwrap_or(0);

    verifier.set_proof(proof);
    let shared = mirror(&mut verifier, &shared_ids);
    let data = mirror(&mut verifier, &data_ids);
    match (config.mode, config.shape) {
        (Mode::Control, _) => {
            for (oracle, column) in shared.iter().zip(&inputs.shared) {
                verifier.add_mv_sumcheck_claim(oracle.id(), column.sum);
            }
            for (oracle, column) in data.iter().zip(&inputs.data) {
                verifier.add_mv_sumcheck_claim(oracle.id(), column.sum);
            }
        }
        (Mode::Lookup, Shape::Material) => {
            for sub in &data {
                verifier
                    .add_mv_lookup_claim(shared[0].id(), sub.id())
                    .unwrap();
            }
        }
        (Mode::Lookup, Shape::Tt) => {
            let table = verifier.track_base_oracle(range_oracle(config.table_log));
            for (i, limb) in data.iter().enumerate() {
                let sub = limb * &shared[i / inputs.group];
                verifier.add_mv_lookup_claim(table.id(), sub.id()).unwrap();
            }
        }
    }
    let start = Instant::now();
    verifier.verify().expect("the verifier must accept");
    let verify_ms = ms(start);

    Measurement {
        build_proof_ms,
        verify_ms,
        proof_bytes,
        mv_commitments,
        gkr_bytes,
    }
}

fn main() {
    let (header, config) = parse_args();
    if header {
        println!("{COLUMNS}");
    }
    let Some(config) = config else { return };

    let srs_nv = env_usize("SRS_NV").unwrap_or(19);
    if config.table_log.max(config.sub_log) > srs_nv {
        eprintln!("SRS_NV={srs_nv} is too small for this configuration");
        exit(2);
    }
    let mut key_generator = KeyGenerator::<B>::new().with_num_mv_vars(srs_nv);
    if let Ok(dir) = std::env::var("SRS_DIR") {
        key_generator = key_generator.with_srs_path(dir.into());
    }
    let start = Instant::now();
    let (pk, vk) = key_generator.gen_keys().expect("generate keys");
    eprintln!(
        "keys for 2^{srs_nv}: {:.1} s, rss {} MiB",
        ms(start) / 1e3,
        status_mb("VmRSS:")
    );

    // An unknown protocol in the environment stops the run here, with or
    // without `--protocol`.
    let arg_config = SharedArgConfig {
        lookup_protocol: config.protocol,
        ..SharedArgConfig::default()
    };
    let prover = || {
        ArgProver::new_from_pk_with_config(pk.clone(), arg_config.clone()).unwrap_or_else(|error| {
            eprintln!("{error}");
            exit(2)
        })
    };

    let start = Instant::now();
    let inputs = build_inputs(&config, &prover());
    eprintln!(
        "inputs: {} commitments in {:.1} s, rss {} MiB",
        inputs.shared.len() + inputs.data.len(),
        ms(start) / 1e3,
        status_mb("VmRSS:")
    );

    let mut best: Option<Measurement> = None;
    for rep in 0..config.reps {
        let run = run_once(
            &config,
            &inputs,
            prover(),
            ArgVerifier::new_from_vk_with_config(vk.clone(), arg_config.clone())
                .expect("the prover was given this configuration"),
        );
        eprintln!(
            "rep {rep}: build_proof {:.1} ms, verify {:.1} ms",
            run.build_proof_ms, run.verify_ms
        );
        let slow = run.build_proof_ms >= REPEAT_BELOW_MS;
        best = Some(match best {
            Some(best) => Measurement {
                build_proof_ms: best.build_proof_ms.min(run.build_proof_ms),
                verify_ms: best.verify_ms.min(run.verify_ms),
                ..run
            },
            None => run,
        });
        if slow {
            break;
        }
    }
    let best = best.expect("at least one repetition");

    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{}\t{}\t{}\t{}\t{}",
        match config.shape {
            Shape::Material => "material",
            Shape::Tt => "tt",
        },
        config.table_log,
        config.sub_log,
        config.n_subs,
        threads(),
        match config.mode {
            Mode::Lookup => "lookup",
            Mode::Control => "control",
        },
        best.build_proof_ms,
        best.verify_ms,
        best.proof_bytes,
        best.mv_commitments,
        best.gkr_bytes,
        status_mb("VmHWM:"),
        match config.protocol {
            LookupProtocol::LogUp => "logup",
            LookupProtocol::LogUpGkr => "gkr",
        },
    );
}
