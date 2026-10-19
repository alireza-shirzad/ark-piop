//! Measures one keyed sum whose sides carry a 0/1 multiplicity of a given
//! density: the shape of a compaction. The left side is a committed column
//! `f` of `2^nv` rows under a committed mask `m` with about `density`% ones;
//! the right side is the column `g` holding the rows of `f` that `m` keeps,
//! first and in order, under the prefix mask `m_g` that keeps exactly those.
//! One configuration per process, so that peak RSS belongs to it alone.
//! Prints one tab-separated line; `build_proof_ms` and `verify_ms` are minima
//! over the repetitions.
//!
//! Run with:
//!     cargo run --release --example bench_sparse_mult --features test-utils -- \
//!         [--header] [--reps N] [--protocol <logup|gkr>] [--virtual-mult] \
//!         <nv> <density_percent>
//!
//! With `--virtual-mult` the left multiplicity is the virtual product `m·m`
//! (the same 0/1 values) instead of the committed `m`.
//!
//! Environment: `SRS_NV` (default `nv`) and `SRS_DIR` (default
//! `<cwd>/../artifacts/srs`) select the SRS, which is generated and written
//! there when missing; `RAYON_NUM_THREADS` the threads. Without
//! `--protocol`, `ARK_PIOP_LOOKUP_PROTOCOL` decides (gkr when unset).

use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    pcs::PCS,
    piop::keyed_sumcheck::{KeyedSumcheckProverInput, KeyedSumcheckVerifierInput},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    setup::KeyGenerator,
    types::{CommitmentBinding, LookupProtocol, SharedArgConfig, TrackerID, artifact::Artifact},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use std::{process::exit, sync::Arc, time::Instant};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;
type Commitment = <<B as SnarkBackend>::MvPCS as PCS<F>>::Commitment;

const COLUMNS: &str = "nv\tdensity_pct\tnnz\tthreads\tprotocol\tmult\tbuild_proof_ms\tverify_ms\t\
                       proof_bytes\tmv_commitments\tpeak_rss_mb";
/// A slower `build_proof` is measured once.
const REPEAT_BELOW_MS: f64 = 30_000.0;

struct Config {
    nv: usize,
    density: f64,
    reps: usize,
    protocol: LookupProtocol,
    virtual_mult: bool,
}

struct Column {
    poly: Arc<MLE<F>>,
    commitment: Commitment,
}

/// `f`, `m`, `g`, `m_g`.
struct Inputs {
    columns: [Column; 4],
    nnz: usize,
}

fn usage() -> ! {
    eprintln!(
        "usage: bench_sparse_mult [--header] [--reps N] [--protocol <logup|gkr>] \
         [--virtual-mult] <nv> <density_percent>"
    );
    exit(2)
}

fn parse_args() -> (bool, Option<Config>) {
    let mut header = false;
    let mut reps = 3;
    let mut protocol = None;
    let mut virtual_mult = false;
    let mut positional = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--header" => header = true,
            "--virtual-mult" => virtual_mult = true,
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
    let [nv, density] = positional.as_slice() else {
        usage()
    };
    let config = Config {
        nv: nv.parse().unwrap_or_else(|_| usage()),
        density: density
            .parse()
            .ok()
            .filter(|d: &f64| (0.0..=100.0).contains(d))
            .unwrap_or_else(|| usage()),
        reps,
        protocol: protocol.unwrap_or_else(|| SharedArgConfig::default().lookup_protocol),
        virtual_mult,
    };
    (header, Some(config))
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

/// Commits a column of small integers, stored the way the tracker stores it.
fn column(prover: &ArgProver<B>, nv: usize, values: Vec<u64>) -> Column {
    let evals = values.into_iter().map(F::from).collect();
    let poly = Arc::new(MLE::from_evaluations_vec(nv, evals).compressed());
    let commitment = <B as SnarkBackend>::MvPCS::commit(prover.mv_pcs_prover_param(), &poly)
        .expect("commit an input column");
    Column { poly, commitment }
}

fn build_inputs(config: &Config, prover: &ArgProver<B>) -> Inputs {
    let rows = 1usize << config.nv;
    let mut state = 0x5eed_0000u64 + config.nv as u64;
    // Distinct-enough values, far from any small gamma.
    let f: Vec<u64> = (0..rows)
        .map(|_| lcg(&mut state) & ((1 << 40) - 1))
        .collect();
    let threshold = (config.density * 1e4).round() as u64;
    let m: Vec<u64> = (0..rows)
        .map(|_| u64::from(lcg(&mut state) % 1_000_000 < threshold))
        .collect();
    let mut g: Vec<u64> = f
        .iter()
        .zip(&m)
        .filter(|(_, keep)| **keep == 1)
        .map(|(value, _)| *value)
        .collect();
    let nnz = g.len();
    g.resize(rows, 0);
    let m_g: Vec<u64> = (0..rows).map(|row| u64::from(row < nnz)).collect();
    Inputs {
        columns: [
            column(prover, config.nv, f),
            column(prover, config.nv, m),
            column(prover, config.nv, g),
            column(prover, config.nv, m_g),
        ],
        nnz,
    }
}

struct Measurement {
    build_proof_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    mv_commitments: usize,
}

fn run_once(
    config: &Config,
    inputs: &Inputs,
    mut prover: ArgProver<B>,
    mut verifier: ArgVerifier<B>,
) -> Measurement {
    let tracked: Vec<TrackedPoly<B>> = inputs
        .columns
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
        .collect();
    let ids: Vec<TrackerID> = tracked.iter().map(TrackedPoly::id).collect();
    let [f, m, g, m_g] = <[TrackedPoly<B>; 4]>::try_from(tracked)
        .ok()
        .expect("four columns");
    let m = if config.virtual_mult { &m * &m } else { m };
    prover
        .add_mv_keyed_sum_claim(KeyedSumcheckProverInput {
            fxs: vec![f],
            gxs: vec![g],
            mfxs: vec![Some(m)],
            mgxs: vec![Some(m_g)],
        })
        .expect("claim the keyed sum");

    let start = Instant::now();
    let proof = prover.build_proof().expect("build_proof");
    let build_proof_ms = ms(start);
    let mv_commitments = prover.commitment_counts().0;
    drop(prover);
    let proof_bytes = proof.to_bytes().expect("serialize the proof").len();

    verifier.set_proof(proof);
    let oracles: Vec<TrackedOracle<B>> = ids
        .iter()
        .map(|id| {
            verifier
                .track_mv_com_by_id(*id)
                .expect("the proof carries every input commitment")
        })
        .collect();
    let [f, m, g, m_g] = <[TrackedOracle<B>; 4]>::try_from(oracles)
        .ok()
        .expect("four columns");
    let m = if config.virtual_mult { &m * &m } else { m };
    verifier
        .add_mv_keyed_sum_claim(KeyedSumcheckVerifierInput {
            fxs: vec![f],
            gxs: vec![g],
            mfxs: vec![Some(m)],
            mgxs: vec![Some(m_g)],
        })
        .expect("mirror the keyed sum");
    let start = Instant::now();
    verifier.verify().expect("the verifier must accept");
    let verify_ms = ms(start);

    Measurement {
        build_proof_ms,
        verify_ms,
        proof_bytes,
        mv_commitments,
    }
}

fn main() {
    let (header, config) = parse_args();
    if header {
        println!("{COLUMNS}");
    }
    let Some(config) = config else { return };

    let srs_nv = std::env::var("SRS_NV")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(config.nv);
    if config.nv > srs_nv {
        eprintln!("SRS_NV={srs_nv} is too small for nv {}", config.nv);
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
        "inputs: {} of {} rows kept, committed in {:.1} s, rss {} MiB",
        inputs.nnz,
        1usize << config.nv,
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
            "rep {rep}: build_proof {:.1} ms, verify {:.1} ms, proof {} B",
            run.build_proof_ms, run.verify_ms, run.proof_bytes
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
        "{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{}\t{}\t{}",
        config.nv,
        config.density,
        inputs.nnz,
        threads(),
        match config.protocol {
            LookupProtocol::LogUp => "logup",
            LookupProtocol::LogUpGkr => "gkr",
        },
        if config.virtual_mult {
            "virtual"
        } else {
            "committed"
        },
        best.build_proof_ms,
        best.verify_ms,
        best.proof_bytes,
        best.mv_commitments,
        status_mb("VmHWM:"),
    );
}
