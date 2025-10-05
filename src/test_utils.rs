use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkError,
    pcs::PCS,
    prover::Prover,
    setup::KeyGenerator,
    verifier::Verifier,
};
use ark_ff::{Field, PrimeField};
use std::sync::Once;
use tracing::instrument;

/// Compute the JSON log file path for test tracing.
///
/// Rules:
/// - If `TRACING_JSON_PATH` is set and non-empty, use it verbatim.
/// - Otherwise, prefer `<target>/logs/log_YYYYMMDD_HHMMSS.jsonl` if a `target` dir
///   is available or creatable.
/// - Fallback to `<crate>/logs/log_YYYYMMDD_HHMMSS.jsonl` (ignored via `.gitignore`).
fn compute_logs_dir() -> std::path::PathBuf {
    use std::path::{Path, PathBuf};

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut target_dir: Option<PathBuf> = None;

    // 1) Respect CARGO_TARGET_DIR if set.
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR") {
        let p = PathBuf::from(p);
        if p.exists() || std::fs::create_dir_all(&p).is_ok() {
            target_dir = Some(p);
        }
    }

    // 2) Prefer `<crate>/target` in the current crate directory
    if target_dir.is_none() {
        let crate_target = Path::new(manifest_dir).join("target");
        if crate_target.exists() || std::fs::create_dir_all(&crate_target).is_ok() {
            target_dir = Some(crate_target);
        }
    }

    // 3) Fallback to `<crate-parent>/target` (workspace root) if needed
    if target_dir.is_none() {
        if let Some(parent) = Path::new(manifest_dir).parent() {
            let candidate = parent.join("target");
            if candidate.exists() || std::fs::create_dir_all(&candidate).is_ok() {
                target_dir = Some(candidate);
            }
        }
    }

    let logs_dir = if let Some(t) = target_dir {
        t.join("logs")
    } else {
        Path::new(manifest_dir).join("logs")
    };
    let _ = std::fs::create_dir_all(&logs_dir);
    logs_dir
}

fn compute_json_log_path(level_suffix: &str) -> String {
    if let Ok(p) = std::env::var("TRACING_JSON_PATH") {
        if !p.trim().is_empty() {
            return p;
        }
    }
    let logs_dir = compute_logs_dir();

    // Build timestamped filename
    let datetime = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    logs_dir
        .join(format!("log_{}_{}.jsonl", datetime, level_suffix))
        .to_string_lossy()
        .into_owned()
}

fn compute_chrome_trace_path(level_suffix: &str) -> String {
    if let Ok(p) = std::env::var("TRACING_CHROME_PATH") {
        if !p.trim().is_empty() {
            return p;
        }
    }
    let logs_dir = compute_logs_dir();
    let datetime = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    logs_dir
        .join(format!("chrome_trace_{}_{}.json", datetime, level_suffix))
        .to_string_lossy()
        .into_owned()
}

fn compute_flame_path(level_suffix: &str) -> String {
    if let Ok(p) = std::env::var("TRACING_FLAME_PATH") {
        if !p.trim().is_empty() {
            return p;
        }
    }
    let logs_dir = compute_logs_dir();
    let datetime = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    logs_dir
        .join(format!("flame_{}_{}.folded", datetime, level_suffix))
        .to_string_lossy()
        .into_owned()
}

/// Initialize a `tracing` subscriber for tests (no-op if already set).
///
/// - Respects `RUST_LOG` via `EnvFilter` (e.g., `RUST_LOG=debug`).
/// - Emits span enter/exit for `#[instrument]` wrappers so you can see
///   `piop.prove`/`piop.verify` boundaries.
pub fn init_tracing_for_tests() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};

        // Build a shared EnvFilter once (honors RUST_LOG)
        let env_filter = EnvFilter::from_default_env();

        // Layer 1: tree test output to stdout (test writer)
        let stdout_layer = tracing_tree::HierarchicalLayer::new(2)
            .with_targets(true)
            .with_indent_lines(true)
            .with_bracketed_fields(true)
            .with_timer(tracing_tree::time::Uptime::default()) // time since process start
            .with_span_modes(true); // labels like `open`/`close`

        // Layer 2: JSON logs to a file (fresh file per run)
        let level_suffix = env_filter
            .max_level_hint()
            .map(|lf| lf.to_string().to_uppercase())
            .unwrap_or_else(|| "UNSPEC".to_string());
        let json_path = compute_json_log_path(&level_suffix);
        let json_layer = fmt::layer()
            .json()
            .pretty()
            .with_ansi(false)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .with_writer(move || {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&json_path)
                    .expect("failed to open JSON log file for appending")
            });

        // Chrome tracing layer (writes to a .json trace file for chrome://tracing)
        let chrome_path = compute_chrome_trace_path(&level_suffix);
        let (chrome_layer, chrome_guard) = tracing_chrome::ChromeLayerBuilder::new()
            .file(chrome_path)
            .build();
        let _guard: &'static _ = Box::leak(Box::new(chrome_guard));

        // Flamegraph layer (writes a .folded stack file consumable by inferno/flamegraph)
        let flame_path = compute_flame_path(&level_suffix);
        let (flame_layer, flame_guard) = tracing_flame::FlameLayer::with_file(flame_path)
            .expect("failed to create tracing-flame output file");
        let _flame_guard: &'static _ = Box::leak(Box::new(flame_guard));

        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout_layer)
            .with(json_layer)
            .with(chrome_layer)
            .with(flame_layer);

        let _ = subscriber.try_init();
    });
}

/// A helper function that outputs given the number of variables (i.e. log of
/// maximum table size), outputs a ready-to-use instance of the prover and
/// verifier
#[allow(clippy::type_complexity)]
#[instrument(level = "debug")]
pub fn prelude_with_vars<
    F: Field + PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    num_mv_vars: usize,
) -> Result<(Prover<F, MvPCS, UvPCS>, Verifier<F, MvPCS, UvPCS>), SnarkError> {
    let key_generator = KeyGenerator::<F, MvPCS, UvPCS>::new().with_num_mv_vars(num_mv_vars);
    let (pk, vk) = key_generator.gen_keys().unwrap();
    let prover = Prover::new_from_pk(pk);
    let verifier = Verifier::new_from_vk(vk);
    Ok((prover, verifier))
}

/// A prelude for testing, with a fewer number of variables, suitable for
/// testing on small tables.
/// This function sets up the proof system and gives you a ready-to-use instance
/// of the prover and verifier
#[allow(clippy::type_complexity)]
#[instrument(level = "debug", skip_all)]
pub fn test_prelude<
    F: Field + PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>() -> Result<(Prover<F, MvPCS, UvPCS>, Verifier<F, MvPCS, UvPCS>), SnarkError> {
    init_tracing_for_tests();
    prelude_with_vars::<F, MvPCS, UvPCS>(16)
}

/// A prelude for benchmarking, with a larger number of variables, suitable for
/// benchmarking on large tables.
/// This function sets up the proof system and gives you a ready-to-use instance
/// of the prover and verifier
#[allow(clippy::type_complexity)]
pub fn bench_prelude<
    F: Field + PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>() -> Result<(Prover<F, MvPCS, UvPCS>, Verifier<F, MvPCS, UvPCS>), SnarkError> {
    init_tracing_for_tests();
    prelude_with_vars::<F, MvPCS, UvPCS>(20)
}
