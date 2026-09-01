use crate::{
    SnarkBackend, errors::SnarkError, prover::ArgProver, setup::KeyGenerator, verifier::ArgVerifier,
};
use std::sync::Once;
use tracing::instrument;

/// Logs directory for test tracing: a creatable `target/logs`, falling back
/// to `<crate>/logs` (gitignored).
#[allow(dead_code)]
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
    if target_dir.is_none()
        && let Some(parent) = Path::new(manifest_dir).parent()
    {
        let candidate = parent.join("target");
        if candidate.exists() || std::fs::create_dir_all(&candidate).is_ok() {
            target_dir = Some(candidate);
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

#[allow(dead_code)]
fn compute_json_log_path(level_suffix: &str) -> String {
    if let Ok(p) = std::env::var("TRACING_JSON_PATH")
        && !p.trim().is_empty()
    {
        return p;
    }
    let logs_dir = compute_logs_dir();

    let datetime = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    logs_dir
        .join(format!("log_{}_{}.jsonl", datetime, level_suffix))
        .to_string_lossy()
        .into_owned()
}

#[allow(dead_code)]
fn compute_chrome_trace_path(level_suffix: &str) -> String {
    if let Ok(p) = std::env::var("TRACING_CHROME_PATH")
        && !p.trim().is_empty()
    {
        return p;
    }
    let logs_dir = compute_logs_dir();
    let datetime = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    logs_dir
        .join(format!("chrome_trace_{}_{}.json", datetime, level_suffix))
        .to_string_lossy()
        .into_owned()
}

#[allow(dead_code)]
fn compute_flame_path(level_suffix: &str) -> String {
    if let Ok(p) = std::env::var("TRACING_FLAME_PATH")
        && !p.trim().is_empty()
    {
        return p;
    }
    let logs_dir = compute_logs_dir();
    let datetime = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    logs_dir
        .join(format!("flame_{}_{}.folded", datetime, level_suffix))
        .to_string_lossy()
        .into_owned()
}

/// Standard `EnvFilter` for ark-piop subscribers: respects `RUST_LOG`
/// (default `"off"`), suppresses `datafusion`/`sqlparser` noise unless
/// requested, and always enables `bench_stats=info` for statistics layers.
pub fn build_env_filter() -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    let rust_log = std::env::var("RUST_LOG").unwrap_or_default();
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    if !rust_log.contains("datafusion") {
        filter = filter.add_directive("datafusion=off".parse().unwrap());
        filter = filter.add_directive("datafusion_=off".parse().unwrap());
    }
    if !rust_log.contains("sqlparser") {
        filter = filter.add_directive("sqlparser=off".parse().unwrap());
    }
    filter = filter.add_directive("bench_stats=info".parse().unwrap());
    filter
}

/// Initialize a `tracing` subscriber (no-op if already set) with tree,
/// span-timing, and event layers. All three exclude the `bench_stats` target,
/// so stats events reach only an extra layer (see [`init_subscriber_with`]).
pub fn init_subscriber() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::filter::filter_fn;
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::prelude::*;

        let filter = build_env_filter();

        let tree_layer = tracing_tree::HierarchicalLayer::default()
            .with_targets(false)
            .with_timer(tracing_tree::time::Uptime::default())
            .with_deferred_spans(true)
            .with_writer(std::io::stdout)
            .with_filter(filter_fn(|metadata| {
                metadata.is_span() && metadata.target() != "bench_stats"
            }));

        let span_timing_layer = tracing_subscriber::fmt::layer()
            .with_span_events(FmtSpan::CLOSE)
            .with_timer(tracing_subscriber::fmt::time::Uptime::default())
            .with_target(false)
            .with_filter(filter_fn(|metadata| {
                metadata.is_span() && metadata.target() != "bench_stats"
            }));

        let event_layer = tracing_subscriber::fmt::layer()
            .with_timer(tracing_subscriber::fmt::time::Uptime::default())
            .with_target(false)
            .with_filter(filter_fn(|metadata| {
                metadata.is_event() && metadata.target() != "bench_stats"
            }));

        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(tree_layer)
            .with(span_timing_layer)
            .with(event_layer)
            .try_init();
    });
}

/// Like [`init_subscriber`] but the caller supplies `setup_fn` (run once) to
/// install extra layers (e.g. a JSONL stats layer receiving `bench_stats`)
/// without fighting generic type bounds.
pub fn init_subscriber_with<F>(setup_fn: F)
where
    F: FnOnce() + Send + 'static,
{
    static INIT: Once = Once::new();
    INIT.call_once(setup_fn);
}

/// Ready-to-use prover/verifier pair for the given number of variables
/// (log of maximum table size).
#[allow(clippy::type_complexity)]
#[instrument(level = "debug")]
pub fn prelude_with_vars<B: SnarkBackend>(
    num_mv_vars: usize,
) -> Result<(ArgProver<B>, ArgVerifier<B>), SnarkError> {
    let key_generator = KeyGenerator::<B>::new().with_num_mv_vars(num_mv_vars);
    let (pk, vk) = key_generator.gen_keys().unwrap();
    let prover = ArgProver::new_from_pk(pk);
    let verifier = ArgVerifier::new_from_vk(vk);
    Ok((prover, verifier))
}

/// Test prelude: small-table prover/verifier pair with tracing initialized.
#[allow(clippy::type_complexity)]
#[instrument(level = "debug", skip_all)]
pub fn test_prelude<B: SnarkBackend>() -> Result<(ArgProver<B>, ArgVerifier<B>), SnarkError> {
    init_subscriber();
    prelude_with_vars::<B>(19)
}

/// Bench prelude: larger-table prover/verifier pair with tracing initialized.
#[allow(clippy::type_complexity)]
pub fn bench_prelude<B: SnarkBackend>() -> Result<(ArgProver<B>, ArgVerifier<B>), SnarkError> {
    init_subscriber();
    prelude_with_vars::<B>(20)
}
