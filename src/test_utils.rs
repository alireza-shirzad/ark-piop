use crate::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkError,
    pcs::PCS,
    prover::ArgProver,
    setup::KeyGenerator,
    verifier::ArgVerifier,
};
use ark_ff::{Field, PrimeField};
use std::{
    io::Write as _,
    sync::Once,
    time::{Duration, Instant},
};
use tracing::{
    Subscriber, instrument,
    span::{Attributes, Id},
};
use tracing_subscriber::{
    layer::{Context, Layer},
    registry::LookupSpan,
};

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
            .with_verbose_exit(true)
            .with_span_modes(true); // labels like `open`/`close`

        let span_timing_layer = SpanTimingLayer::default();

        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(span_timing_layer)
            .with(stdout_layer);

        let _ = subscriber.try_init();
    });
}

/// A helper function that outputs given the number of variables (i.e. log of
/// maximum table size), outputs a ready-to-use instance of the prover and
/// verifier
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

/// A prelude for testing, with a fewer number of variables, suitable for
/// testing on small tables.
/// This function sets up the proof system and gives you a ready-to-use instance
/// of the prover and verifier
#[allow(clippy::type_complexity)]
#[instrument(level = "debug", skip_all)]
pub fn test_prelude<B: SnarkBackend>() -> Result<(ArgProver<B>, ArgVerifier<B>), SnarkError> {
    init_tracing_for_tests();
    prelude_with_vars::<B>(19)
}

/// A prelude for benchmarking, with a larger number of variables, suitable for
/// benchmarking on large tables.
/// This function sets up the proof system and gives you a ready-to-use instance
/// of the prover and verifier
#[allow(clippy::type_complexity)]
pub fn bench_prelude<B: SnarkBackend>() -> Result<(ArgProver<B>, ArgVerifier<B>), SnarkError> {
    init_tracing_for_tests();
    prelude_with_vars::<B>(20)
}

#[derive(Default)]
struct SpanTimingLayer;

#[derive(Default)]
struct SpanTiming {
    first_enter_wall: Option<chrono::DateTime<chrono::Local>>,
    first_enter_instant: Option<Instant>,
    enter_stack: Vec<Instant>,
    busy: Duration,
    enters: u64,
}

impl<S> Layer<S> for SpanTimingLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, _attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanTiming::default());
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            let data = match extensions.get_mut::<SpanTiming>() {
                Some(existing) => existing,
                None => {
                    extensions.insert(SpanTiming::default());
                    extensions
                        .get_mut::<SpanTiming>()
                        .expect("timing layer inserted span data")
                }
            };
            let now = Instant::now();
            if data.first_enter_instant.is_none() {
                data.first_enter_instant = Some(now);
                data.first_enter_wall = Some(chrono::Local::now());
            }
            data.enter_stack.push(now);
            data.enters = data.enters.saturating_add(1);
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            let Some(data) = extensions.get_mut::<SpanTiming>() else {
                return;
            };
            if let Some(start) = data.enter_stack.pop() {
                let now = Instant::now();
                data.busy += now.duration_since(start);
            }
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            let mut extensions = span.extensions_mut();
            if let Some(mut data) = extensions.remove::<SpanTiming>() {
                let now = Instant::now();
                while let Some(start) = data.enter_stack.pop() {
                    data.busy += now.duration_since(start);
                }

                let Some(first_enter) = data.first_enter_instant else {
                    return;
                };
                let total_elapsed = now.duration_since(first_enter);
                let start_wall = data
                    .first_enter_wall
                    .unwrap_or_else(|| chrono::Local::now());
                let end_wall = chrono::Local::now();

                let depth = span.scope().from_root().count().saturating_sub(1);
                let indent = "  ".repeat(depth);
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "{indent}span {}::{} closed; wall={} busy={} entries={} ({} -> {})",
                    span.metadata().target(),
                    span.metadata().name(),
                    format_duration(total_elapsed),
                    format_duration(data.busy),
                    data.enters,
                    format_wall_time(start_wall),
                    format_wall_time(end_wall),
                );
            }
        }
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.is_zero() {
        return "0s".to_string();
    }
    if duration.as_secs() >= 1 {
        format!("{:.3}s", duration.as_secs_f64())
    } else if duration.as_millis() >= 1 {
        format!("{:.3}ms", duration.as_secs_f64() * 1_000.0)
    } else if duration.as_micros() >= 1 {
        format!("{}us", duration.as_micros())
    } else {
        format!("{}ns", duration.as_nanos())
    }
}

fn format_wall_time(ts: chrono::DateTime<chrono::Local>) -> String {
    ts.format("%H:%M:%S%.3f").to_string()
}
