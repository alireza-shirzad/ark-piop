//! Proof compilation — the full pipeline from claims to a serializable SNARK
//! proof. Split into three focused submodules:
//!
//! - [`virt_poly`] — virtual polynomial preprocessing (HP-interface
//!   conversion, linear-term dedup, nv equalization).
//! - [`sumcheck`] — claim batching, degree reduction, the single aggregated
//!   sumcheck invocation, nozerocheck batching, and the orchestrating
//!   `compile_piop_subproof`.
//! - [`pcs`] — batched multivariate and univariate PCS subproofs.
//!
//! This `mod.rs` hosts the top-level `compile_proof` entry point and the
//! [`SNARK_PROVER_TIMED_SPANS`] contract that subscribers use to turn the
//! three subproof spans into `bench_stats` timings.

mod pcs;
mod sumcheck;
mod virt_poly;

use super::*;

/// Run one statement inside a `bench_stats` span named `$name`, so a
/// subscriber can time it. Covers mid-function regions that a
/// `#[piop_stage]` attribute can't reach; `?` propagates unchanged.
macro_rules! region {
    ($name:literal, $body:expr) => {{
        let _region = ::tracing::info_span!(target: SNARK_PROVER_SPAN_TARGET, $name).entered();
        $body
    }};
}
pub(crate) use region;

/// The spans whose open→close duration *is* each subproof's timing, paired
/// with the record key a subscriber files it under. This table is a contract
/// with out-of-tree subscribers; each span must stay declared
/// `#[instrument(target = "bench_stats", level = "info")]` (the default env
/// filter only enables `bench_stats=info`). Renames are caught by the
/// `snark_prover_timed_spans_are_instrumented` test below.
pub const SNARK_PROVER_TIMED_SPANS: &[(&str, &str)] = &[
    ("compile_piop_subproof", "snark_prover_piop_time_s"),
    ("compile_mv_pcs_subproof", "snark_prover_mv_pcs_time_s"),
    ("compile_uv_pcs_subproof", "snark_prover_uv_pcs_time_s"),
];

/// The tracing target every span in this module's timing contract is
/// declared on — [`SNARK_PROVER_TIMED_SPANS`], [`SC_BUCKET_SPAN`], and
/// [`SC_REGION_SPANS`].
pub const SNARK_PROVER_SPAN_TARGET: &str = "bench_stats";

/// Span wrapping one bucket's run of the sumcheck compile pipeline. Every
/// [`SC_REGION_SPANS`] span opened inside it belongs to that bucket — how a
/// subscriber attributes region durations — and its own timestamps mark
/// bucket boundaries on the dashboard's RSS curve.
pub const SC_BUCKET_SPAN: &str = "sc_bucket";

/// Regions whose span duration *is* that stage's timing; the name doubles
/// as the subscriber's record key. Named at the call site because two
/// stages run on both sides of degree reduction and are reported as
/// separate passes. The first two run before the partition is drawn, so
/// they reach the aggregate but no per-bucket entry. Order is execution
/// order, which the dashboard renders.
pub const SC_REGION_SPANS: &[&str] = &[
    "nozerocheck_batching",
    // Also covers per-nv batching inside `convert_zerochecks_by_nv`.
    "first_zerocheck_to_sumcheck",
    "first_batch_sumcheck",
    "reduce_sumcheck",
    "second_batch_zerocheck",
    "second_zerocheck_to_sumcheck",
    "sumcheck",
];

/// Whether `span_name` is one of [`SC_REGION_SPANS`].
pub fn is_sc_region_span(span_name: &str) -> bool {
    SC_REGION_SPANS.contains(&span_name)
}

/// Record key for the span named `span_name`, or `None` if that span
/// isn't one we derive a timing from.
pub fn snark_prover_timing_key(span_name: &str) -> Option<&'static str> {
    SNARK_PROVER_TIMED_SPANS
        .iter()
        .find(|(name, _)| *name == span_name)
        .map(|(_, key)| *key)
}

impl<B> ProverTracker<B>
where
    B: SnarkBackend,
{
    /// Compiles the final proof, which contains three subproofs:
    /// 1. The batched sumcheck subproof
    /// 2. The multivariate PCS subproof
    /// 3. The univariate PCS subproof
    #[instrument(level = "debug", skip(self))]
    pub fn compile_proof(&mut self) -> SnarkResult<SNARKProof<B>>
    where
        B: SnarkBackend,
    {
        let sc_subproof = self.compile_piop_subproof()?;
        let mv_pcs_subproof = self.compile_mv_pcs_subproof()?;
        let uv_pcs_subproof = self.compile_uv_pcs_subproof()?;

        Ok(SNARKProof {
            sc_subproof,
            mv_pcs_subproof,
            uv_pcs_subproof,
            miscellaneous_field_elements: take(&mut self.state.miscellaneous_field_elements),
            miscellaneous_field_vectors: take(&mut self.state.miscellaneous_field_vectors),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::span::{Attributes, Id};
    use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

    /// Records the metadata of every span opened, and the `phase` of every
    /// tracker snapshot emitted, while it's installed.
    #[derive(Clone, Default)]
    struct SpanCapture {
        spans: Arc<Mutex<Vec<(String, String, tracing::Level)>>>,
        phases: Arc<Mutex<Vec<String>>>,
    }

    impl<S> Layer<S> for SpanCapture
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>
    {
        fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
            let meta = attrs.metadata();
            self.spans.lock().unwrap().push((
                meta.name().to_string(),
                meta.target().to_string(),
                *meta.level(),
            ));
        }

        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            if event.metadata().target() != SNARK_PROVER_SPAN_TARGET {
                return;
            }
            // `%`-recorded fields reach a visitor via `record_debug`, whose
            // Debug output is the Display string — JSON round-trips as-is.
            struct PhaseVisitor(Option<String>);
            impl tracing::field::Visit for PhaseVisitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "tracker_snapshot_json"
                        && let Ok(parsed) =
                            serde_json::from_str::<serde_json::Value>(&format!("{value:?}"))
                        && let Some(phase) = parsed.get("phase").and_then(|p| p.as_str())
                    {
                        self.0 = Some(phase.to_string());
                    }
                }
            }
            let mut visitor = PhaseVisitor(None);
            event.record(&mut visitor);
            if let Some(phase) = visitor.0 {
                self.phases.lock().unwrap().push(phase);
            }
        }
    }

    /// Install a capture layer, run a claim-free compile under it, and
    /// return what it saw.
    fn capture_empty_compile() -> SpanCapture {
        use tracing_subscriber::layer::SubscriberExt;

        let capture = SpanCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            let (mut prover, _verifier) =
                crate::test_utils::prelude_with_vars::<crate::DefaultSnarkBackend>(4).unwrap();
            prover.build_proof().unwrap();
        });
        capture
    }

    /// Nothing else fails if a listed function is renamed or loses its
    /// `bench_stats`/`info` attribute — the metric just silently disappears
    /// from the dashboard — so assert the spans really open on the target
    /// and level the subscriber filters on.
    #[test]
    fn snark_prover_timed_spans_are_instrumented() {
        let capture = capture_empty_compile();
        let seen = capture.spans.lock().unwrap();
        for (span_name, key) in SNARK_PROVER_TIMED_SPANS {
            let opened = seen.iter().find(|(name, _, _)| name == span_name);
            let Some((_, target, level)) = opened else {
                panic!(
                    "span `{span_name}` (recorded as `{key}`) never opened — \
                     SNARK_PROVER_TIMED_SPANS is stale or the #[instrument] \
                     attribute was dropped"
                );
            };
            assert_eq!(
                target, SNARK_PROVER_SPAN_TARGET,
                "span `{span_name}` must stay on the `{SNARK_PROVER_SPAN_TARGET}` target"
            );
            assert_eq!(
                *level,
                tracing::Level::INFO,
                "span `{span_name}` must stay at INFO — the default env filter \
                 only enables `{SNARK_PROVER_SPAN_TARGET}=info`"
            );
        }
    }

    /// The phase strings are a wire contract with the dashboard, and an
    /// unrecognised phase silently degrades to a raw label. Also pins that
    /// snapshots fire on early-return paths — the `#[piop_stage]` macro
    /// snapshots after the body closure, which an inline version would skip.
    #[test]
    fn pipeline_boundary_snapshots_fire_on_every_exit_path() {
        let capture = capture_empty_compile();
        let phases = capture.phases.lock().unwrap().clone();

        let expected = [
            "compile_start",
            "after_compile_piop_subproof",
            "after_compile_mv_pcs_subproof",
            "after_compile_uv_pcs_subproof",
        ];
        for phase in expected {
            assert!(
                phases.iter().any(|seen| seen == phase),
                "snapshot phase `{phase}` never emitted — the `piop_stage` \
                 attribute was dropped or renamed. Saw: {phases:?}"
            );
        }
        // The dashboard plots these as sequential markers on the RSS curve.
        let ordered: Vec<&str> = phases
            .iter()
            .map(String::as_str)
            .filter(|p| expected.contains(p))
            .collect();
        assert_eq!(ordered, expected, "pipeline snapshots fired out of order");
    }
}
