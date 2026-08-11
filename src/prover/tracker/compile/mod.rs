//! Proof compilation — the full pipeline from claims to a serializable SNARK
//! proof. Split into three focused submodules:
//!
//! - [`virt_poly`] — virtual polynomial preprocessing (HP-interface
//!   conversion, linear-term dedup, nv equalization).
//! - [`sumcheck`] — claim batching, degree reduction, the single aggregated
//!   sumcheck invocation, nozerocheck batching, and the orchestrating
//!   `compile_sc_subproof`.
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
/// subscriber can time it. For whole functions prefer
/// [`ark_piop_macros::piop_stage`]; this covers the mid-function regions an
/// attribute can't reach, such as the stages of `run_bucket_pipeline`.
///
/// The span closes at the end of the statement, so `?` propagates from the
/// enclosing function exactly as it would without the wrapper.
macro_rules! region {
    ($name:literal, $body:expr) => {{
        let _region = ::tracing::info_span!(target: SNARK_PROVER_SPAN_TARGET, $name).entered();
        $body
    }};
}
pub(crate) use region;

/// The `bench_stats`-targeted spans whose open→close duration *is* the
/// timing for that subproof, paired with the `bench_stats` record key a
/// subscriber should file the duration under.
///
/// `compile_proof` used to wrap each of these three calls in its own
/// `Instant` and emit a `snark_prover_times` event, duplicating a clock
/// that `#[instrument]` already ran over exactly the same code. The spans
/// are now the only measurement, and this table is the contract a
/// subscriber needs: it can't infer the key from the span name, and a
/// silently-renamed function would otherwise drop a metric with no error.
///
/// Each listed span is declared `#[instrument(target = "bench_stats",
/// level = "info")]`. Both parts matter: `bench_stats` keeps the span out
/// of the console tree/timing layers (which filter that target out — this
/// is data, not a log line), and `info` is required because the default
/// env filter is `off` + `bench_stats=info`, so a `debug` span would
/// never be created during a normal bench run.
///
/// Renaming any of these functions without updating this table is caught
/// by the `snark_prover_timed_spans_are_instrumented` test below.
pub const SNARK_PROVER_TIMED_SPANS: &[(&str, &str)] = &[
    ("compile_sc_subproof", "snark_prover_piop_time_s"),
    ("compile_mv_pcs_subproof", "snark_prover_mv_pcs_time_s"),
    ("compile_uv_pcs_subproof", "snark_prover_uv_pcs_time_s"),
];

/// The tracing target every span in this module's timing contract is
/// declared on — [`SNARK_PROVER_TIMED_SPANS`], [`SC_BUCKET_SPAN`], and
/// [`SC_REGION_SPANS`].
pub const SNARK_PROVER_SPAN_TARGET: &str = "bench_stats";

/// Span wrapping one bucket's run of the sumcheck compile pipeline. Carries
/// `bucket_index` and `target_nv` fields; every [`SC_REGION_SPANS`] span
/// opened inside it belongs to that bucket, which is how a subscriber
/// attributes region durations without the prover threading an index
/// through.
///
/// Its own open→close timestamps replace the `wall_start_ms` /
/// `wall_end_ms` the prover used to stamp by hand. Those exist so the
/// dashboard can overlay bucket boundaries on the RSS-over-time curve, and
/// the sampler producing that curve lives in the subscriber's process —
/// so a timestamp taken there is in a strictly better reference frame than
/// one taken here.
pub const SC_BUCKET_SPAN: &str = "sc_bucket";

/// Regions inside `run_bucket_pipeline` whose span duration *is* that
/// stage's timing. The name doubles as the key: a subscriber files each
/// under `snark_prover_piop_<name>_time_s` in the aggregate (summed across
/// buckets) and under `timing.<name>_time_s` in the per-bucket
/// `sc_buckets_json` entry.
///
/// Named at the call site rather than reusing each callee's own span
/// because three of them — `batch_z_check_claims`,
/// `z_check_claim_to_s_check_claim`, `batch_s_check_claims` — run twice per
/// bucket, before and after degree reduction, and the record reports the
/// two passes separately. A callee-owned span could not tell them apart.
///
/// Order here is execution order, which is also the order the dashboard
/// renders the breakdown in.
pub const SC_REGION_SPANS: &[&str] = &[
    "nozerocheck_batching",
    "first_batch_zerocheck",
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
        let sc_subproof = self.compile_sc_subproof()?;
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
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
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
            // The payload is one JSON field; pull `phase` back out of it
            // rather than re-deriving what the prover meant to emit. It is
            // recorded with `%`, which reaches a visitor as `record_debug`
            // over a `format_args!` — whose Debug is the Display string, so
            // it round-trips through serde as-is.
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

    /// [`SNARK_PROVER_TIMED_SPANS`] is a contract with out-of-tree
    /// subscribers (tt-exec's JSONL stats layers) that match on span name
    /// to recover a duration. Nothing else fails if a listed function is
    /// renamed or loses its `bench_stats`/`info` attribute — the metric
    /// just silently stops appearing in the dashboard. So assert the spans
    /// really open, on the target and at the level the subscriber filters
    /// on. An empty compile is enough: the spans open before any of the
    /// three subproof bodies decide they have nothing to do.
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

    /// The four pipeline-boundary snapshots moved off `compile_proof` and
    /// into `#[piop_stage]` attributes on the stages themselves. The phase
    /// strings are a wire contract: the dashboard's `_describe_phase` has a
    /// hardcoded table keyed on exactly these, and an unrecognised phase
    /// silently degrades to a raw-string marker label rather than failing.
    ///
    /// This also pins the property a hand-written version would not have.
    /// A claim-free compile takes `compile_sc_subproof`'s early
    /// `return Ok(None)` path, so `after_compile_sc_subproof` only fires
    /// because the macro runs the body as a closure and snapshots after it.
    /// Written inline above the final `Ok(..)`, it would be skipped here.
    #[test]
    fn pipeline_boundary_snapshots_fire_on_every_exit_path() {
        let capture = capture_empty_compile();
        let phases = capture.phases.lock().unwrap().clone();

        let expected = [
            "compile_start",
            "after_compile_sc_subproof",
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
        // Order matters: the dashboard plots these as sequential markers on
        // the RSS curve, and each `after_*` doubles as the next stage's
        // start boundary.
        let ordered: Vec<&str> = phases
            .iter()
            .map(String::as_str)
            .filter(|p| expected.contains(p))
            .collect();
        assert_eq!(ordered, expected, "pipeline snapshots fired out of order");
    }
}
