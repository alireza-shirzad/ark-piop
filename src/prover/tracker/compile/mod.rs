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
//! This `mod.rs` hosts only the top-level `compile_proof` entry point.

mod pcs;
mod sumcheck;
mod virt_poly;

use super::*;

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
        // `compile_sc_subproof` partitions pending claims into buckets by
        // running the cost-model picker in `tracker_core::bucketing`
        // against `state.num_vars`, then emits one aggregated sumcheck per
        // bucket. One-nv queries collapse to a single bucket that mirrors
        // the historical (pre-bucketing) transcript byte-for-byte.
        //
        // Snapshots at each phase boundary let the dashboard correlate
        // spikes in the RSS-over-time curve with which polys are alive.
        self.emit_tracker_snapshot("compile_start");
        let compile_sc_subproof_started = Instant::now();
        let sc_subproof = self.compile_sc_subproof()?;
        let compile_sc_subproof_time_s = compile_sc_subproof_started.elapsed().as_secs_f64();
        self.emit_tracker_snapshot("after_compile_sc_subproof");

        let compile_mv_pcs_subproof_started = Instant::now();
        let mv_pcs_subproof = self.compile_mv_pcs_subproof()?;
        let compile_mv_pcs_subproof_time_s =
            compile_mv_pcs_subproof_started.elapsed().as_secs_f64();
        self.emit_tracker_snapshot("after_compile_mv_pcs_subproof");

        let compile_uv_pcs_subproof_started = Instant::now();
        let uv_pcs_subproof = self.compile_uv_pcs_subproof()?;
        let compile_uv_pcs_subproof_time_s =
            compile_uv_pcs_subproof_started.elapsed().as_secs_f64();
        self.emit_tracker_snapshot("after_compile_uv_pcs_subproof");

        info!(
            target: "bench_stats",
            snark_prover_piop_time_s = compile_sc_subproof_time_s,
            snark_prover_mv_pcs_time_s = compile_mv_pcs_subproof_time_s,
            snark_prover_uv_pcs_time_s = compile_uv_pcs_subproof_time_s,
            "snark_prover_times"
        );
        // Assemble and output the final proof
        let proof = SNARKProof {
            sc_subproof,
            mv_pcs_subproof,
            uv_pcs_subproof,
            miscellaneous_field_elements: self.state.miscellaneous_field_elements.clone(),
            miscellaneous_field_vectors: self.state.miscellaneous_field_vectors.clone(),
        };
        self.state.miscellaneous_field_elements.clear();
        self.state.miscellaneous_field_vectors.clear();
        Ok(proof)
    }
}
