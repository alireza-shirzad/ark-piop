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
        // Transform all the materialized polynomials to polynomials with the maximum
        // number of variables needed
        let max_nv = self.equalize_mat_poly_nv();
        let compile_sc_subproof_started = Instant::now();
        let sc_subproof = self.compile_sc_subproof(max_nv)?;
        let compile_sc_subproof_time_s = compile_sc_subproof_started.elapsed().as_secs_f64();

        let compile_mv_pcs_subproof_started = Instant::now();
        let mv_pcs_subproof = self.compile_mv_pcs_subproof()?;
        let compile_mv_pcs_subproof_time_s =
            compile_mv_pcs_subproof_started.elapsed().as_secs_f64();

        let compile_uv_pcs_subproof_started = Instant::now();
        let uv_pcs_subproof = self.compile_uv_pcs_subproof()?;
        let compile_uv_pcs_subproof_time_s =
            compile_uv_pcs_subproof_started.elapsed().as_secs_f64();

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
        };
        self.state.miscellaneous_field_elements.clear();
        Ok(proof)
    }
}
