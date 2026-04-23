//! Calibrate `ark_piop::arithmetic::msm` for the current hardware.
//!
//! Run with:
//!     cargo run --release --example calibrate_msm --features test-utils
//!
//! Prints a `NAIVE_THRESHOLD` / `THREAD_TABLE` block you can paste over the
//! defaults in `src/arithmetic/msm.rs`.

use ark_bn254::G1Projective;
use ark_piop::arithmetic::msm::calibrate::calibrate;

fn main() {
    // Sweep sizes. Dense below the naive/Pippenger crossover, sparser above.
    let sizes: Vec<usize> = vec![
        4, 8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096,
        6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 131072, 262144,
    ];

    // Try every thread count up to the number of logical cores.
    let max_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);

    // 3 iterations per (size, threads) keeps the sweep under ~minutes for most
    // machines; bump if you want steadier numbers.
    let iters = 3;

    println!(
        "calibrating on {max_threads} logical cores over {} sizes, {iters} iter(s) each",
        sizes.len()
    );
    println!("(naive vs arkworks VariableBaseMSM::msm_unchecked, BN254 G1)");
    println!();

    let cal = calibrate::<G1Projective>(&sizes, max_threads, iters);

    println!();
    println!("== recommended constants (paste into src/arithmetic/msm.rs) ==");
    cal.print_as_constants();
}
