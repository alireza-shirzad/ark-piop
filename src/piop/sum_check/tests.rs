use std::sync::Arc;

use ark_ff::PrimeField;
use ark_std::rand::RngCore;

use crate::arithmetic::mat_poly::mle::MLE;

/// Sample a random list of multilinear polynomials.
/// Returns
/// - the list of polynomials,
/// - its sum of polynomial evaluations over the boolean hypercube.
#[allow(dead_code)]
pub fn random_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> (Vec<Arc<MLE<F>>>, F) {
    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    let mut sum = F::zero();

    for _ in 0..(1 << nv) {
        let mut product = F::one();

        for e in multiplicands.iter_mut() {
            let val = F::rand(rng);
            e.push(val);
            product *= val;
        }
        sum += product;
    }

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(MLE::from_evaluations_vec(nv, x)))
        .collect();

    (list, sum)
}

// TODO: Write tests for sumcheck piop

// Streaming vs eager parity: the streaming prover must produce bit-identical round
// messages to the eager path — any deviation would silently break soundness. Tests
// drive the same poly at k = 0 (eager), k = nv (full), and partial k.

#[cfg(test)]
mod streaming_parity {
    use crate::arithmetic::mat_poly::mle::MLE;
    use crate::arithmetic::virt_poly::hp_interface::HPVirtualPolynomial;
    use crate::piop::structs::SumcheckProverState;
    use ark_bn254::Fr;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use std::sync::Arc;

    /// Run the prover to completion at streaming window `stream_k` with fixed
    /// challenges; returns per-round message evaluations for bit-comparison.
    fn run_prover(
        poly: &HPVirtualPolynomial<Fr>,
        challenges: &[Fr],
        stream_k: usize,
    ) -> Vec<Vec<Fr>> {
        let mut state = SumcheckProverState::prover_init_with_stream_k(poly, stream_k).unwrap();
        let mut msgs = Vec::with_capacity(poly.aux_info.num_variables);
        let mut chal: Option<Fr> = None;
        for round in 0..poly.aux_info.num_variables {
            let msg = SumcheckProverState::prove_round_and_update_state(&mut state, &chal).unwrap();
            msgs.push(msg.evaluations.clone());
            chal = Some(challenges[round]);
        }
        msgs
    }

    /// Product of two u32-storage MLEs — the shape native-typed arithmetization
    /// emits; the primary streaming regression test.
    #[test]
    fn u32_storage_product_stream_matches_eager() {
        let nv = 5;
        let n = 1usize << nv;
        let mut rng = StdRng::seed_from_u64(0xdead_beef);
        use ark_std::rand::Rng;
        let words_a: Vec<u32> = (0..n).map(|_| rng.r#gen::<u32>()).collect();
        let words_b: Vec<u32> = (0..n).map(|_| rng.r#gen::<u32>()).collect();
        let a = Arc::new(MLE::<Fr>::from_u32s(words_a, nv));
        let b = Arc::new(MLE::<Fr>::from_u32s(words_b, nv));
        let mut poly = HPVirtualPolynomial::<Fr>::new(nv);
        poly.add_mle_list([a, b], Fr::from(7u64)).unwrap();

        let challenges: Vec<Fr> = (0..nv).map(|i| Fr::from((i as u64) * 13 + 5)).collect();
        let eager = run_prover(&poly, &challenges, 0);
        let full_stream = run_prover(&poly, &challenges, nv);
        let partial = run_prover(&poly, &challenges, nv / 2);

        assert_eq!(
            eager, full_stream,
            "full streaming (k=nv) diverged from eager"
        );
        assert_eq!(
            eager, partial,
            "partial streaming (k=nv/2) diverged from eager"
        );
    }

    /// Exercises the U8 arm of the streaming read path.
    #[test]
    fn u8_storage_stream_matches_eager() {
        let nv = 4;
        let n = 1usize << nv;
        let bytes_a: Vec<u8> = (0..n).map(|i| ((i * 3 + 1) & 0xff) as u8).collect();
        let bytes_b: Vec<u8> = (0..n).map(|i| ((i * 5 + 7) & 0xff) as u8).collect();
        let a = Arc::new(MLE::<Fr>::from_u8s(bytes_a, nv));
        let b = Arc::new(MLE::<Fr>::from_u8s(bytes_b, nv));
        let mut poly = HPVirtualPolynomial::<Fr>::new(nv);
        poly.add_mle_list([a, b], Fr::from(1u64)).unwrap();

        let challenges: Vec<Fr> = (0..nv).map(|i| Fr::from((i as u64) + 2)).collect();
        let eager = run_prover(&poly, &challenges, 0);
        let full_stream = run_prover(&poly, &challenges, nv);
        assert_eq!(eager, full_stream);
    }

    /// Bit-packed storage (activator-shaped polys), degree-2 product.
    #[test]
    fn bit_storage_stream_matches_eager() {
        let nv = 5;
        let len = 1usize << nv;
        let byte_len = len.div_ceil(8);
        // Alternating bit pattern, mid-density.
        let mut bits_a = vec![0u8; byte_len];
        let mut bits_b = vec![0u8; byte_len];
        for i in 0..len {
            if i.is_multiple_of(3) {
                bits_a[i >> 3] |= 1 << (i & 7);
            }
            if i.is_multiple_of(2) {
                bits_b[i >> 3] |= 1 << (i & 7);
            }
        }
        let a = Arc::new(MLE::<Fr>::from_bit_backing(bits_a, nv));
        let b = Arc::new(MLE::<Fr>::from_bit_backing(bits_b, nv));
        let mut poly = HPVirtualPolynomial::<Fr>::new(nv);
        poly.add_mle_list([a, b], Fr::from(2u64)).unwrap();

        let challenges: Vec<Fr> = (0..nv).map(|i| Fr::from((i as u64) * 11 + 3)).collect();
        let eager = run_prover(&poly, &challenges, 0);
        let full_stream = run_prover(&poly, &challenges, nv);
        let partial = run_prover(&poly, &challenges, 2);
        assert_eq!(eager, full_stream);
        assert_eq!(eager, partial);
    }

    /// Asserts `decide_auto_stream_k`'s decision directly: no streaming below nv=20
    /// or when all factors are Field-backed; streaming when enough compressed
    /// factors are present.
    #[test]
    fn auto_stream_k_decision_matches_expected_shape() {
        use crate::piop::sum_check::prover::decide_auto_stream_k;
        // Small poly: never stream.
        {
            let nv = 5;
            let n = 1usize << nv;
            let a = Arc::new(MLE::<Fr>::from_u32s(vec![7u32; n], nv));
            let b = Arc::new(MLE::<Fr>::from_u32s(vec![9u32; n], nv));
            let mut poly = HPVirtualPolynomial::<Fr>::new(nv);
            poly.add_mle_list([a, b], Fr::from(1u64)).unwrap();
            assert_eq!(
                decide_auto_stream_k(&poly),
                0,
                "small nv should not auto-stream"
            );
        }
        // Large-nv but all Field storage: never stream.
        {
            let nv = 22;
            let n = 1usize << nv;
            use ark_std::rand::SeedableRng;
            let mut rng = StdRng::seed_from_u64(1);
            use ark_ff::UniformRand;
            let evals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let a = Arc::new(MLE::<Fr>::from_evaluations_vec(nv, evals));
            let mut poly = HPVirtualPolynomial::<Fr>::new(nv);
            poly.add_mle_list([a], Fr::from(1u64)).unwrap();
            assert_eq!(
                decide_auto_stream_k(&poly),
                0,
                "Field-only factors should not trigger auto-streaming"
            );
        }
        // Large-nv with compressed factors above the threshold: stream to `nv`.
        {
            let nv = 22;
            let n = 1usize << nv;
            let mut poly = HPVirtualPolynomial::<Fr>::new(nv);
            // 5 distinct U32-backed factors — above the 4-factor threshold.
            for i in 0..5 {
                let arc = Arc::new(MLE::<Fr>::from_u32s(vec![i as u32; n], nv));
                poly.add_mle_list([arc], Fr::from(1u64)).unwrap();
            }
            assert_eq!(
                decide_auto_stream_k(&poly),
                nv,
                "several large-nv compressed factors should trigger auto-streaming"
            );
        }
    }

    /// Mixed Field + U32 storage: the Field factor is always Materialized, the U32
    /// one Streaming when k > 0 — confirms per-slot routing.
    #[test]
    fn mixed_field_and_u32_storage_stream_matches_eager() {
        let nv = 4;
        let n = 1usize << nv;
        let mut rng = StdRng::seed_from_u64(0xc0ffee);
        use ark_ff::UniformRand;
        use ark_std::rand::Rng;
        let f_evals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let words: Vec<u32> = (0..n).map(|_| rng.r#gen::<u32>()).collect();
        let f = Arc::new(MLE::<Fr>::from_evaluations_vec(nv, f_evals));
        let u = Arc::new(MLE::<Fr>::from_u32s(words, nv));
        let mut poly = HPVirtualPolynomial::<Fr>::new(nv);
        poly.add_mle_list([f, u], Fr::from(3u64)).unwrap();

        let challenges: Vec<Fr> = (0..nv).map(|i| Fr::from((i as u64) * 17 + 1)).collect();
        let eager = run_prover(&poly, &challenges, 0);
        let full_stream = run_prover(&poly, &challenges, nv);
        assert_eq!(eager, full_stream);
    }
}
