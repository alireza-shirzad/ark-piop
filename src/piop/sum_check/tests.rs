use std::sync::Arc;

use ark_ff::PrimeField;
use ark_std::rand::RngCore;

use crate::arithmetic::mat_poly::mle::MLE;

/// `degree` random multilinear polynomials and the sum of their product over
/// the boolean hypercube.
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

// The streaming prover must produce the same round messages as the eager path.
// Each test drives one poly at k = 0 (eager), k = nv (full) and a partial k.
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

    /// Product of two u32-storage MLEs, the shape native-typed arithmetization
    /// emits.
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

    /// No streaming below nv=20 or when all factors are Field-backed; streaming
    /// when enough compressed factors are present.
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
            // 5 distinct U32-backed factors, above the 4-factor threshold.
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
    /// one Streaming when k > 0.
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

// Factoring `eq(x, r)` out of the terms that hold it must not change any
// round message.
#[cfg(test)]
mod eq_factoring {
    use crate::arithmetic::mat_poly::{mle::MLE, utils::build_eq_x_r};
    use crate::arithmetic::virt_poly::hp_interface::HPVirtualPolynomial;
    use crate::piop::structs::SumcheckProverState;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};
    use std::sync::Arc;

    fn messages(poly: &HPVirtualPolynomial<Fr>, challenges: &[Fr]) -> Vec<Vec<Fr>> {
        let mut state = SumcheckProverState::prover_init_with_stream_k(poly, 0).unwrap();
        let mut chal = None;
        (0..poly.aux_info.num_variables)
            .map(|round| {
                let msg = state.prove_round_and_update_state(&chal).unwrap();
                chal = Some(challenges[round]);
                msg.evaluations
            })
            .collect()
    }

    /// Terms with `eq` alone, with full-size, smaller, bit, scalar and
    /// mostly-zero factors, with `eq` twice, and without `eq`.
    #[test]
    fn eq_factored_terms_give_the_same_messages() {
        let mut rng = StdRng::seed_from_u64(0xe9);
        for nv in [1, 2, 5, 9] {
            let r: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
            let eq = Arc::new(build_eq_x_r(&r).unwrap());
            let dense = |rng: &mut StdRng, inner: usize| {
                let evals = (0..1 << inner).map(|_| Fr::rand(rng)).collect();
                let mle = ark_poly::DenseMultilinearExtension::from_evaluations_vec(inner, evals);
                Arc::new(MLE::new(mle, (inner < nv).then_some(nv)))
            };
            let a = dense(&mut rng, nv);
            let b = dense(&mut rng, nv);
            let small = dense(&mut rng, nv.saturating_sub(1));
            let scalar = dense(&mut rng, 0);
            let bits: Vec<bool> = (0..1 << nv).map(|_| rng.r#gen()).collect();
            let bit = Arc::new(MLE::<Fr>::from_bits(bits, nv));
            // Nonzero on about one row in sixteen, so terms holding it walk
            // its nonzero rows.
            let sparse = |rng: &mut StdRng, inner: usize| {
                let evals = (0..1 << inner)
                    .map(|_| {
                        if rng.gen_ratio(1, 16) {
                            Fr::rand(rng)
                        } else {
                            Fr::from(0u64)
                        }
                    })
                    .collect();
                let mle = ark_poly::DenseMultilinearExtension::from_evaluations_vec(inner, evals);
                Arc::new(MLE::new(mle, (inner < nv).then_some(nv)))
            };
            let rare = sparse(&mut rng, nv);
            let rare_small = sparse(&mut rng, nv.saturating_sub(1).max(1));
            let terms: Vec<Vec<Arc<MLE<Fr>>>> = vec![
                vec![eq.clone()],
                vec![a.clone(), eq.clone()],
                vec![eq.clone(), a.clone(), b.clone(), bit.clone()],
                vec![small.clone(), eq.clone(), a.clone()],
                vec![eq.clone(), scalar.clone()],
                vec![eq.clone(), eq.clone(), a.clone()],
                vec![a.clone(), b.clone()],
                vec![bit.clone(), small.clone(), scalar],
                vec![rare.clone(), a.clone(), eq.clone()],
                vec![rare.clone(), rare_small.clone(), b.clone()],
                vec![rare_small, small, bit],
                vec![rare],
            ];
            let mut plain = HPVirtualPolynomial::<Fr>::new(nv);
            for term in terms {
                plain.add_mle_list(term, Fr::rand(&mut rng)).unwrap();
            }
            let mut marked = plain.clone();
            marked.mark_eq(&eq, r.clone());
            assert_eq!(marked.eq_factors.len(), 1);

            let challenges: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
            assert_eq!(
                messages(&plain, &challenges),
                messages(&marked, &challenges)
            );
        }
    }
}
