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

// ── Streaming vs eager parity ────────────────────────────────────────────
//
// The streaming sumcheck prover (`TT_SUMCHECK_STREAM_K > 0`) must produce
// bit-identical round messages to the eager path — the two are equivalent
// mathematical computations, and any deviation would silently break
// soundness. These tests drive the same virtual polynomial through
// `prover_init_with_stream_k` at k = 0 (eager), k = nv (full streaming),
// and k = nv/2 (partial streaming), and assert every round message matches.

#[cfg(test)]
mod streaming_parity {
    use crate::arithmetic::mat_poly::mle::MLE;
    use crate::arithmetic::virt_poly::hp_interface::HPVirtualPolynomial;
    use crate::piop::structs::SumcheckProverState;
    use ark_bn254::Fr;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use std::sync::Arc;

    /// Run the sumcheck prover to completion for `poly`, driven by a
    /// fixed challenge sequence, at the given streaming window `k`.
    /// Returns per-round message evaluation vectors so callers can
    /// bit-compare across `k` values.
    fn run_prover(
        poly: &HPVirtualPolynomial<Fr>,
        challenges: &[Fr],
        stream_k: usize,
    ) -> Vec<Vec<Fr>> {
        let mut state =
            SumcheckProverState::prover_init_with_stream_k(poly, stream_k).unwrap();
        let mut msgs = Vec::with_capacity(poly.aux_info.num_variables);
        let mut chal: Option<Fr> = None;
        for round in 0..poly.aux_info.num_variables {
            let msg =
                SumcheckProverState::prove_round_and_update_state(&mut state, &chal).unwrap();
            msgs.push(msg.evaluations.clone());
            chal = Some(challenges[round]);
        }
        msgs
    }

    /// Product of two u32-storage MLEs — the shape sumcheck sees when
    /// arithmetization emits native-typed columns. Streaming here is
    /// meaningful (compressed → Field materialization is deferred), so
    /// this is the primary regression test.
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

        assert_eq!(eager, full_stream, "full streaming (k=nv) diverged from eager");
        assert_eq!(eager, partial, "partial streaming (k=nv/2) diverged from eager");
    }

    /// Same as above but for u8 storage — exercises the U8 arm of the
    /// streaming read path.
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

    /// Sum-of-products with mixed storage kinds — a Field-storage MLE
    /// mixed with a U32-storage MLE. The Field one is always
    /// Materialized (streaming can't help it); the U32 one goes into
    /// Streaming when k > 0. This confirms per-slot routing works.
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
