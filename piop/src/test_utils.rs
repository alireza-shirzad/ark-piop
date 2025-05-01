use crate::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkError,
    pcs::PCS,
    prover::Prover,
    setup::KeyGenerator,
    verifier::Verifier,
};
use ark_ff::{Field, PrimeField};

/// A helper function that outputs given the number of variables (i.e. log of
/// maximum table size), outputs a ready-to-use instance of the prover and
/// verifier
#[allow(clippy::type_complexity)]
pub fn prelude_with_vars<
    F: Field + PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    num_mv_vars: usize,
) -> Result<(Prover<F, MvPCS, UvPCS>, Verifier<F, MvPCS, UvPCS>), SnarkError> {
    let key_generator = KeyGenerator::<F, MvPCS, UvPCS>::new().with_num_mv_vars(num_mv_vars);
    let (pk, vk) = key_generator.gen_keys().unwrap();
    let prover = Prover::new_from_pk(pk);
    let verifier = Verifier::new_from_vk(vk);
    Ok((prover, verifier))
}

/// A prelude for testing, with a fewer number of variables, suitable for
/// testing on small tables.
/// This function sets up the proof system and gives you a ready-to-use instance
/// of the prover and verifier
#[allow(clippy::type_complexity)]
pub fn test_prelude<
    F: Field + PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>() -> Result<(Prover<F, MvPCS, UvPCS>, Verifier<F, MvPCS, UvPCS>), SnarkError> {
    prelude_with_vars::<F, MvPCS, UvPCS>(16)
}

/// A prelude for benchmarking, with a larger number of variables, suitable for
/// benchmarking on large tables.
/// This function sets up the proof system and gives you a ready-to-use instance
/// of the prover and verifier
#[allow(clippy::type_complexity)]
pub fn bench_prelude<
    F: Field + PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>() -> Result<(Prover<F, MvPCS, UvPCS>, Verifier<F, MvPCS, UvPCS>), SnarkError> {
    prelude_with_vars::<F, MvPCS, UvPCS>(23)
}
