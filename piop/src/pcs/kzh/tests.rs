use super::*;
use ark_ec::pairing::Pairing;
use ark_std::{UniformRand, rand::Rng, test_rng, vec::Vec};
use rayon::vec;
use std::sync::Arc;

type E = ark_test_curves::bls12_381::Bls12_381;
type Fr = <E as Pairing>::ScalarField;

fn test_single_helper<R: Rng>(
    params: &KZH2UniversalParams<E>,
    poly: &Arc<DenseMultilinearExtension<Fr>>,
    rng: &mut R,
) -> SnarkResult<()> {
    let nv = poly.num_vars();
    assert_ne!(nv, 0);
    let (ck, vk) = KZH2::trim(params, None, Some(nv))?;
    let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
    let com = KZH2::commit(&ck, poly)?;
    let (proof, value) = KZH2::open(&ck, poly, &point, None)?;

    assert_eq!(poly.evaluate(&point), value);
    assert!(KZH2::verify(&vk, &com, &point, &value, &proof)?);

    // let value = Fr::rand(rng);
    // assert!(!KZH2::verify(&vk, &com, &point, &value, &proof)?);

    Ok(())
}

#[test]
fn test_single_commit() -> SnarkResult<()> {
    let nv = 4;
    let mut rng = test_rng();
    let params = KZH2::<E>::gen_srs_for_testing(&mut rng, nv)?;

    // normal polynomials
    let poly1 = Arc::new(DenseMultilinearExtension::rand(nv, &mut rng));
    test_single_helper(&params, &poly1, &mut rng)?;

    // single-variate polynomials
    let poly2 = Arc::new(DenseMultilinearExtension::rand(nv, &mut rng));
    test_single_helper(&params, &poly2, &mut rng)?;

    Ok(())
}

#[test]
fn setup_commit_verify_constant_polynomial() {
    let mut rng = test_rng();

    // normal polynomials
    assert!(KZH2::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
}

#[test]
fn test() {
    let poly: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_vec(
        2,
        vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)],
    );
    let eval = poly.evaluate(&vec![Fr::from(0), Fr::from(1)]);
}
