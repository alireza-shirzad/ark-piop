//! Sumcheck based batch opening and verify commitment.
// TODO: refactoring this code to somewhere else
// currently IOP depends on PCS because perm check requires commitment.
// The sumcheck based batch opening therefore cannot stay in the PCS repo --
// which creates a cyclic dependency.
use super::PCS;
use crate::errors::SnarkResult;
use crate::pcs::CanonicalDeserialize;
use crate::pcs::errors::PCSError;
use crate::pcs::pst13::Commitment;
use crate::pcs::pst13::SnarkError;
use crate::{
    arithmetic::{
        f_mat_short_str, f_vec_short_str,
        mat_poly::{mle::MLE, utils::build_eq_x_r_vec},
        virt_poly::hp_interface::{HPVirtualPolynomial, VPAuxInfo},
    },
    pcs::pst13::util::eq_eval,
    piop::{structs::SumcheckProof, sum_check::SumCheck},
    transcript::Tr,
};
use ark_ec::{CurveGroup, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM};
use ark_poly::{MultilinearExtension, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{One, Zero, end_timer, log2, start_timer};

use std::{collections::BTreeMap, iter, marker::PhantomData, ops::Deref, sync::Arc};
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MlBatchProof<E, MvPCS>
where
    E: Pairing,
    MvPCS: PCS<E::ScalarField>,
{
    /// A sum check proof proving tilde g's sum
    pub(crate) sum_check_proof: SumcheckProof<E::ScalarField>,
    /// f_i(point_i)
    pub f_i_eval_at_point_i: Vec<E::ScalarField>,
    /// proof for g'(a_2)
    pub(crate) g_prime_proof: MvPCS::Proof,
}

impl<E, MvPCS> Default for MlBatchProof<E, MvPCS>
where
    E: Pairing,
    MvPCS: PCS<E::ScalarField>,
{
    fn default() -> Self {
        Self {
            sum_check_proof: SumcheckProof::default(),
            f_i_eval_at_point_i: vec![],
            g_prime_proof: MvPCS::Proof::default(),
        }
    }
}

/// Steps:
/// 1. get challenge point t from transcript
/// 2. build eq(t,i) for i in [0..k]
/// 3. build \tilde g_i(b) = eq(t, i) * f_i(b)
/// 4. compute \tilde eq_i(b) = eq(b, point_i)
/// 5. run sumcheck on \sum_i=1..k \tilde eq_i * \tilde g_i
/// 6. build g'(X) = \sum_i=1..k \tilde eq_i(a2) * \tilde g_i(X) where (a2) is
///    the sumcheck's point 7. open g'(X) at point (a2)

pub(crate) fn multi_open_internal<E, MvPCS>(
    prover_param: &MvPCS::ProverParam,
    polynomials: &[Arc<MvPCS::Poly>],
    points: &[<MvPCS::Poly as Polynomial<E::ScalarField>>::Point],
    evals: &[E::ScalarField],
    transcript: &mut Tr<E::ScalarField>,
) -> SnarkResult<MlBatchProof<E, MvPCS>>
where
    E: Pairing,
    MvPCS: PCS<E::ScalarField, Poly = MLE<E::ScalarField>>,
{
    // TODO: sanity checks
    let num_var = polynomials[0].num_vars();
    let k = polynomials.len();
    let ell = log2(k) as usize;

    // challenge point t
    let t = transcript.and_append_challenge_vectors("t".as_ref(), ell)?;

    // eq(t, i) for i in [0..k]
    let eq_t_i_list = build_eq_x_r_vec(t.as_ref())?;
    // combine the polynomials that have same opening point first to reduce the
    // cost of sum check later.
    let point_indices = points
        .iter()
        .fold(BTreeMap::<_, _>::new(), |mut indices, point| {
            let idx = indices.len();
            indices.entry(point).or_insert(idx);
            indices
        });
    let deduped_points =
        BTreeMap::from_iter(point_indices.iter().map(|(point, idx)| (*idx, *point)))
            .into_values()
            .collect::<Vec<_>>();
    let merged_tilde_gs = polynomials
        .iter()
        .zip(points.iter())
        .zip(eq_t_i_list.iter())
        .fold(
            iter::repeat_with(MLE::zero)
                .map(Arc::new)
                .take(point_indices.len())
                .collect::<Vec<_>>(),
            |mut merged_tilde_gs, ((poly, point), coeff)| {
                *Arc::make_mut(&mut merged_tilde_gs[point_indices[point]]) +=
                    (*coeff, poly.deref());
                merged_tilde_gs
            },
        );

    let tilde_eqs: Vec<_> = deduped_points
        .iter()
        .map(|point| {
            let eq_b_zi = build_eq_x_r_vec(point).unwrap();
            Arc::new(MLE::from_evaluations_vec(num_var, eq_b_zi))
        })
        .collect();

    // built the virtual polynomial for SumCheck

    let mut sum_check_vp = HPVirtualPolynomial::new(num_var);
    for (merged_tilde_g, tilde_eq) in merged_tilde_gs.iter().zip(tilde_eqs.into_iter()) {
        sum_check_vp.add_mle_list([merged_tilde_g.clone(), tilde_eq], E::ScalarField::one())?;
    }

    let proof = match SumCheck::<E::ScalarField>::prove(&sum_check_vp, transcript) {
        Ok(p) => p,
        Err(_e) => {
            // cannot wrap IOPError with PCSError due to cyclic dependency
            return Err(SnarkError::PCSErrors(PCSError::InvalidProver(
                "Sumcheck in batch proving Failed".to_string(),
            )));
        }
    };

    // a2 := sumcheck's point
    let a2 = &proof.point[..num_var];

    // build g'(X) = \sum_i=1..k \tilde eq_i(a2) * \tilde g_i(X) where (a2) is the
    // sumcheck's point \tilde eq_i(a2) = eq(a2, point_i)
    let mut g_prime = Arc::new(MLE::zero());
    for (merged_tilde_g, point) in merged_tilde_gs.iter().zip(deduped_points.iter()) {
        let eq_i_a2 = eq_eval(a2, point)?;
        *Arc::make_mut(&mut g_prime) += (eq_i_a2, merged_tilde_g.deref());
    }

    let (g_prime_proof, _g_prime_eval) =
        MvPCS::open(prover_param, &g_prime, a2.to_vec().as_ref(), None)?;
    // assert_eq!(g_prime_eval, tilde_g_eval);

    Ok(MlBatchProof {
        sum_check_proof: proof,
        f_i_eval_at_point_i: evals.to_vec(),
        g_prime_proof,
    })
}

/// Steps:
/// 1. get challenge point t from transcript
/// 2. build g' commitment
/// 3. ensure \sum_i eq(a2, point_i) * eq(t, <i>) * f_i_evals matches the sum
///    via SumCheck verification 4. verify commitment
pub(crate) fn batch_verify_internal<E, MvPCS>(
    verifier_param: &MvPCS::VerifierParam,
    f_i_commitments: &[Commitment<E>],
    points: &[<MvPCS::Poly as Polynomial<E::ScalarField>>::Point],
    proof: &MlBatchProof<E, MvPCS>,
    transcript: &mut Tr<E::ScalarField>,
) -> SnarkResult<bool>
where
    E: Pairing,
    MvPCS: PCS<E::ScalarField, Poly = MLE<E::ScalarField>, Commitment = Commitment<E>>,
{
    let k = f_i_commitments.len();
    let ell = log2(k) as usize;
    let num_var = proof.sum_check_proof.point.len();
    // challenge point t
    let t = transcript.and_append_challenge_vectors("t".as_ref(), ell)?;

    // sum check point (a2)
    let a2 = &proof.sum_check_proof.point[..num_var];

    // build g' commitment
    let eq_t_list = build_eq_x_r_vec(t.as_ref())?;

    let mut scalars = vec![];
    let mut bases = vec![];

    for (i, point) in points.iter().enumerate() {
        let eq_i_a2 = eq_eval(a2, point)?;
        scalars.push(eq_i_a2 * eq_t_list[i]);
        bases.push(f_i_commitments[i].com);
    }
    let g_prime_commit = E::G1::msm_unchecked(&bases, &scalars);

    // ensure \sum_i eq(t, <i>) * f_i_evals matches the sum via SumCheck
    let mut sum = E::ScalarField::zero();
    for (i, &e) in eq_t_list.iter().enumerate().take(k) {
        sum += e * proof.f_i_eval_at_point_i[i];
    }
    let aux_info = VPAuxInfo {
        max_degree: 2,
        num_variables: num_var,
        phantom: PhantomData,
    };
    let subclaim = match SumCheck::<E::ScalarField>::verify(
        sum,
        &proof.sum_check_proof,
        &aux_info,
        transcript,
    ) {
        Ok(p) => p,
        Err(_e) => {
            // cannot wrap IOPError with PCSError due to cyclic dependency
            return Err(SnarkError::PCSErrors(PCSError::InvalidProver(
                "Sumcheck in batch verifying Failed".to_string(),
            )));
        }
    };
    let tilde_g_eval = subclaim.expected_evaluation;

    // verify commitment
    let res = MvPCS::verify(
        verifier_param,
        &Commitment {
            com: g_prime_commit.into_affine(),
            nv: num_var,
        },
        a2.to_vec().as_ref(),
        &tilde_g_eval,
        &proof.g_prime_proof,
    )?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::pcs::pst13::srs::MultilinearUniversalParams;

    use super::*;
    use crate::pcs::pst13::PST13;
    use ark_ec::pairing::Pairing;
    use ark_poly::MultilinearExtension;
    use ark_std::{UniformRand, rand::Rng, test_rng, vec::Vec};
    use ark_test_curves::bls12_381::Bls12_381;
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    fn test_single_helper<R: Rng>(
        params: &MultilinearUniversalParams<E>,
        poly: &Arc<MLE<Fr>>,
        rng: &mut R,
    ) -> SnarkResult<()> {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let (ck, vk) = PST13::trim(params, None, Some(nv))?;
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = PST13::commit(&ck, poly)?;
        let (proof, value) = PST13::open(&ck, poly, &point, None)?;

        assert!(PST13::verify(&vk, &com, &point, &value, &proof)?);

        let value = Fr::rand(rng);
        assert!(!PST13::verify(&vk, &com, &point, &value, &proof)?);

        Ok(())
    }

    #[test]
    fn test_single_commit() -> SnarkResult<()> {
        let mut rng = test_rng();

        let params = PST13::<E>::gen_srs_for_testing(&mut rng, 10)?;

        // normal polynomials
        let poly1 = Arc::new(MLE::rand(8, &mut rng));
        test_single_helper(&params, &poly1, &mut rng)?;

        // single-variate polynomials
        let poly2 = Arc::new(MLE::rand(1, &mut rng));
        test_single_helper(&params, &poly2, &mut rng)?;

        Ok(())
    }

    #[test]
    fn setup_commit_verify_constant_polynomial() {
        let mut rng = test_rng();

        // normal polynomials
        assert!(PST13::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
    }
}
