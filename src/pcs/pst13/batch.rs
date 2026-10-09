//! One opening proof for many committed polynomials of any sizes.
//!
//! A polynomial of `n` variables is committed over the basis of the last `n`
//! variables of the SRS. Its commitment is therefore also that of the
//! polynomial of any `N >= n` variables that reads its last `n` variables
//! only, `F(y) = f(y[N - n..])`, and commitments of different sizes add up
//! as commitments of such polynomials of one frame of `N` variables.
//!
//! A claim `f(z[..n]) = v`, which is what a claim at a longer point `z` says
//! of a polynomial that repeats along the variables it does not have, is the
//! claim `F(w) = v` at the frame point `w = (0, .., 0, z[..n])`. The batch
//! reduces all of them to one opening of one polynomial of the frame:
//!
//! 1. the claims are bound to the transcript, and a challenge `t` gives
//!    claim `i` the weight `eq(t, i)`;
//! 2. a sumcheck proves `sum_x sum_i eq(t, i) F_i(x) eq(x, w_i)` to be the
//!    weighted sum of the claimed values, and leaves a point `a`;
//! 3. `g' = sum_i eq(t, i) eq(a, w_i) F_i`, whose commitment the verifier
//!    forms from those of the `f_i`, is opened at `a`.
//!
//! Claims of one size at one point share their tables, and a table of `n`
//! variables enters the sumcheck only in its last `n` rounds: before that
//! its round polynomial is its claimed sum times `(1 - X)`.

use super::{PST13, structs::PST13BatchProof, structs::PST13Commitment};
use crate::{
    arithmetic::{
        mat_poly::{mle::MLE, rows::add_scaled_product, utils::build_eq_x_r},
        virt_poly::hp_interface::VPAuxInfo,
    },
    errors::{SnarkError, SnarkResult},
    pcs::{
        PCS,
        errors::PCSError,
        pst13::srs::{PST13ProverParam, PST13VerifierParam},
    },
    piop::{
        structs::{SumcheckProof, SumcheckProverMessage},
        sum_check::SumCheck,
    },
    transcript::Tr,
};
use ark_ec::{CurveGroup, pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM};
use ark_ff::{One, PrimeField, Zero};
use ark_std::{cfg_iter, cfg_iter_mut, log2};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};

/// The round polynomials have degree 2: a table times an `eq` table.
const DEGREE: usize = 2;

fn prover_error(reason: &str) -> SnarkError {
    SnarkError::PCSErrors(PCSError::ProverError(reason.to_string()))
}

fn verifier_error(reason: &str) -> SnarkError {
    SnarkError::PCSErrors(PCSError::VerifierError(reason.to_string()))
}

/// Binds the claims of a batch to the transcript and returns the weight of
/// each. The weights must not be known before the claimed values are: a
/// prover free to choose values afterwards can make false ones add up.
///
/// The commitments are not absorbed here. The caller's transcript has to
/// hold them already, or they have to be fixed in advance.
fn claim_weights<F: PrimeField>(
    sizes: &[usize],
    points: &[Vec<F>],
    evals: &[F],
    transcript: &mut Tr<F>,
) -> SnarkResult<Vec<F>> {
    let sizes_u64: Vec<u64> = sizes.iter().map(|size| *size as u64).collect();
    let read: Vec<F> = sizes
        .iter()
        .zip(points)
        .flat_map(|(size, point)| point[..*size].iter().copied())
        .collect();
    transcript.append_serializable_element(b"pst13 batch sizes", &sizes_u64)?;
    transcript.append_serializable_element(b"pst13 batch points", &read)?;
    transcript.append_serializable_element(b"pst13 batch evals", &evals.to_vec())?;

    let ell = log2(sizes.len()) as usize;
    if ell == 0 {
        return Ok(vec![F::one()]);
    }
    let t = transcript.get_and_append_challenge_vectors(b"t", ell)?;
    Ok(build_eq_x_r(&t)?.into_evaluations())
}

/// `eq(a, w)` for the frame point `w = (0, .., 0, point)` of `a`'s frame.
fn eq_at_frame_point<F: PrimeField>(a: &[F], point: &[F]) -> F {
    let skip = a.len() - point.len();
    let low: F = a[..skip].iter().map(|a_j| F::one() - a_j).product();
    a[skip..].iter().zip(point).fold(low, |eq, (a_j, z_j)| {
        let both = *a_j * z_j;
        eq * (both + both - a_j - z_j + F::one())
    })
}

/// The `eq(., point)` table, also for the empty point.
fn eq_table<F: PrimeField>(point: &[F]) -> SnarkResult<Vec<F>> {
    if point.is_empty() {
        return Ok(vec![F::one()]);
    }
    Ok(build_eq_x_r(point)?.into_evaluations())
}

/// The claims of one size at one point, as one table.
struct Class<F> {
    /// The point, as long as the tables have variables.
    point: Vec<F>,
    /// `sum_i eq(t, i) f_i` over the claims of the class.
    merged: Vec<F>,
}

/// A class inside the sumcheck.
struct Active<F> {
    /// Rounds before the first variable of the tables.
    skip: usize,
    /// `merged`, bound to the challenges of its rounds so far. Empty until
    /// the first of them: the class's own table is read for that round, so
    /// that it is never held twice.
    table: Vec<F>,
    /// `eq(., point)`, bound likewise.
    eq: Vec<F>,
    /// `sum_x merged(x) eq(x, point)`.
    sum: F,
    /// `prod_j (1 - r_j)` over the rounds before the tables' variables.
    scale: F,
}

/// `[p(0), p(1), p(2)]` of the round polynomial of `table * eq`, whose
/// round variable is the lowest of both.
fn round_evals<F: PrimeField>(table: &[F], eq: &[F]) -> [F; 3] {
    let (table, _) = table.as_chunks::<2>();
    let (eq, _) = eq.as_chunks::<2>();
    let term = |(t, e): (&[F; 2], &[F; 2])| {
        let (t2, e2) = (t[1] + t[1] - t[0], e[1] + e[1] - e[0]);
        [t[0] * e[0], t[1] * e[1], t2 * e2]
    };
    let add = |a: [F; 3], b: [F; 3]| [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
    #[cfg(feature = "parallel")]
    return table
        .par_iter()
        .zip(eq)
        .map(term)
        .reduce(|| [F::zero(); 3], add);
    #[cfg(not(feature = "parallel"))]
    table.iter().zip(eq).map(term).fold([F::zero(); 3], add)
}

/// `table` with its lowest variable bound to `r`.
fn bound<F: PrimeField>(table: &[F], r: F) -> Vec<F> {
    let (pairs, _) = table.as_chunks::<2>();
    cfg_iter!(pairs)
        .map(|pair| pair[0] + r * (pair[1] - pair[0]))
        .collect()
}

/// `values` over `nv` variables, as the table of the frame of `frame`
/// variables that reads its last `nv` ones.
fn stretch<F: PrimeField>(values: Vec<F>, nv: usize, frame: usize) -> Vec<F> {
    if nv == frame {
        return values;
    }
    let shift = frame - nv;
    let mut out = vec![F::zero(); 1 << frame];
    cfg_iter_mut!(out)
        .enumerate()
        .for_each(|(row, slot)| *slot = values[row >> shift]);
    out
}

pub(super) fn open_batch<E: Pairing>(
    prover_param: &PST13ProverParam<E>,
    polynomials: &[Arc<MLE<E::ScalarField>>],
    points: &[Vec<E::ScalarField>],
    evals: &[E::ScalarField],
    transcript: &mut Tr<E::ScalarField>,
) -> SnarkResult<PST13BatchProof<E, PST13<E>>> {
    if polynomials.is_empty() || polynomials.len() != points.len() || points.len() != evals.len() {
        return Err(prover_error(
            "a batch needs one point and one value per polynomial",
        ));
    }
    // The size a polynomial is committed at, not the one it is padded to.
    let sizes: Vec<usize> = polynomials
        .iter()
        .map(|poly| poly.storage().inner_num_vars())
        .collect();
    if sizes
        .iter()
        .zip(points)
        .any(|(nv, point)| point.len() < *nv)
    {
        return Err(prover_error("a point is shorter than its polynomial"));
    }
    let frame = *sizes.iter().max().expect("the batch is not empty");
    let weights = claim_weights(&sizes, points, evals, transcript)?;

    let mut index: BTreeMap<(usize, &[E::ScalarField]), usize> = BTreeMap::new();
    let mut classes: Vec<(usize, Class<E::ScalarField>)> = Vec::new();
    for (((poly, point), nv), weight) in polynomials.iter().zip(points).zip(&sizes).zip(&weights) {
        let slot = *index.entry((*nv, &point[..*nv])).or_insert_with(|| {
            classes.push((
                *nv,
                Class {
                    point: point[..*nv].to_vec(),
                    merged: vec![E::ScalarField::zero(); 1 << nv],
                },
            ));
            classes.len() - 1
        });
        add_scaled_product(&mut classes[slot].1.merged, *weight, &[poly.as_ref()]);
    }

    let mut active = classes
        .iter()
        .map(|(nv, class)| {
            let eq = eq_table(&class.point)?;
            let sum = cfg_iter!(class.merged).zip(&eq).map(|(m, e)| *m * e).sum();
            Ok(Active {
                skip: frame - nv,
                table: Vec::new(),
                eq,
                sum,
                scale: E::ScalarField::one(),
            })
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    // The transcript is driven as `SumCheck::verify` reads it.
    let aux_info = VPAuxInfo::<E::ScalarField> {
        max_degree: DEGREE,
        num_variables: frame,
        phantom: PhantomData,
    };
    transcript.append_serializable_element(b"aux info", &aux_info)?;
    let mut messages = Vec::with_capacity(frame);
    let mut a = Vec::with_capacity(frame);
    for round in 0..frame {
        let mut evaluations = [E::ScalarField::zero(); DEGREE + 1];
        for (class, (_, own)) in active.iter().zip(&classes) {
            if round < class.skip {
                // sum * scale * (1 - X)
                let at_zero = class.sum * class.scale;
                evaluations[0] += at_zero;
                evaluations[2] -= at_zero;
            } else {
                let table = match round == class.skip {
                    true => &own.merged,
                    false => &class.table,
                };
                let [p0, p1, p2] = round_evals(table, &class.eq);
                evaluations[0] += class.scale * p0;
                evaluations[1] += class.scale * p1;
                evaluations[2] += class.scale * p2;
            }
        }
        let message = SumcheckProverMessage {
            evaluations: evaluations.to_vec(),
        };
        transcript.append_serializable_element(b"prover msg", &message)?;
        messages.push(message);
        let r = transcript.get_and_append_challenge(b"Internal round")?;
        a.push(r);
        for (class, (_, own)) in active.iter_mut().zip(&classes) {
            if round < class.skip {
                class.scale *= E::ScalarField::one() - r;
            } else {
                class.table = match round == class.skip {
                    true => bound(&own.merged, r),
                    false => bound(&class.table, r),
                };
                class.eq = bound(&class.eq, r);
            }
        }
    }

    // g' = sum over the classes of eq(a, w) F, built from the smallest
    // class up so that every table is stretched once per size above it.
    let mut order: Vec<usize> = (0..classes.len()).collect();
    order.sort_by_key(|slot| classes[*slot].0);
    let (mut g_prime, mut g_prime_nv) = (vec![E::ScalarField::zero()], 0);
    for slot in order {
        let (nv, class) = &classes[slot];
        let coeff = active[slot].scale * active[slot].eq[0];
        g_prime = stretch(g_prime, g_prime_nv, *nv);
        g_prime_nv = *nv;
        cfg_iter_mut!(g_prime)
            .zip(&class.merged)
            .for_each(|(g, m)| *g += coeff * m);
    }
    let g_prime = Arc::new(MLE::from_evaluations_vec(frame, g_prime));
    let (g_prime_proof, _) = PST13::<E>::open(prover_param, &g_prime, &a, None)?;

    Ok(PST13BatchProof {
        sum_check_proof: SumcheckProof {
            point: a,
            proofs: messages,
        },
        g_prime_proof,
    })
}

pub(super) fn verify_batch<E: Pairing>(
    verifier_param: &PST13VerifierParam<E>,
    commitments: &[PST13Commitment<E>],
    points: &[Vec<E::ScalarField>],
    evals: &[E::ScalarField],
    batch_proof: &PST13BatchProof<E, PST13<E>>,
    transcript: &mut Tr<E::ScalarField>,
) -> SnarkResult<bool> {
    if commitments.is_empty() || commitments.len() != points.len() || points.len() != evals.len() {
        return Err(verifier_error(
            "a batch needs one point and one value per commitment",
        ));
    }
    let sizes: Vec<usize> = commitments.iter().map(|com| com.nv as usize).collect();
    if sizes
        .iter()
        .zip(points)
        .any(|(nv, point)| point.len() < *nv)
    {
        return Err(verifier_error("a point is shorter than its polynomial"));
    }
    let frame = *sizes.iter().max().expect("the batch is not empty");
    if frame > verifier_param.num_vars {
        return Err(SnarkError::PCSErrors(PCSError::TooLargePolynomial(
            frame,
            verifier_param.num_vars,
        )));
    }
    let weights = claim_weights(&sizes, points, evals, transcript)?;
    let claimed_sum: E::ScalarField = weights.iter().zip(evals).map(|(w, v)| *w * v).sum();

    // `SumCheck::verify` trusts the shape of what it is given.
    let sum_check_proof = &batch_proof.sum_check_proof;
    if sum_check_proof.proofs.len() != frame
        || sum_check_proof
            .proofs
            .iter()
            .any(|message| message.evaluations.len() != DEGREE + 1)
    {
        return Err(verifier_error(
            "the sumcheck of a batch opening has another shape than its claims",
        ));
    }
    let aux_info = VPAuxInfo::<E::ScalarField> {
        max_degree: DEGREE,
        num_variables: frame,
        phantom: PhantomData,
    };
    let (a, g_prime_eval) = if frame == 0 {
        // No round: the polynomials are constants and g' is their sum.
        transcript.append_serializable_element(b"aux info", &aux_info)?;
        (Vec::new(), claimed_sum)
    } else {
        let subclaim = SumCheck::verify(claimed_sum, sum_check_proof, &aux_info, transcript)
            .map_err(|_| verifier_error("the sumcheck of a batch opening failed"))?;
        (subclaim.point, subclaim.expected_evaluation)
    };
    // The point is the transcript's. A proof that carries another one was
    // not made by this protocol.
    if sum_check_proof.point != a {
        return Ok(false);
    }

    let scalars: Vec<E::ScalarField> = weights
        .iter()
        .zip(&sizes)
        .zip(points)
        .map(|((weight, nv), point)| *weight * eq_at_frame_point(&a, &point[..*nv]))
        .collect();
    let bases: Vec<E::G1Affine> = commitments.iter().map(|com| com.com).collect();
    let g_prime_commitment = PST13Commitment {
        com: E::G1::msm_unchecked(&bases, &scalars).into_affine(),
        nv: frame as u8,
    };
    PST13::<E>::verify(
        verifier_param,
        &g_prime_commitment,
        &a,
        &g_prime_eval,
        &batch_proof.g_prime_proof,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcs::StructuredReferenceString;
    use ark_ec::AffineRepr;
    use ark_std::{UniformRand, rand::Rng, test_rng};

    type E = ark_bn254::Bn254;
    type Fr = <E as Pairing>::ScalarField;
    type Ck = PST13ProverParam<E>;
    type Vk = PST13VerifierParam<E>;

    /// The SRS is wider than any polynomial here, as it is in use.
    const SRS_NV: usize = 7;
    const POINT_LEN: usize = 5;

    fn keys() -> (Ck, Vk) {
        let srs = PST13::<E>::gen_srs_for_testing(&mut test_rng(), SRS_NV).unwrap();
        srs.trim(SRS_NV).unwrap()
    }

    fn transcript() -> Tr<Fr> {
        let mut transcript = Tr::new(b"pst13 batch test");
        transcript.append_message(b"seed", b"fixed").unwrap();
        transcript
    }

    /// `f(point[..n])` for the table `evals` of `2^n` rows, by its definition.
    fn evaluate(evals: &[Fr], point: &[Fr]) -> Fr {
        let nv = evals.len().trailing_zeros() as usize;
        evals
            .iter()
            .enumerate()
            .map(|(row, value)| {
                let weight: Fr = (0..nv)
                    .map(|bit| match (row >> bit) & 1 {
                        1 => point[bit],
                        _ => Fr::one() - point[bit],
                    })
                    .product();
                weight * value
            })
            .sum()
    }

    struct Batch {
        ck: Ck,
        vk: Vk,
        polys: Vec<Arc<MLE<Fr>>>,
        commitments: Vec<PST13Commitment<E>>,
        points: Vec<Vec<Fr>>,
        evals: Vec<Fr>,
    }

    impl Batch {
        /// One claim per polynomial, at the point `points[which[i]]`.
        fn new(polys: Vec<MLE<Fr>>, tables: &[Vec<Fr>], which: &[usize]) -> Self {
            let mut rng = test_rng();
            let (ck, vk) = keys();
            let two_points: Vec<Vec<Fr>> = (0..2)
                .map(|_| (0..POINT_LEN).map(|_| Fr::rand(&mut rng)).collect())
                .collect();
            let polys: Vec<Arc<MLE<Fr>>> = polys.into_iter().map(Arc::new).collect();
            let commitments = polys
                .iter()
                .map(|poly| PST13::<E>::commit(&ck, poly).unwrap())
                .collect();
            let points: Vec<Vec<Fr>> = which.iter().map(|p| two_points[*p].clone()).collect();
            let evals = tables
                .iter()
                .zip(&points)
                .map(|(table, point)| evaluate(table, point))
                .collect();
            Self {
                ck,
                vk,
                polys,
                commitments,
                points,
                evals,
            }
        }

        /// Polynomials of 0 to 5 variables in every storage the batch reads
        /// differently, some padded to the length of the points, at two
        /// points. Two of one size share a point and so a class.
        fn mixed() -> Self {
            let mut rng = test_rng();
            let mut random =
                |nv: usize| -> Vec<Fr> { (0..1usize << nv).map(|_| Fr::rand(&mut rng)).collect() };
            let field = |table: &[Fr]| {
                MLE::from_evaluations_vec(table.len().trailing_zeros() as usize, table.to_vec())
            };
            let padded =
                |table: &[Fr]| MLE::new(field(table).mat_mle().into_owned(), Some(POINT_LEN));
            let bytes: Vec<u8> = (0..8u8).map(|row| row.wrapping_mul(37)).collect();
            let bits: Vec<bool> = (0..16).map(|row| row % 3 == 0).collect();

            let tables = vec![
                random(0),
                random(2),
                random(3),
                random(3),
                bytes.iter().map(|b| Fr::from(*b)).collect(),
                bits.iter().map(|b| Fr::from(*b)).collect(),
                random(5),
                random(2),
            ];
            let polys = vec![
                field(&tables[0]),
                padded(&tables[1]),
                field(&tables[2]),
                padded(&tables[3]),
                MLE::from_u8s(bytes, 3),
                MLE::from_bits(bits, 4),
                field(&tables[6]),
                field(&tables[7]),
            ];
            Self::new(polys, &tables, &[0, 0, 0, 0, 1, 1, 0, 1])
        }

        fn open(&self) -> PST13BatchProof<E, PST13<E>> {
            open_batch(
                &self.ck,
                &self.polys,
                &self.points,
                &self.evals,
                &mut transcript(),
            )
            .unwrap()
        }

        fn verify(&self, proof: &PST13BatchProof<E, PST13<E>>) -> SnarkResult<bool> {
            verify_batch(
                &self.vk,
                &self.commitments,
                &self.points,
                &self.evals,
                proof,
                &mut transcript(),
            )
        }

        /// Whether `proof` is turned down, with an error or without.
        fn rejects(&self, proof: &PST13BatchProof<E, PST13<E>>) -> bool {
            !matches!(self.verify(proof), Ok(true))
        }
    }

    #[test]
    fn polynomials_of_mixed_sizes_are_opened_in_one_batch() {
        let batch = Batch::mixed();
        let sizes: Vec<u8> = batch.commitments.iter().map(|com| com.nv).collect();
        assert_eq!(sizes, [0, 2, 3, 3, 3, 4, 5, 2]);
        let proof = batch.open();
        assert_eq!(proof.sum_check_proof.proofs.len(), 5);
        assert!(batch.verify(&proof).unwrap());
    }

    /// A batch whose polynomials all have the size of the SRS and one of
    /// constants only, which has no sumcheck round at all, and one claim.
    #[test]
    fn the_frame_is_the_largest_polynomial_whatever_that_is() {
        let mut rng = test_rng();
        let mut random =
            |nv: usize| -> Vec<Fr> { (0..1usize << nv).map(|_| Fr::rand(&mut rng)).collect() };
        let field = |table: &[Fr]| {
            MLE::from_evaluations_vec(table.len().trailing_zeros() as usize, table.to_vec())
        };
        for sizes in [vec![0, 0, 0], vec![3], vec![0], vec![1, 0]] {
            let tables: Vec<Vec<Fr>> = sizes.iter().map(|nv| random(*nv)).collect();
            let polys = tables.iter().map(|table| field(table)).collect();
            let batch = Batch::new(polys, &tables, &vec![0; sizes.len()]);
            let proof = batch.open();
            assert_eq!(
                proof.sum_check_proof.proofs.len(),
                *sizes.iter().max().unwrap()
            );
            assert!(batch.verify(&proof).unwrap(), "sizes {sizes:?}");
        }
    }

    #[test]
    fn a_value_that_is_not_the_evaluation_is_rejected() {
        let honest = Batch::mixed();
        let proof = honest.open();
        for claim in 0..honest.evals.len() {
            // Against the proof of the true values, and against the one a
            // prover makes for the false value itself.
            let mut forged = Batch::mixed();
            forged.evals[claim] += Fr::one();
            assert!(forged.rejects(&proof), "claim {claim}");
            if !cfg!(feature = "honest-prover") {
                assert!(forged.rejects(&forged.open()), "claim {claim}");
            }
        }
    }

    /// The weights are drawn after the values are bound: with weights known
    /// first, false values whose weighted errors cancel would pass.
    #[test]
    fn weights_depend_on_every_part_of_the_claims() {
        let batch = Batch::mixed();
        let sizes: Vec<usize> = batch.commitments.iter().map(|c| c.nv as usize).collect();
        let weights = |sizes: &[usize], points: &[Vec<Fr>], evals: &[Fr]| {
            claim_weights(sizes, points, evals, &mut transcript()).unwrap()
        };
        let reference = weights(&sizes, &batch.points, &batch.evals);
        assert_eq!(reference, weights(&sizes, &batch.points, &batch.evals));

        let mut evals = batch.evals.clone();
        evals[3] += Fr::one();
        assert_ne!(reference, weights(&sizes, &batch.points, &evals));

        // A coordinate a polynomial reads moves them; one it does not read
        // is no part of its claim.
        let mut points = batch.points.clone();
        points[2][1] += Fr::one();
        assert_ne!(reference, weights(&sizes, &points, &batch.evals));
        let mut points = batch.points.clone();
        points[2][4] += Fr::one();
        assert_eq!(reference, weights(&sizes, &points, &batch.evals));

        let mut smaller = sizes.clone();
        smaller[6] -= 1;
        assert_ne!(reference, weights(&smaller, &batch.points, &batch.evals));
    }

    #[test]
    fn claims_in_another_order_than_the_provers_are_rejected() {
        let batch = Batch::mixed();
        let proof = batch.open();
        let mut swapped = Batch::mixed();
        swapped.commitments.swap(2, 6);
        swapped.points.swap(2, 6);
        swapped.evals.swap(2, 6);
        assert!(swapped.rejects(&proof));
    }

    /// A commitment declared one variable larger or smaller than it was
    /// made is another polynomial of the frame, with other claims.
    #[test]
    fn a_commitment_of_another_declared_size_is_rejected() {
        let batch = Batch::mixed();
        let proof = batch.open();
        for (claim, nv) in [(2, 4), (2, 2), (6, 4), (0, 1)] {
            let mut resized = Batch::mixed();
            resized.commitments[claim].nv = nv;
            assert!(resized.rejects(&proof), "claim {claim} as {nv} variables");
        }
    }

    #[test]
    fn a_tampered_proof_is_rejected() {
        let batch = Batch::mixed();
        let proof = batch.open();
        let edit = |edit: &dyn Fn(&mut PST13BatchProof<E, PST13<E>>)| {
            let mut tampered = proof.clone();
            edit(&mut tampered);
            assert_ne!(tampered, proof);
            tampered
        };

        // A round message whose two halves still add up to the claim.
        for round in [0, 2, 4] {
            let tampered = edit(&|proof| {
                let message = &mut proof.sum_check_proof.proofs[round].evaluations;
                message[0] += Fr::one();
                message[1] -= Fr::one();
            });
            assert!(batch.rejects(&tampered), "round {round}");
        }
        // The point is the transcript's, not the proof's.
        let tampered = edit(&|proof| proof.sum_check_proof.point[1] += Fr::one());
        assert!(batch.rejects(&tampered));
        // Another quotient, and none.
        let generator = <E as Pairing>::G1Affine::generator();
        let tampered = edit(&|proof| proof.g_prime_proof.proofs[3] = generator);
        assert!(batch.rejects(&tampered));
        let tampered = edit(&|proof| {
            proof.g_prime_proof.proofs.pop();
        });
        assert!(batch.rejects(&tampered));
    }

    /// Shapes the sumcheck verifier would index out of bounds on.
    #[test]
    fn a_malformed_proof_is_an_error_not_a_panic() {
        let batch = Batch::mixed();
        let proof = batch.open();
        let mut short = proof.clone();
        short.sum_check_proof.proofs.pop();
        let mut long = proof.clone();
        long.sum_check_proof
            .proofs
            .push(proof.sum_check_proof.proofs[0].clone());
        let mut thin = proof.clone();
        thin.sum_check_proof.proofs[1].evaluations.pop();
        let mut empty = proof.clone();
        empty.sum_check_proof.proofs[1].evaluations.clear();
        for malformed in [short, long, thin, empty] {
            assert!(batch.verify(&malformed).is_err());
        }

        let mut one_claim_less = Batch::mixed();
        one_claim_less.evals.pop();
        assert!(one_claim_less.verify(&proof).is_err());
        let mut short_point = Batch::mixed();
        short_point.points[6].pop();
        assert!(short_point.verify(&proof).is_err());
    }

    /// The prover's two shortcuts against the sums they stand for: the
    /// round polynomial of a class before its tables' variables, and `g'`
    /// stretched from the smallest class up.
    #[test]
    fn the_sumcheck_is_the_one_of_the_frame_polynomials() {
        let batch = Batch::mixed();
        let proof = batch.open();
        let sizes: Vec<usize> = batch.commitments.iter().map(|c| c.nv as usize).collect();
        let frame = *sizes.iter().max().unwrap();
        let weights =
            claim_weights(&sizes, &batch.points, &batch.evals, &mut transcript()).unwrap();

        // F_i and eq(., w_i) over the frame, by their definitions.
        let frame_tables: Vec<(Vec<Fr>, Vec<Fr>)> = batch
            .polys
            .iter()
            .zip(&sizes)
            .zip(&batch.points)
            .map(|((poly, nv), point)| {
                let table = poly.storage().to_evaluations_vec();
                let stretched = stretch(table, *nv, frame);
                let mut w = vec![Fr::zero(); frame - nv];
                w.extend_from_slice(&point[..*nv]);
                (stretched, eq_table(&w).unwrap())
            })
            .collect();
        let round_zero: Vec<Fr> = (0..=DEGREE as u64)
            .map(|x| {
                let x = Fr::from(x);
                let at = |table: &[Fr], pair: usize| {
                    table[2 * pair] + x * (table[2 * pair + 1] - table[2 * pair])
                };
                frame_tables
                    .iter()
                    .zip(&weights)
                    .map(|((table, eq), weight)| {
                        let sum: Fr = (0..1usize << (frame - 1))
                            .map(|pair| at(table, pair) * at(eq, pair))
                            .sum();
                        *weight * sum
                    })
                    .sum()
            })
            .collect();
        assert_eq!(proof.sum_check_proof.proofs[0].evaluations, round_zero);
    }

    #[test]
    fn a_random_statement_of_many_claims_verifies() {
        let mut rng = test_rng();
        for _ in 0..4 {
            let count = rng.gen_range(2..12);
            let sizes: Vec<usize> = (0..count).map(|_| rng.gen_range(0..=POINT_LEN)).collect();
            let tables: Vec<Vec<Fr>> = sizes
                .iter()
                .map(|nv| (0..1usize << nv).map(|_| Fr::rand(&mut rng)).collect())
                .collect();
            let polys = tables
                .iter()
                .zip(&sizes)
                .map(|(table, nv)| MLE::from_evaluations_vec(*nv, table.clone()))
                .collect();
            let which: Vec<usize> = (0..count).map(|_| rng.gen_range(0..2)).collect();
            let batch = Batch::new(polys, &tables, &which);
            assert!(batch.verify(&batch.open()).unwrap(), "sizes {sizes:?}");
        }
    }
}
