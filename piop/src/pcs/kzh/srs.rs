use crate::{errors::SnarkResult, pcs::StructuredReferenceString};
use ark_ec::CurveGroup;
use ark_ec::ScalarMul;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, cfg_iter, cfg_iter_mut};
use ark_std::{end_timer, rand::Rng, start_timer};
use macros::timed;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator};
/// Universal Parameter
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH2UniversalParams<E: Pairing> {
    nu: usize,
    mu: usize,
    h_mat: Vec<E::G1Affine>,
    h_vec: Vec<E::G1Affine>,
    v_vec: Vec<E::G2Affine>,
    minus_v_prime: E::G2Affine,
    gi: Vec<E::G1Affine>,
}

impl<E: Pairing> KZH2UniversalParams<E> {
    /// Create a new universal parameter
    pub fn new(
        nu: usize,
        mu: usize,
        h_mat: Vec<E::G1Affine>,
        h_vec: Vec<E::G1Affine>,
        v_vec: Vec<E::G2Affine>,
        minus_v_prime: E::G2Affine,
        gi: Vec<E::G1Affine>,
    ) -> Self {
        Self {
            nu,
            mu,
            h_mat,
            h_vec,
            v_vec,
            minus_v_prime,
            gi,
        }
    }

    pub fn nu(&self) -> usize {
        self.nu
    }
    pub fn mu(&self) -> usize {
        self.mu
    }

    pub fn h_mat(&self) -> &Vec<E::G1Affine> {
        &self.h_mat
    }
    pub fn h_vec(&self) -> &Vec<E::G1Affine> {
        &self.h_vec
    }
    pub fn v_vec(&self) -> &Vec<E::G2Affine> {
        &self.v_vec
    }
    pub fn minus_v_prime(&self) -> E::G2Affine {
        self.minus_v_prime
    }
    pub fn gi(&self) -> &Vec<E::G1Affine> {
        &self.gi
    }
}

/// Prover Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH2ProverParam<E: Pairing> {
    nu: usize,
    mu: usize,
    h_mat: Vec<E::G1Affine>,
    h_vec: Vec<E::G1Affine>,
}
impl<E: Pairing> KZH2ProverParam<E> {
    /// Create a new prover parameter
    pub fn new(nu: usize, mu: usize, h_mat: Vec<E::G1Affine>, h_vec: Vec<E::G1Affine>) -> Self {
        Self {
            nu,
            mu,
            h_mat,
            h_vec,
        }
    }

    pub fn nu(&self) -> usize {
        self.nu
    }
    pub fn mu(&self) -> usize {
        self.mu
    }
    pub fn h_mat(&self) -> &Vec<E::G1Affine> {
        &self.h_mat
    }
    pub fn h_vec(&self) -> &Vec<E::G1Affine> {
        &self.h_vec
    }
}

/// Verifier Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH2VerifierParam<E: Pairing> {
    nu: usize,
    mu: usize,
    h_vec: Vec<E::G1Affine>,
    minus_v_prime: E::G2Affine,
    v_vec: Vec<E::G2Affine>,
}

impl<E: Pairing> KZH2VerifierParam<E> {
    /// Create a new verifier parameter
    pub fn new(
        nu: usize,
        mu: usize,
        h_vec: Vec<E::G1Affine>,
        minus_v_prime: E::G2Affine,
        v_vec: Vec<E::G2Affine>,
    ) -> Self {
        Self {
            nu,
            mu,
            h_vec,
            minus_v_prime,
            v_vec,
        }
    }

    pub fn nu(&self) -> usize {
        self.nu
    }
    pub fn mu(&self) -> usize {
        self.mu
    }
    pub fn h_vec(&self) -> &Vec<E::G1Affine> {
        &self.h_vec
    }
    pub fn minus_v_prime(&self) -> E::G2Affine {
        self.minus_v_prime
    }
    pub fn v_vec(&self) -> &Vec<E::G2Affine> {
        &self.v_vec
    }
}

impl<E: Pairing> StructuredReferenceString<E> for KZH2UniversalParams<E> {
    type ProverParam = KZH2ProverParam<E>;
    type VerifierParam = KZH2VerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_num_vars: usize) -> Self::ProverParam {
        assert_eq!(supported_num_vars, self.nu + self.mu);
        KZH2ProverParam::new(self.nu, self.mu, self.h_mat.clone(), self.h_vec.clone())
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_num_vars: usize) -> Self::VerifierParam {
        assert_eq!(supported_num_vars, self.nu + self.mu);
        KZH2VerifierParam::new(
            self.nu,
            self.mu,
            self.h_vec.clone(),
            self.minus_v_prime,
            self.v_vec.clone(),
        )
    }

    #[timed]
    fn trim(
        &self,
        supported_num_vars: usize,
    ) -> SnarkResult<(Self::ProverParam, Self::VerifierParam)> {
        Ok((
            self.extract_prover_param(supported_num_vars),
            self.extract_verifier_param(supported_num_vars),
        ))
    }

    #[timed]
    fn gen_srs_for_testing<R: Rng>(rng: &mut R, num_vars: usize) -> SnarkResult<Self> {
        // Dimensions of the polynomials
        let nu = num_vars / 2;
        let mu = num_vars - nu;
        let m = 1 << mu;
        let n = 1 << nu;
        // Sampling generators
        let generators_1 = (0..m).map(|_| E::G1::rand(rng)).collect::<Vec<_>>();
        let v = E::G2::rand(rng);
        // Sampling trapdoors
        let tau_vec = (0..n)
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let alpha = E::ScalarField::rand(rng);
        // Compute the srs elements
        let minus_v_prime: E::G2Affine = (-v * alpha).into_affine();
        let v_vec = v.batch_mul(&tau_vec);
        let h_vec: Vec<E::G1Affine> = cfg_iter!(generators_1)
            .map(|g| (*g * alpha).into_affine())
            .collect::<Vec<_>>();
        let mut h_mat_transpose: Vec<Vec<E::G1Affine>> = vec![Vec::new(); m];
        cfg_iter_mut!(h_mat_transpose)
            .enumerate()
            .for_each(|(i, h)| {
                *h = generators_1[i].batch_mul(&tau_vec);
            });

        let h_mat: Vec<E::G1Affine> = (0..n)
            .into_par_iter()
            .flat_map_iter(|i| {
                let h = &h_mat_transpose;
                (0..m).map(move |j| h[j][i])
            })
            .collect();
        Ok(KZH2UniversalParams::new(
            nu,
            mu,
            h_mat,
            h_vec,
            v_vec,
            minus_v_prime,
            generators_1.into_iter().map(|g| g.into_affine()).collect(),
        ))
    }
}
