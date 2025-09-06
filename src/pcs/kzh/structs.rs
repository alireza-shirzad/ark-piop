use std::fmt;

use crate::{
    arithmetic::{g1_affine_short_str},
    pcs::PolynomialCommitment,
    util::display::ShortDisplay,
};
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;

///////////////// Commitment //////////////////////

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
/// A commitment is an Affine point.
pub struct KZH2Commitment<E: Pairing> {
    /// the actual commitment is an affine point.
    com: E::G1Affine,
    nv: usize,
}

impl<E: Pairing> KZH2Commitment<E> {
    /// Create a new commitment
    pub fn new(com: E::G1Affine, nv: usize) -> Self {
        Self { com, nv }
    }

    /// Get the commitment
    pub fn commitment(&self) -> E::G1Affine {
        self.com
    }

    /// Get the number of variables
    pub fn num_vars(&self) -> usize {
        self.nv
    }
}

impl<E: Pairing> PolynomialCommitment<E::ScalarField> for KZH2Commitment<E> {
    fn num_vars(&self) -> usize {
        self.nv
    }
    fn set_num_vars(&mut self, nv: usize) {
        self.nv = nv;
    }
}

impl<E: Pairing> ShortDisplay for KZH2Commitment<E> {
    fn fmt_short(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let coords = g1_affine_short_str(&self.com);
        write!(f, "nv{}: {}", self.nv, coords)
    }
}

////////////// Auxiliary information /////////////////

#[derive(Debug, Derivative, CanonicalSerialize, CanonicalDeserialize, Clone, PartialEq, Eq)]
pub struct KZH2AuxInfo<E: Pairing> {
    d: Vec<E::G1Affine>,
}

impl<E: Pairing> KZH2AuxInfo<E> {
    /// Create a new auxiliary information
    pub fn new(d: Vec<E::G1Affine>) -> Self {
        Self { d }
    }

    /// Get the auxiliary information
    pub fn d(&self) -> Vec<E::G1Affine> {
        self.d.clone()
    }
}

impl<E: Pairing> Default for KZH2AuxInfo<E> {
    fn default() -> Self {
        KZH2AuxInfo { d: vec![] }
    }
}

///////////// Opening Proof /////////////////

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]

/// proof of opening
pub struct KZH2OpeningProof<E: Pairing> {
    /// Evaluation of quotients
    f_star: DenseMultilinearExtension<E::ScalarField>,
    aux: KZH2AuxInfo<E>,
}

impl<E: Pairing> KZH2OpeningProof<E> {
    /// Create a new opening proof
    pub fn new(f_star: DenseMultilinearExtension<E::ScalarField>, aux: KZH2AuxInfo<E>) -> Self {
        Self { f_star, aux }
    }

    /// Get the opening proof
    pub fn f_star(&self) -> DenseMultilinearExtension<E::ScalarField> {
        self.f_star.clone()
    }

    /// Get the auxiliary information
    pub fn aux(&self) -> KZH2AuxInfo<E> {
        self.aux.clone()
    }
}

impl<E: Pairing> Default for KZH2OpeningProof<E> {
    fn default() -> Self {
        KZH2OpeningProof {
            f_star: DenseMultilinearExtension::default(),
            aux: KZH2AuxInfo::default(),
        }
    }
}
