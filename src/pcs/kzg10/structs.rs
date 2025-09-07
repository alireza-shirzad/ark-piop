use std::fmt;

use ark_ec::pairing::Pairing;
use ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;

use crate::{
    arithmetic::g1_affine_short_str, pcs::PolynomialCommitment, util::display::ShortDisplay,
};
use ark_ec::AffineRepr;
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
pub struct KZG10Commitment<E: Pairing> {
    /// the actual commitment is an affine point.
    pub com: E::G1Affine,
    pub nv: usize,
}
impl<E: Pairing> PolynomialCommitment<E::ScalarField> for KZG10Commitment<E> {
    fn num_vars(&self) -> usize {
        self.nv
    }
    fn set_num_vars(&mut self, nv: usize) {
        self.nv = nv;
    }
}

impl<E: Pairing> ShortDisplay for KZG10Commitment<E> {
    fn fmt_short(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let coords = g1_affine_short_str(&self.com);
        write!(f, "nv{}: {}", self.nv, coords)
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct KZG10Proof<E: Pairing> {
    /// Evaluation of quotients
    pub proof: E::G1Affine,
}
impl<E: Pairing> Default for KZG10Proof<E> {
    fn default() -> Self {
        Self {
            proof: E::G1Affine::zero(),
        }
    }
}
/// batch proof
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct KZG10BatchProof<E: Pairing>(pub Vec<KZG10Proof<E>>);

impl<E: Pairing> Default for KZG10BatchProof<E> {
    fn default() -> Self {
        Self(vec![])
    }
}
