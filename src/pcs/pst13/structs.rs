use std::fmt;

use crate::pcs::PCS;
use crate::piop::structs::SumcheckProof;
use crate::{
    arithmetic::g1_affine_short_str, pcs::PolynomialCommitment, util::display::ShortDisplay,
};
use ark_ec::pairing::Pairing;
use ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;

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
pub struct PST13Commitment<E: Pairing> {
    /// the actual commitment is an affine point.
    pub com: E::G1Affine,
    pub nv: u8,
}
impl<E: Pairing> PolynomialCommitment<E::ScalarField> for PST13Commitment<E> {
    fn log_size(&self) -> u8 {
        self.nv
    }
    fn set_log_size(&mut self, nv: u8) {
        self.nv = nv;
    }
}
impl<E: Pairing> ShortDisplay for PST13Commitment<E> {
    fn fmt_short(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let coords = g1_affine_short_str(&self.com);
        write!(f, "nv{}: {}", self.nv, coords)
    }
}
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct PST13Proof<E: Pairing> {
    /// Evaluation of quotients
    pub proofs: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for PST13Proof<E> {
    fn default() -> Self {
        Self { proofs: vec![] }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PST13BatchProof<E, MvPCS>
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

impl<E, MvPCS> Default for PST13BatchProof<E, MvPCS>
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
