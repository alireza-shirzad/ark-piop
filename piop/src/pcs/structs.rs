// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

use std::{collections::BTreeMap, fmt};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;

use crate::{arithmetic::g1_affine_short_str, structs::TrackerID, util::display::ShortDisplay};

use super::{PCS, PolynomialCommitment};

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
pub struct Commitment<E: Pairing> {
    /// the actual commitment is an affine point.
    pub com: E::G1Affine,
    pub nv: usize,
}
impl<E: Pairing> PolynomialCommitment<E::ScalarField> for Commitment<E> {
    fn num_vars(&self) -> usize {
        self.nv
    }
    fn set_num_vars(&mut self, nv: usize) {
        self.nv = nv;
    }
}

impl<E: Pairing> ShortDisplay for Commitment<E> {
    fn fmt_short(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let coords = g1_affine_short_str(&self.com);
        write!(f, "nv{}: {}", self.nv, coords)
    }
}
