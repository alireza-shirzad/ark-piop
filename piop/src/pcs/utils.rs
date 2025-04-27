use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use crate::add_trace;

use super::PCS;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{add_to_trace, test_rng};
use macros::timed;

#[timed]
pub fn load_or_generate_srs<F: PrimeField, PCSImpl: PCS<F>>(
    srs_path: &Path,
    size: usize,
) -> PCSImpl::SRS {
    if srs_path.exists() {
        add_trace!("load_or_generate_srs", "loading path = {:?}", srs_path);
        let mut buffer = Vec::new();
        BufReader::new(File::open(srs_path).unwrap())
            .read_to_end(&mut buffer)
            .unwrap();
        PCSImpl::SRS::deserialize_uncompressed_unchecked(&buffer[..]).unwrap_or_else(|_| {
            panic!("Failed to deserialize SRS from {:?}", srs_path);
        })
    } else {
        add_trace!("load_or_generate_srs", "saving path = {:?}", srs_path);
        let mut rng = test_rng();
        let srs = PCSImpl::gen_srs_for_testing(&mut rng, size).unwrap();
        let mut serialized = Vec::new();
        srs.serialize_uncompressed(&mut serialized).unwrap();
        BufWriter::new(
            File::create(srs_path)
                .unwrap_or_else(|_| panic!("could not create file for SRS at {:?}", srs_path)),
        )
        .write_all(&serialized)
        .unwrap();
        srs
    }
}
