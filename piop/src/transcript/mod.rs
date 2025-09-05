pub(crate) mod errors;
use crate::{
    add_trace,
    arithmetic::{f_short_str, f_vec_short_str},
    to_bytes,
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use errors::TranscriptError;
use merlin::Transcript;
use std::marker::PhantomData;
/// An IOP transcript consists of a Merlin transcript and a flag `is_empty` to
/// indicate that if the transcript is empty.
///
/// It is associated with a prime field `F` for which challenges are generated
/// over.
///
/// The `is_empty` flag is useful in the case where a protocol is initiated by
/// the verifier, in which case the prover should start its phase by receiving a
/// `non-empty` transcript.
#[derive(Clone)]
pub struct Tr<F: PrimeField> {
    transcript: Transcript,
    is_empty: bool,
    #[doc(hidden)]
    phantom: PhantomData<F>,
}

impl<F: PrimeField> Default for Tr<F> {
    fn default() -> Self {
        Self {
            transcript: Transcript::new(b""),
            is_empty: true,
            phantom: PhantomData,
        }
    }
}

// TODO: Make this into a Trait
impl<F: PrimeField> Tr<F> {
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            transcript: Transcript::new(label),
            is_empty: true,
            phantom: PhantomData,
        }
    }

    // Append the message to the transcript.
    pub(crate) fn append_message(
        &mut self,
        label: &'static [u8],
        msg: &[u8],
    ) -> Result<(), TranscriptError> {
        self.transcript.append_message(label, msg);
        self.is_empty = false;
        Ok(())
    }

    // Append the message to the transcript.
    #[allow(dead_code)]
    pub(crate) fn append_field_element(
        &mut self,
        label: &'static [u8],
        field_elem: &F,
    ) -> Result<(), TranscriptError> {
        self.append_message(label, &to_bytes!(field_elem)?)
    }

    // Append the message to the transcript.
    pub(crate) fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        self.append_message(label, &to_bytes!(group_elem)?)
    }

    // Generate the challenge from the current transcript
    // and append it to the transcript.
    //
    // The output field element is statistical uniform as long
    // as the field has a size less than 2^384.

    pub(crate) fn and_append_challenge(
        &mut self,
        label: &'static [u8],
    ) -> Result<F, TranscriptError> {
        //  we need to reject when transcript is empty
        if self.is_empty {
            return Err(TranscriptError::InvalidTranscript(
                "transcript is empty".to_string(),
            ));
        }

        let mut buf = [0u8; 64];
        self.transcript.challenge_bytes(label, &mut buf);
        let challenge = F::from_le_bytes_mod_order(&buf);
        self.append_serializable_element(label, &challenge)?;
        add_trace!(
            "and_append_challenge",
            "label={}, challenge={:?}",
            std::str::from_utf8(label).unwrap(),
            f_short_str(challenge)
        );
        Ok(challenge)
    }

    // Generate a list of challenges from the current transcript
    // and append them to the transcript.
    //
    // The output field element are statistical uniform as long
    // as the field has a size less than 2^384.

    pub(crate) fn and_append_challenge_vectors(
        &mut self,
        label: &'static [u8],
        len: usize,
    ) -> Result<Vec<F>, TranscriptError> {
        //  we need to reject when transcript is empty
        if self.is_empty {
            return Err(TranscriptError::InvalidTranscript(
                "transcript is empty".to_string(),
            ));
        }

        let mut res = vec![];
        for _ in 0..len {
            res.push(self.and_append_challenge(label)?)
        }
        add_trace!(
            "and_append_challenge_vectors",
            "label={}, challenge={:?}",
            std::str::from_utf8(label).unwrap(),
            f_vec_short_str(&res)
        );
        Ok(res)
    }
}

/// Takes as input a struct, and converts them to a series of bytes. All traits
/// that implement `CanonicalSerialize` can be automatically converted to bytes
/// in this manner.
#[macro_export]
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = ark_std::vec![];
        ark_serialize::CanonicalSerialize::serialize_compressed($x, &mut buf).map(|_| buf)
    }};
}
