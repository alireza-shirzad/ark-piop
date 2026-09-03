//! Fiat-Shamir transcript: [`Tr`] wraps [`merlin::Transcript`] to append
//! field/serializable elements and generate challenges.

pub(crate) mod errors;
use crate::to_bytes;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use errors::TranscriptError;
use merlin::Transcript;
use std::marker::PhantomData;
/// IOP transcript over field `F`: a Merlin transcript plus an `is_empty` flag.
/// Challenges are refused on an empty transcript — when the verifier initiates
/// a protocol, the prover must start from a non-empty one.
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

    pub(crate) fn append_message(
        &mut self,
        label: &'static [u8],
        msg: &[u8],
    ) -> Result<(), TranscriptError> {
        self.transcript.append_message(label, msg);
        self.is_empty = false;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn append_field_element(
        &mut self,
        label: &'static [u8],
        field_elem: &F,
    ) -> Result<(), TranscriptError> {
        self.append_message(label, &to_bytes!(field_elem)?)
    }

    pub(crate) fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        self.append_message(label, &to_bytes!(group_elem)?)
    }

    // Generate a challenge and append it to the transcript. The output is
    // statistically uniform as long as the field size is below 2^384.
    pub(crate) fn get_and_append_challenge(
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
        Ok(challenge)
    }

    // Generate `len` challenges, each appended to the transcript (same
    // uniformity bound as `get_and_append_challenge`).
    pub(crate) fn get_and_append_challenge_vectors(
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
            res.push(self.get_and_append_challenge(label)?)
        }
        Ok(res)
    }
}

/// Serialize any `CanonicalSerialize` value into compressed bytes.
#[macro_export]
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = ark_std::vec![];
        ark_serialize::CanonicalSerialize::serialize_compressed($x, &mut buf).map(|_| buf)
    }};
}
