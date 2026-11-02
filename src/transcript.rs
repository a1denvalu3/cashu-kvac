use merlin::Transcript;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::secp::{GroupElement, Scalar};

/// A wrapper around `merlin::Transcript` for Fiat-Shamir transformations.
#[wasm_bindgen]
#[derive(Clone)]
pub struct CashuTranscript {
    inner: Transcript,
}

impl Default for CashuTranscript {
    fn default() -> Self {
        Self::new()
    }
}

impl CashuTranscript {
    /// Creates a new transcript with a Cashu-specific domain separator.
    ///
    /// # Returns
    ///
    /// A new `CashuTranscript` instance.
    pub fn new() -> Self {
        let inner = Transcript::new(b"Secp256k1_Cashu_");
        CashuTranscript { inner }
    }

    /// Appends a domain separation message to the transcript.
    ///
    /// # Arguments
    ///
    /// * `message` - A byte slice representing the domain separation message.
    pub fn domain_sep(&mut self, message: &[u8]) {
        self.inner.append_message(b"dom-sep", message);
    }

    /// Appends a `GroupElement` to the transcript.
    ///
    /// # Arguments
    ///
    /// * `label` - A static byte slice used as a label for the element.
    /// * `element` - The `GroupElement` to be appended.
    pub fn append_element(&mut self, label: &'static [u8], element: &GroupElement) {
        let element_bytes_compressed: [u8; 33] = element.into();
        self.inner.append_message(label, &element_bytes_compressed);
    }

    /// Computes a challenge scalar from the transcript.
    ///
    /// # Arguments
    ///
    /// * `label` - A static byte slice used as a label for the challenge.
    ///
    /// # Returns
    ///
    /// A `Scalar` derived from the transcript state.
    pub fn get_challenge(&mut self, label: &'static [u8]) -> Scalar {
        let mut challenge: [u8; 32] = [0; 32];
        self.inner.challenge_bytes(label, &mut challenge);
        Scalar::new(&challenge)
    }
}

impl AsMut<CashuTranscript> for CashuTranscript {
    /// Returns a mutable reference to `self`, allowing mutation of the transcript.
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}
