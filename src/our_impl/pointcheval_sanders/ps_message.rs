use ark_bls12_381::Fr;
use digest::Digest;
use sha2::Sha256;
use ark_ff::PrimeField;
#[derive(Clone, Debug)]
pub struct PSMessage {
    index: usize,
    message: Fr,
}

impl PSMessage {
    pub fn new(index: usize, message: Fr) -> Self {
        Self { index, message }
    }
    pub fn new_from_bytes(index: usize, data: &[u8]) -> Self {

        let binding = Sha256::digest(data);
        let msg_digest = binding.as_slice();

        Self { index, message: PrimeField::from_be_bytes_mod_order(msg_digest) }
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn message(&self) -> Fr {
        self.message
    }
}