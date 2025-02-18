use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use serde::{Serialize, Serializer};
use serde::ser::SerializeSeq;

#[derive(Clone)]
pub struct PSPrivateKey {
    x: Fr,
    y_vec: Vec<Fr>
}

impl PSPrivateKey {
    pub fn new(x: Fr, y_vec: Vec<Fr>) -> Self {
        Self { x, y_vec }
    }
    pub fn x(&self) -> Fr {
        self.x
    }
    pub fn y_vec(&self) -> &Vec<Fr> {
        &self.y_vec
    }
}

impl Serialize for PSPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        let mut seq = serializer.serialize_seq(Some(4usize))?;

        let mut byte_vec: Vec<u8> = vec![];
        self.x.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.y_vec.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        seq.end()

    }
}

