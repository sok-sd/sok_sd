use ark_bls12_381::{G1Affine, G2Affine};
use ark_serialize::CanonicalSerialize;
use serde::{Serialize, Serializer};
use serde::ser::SerializeSeq;

#[derive(Clone)]
pub struct PSPublicKey {
    g: G1Affine,
    g_tilde: G2Affine,
    capital_x: G1Affine,
    capital_y_vec: Vec<(G1Affine, G2Affine)>,
    capital_z_matrix: Vec<Vec<G1Affine>>,
}

impl PSPublicKey {
    pub fn new(g: G1Affine, g_tilde: G2Affine, capital_x: G1Affine, capital_y_vec: Vec<(G1Affine, G2Affine)>, capital_z_matrix: Vec<Vec<G1Affine>>) -> Self {
        Self { g, g_tilde, capital_x, capital_y_vec, capital_z_matrix }
    }
    pub fn g(&self) -> G1Affine {
        self.g
    }
    pub fn g_tilde(&self) -> G2Affine {
        self.g_tilde
    }
    pub fn capital_x(&self) -> G1Affine {
        self.capital_x
    }
    pub fn capital_y_vec(&self) -> &Vec<(G1Affine, G2Affine)> {
        &self.capital_y_vec
    }
    pub fn capital_z_matrix(&self) -> &Vec<Vec<G1Affine>> {
        &self.capital_z_matrix
    }
}

impl Serialize for PSPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        let mut seq = serializer.serialize_seq(Some(4usize))?;

        let mut byte_vec: Vec<u8> = vec![];
        self.g.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.g_tilde.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.capital_x.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.capital_y_vec.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.capital_z_matrix.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        seq.end()

    }
}

