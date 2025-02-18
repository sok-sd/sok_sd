use std::io::Cursor;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::prelude::StdRng;
use ark_std::UniformRand;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::ser::SerializeSeq;

use crate::our_impl::pointcheval_sanders::ps_message::PSMessage;
use crate::our_impl::pointcheval_sanders::ps_private_key::PSPrivateKey;
use crate::our_impl::pointcheval_sanders::ps_public_key::PSPublicKey;
use crate::utils::Utils;

/// Efficient Redactable Signature and Application to Anonymous Credentials
#[derive(Debug, Clone)]
pub struct PSSignature {
    sigma_1: G1Affine,
    sigma_2: G1Affine,
    sigma_tilde_1: G2Affine,
    sigma_tilde_2: G2Affine,
}

impl PSSignature {

    pub fn sigma_1(&self) -> G1Affine {
        self.sigma_1
    }
    pub fn sigma_2(&self) -> G1Affine {
        self.sigma_2
    }
    pub fn sigma_tilde_1(&self) -> G2Affine {
        self.sigma_tilde_1
    }
    pub fn sigma_tilde_2(&self) -> G2Affine {
        self.sigma_tilde_2
    }

    pub fn keygen(messages_len: usize, rng: &mut StdRng) -> Result<(PSPrivateKey, PSPublicKey), String> {

        let g = G1Affine::generator();
        let g_tilde = G2Affine::generator();

        let x = Fr::rand(rng);
        let capital_x: G1Affine = (g * x).into();

        let mut y_vec: Vec<Fr> = vec![];
        let mut capital_y_vec: Vec<(G1Affine, G2Affine)> = vec![];

        let mut y_i: Fr;
        let mut y_j: Fr;
        let mut capital_y: G1Affine;
        let mut capital_y_tilde: G2Affine;

        for _ in 0..messages_len {
            y_i = Fr::rand(rng);
            y_vec.push(y_i);

            capital_y = (g * y_i).into();
            capital_y_tilde = (g_tilde * y_i).into();

            capital_y_vec.push((capital_y, capital_y_tilde));
        }

        let mut capital_z_matrix: Vec<Vec<G1Affine>> = vec![];
        let mut capital_z_i_j: G1Affine;
        for i in 0..messages_len {

            let mut capital_z_i: Vec<G1Affine> = vec![];

            y_i = match y_vec.get(i) {
                None => { return Err(format!("Could not retrieve element y_i at index {i}.")); }
                Some(y_i) => { y_i.clone() }
            };

            for j in 0..messages_len {

                if i == j {
                    capital_z_i.push(G1Affine::zero());        // Placeholder
                    continue;
                }

                y_j = match y_vec.get(j) {
                    None => { return Err(format!("Could not retrieve element y_j at index {j}.")); }
                    Some(y_j) => { y_j.clone() }
                };

                capital_z_i_j = (g * y_i * y_j).into();
                capital_z_i.push(capital_z_i_j)

            }

            capital_z_matrix.push(capital_z_i);

        }

        Ok((PSPrivateKey::new(x, y_vec), PSPublicKey::new(g, g_tilde, capital_x, capital_y_vec, capital_z_matrix)))
    }

    pub fn sign(sk: &PSPrivateKey, messages: &Vec<PSMessage>, rng: &mut StdRng) -> Result<Self, String> {

        let sigma_tilde_1 = G2Affine::rand(rng);
        let mut exponent: Fr = sk.x();

        let mut message: PSMessage;

        for (i, y_i) in sk.y_vec().iter().enumerate() {
            message = match messages.get(i) {
                Some(message) => { message.clone() },
                None => { return Err(format!("Could not retrieve message at index {i}")) }
            };

            exponent = exponent + y_i.clone() * message.message();
        }

        let sigma_tilde_2: G2Affine = (sigma_tilde_1 * exponent).into();
        Ok(PSSignature {
            sigma_1: G1Affine::default(),        // For bls12_381, this is the identity value
            sigma_2: G1Affine::default(),        // For bls12_381, this is the identity value
            sigma_tilde_1,
            sigma_tilde_2,
        })

    }

    pub fn verify(pk: &PSPublicKey, sigma: &PSSignature, disclosed_messages: &Vec<PSMessage>) -> Result<bool, String> {

        #![allow(unused_labels)]
        'first_check: {
            let mut product: G1Affine = (pk.capital_x() + sigma.sigma_1()).into();
            let mut capital_y_i: G1Affine;

            for disclosed_message in disclosed_messages {
                (capital_y_i, _) = match pk.capital_y_vec().get(disclosed_message.index()) {
                    None => { return Err(format!("Could not retrieve Y_i at index {:?}", disclosed_message.index())) }
                    Some(result) => { result.clone() }
                };
                product = (product + (capital_y_i * disclosed_message.message())).into();
            }

            if Bls12_381::pairing(product, sigma.sigma_tilde_1()) != Bls12_381::pairing(pk.g(), sigma.sigma_tilde_2()) {
                return Err("Signature verification failed. [First check]".to_string());
            }
        }

        'second_check: {
            let mut product: G2Affine = G2Affine::default();      // Identity, for initialization
            let mut capital_y_tilde_i: G2Affine;

            for disclosed_message in disclosed_messages {
                (_, capital_y_tilde_i) = match pk.capital_y_vec().get(disclosed_message.index()) {
                    None => { return Err(format!("Could not retrieve Y_tilde_i at index {:?}", disclosed_message.index())) }
                    Some(result) => { result.clone() }
                };
                product = (product + capital_y_tilde_i).into();
            }

            if Bls12_381::pairing(sigma.sigma_1(), product) != Bls12_381::pairing(sigma.sigma_2(), pk.g_tilde()) {
                return Err("Signature verification failed. [Second check]".to_string());
            }
        }

        return Ok(true);
    }

    pub fn derive(pk: &PSPublicKey, sigma: &PSSignature, messages: &Vec<PSMessage>, disclosed_indices: &Vec<usize>, rng: &mut StdRng) -> Result<Self, String> {
        let t: Fr = Fr::rand(rng);
        let r: Fr = Fr::rand(rng);

        let undisclosed_indices: Vec<usize> = Utils::complementary_indices(disclosed_indices.clone(), messages.len());

        let sigma_tilde_1_prime: G2Affine = (sigma.sigma_tilde_1() * r).into();
        let sigma_tilde_2_prime: G2Affine = ((sigma.sigma_tilde_2() * r) + sigma_tilde_1_prime * t).into();

        let mut sigma_1_prime: G1Affine = (pk.g() * t).into();
        let mut capital_y_j: G1Affine;
        let mut undisclosed_message: PSMessage;
        for undisclosed_index in &undisclosed_indices {
            (capital_y_j, _) = match pk.capital_y_vec().get(*undisclosed_index) {
                None => { return Err(format!("Could not retrieve Y_j at index {:?}", *undisclosed_index)) }
                Some(result) => { result.clone() }
            };

            undisclosed_message = match messages.get(*undisclosed_index) {
                None => { return Err(format!("Could not retrieve undisclosed_message at index {:?}", *undisclosed_index)) }
                Some(result) => { result.clone() }
            };
            sigma_1_prime = (sigma_1_prime + capital_y_j * undisclosed_message.message()).into();
        }

        let mut sigma_2_prime: G1Affine = G1Affine::default();
        let mut capital_y_i: G1Affine;
        for disclosed_index in disclosed_indices {
            (capital_y_i, _) = match pk.capital_y_vec().get(*disclosed_index) {
                None => { return Err(format!("Could not retrieve Y_i at index {:?}", disclosed_index)) }
                Some(result) => { result.clone() }
            };
            sigma_2_prime = (sigma_2_prime + capital_y_i).into()
        }
        sigma_2_prime = (sigma_2_prime * t).into();

        let mut capital_z_i: Vec<G1Affine>;
        let mut capital_z_i_j: G1Affine;
        for disclosed_index in disclosed_indices {
            for undisclosed_index in &undisclosed_indices {
                capital_z_i = match pk.capital_z_matrix().get(*disclosed_index) {
                    None => { return Err(format!("Could not retrieve Z_i array at index {:?}", disclosed_index)) }
                    Some(vec) => { vec.clone() }
                };
                capital_z_i_j = match capital_z_i.get(*undisclosed_index) {
                    None => { return Err(format!("Could not retrieve Z_i_j at index {:?}", *undisclosed_index)) }
                    Some(result) => { result.clone() }
                };
                undisclosed_message = match messages.get(*undisclosed_index) {
                    None => { return Err(format!("Could not retrieve undisclosed_message at index {:?}", *undisclosed_index)) }
                    Some(result) => { result.clone() }
                };

                sigma_2_prime = (sigma_2_prime + capital_z_i_j * undisclosed_message.message()).into();
            }

        }

        Ok(PSSignature {
            sigma_1: sigma_1_prime,
            sigma_2: sigma_2_prime,
            sigma_tilde_1: sigma_tilde_1_prime,
            sigma_tilde_2: sigma_tilde_2_prime,
        })
    }

}


impl Serialize for PSSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        let mut seq = serializer.serialize_seq(Some(4usize))?;

        let mut byte_vec: Vec<u8> = vec![];
        self.sigma_1.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.sigma_2.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.sigma_tilde_1.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        byte_vec.clear();
        self.sigma_tilde_2.serialize_compressed(&mut byte_vec).unwrap();
        seq.serialize_element(&byte_vec)?;

        seq.end()

    }
}

impl<'de> Deserialize<'de> for PSSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {

        let des: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;

        let cursor = Cursor::new(des.get(0).unwrap());
        let sigma_1: G1Affine = CanonicalDeserialize::deserialize_compressed(cursor).unwrap();

        let cursor = Cursor::new(des.get(1).unwrap());
        let sigma_2: G1Affine = CanonicalDeserialize::deserialize_compressed(cursor).unwrap();

        let cursor = Cursor::new(des.get(2).unwrap());
        let sigma_tilde_1: G2Affine = CanonicalDeserialize::deserialize_compressed(cursor).unwrap();

        let cursor = Cursor::new(des.get(3).unwrap());
        let sigma_tilde_2: G2Affine = CanonicalDeserialize::deserialize_compressed(cursor).unwrap();

        let result = PSSignature { sigma_1, sigma_2, sigma_tilde_1, sigma_tilde_2 };

        Ok(result)
    }
}


#[cfg(test)]
mod test {
    use ark_bls12_381::Fr;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;

    use crate::our_impl::pointcheval_sanders::ps_message::PSMessage;
    use crate::our_impl::pointcheval_sanders::ps_signature::PSSignature;

    #[test]
    fn correctness() {

        let mut rng = StdRng::from_entropy();
        let mut messages: Vec<PSMessage> = vec![];
        let mut message: PSMessage;

        for i in 0..10 {
            message = PSMessage::new(i, Fr::rand(&mut rng));
            messages.push(message);
        }

        let (sk, pk) = PSSignature::keygen(messages.len(), &mut rng).unwrap();
        let sigma = PSSignature::sign(&sk, &messages.clone(), &mut rng).unwrap();
        let result = PSSignature::verify(&pk, &sigma, &messages).unwrap();

        assert!(result)

    }

    #[test]
    fn correctness_of_sd() {

        let mut rng = StdRng::from_entropy();
        let mut messages: Vec<PSMessage> = vec![];
        let mut message: PSMessage;

        for i in 0..10 {
            message = PSMessage::new(i, Fr::rand(&mut rng));
            messages.push(message);
        }

        let (sk, pk) = PSSignature::keygen(messages.len(), &mut rng).unwrap();
        let sigma = PSSignature::sign(&sk, &messages.clone(), &mut rng).unwrap();

        let disclosed_indices = (1..10).step_by(2).collect::<Vec<usize>>();
        let sigma_prime = PSSignature::derive(&pk, &sigma, &messages, &disclosed_indices.clone(), &mut rng).unwrap();
        let disclosed_messages = messages.iter().filter(|message| {
            disclosed_indices.contains(&message.index())
        }).map(|message| { message.clone() }).collect();

        let result = PSSignature::verify(&pk, &sigma_prime, &disclosed_messages).unwrap();

        assert!(result)

    }

}