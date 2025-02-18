use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use ark_std::rand::rngs::StdRng;
use ark_std::UniformRand;

#[allow(dead_code)]
struct PedersenCommitment <P: Pairing>{
    g: P::G1Affine,
    h: P::G1Affine,
    commitment: P::G1Affine,
}

#[allow(dead_code)]
impl<P: Pairing> PedersenCommitment <P>{

    pub fn commit(message: P::ScalarField, rng: &mut StdRng) -> (Self, P::ScalarField) {
        let randomness = P::ScalarField::rand(rng);
        let commitment = Self::commit_with_randomness(message, randomness.clone());

        (commitment, randomness)
    }

    pub fn commit_with_randomness(message: P::ScalarField, randomness: P::ScalarField) -> Self {
        let g: P::G1Affine = P::G1Affine::generator();
        let h: P::G1Affine = P::G1Affine::generator();
        let c: P::G1Affine = ((g.clone() * message) + (h.clone() * randomness)).into();

        PedersenCommitment {
            g: g,
            h: h,
            commitment: c,
        }
    }

    pub fn verify(&self, message: P::ScalarField, randomness: P::ScalarField) -> bool {
        let expected_commitment = (self.g.clone() * message) + (self.h.clone() * randomness);

        expected_commitment == self.commitment.into()
    }

    pub fn okamoto_pok_param_gen(&self, rng: &mut StdRng) -> (P:: ScalarField, P::ScalarField, P::G1Affine) {
        let alpha_t: P::ScalarField = P::ScalarField::rand(rng);
        let beta_t: P::ScalarField = P::ScalarField::rand(rng);
        let u_t: P::G1Affine = ((self.g.clone() * alpha_t) + (self.h.clone() * beta_t)).into();

        (alpha_t, beta_t, u_t)
    }

    pub fn okamoto_challenge_gen(rng: &mut StdRng) -> P::ScalarField {

        P::ScalarField::rand(rng)
    }

    pub fn okamoto_pok(&self, message: P::ScalarField, randomness: P::ScalarField, alpha_t: P::ScalarField, beta_t: P::ScalarField, challenge: P::ScalarField) -> (P::ScalarField, P::ScalarField) {
        let alpha_z: P::ScalarField = alpha_t + message * challenge;
        let beta_z: P::ScalarField = beta_t + randomness * challenge;

        (alpha_z, beta_z)
    }

    pub fn okamoto_pok_verify(alpha_z: P::ScalarField, beta_z: P::ScalarField, u_t: P::G1Affine, u: P::G1Affine, challenge: P::ScalarField, g: P::G1Affine, h: P::G1Affine,) -> bool {
        let left_hand_side: P::G1Affine = (g * alpha_z + h * beta_z).into();
        let right_hand_side: P::G1Affine = (u_t + u * challenge).into();

        left_hand_side == right_hand_side
    }

}

#[cfg(test)]
mod test {
    use std::ops::Add;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::{One, UniformRand};

    use crate::our_impl::pedersen_commitments::PedersenCommitment;

    #[test]
    fn correctness() {
        let mut rng = StdRng::from_entropy();
        let message: Fr = Fr::rand(&mut rng);

        let (commitment, randomness) = PedersenCommitment::<Bls12_381>::commit(message, &mut rng);

        assert!(commitment.verify(message, randomness));
        // println!("[PedersenCommitments] Correct commitment verification granted test: successful.");
        let randomness = randomness.add(Fr::one());

        assert_eq!(commitment.verify(message, randomness), false);
        // println!("[PedersenCommitments] Incorrect commitment verification failed test: successful.");

    }

    #[test]
    fn pok() {
        let mut rng = StdRng::from_entropy();
        let message: Fr = Fr::rand(&mut rng);

        let (commitment, randomness) = PedersenCommitment::<Bls12_381>::commit(message, &mut rng);
        let (alpha_t, beta_t, u_t) = commitment.okamoto_pok_param_gen(&mut rng);
        let challenge = PedersenCommitment::<Bls12_381>::okamoto_challenge_gen(&mut rng);
        let (alpha_z, beta_z) = commitment.okamoto_pok(message, randomness, alpha_t, beta_t, challenge);

        assert!(PedersenCommitment::<Bls12_381>::okamoto_pok_verify(alpha_z, beta_z, u_t, commitment.commitment.clone(), challenge, commitment.g.clone(), commitment.h.clone()));
        // println!("[PedersenCommitments] Incorrect commitment okamoto protocol for proof of knowledge: successful.");
    }
}