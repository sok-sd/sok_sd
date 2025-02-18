use ark_std::rand::rngs::StdRng;
use serde_json::{Map, Value};
use crate::common_data::SIGNATURE;

use crate::our_impl::pointcheval_sanders::ps_message::PSMessage;
use crate::our_impl::pointcheval_sanders::ps_private_key::PSPrivateKey;
use crate::our_impl::pointcheval_sanders::ps_public_key::PSPublicKey;
use crate::our_impl::pointcheval_sanders::ps_signature::PSSignature;
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;

pub const NONCE: &str = "nonce";
pub const INDICES: &str = "indices";

pub struct PSInstance {}

impl SdAlgorithm for PSInstance {
    const HEADER_TYP: &'static str = "ps";
}

impl PSInstance {

    fn build_messages(claims: &Map<String, Value>) -> Result<Vec<PSMessage>, String> {
        let claims_bytes = Self::claims_as_bytes(&claims)?;
        let messages: Vec<PSMessage> = claims_bytes.iter().enumerate().map(|(index, claim_bytes)| {
            PSMessage::new_from_bytes(index, claim_bytes.as_slice())
        }).collect();

        Ok(messages)
    }

    fn build_disclosed_messages(disclosed_indices: Vec<usize>, disclosed_claims: &Map<String, Value>) -> Result<Vec<PSMessage>, String> {
        let disclosed_claim_bytes = Self::claims_as_bytes(&disclosed_claims)?;
        let disclosed_messages: Vec<PSMessage> = disclosed_indices.iter().zip(disclosed_claim_bytes).map(|(index, claim_bytes)| {
            PSMessage::new_from_bytes(index.clone(), claim_bytes.as_slice())
        }).collect();

        Ok(disclosed_messages)
    }

    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_private_key: &PSPrivateKey, rng: &mut StdRng) -> Result<(Map<String, Value>, String), String> {

        let mut raw_vc = raw_vc.clone();

        let claims = Self::extract_claims(&raw_vc)?;
        let messages = Self::build_messages(claims)?;

        let signature = match PSSignature::sign(
            issuer_private_key,
            &messages,
            rng,
        ) {
            Ok(signature) => { signature }
            Err(err) => { return Err(format!("Error in producing signature [{}]", err.to_string()).to_string()) }
        };

        Self::serialize_and_insert(&mut raw_vc, SIGNATURE.to_string(), &signature)?;
        let jwt: String = Self::encode_jwt(&raw_vc)?;

        Ok((raw_vc, jwt))
    }


    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &PSPublicKey) -> Result<(), String> {

        let signature: PSSignature = Self::get_and_decode(vc, SIGNATURE.to_string())?;
        let claims = Self::extract_claims(vc)?;
        let messages = Self::build_messages(claims)?;

        match PSSignature::verify(issuer_public_key, &signature, &messages) {
            Ok(_) => {}
            Err(err) => { return Err(format!("Signature verification failed [{err}]")); }
        };

        Ok(())

    }

    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, issuer_public_key: &PSPublicKey, holder_private_key: &impl AsRef<[u8]>, rng: &mut StdRng) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();
        let claims = &Self::extract_claims(&mut vp)?.clone();
        let disclosed_indices = Self::filter_claims_by_disclosure_and_insert(&mut vp, disclosures)?;
        let signature = Self::get_and_decode(&mut vp, SIGNATURE.to_string())?;
        let messages = Self::build_messages(claims)?;
        let derived_signature: PSSignature = PSSignature::derive(issuer_public_key, &signature, &messages, &disclosed_indices, rng)?;

        Self::serialize_and_insert(&mut vp, SIGNATURE.to_string(), &derived_signature)?;
        Self::serialize_and_insert(&mut vp, INDICES.to_string(), &disclosed_indices)?;

        let jwt = Self::encode_and_sign_jwt(&mut vp, &holder_private_key)?;

        Ok((vp, jwt))

    }

    pub fn verify_vp(signed_jwt: &String, issuer_public_key: &PSPublicKey, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let vp: Map<String, Value> = Self::decode_and_verify_jwt(signed_jwt, &holder_public_key)?;
        let disclosed_indices: Vec<usize> = Self::get_and_decode(&vp, INDICES.to_string())?;
        let signature: PSSignature = Self::get_and_decode(&vp, SIGNATURE.to_string())?;
        let disclosed_claims: &Map<String, Value> = Self::extract_claims(&vp)?;
        let disclosed_messages: Vec<PSMessage> = Self::build_disclosed_messages(disclosed_indices, disclosed_claims)?;

        PSSignature::verify(issuer_public_key, &signature, &disclosed_messages)?;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use serde_json::{Map, Value};

    use crate::common_data::{CommonData, VC};
    use crate::our_impl::pointcheval_sanders::ps_signature::PSSignature;
    use crate::sd_algorithms::sd_algorithm::SdAlgorithm;
    use crate::sd_algorithms::signatures::ps::PSInstance;

    #[test]
    fn test_vc() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[PS] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[PS] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let raw_vc = &mut raw_vc;
        let claims = PSInstance::extract_claims(raw_vc)?;

        let mut rng = StdRng::from_entropy();
        let (issuer_sk, issuer_pk) = PSSignature::keygen(claims.len(), &mut rng)?;
        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;

        let (vc, _vc_jwt) = match PSInstance::issue_vc(raw_vc, &issuer_sk, &mut rng) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[PS] Failed to issue vc [{err}]."))}
        };

        match PSInstance::verify_vc(&vc, &issuer_pk) {
            Ok(_) => { println!("[PS] Successfully verified vc.")}
            Err(err) => { return Err(format!("[PS] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();

        let (_vp, vp_jwt) = match PSInstance::issue_vp(&vc, &disclosures, &issuer_pk, &holder_private_key, &mut rng) {
            Ok(vp) => { vp }
            Err(err) => { return Err(format!("[PS] Failed to issue vp: [{err}].")) }
        };

        match PSInstance::verify_vp(&vp_jwt, &issuer_pk, &holder_public_key) {
            Ok(_) => { println!("[PS] Successfully verified vp.")}
            Err(err) => { return Err(format!("[PS] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}