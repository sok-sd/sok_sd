use josekit::jws::alg::ecdsa::{EcdsaJwsSigner, EcdsaJwsVerifier};
use josekit::jws::ES256;
use serde_json::{Map, Value};
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;

pub struct MonoclaimCredentialsInstance {}

impl SdAlgorithm for MonoclaimCredentialsInstance {
    const HEADER_TYP: &'static str = "monoclaim";
}

impl MonoclaimCredentialsInstance {

    fn sign_claims(claims: &Map<String, Value>, private_key: &impl AsRef<[u8]>) -> Result<Map<String, Value>, String> {
        fn sign_claim(key: String, value: String, signer: &EcdsaJwsSigner) -> Result<String, String> {
            let mut message: String = String::new();
            message.push_str(key.as_str());
            message.push('=');
            message.push_str(value.as_str());
            let signature: Vec<u8> = match signer.sign(message.as_ref()) {
                Ok(signature) => { signature }
                Err(err) => { return Err(format!("Failed to sign message: [{err}]")) }
            };

            Ok(multibase::Base::Base64Url.encode(signature))
        }

        let mut signature: String;
        let mut signed_claims: Map<String, Value> = Map::new();
        let signer = match ES256.signer_from_pem(private_key) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Failed to create signer: [{err}]"));}
        };

        for (key, value) in claims {
            if let Value::String(val) = value {
                signature = sign_claim(key.clone(), val.clone(), &signer)?;
                signed_claims.insert(key.clone(), Value::Array(vec![value.clone(), Value::String(signature)]));
            }
        }

        Ok(signed_claims)
    }


    fn verify_claims(claims: &Map<String, Value>, public_key: &impl AsRef<[u8]>) -> Result<(), String> {
        fn verify_claim(key: String, value: String, signature: String, verifier: &EcdsaJwsVerifier) ->  Result<(), String> {
            let mut message: String = String::new();
            message.push_str(key.as_str());
            message.push('=');
            message.push_str(value.as_str());

            let signature = match multibase::Base::Base64Url.decode(signature) {
                Ok(signature) => { signature }
                Err(err) => { return Err(format!("Could not decode signature: [{err}]")) }
            };

            let bytes = message.as_bytes();
            match verifier.verify(bytes, &signature) {
                Ok(()) => { Ok(()) }
                Err(err) => { Err(format!("Error in VP verification: [{err}]")) }
            }
        }

        let verifier = match ES256.verifier_from_pem(public_key) {
            Ok(verifier)  => { verifier }
            Err(err) => { return Err(format!("Failed to create verifier: {err}")); }
        };

        for (key, value) in claims {
            if let Value::Array(arr) = value {
                if let (Value::String(val), Value::String(signature)) = (arr[0].clone(), arr[1].clone()) {
                    verify_claim(key.clone(), val, signature, &verifier)?;
                } else {
                    return Err("Verification failed: claim array does not contain two strings".to_string());
                }
            } else {
                return Err("Verification failed: not a value-signature array".to_string())
            }
        }

        Ok(())
    }

    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut raw_vc = raw_vc.clone();

        let claims = Self::extract_claims(&raw_vc)?;
        let signed_claims = Self::sign_claims(claims, &issuer_private_key)?;

        Self::insert_claims(&mut raw_vc, signed_claims)?;
        let jwt: String = Self::encode_jwt(&raw_vc)?;

        Ok((raw_vc, jwt))
    }

    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let claims = Self::extract_claims(&vc)?;
        Self::verify_claims(&claims, &issuer_public_key)

    }

    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, holder_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();
        /*let claims: &Map<String, Value> = Self::extract_claims(&mut vp)?;

        let mut disclosed_claims: Map<String, Value> = Map::new();
        for disclosure in disclosures {
            match claims.get(disclosure) {
                None => { return Err(format!("Disclosure {disclosure} not found in claims")) }
                Some(value) => { disclosed_claims.insert(disclosure.clone(), value.clone()) }
            };
        }

        Self::insert_claims(&mut vp, disclosed_claims)?;*/

        Self::filter_claims_by_disclosure_and_insert(&mut vp, disclosures)?;
        let jwt  = Self::encode_and_sign_jwt(&mut vp, &holder_private_key)?;

        Ok((vp, jwt))

    }

    pub fn verify_vp(jwt: &String, issuer_public_key: &impl AsRef<[u8]>, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let decoded_jwt = Self::decode_and_verify_jwt(jwt, &holder_public_key)?;
        let claims = Self::extract_claims(&decoded_jwt)?;
        Self::verify_claims(&claims, &issuer_public_key)?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::common_data::{CommonData, VC};
    use serde_json::{Map, Value};

    #[test]
    fn monoclaim() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[MC] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[MC] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let raw_vc = &mut raw_vc;
        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = CommonData::issuer_keys()?;

        let (vc, _vc_jwt) = match MonoclaimCredentialsInstance::issue_vc(raw_vc, &issuer_private_key) {
            Ok(json_credential) => { json_credential }
            Err(err) => { return Err(format!("[MC] Failed to issue vc [{err}]."))}
        };

        match MonoclaimCredentialsInstance::verify_vc(&vc,& issuer_public_key) {
            Ok(_) => { println!("[MC] Successfully verified vc.")}
            Err(err) => { return Err(format!("[MC] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();

        let (_vp, vp_jwt) = match MonoclaimCredentialsInstance::issue_vp(&vc, &disclosures, &holder_private_key) {
            Ok(vp) => { vp }
            Err(err) => { return Err(format!("[MC] Failed to issue vp: [{err}].")) }
        };

        match MonoclaimCredentialsInstance::verify_vp(&vp_jwt, &issuer_public_key, &holder_public_key) {
            Ok(_) => { println!("[MC] Successfully verified vp.")}
            Err(err) => { return Err(format!("[MC] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}