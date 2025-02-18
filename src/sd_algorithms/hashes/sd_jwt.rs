use crate::common_data::{CLAIMS, SIGNATURE};
use rand::Rng;
use serde_json::{Map, Value};
use digest::Digest;
use sha2::Sha256;
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;

const SALT_DIMENSION: usize = 16;   // 16 u8 = 16 * 8 = 128 bits
const HASHES: &str = "hashes";
const SVC: &str = "svc";

pub struct SdJwtInstance {}

impl SdAlgorithm for SdJwtInstance {
    const HEADER_TYP: &'static str = "sd-jwt";
}
impl SdJwtInstance {

    fn generate_random_salt() -> String {
        let mut bytes = vec![0; SALT_DIMENSION];
        let mut rng = rand::thread_rng();

        rng.fill(&mut bytes[..]);
        multibase::Base::Base64Url.encode(bytes)
    }

    fn hash_from_value_and_salt(key: &String, value: &String, salt: &String) -> String {
        let mut hasher = Sha256::new();
        let mut hasher_input = key.clone();

        hasher_input.push_str(value.as_str());
        hasher_input.push_str(salt.as_str());
        hasher.update(hasher_input);

        let encoded_result = multibase::Base::Base64Url.encode(hasher.finalize());
        encoded_result
    }

    fn verify_salt_value_container(salt_value_container: &Map<String, Value>, hashes: Vec<String>) -> Result<(), String> {
        for (field, array_value) in salt_value_container {

            if let Value::Array(array) = array_value {
                let salt = match array.get(0) {
                    None => { return Err("Salt not found in salt value container.".to_string()) }
                    Some(key) => { key }
                };
                let value = match array.get(1) {
                    None => { return Err("Value not found in salt value container.".to_string()) }
                    Some(value) => { value }
                };

                match (salt, value) {
                    (Value::String(salt), Value::String(value)) => {


                        let hash = Self::hash_from_value_and_salt(field, value, salt);
                        if !hashes.contains(&hash) {
                            return Err("Hashes array does not contain hash".to_string());
                        }
                    }
                    _ => { return Err("Either salts or values are not strings.".to_string())}
                }

            } else {
                return Err("Error, array field in salt value container is not an array".to_string());
            }
        }

        Ok(())
    }

    pub fn decode_hashes_value(hashes_value: &Value) -> Result<Vec<String>, String> {

        let mut hashes = vec![];
        if let Value::Array(array) = hashes_value {
            for element in array {
                if let Value::String(hmac) = element {
                    hashes.push(hmac.clone());
                } else {
                    return Err("Non-String element in hashes array".to_string());
                }
            }
        } else {
            return Err("Hash value is not an array.".to_string());
        };

        Ok(hashes)
    }

    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vc = raw_vc.clone();

        let claims: &Map<String, Value> = Self::extract_claims(&vc)?;
        let mut salt_value_container: Map<String, Value> = Map::new();
        let mut hashes: Vec<Value> = vec![];
        let mut hash: String;

        for (field, value) in claims {
            if let Value::String(val) = value { // Only works with strings
                let salt: String = Self::generate_random_salt();

                hash = Self::hash_from_value_and_salt(field, val, &salt);
                hashes.push(Value::String(hash));

                salt_value_container.insert(field.clone(), Value::Array(vec![Value::String(salt), Value::String(val.clone())]));
            }
        }

        let hashes_value: Value = Value::Array(hashes);
        let signature: Vec<u8> = Self::sign_message(hashes_value.to_string().as_bytes(), issuer_private_key)?;

        Self::serialize_and_insert(&mut vc, SIGNATURE.to_string(), &signature)?;
        Self::serialize_and_insert(&mut vc, HASHES.to_string(), &hashes_value)?;
        Self::serialize_and_insert(&mut vc, SVC.to_string(), &salt_value_container)?;

        match vc.remove(CLAIMS) {
            None => { return Err("Claims removed should not be none here.".to_string()) }
            Some(_) => { }
        }

        let jwt = Self::encode_jwt(&vc)?;

        Ok((vc, jwt))
    }

    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let salt_value_container: Map<String, Value> = Self::get_and_decode(vc, SVC.to_string())?;
        let hashes_value: Value = Self::get_and_decode(vc, HASHES.to_string())?;
        let signature: Vec<u8> = Self::get_and_decode(vc, SIGNATURE.to_string())?;
        let hashes: Vec<String> = Self::decode_hashes_value(&hashes_value)?;

        Self::verify_salt_value_container(&salt_value_container, hashes)?;
        Self::verify_message(hashes_value.to_string().as_bytes(), &signature, issuer_public_key)?;

        Ok(())
    }

    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, holder_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();

        let salt_value_container: Map<String, Value> = Self::get_and_decode(&mut vp, SVC.to_string())?;
        let mut new_salt_value_container: Map<String, Value> = Map::new();

        for (field, value) in salt_value_container {
            if disclosures.contains(&field) {
                new_salt_value_container.insert(field, value);
            }
        }

        Self::serialize_and_insert(&mut vp, SVC.to_string(), &new_salt_value_container)?;

        let jwt: String = Self::encode_and_sign_jwt(&mut vp, holder_private_key)?;

        Ok((vp, jwt))
    }

    pub fn verify_vp(jwt: &String, issuer_public_key: &impl AsRef<[u8]>, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let vp = Self::decode_and_verify_jwt(jwt, holder_public_key)?;
        let salt_value_container: Map<String, Value> = Self::get_and_decode(&vp, SVC.to_string())?;
        let hashes_value: Value = Self::get_and_decode(&vp, HASHES.to_string())?;
        let signature: Vec<u8> = Self::get_and_decode(&vp, SIGNATURE.to_string())?;
        let hash: Vec<String> = Self::decode_hashes_value(&hashes_value)?;

        Self::verify_salt_value_container(&salt_value_container, hash)?;
        Self::verify_message(hashes_value.to_string().as_bytes(), &signature, issuer_public_key)?;

        Ok(())
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::common_data::{CommonData, VC};
    use serde_json::{Map, Value};

    #[test]
    fn sd_jwt() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[SD-JWT] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[SD-JWT] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let raw_vc = &mut raw_vc;
        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = CommonData::issuer_keys()?;

        let (vc, _vc_jwt) = match SdJwtInstance::issue_vc(raw_vc, &issuer_private_key) {
            Ok((vc, jwt)) => { (vc, jwt) }
            Err(err) => { return Err(format!("[SD-JWT] Failed to issue vc [{err}]."))}
        };

        match SdJwtInstance::verify_vc(&vc, &issuer_public_key) {
            Ok(_) => { println!("[SD-JWT] Successfully verified vc.")}
            Err(err) => { return Err(format!("[SD-JWT] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();

        let (_vp, vp_jwt) = match SdJwtInstance::issue_vp(&vc, &disclosures, &holder_private_key) {
            Ok(vp_jwt) => { vp_jwt }
            Err(err) => { return Err(format!("[SD-JWT] Failed to issue vp: [{err}].")) }
        };

        match SdJwtInstance::verify_vp(&vp_jwt, &issuer_public_key, &holder_public_key) {
            Ok(_) => { println!("[SD-JWT] Successfully verified vp.")}
            Err(err) => { return Err(format!("[SD-JWT] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}