use josekit::jws::{JwsHeader, ES256};
use josekit::jwt;
use josekit::jwt::JwtPayload;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Value};
use crate::common_data::CLAIMS;

pub trait SdAlgorithm {

    const HEADER_TYP: &'static str;

    fn extract_claims(map: &Map<String, Value>) -> Result<&Map<String, Value>, String> {
        let claims_value = match map.get(CLAIMS) {
            None => { return Err("Map does not contain the credentialSubject field. No claims can be disclosed.".to_string()); }
            Some(claims) => { claims }
        };

        match claims_value {
            Value::Object(claims) => { Ok(&claims) }
            _ => { Err("CredentialSubject field is not an object".to_string()) }
        }
    }

    fn insert_claims(map: &mut Map<String, Value>, claims: Map<String, Value>) -> Result<(), String> {
        match map.insert(CLAIMS.to_string(), Value::Object(claims)) {
            None => { Err("Claim set not present. This should never happen.".to_string()) }
            Some(_) => { Ok(()) }
        }
    }

    fn filter_claims_by_disclosure_and_insert(map: &mut Map<String, Value>, disclosures: &Vec<String>) -> Result<Vec<usize>, String> {

        let claims = Self::extract_claims(map)?;
        let mut disclosed_claims: Map<String, Value> = Map::new();
        let mut disclosed_indices: Vec<usize> = vec![];

        'disclosure_loop: for disclosure in disclosures {
            for (i, (key, value)) in claims.iter().enumerate() {
                if *key == *disclosure {
                    disclosed_claims.insert(key.clone(), value.clone());
                    disclosed_indices.push(i);
                    continue 'disclosure_loop;
                }
            }
        }

        Self::insert_claims(map, disclosed_claims)?;

        Ok(disclosed_indices)
    }

    fn claims_as_bytes(claims: &Map<String, Value>) -> Result<Vec<Vec<u8>>, String> {
        let mut messages: Vec<String> = vec![];
        let mut message;

        for (key, value) in claims {
            if let Value::String(val) = value { // Only works with strings
                message = key.clone();
                message.push(':');
                message.push_str(val);
                messages.push(message);
            }
        }

        let byte_messages: Vec<Vec<u8>> = messages.iter().map(|message| {
            message.clone().into_bytes()
        }).collect();

        Ok(byte_messages)
    }

    fn map_to_payload_header(map: &Map<String, Value>) -> Result<(JwsHeader, JwtPayload), String> {
        let mut header: JwsHeader = JwsHeader::new();
        header.set_algorithm(Self::HEADER_TYP);

        let payload: JwtPayload = match JwtPayload::from_map(map.clone()) {
            Ok(payload) => { payload }
            Err(err) => { return Err(format!("Failed to encode payload from map: [{err}]")); }
        };

        Ok((header, payload))
    }

    fn encode_jwt(map: &Map<String, Value>) -> Result<String, String> {

        let (header, payload) = Self::map_to_payload_header(map)?;

        let jwt = match jwt::encode_unsecured(&payload, &header) {
            Ok(jwt) => { jwt }
            Err(err) => { return Err(format!("Failed to encode jwt: [{err}]")); }
        };

        Ok(jwt)
    }

    fn encode_and_sign_jwt(map: &Map<String, Value>, private_key: &impl AsRef<[u8]>) -> Result<String, String> {

        let (header, payload) = Self::map_to_payload_header(map)?;

        let signer = match ES256.signer_from_pem(private_key) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Failed to create signer: [{err}]"));}
        };

        let jwt = match jwt::encode_with_signer(&payload, &header, &signer) {
            Ok(jwt) => { jwt }
            Err(err) => { return Err(format!("Failed to encode and sign jwt: [{err}]")); }
        };

        Ok(jwt)
    }

    fn decode_jwt(jwt: &String) -> Result<Map<String, Value>, String> {
        let (payload, _header) = match jwt::decode_unsecured(&jwt) {
            Ok((vc, header)) => { (vc, header) }
            Err(err) => { return Err(format!("Failed to decode jwt: [{err}]")); }
        };

        Ok(payload.claims_set().clone())
    }

    fn decode_and_verify_jwt(jwt: &String, public_key: &impl AsRef<[u8]>) -> Result<Map<String, Value>, String> {

        let verifier = match ES256.verifier_from_pem(public_key) {
            Ok(verifier) => { verifier }
            Err(err) => { return Err(format!("Failed to create verifier: [{err}]")); }
        };

        let (payload, _header) = match jwt::decode_with_verifier(&jwt, &verifier) {
            Ok(jwt) => { jwt }
            Err(err) => { return Err(format!("Failed to decode and verify jwt: [{err}]")); }
        };

        Ok(payload.claims_set().clone())
    }

    fn sign_message(bytes: &[u8], private_key: &impl AsRef<[u8]>) -> Result<Vec<u8>, String> {
        let signer = match ES256.signer_from_pem(private_key) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Failed to create signer: [{err}]"));}
        };

        match signer.sign(bytes) {
            Ok(signature) => { Ok(signature) }
            Err(_) => { return Err("Failed to sign message".to_string()); }
        }
    }

    fn verify_message(bytes: &[u8], signature: &Vec<u8>, public_key: &impl AsRef<[u8]>) -> Result<(), String> {
        let verifier = match ES256.verifier_from_pem(public_key) {
            Ok(verifier)  => { verifier }
            Err(err) => { return Err(format!("Failed to create verifier: {err}")); }
        };
        match verifier.verify(bytes, &signature) {
            Ok(_) => { Ok(()) }
            Err(err) => { return Err(format!("Error in verification: {}", err.to_string())) }
        }
    }

    fn serialize_and_insert<T>(map: &mut Map<String, Value>, field: String, element: &T) -> Result<(), String>
    where
        T: ?Sized + Serialize,
    {
        let serialized_element = match serde_json::to_string(&element) {
            Ok(serialized_element) => { serialized_element }
            Err(err) => { return Err(format!("Failed to serialize {field}: [{err}]")); }
        };

        map.insert(field.to_string(), Value::String(serialized_element));       // We just ignore if another field was present

        Ok(())
    }

    fn get_and_decode<T>(map: &Map<String, Value>, field: String) -> Result<T, String>
    where
        T: DeserializeOwned,
    {
        let serialized_element: String = match map.get(&field) {
            None => return Err(format!("Failed to retrieve {field} from {:?}", map)),
            Some(value) => match value {
                Value::String(encoded_element) => { encoded_element.clone() }
                _ => { return Err(format!("Encoded {field} in is not a string")) }
            },
        };

        let element: T = match serde_json::from_str::<T>(&serialized_element) {
            Ok(element) => { element }
            Err(err) => { return Err(format!("Could not deserialize {field}: [{err}]")) }
        };

        Ok(element)
    }
}