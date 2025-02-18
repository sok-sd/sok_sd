use josekit::jws::{ES256, JwsVerifier};
use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use rs_merkle::algorithms::Sha256;
use serde_json::{Map, Value};
use crate::sd_algorithms::sd_algorithm::SdAlgorithm;

const ROOT: &str = "root";
const MERKLE_PROOF: &str = "merkle_proof";
const LEN: &str = "leaves_len";
const ROOT_SIGNATURE: &str = "root_sig";
const DISCLOSED_INDICES: &str = "disclosed_indices";
const HASH_LEN: usize = 32;

pub struct MerkleTreeInstance {}

impl SdAlgorithm for MerkleTreeInstance {
    const HEADER_TYP: &'static str = "merkle-trees";
}
impl MerkleTreeInstance {

    fn map_key_value_to_sha256(key: String, value: String) -> [u8; HASH_LEN] {
        let mut result = key.clone();
        result.push(':');
        result.push_str(value.as_str());

        Sha256::hash(result.as_bytes())
    }

    fn convert_claim_to_leaves(claims: &Map<String, Value>) -> Vec<[u8;HASH_LEN]> {
        let leaves: Vec<[u8; HASH_LEN]> = claims.iter().filter_map(|(key, value)| {
            if let Value::String(val) = value {
                Some(Self::map_key_value_to_sha256(key.clone(), val.clone()))
            } else {
                None
            }
        }).collect();
        leaves
    }

    fn verify_root_signature(map: &Map<String, Value>, issuer_public_key: &impl AsRef<[u8]>) -> Result<Vec<u8>, String> {
        let serialized_merkle_root: [u8; HASH_LEN] = Self::get_and_decode(map, ROOT.to_string())?;
        let root_signature: Vec<u8> = Self::get_and_decode(map, ROOT_SIGNATURE.to_string())?;

        let verifier = match ES256.verifier_from_pem(issuer_public_key) {
            Ok(verifier) => { verifier }
            Err(err) => { return Err(format!("Could not create verifier from pem: [{err}]")); }
        };

        match verifier.verify(&serialized_merkle_root, root_signature.as_slice()) {
            Ok(_) => { Ok(serialized_merkle_root.to_vec()) }
            Err(err) => { Err(format!("Failed verification of merkle root signature: [{err}]")) }
        }
    }

    fn derive_root_from_leaves(leaves: &Vec<[u8; HASH_LEN]>) -> Result<[u8; HASH_LEN], String> {
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        match merkle_tree.root() {
            None => { return Err("Could not retrieve root of Merkle Trees".to_string()) }
            Some(root) => { Ok(root) }
        }
    }

    pub fn issue_vc(raw_vc: &Map<String, Value>, issuer_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vc = raw_vc.clone();

        let claims: &Map<String, Value> = Self::extract_claims(&vc)?;
        let leaves = Self::convert_claim_to_leaves(claims);

        let merkle_root: [u8; HASH_LEN] = Self::derive_root_from_leaves(&leaves)?;

        Self::serialize_and_insert(&mut vc, ROOT.to_string(), &merkle_root)?;
        Self::serialize_and_insert(&mut vc, LEN.to_string(), &leaves.len())?;

        let signer = match ES256.signer_from_pem(issuer_private_key) {
            Ok(signer) => { signer }
            Err(err) => { return Err(format!("Failed to create signer: [{err}]"));}
        };

        let signature: Vec<u8> = match signer.sign(merkle_root.as_slice()) {
            Ok(signature) => { signature }
            Err(err) => { return Err(format!("Failed to sign message: [{err}]")) }
        };

        Self::serialize_and_insert(&mut vc, ROOT_SIGNATURE.to_string(), &signature)?;
        let json_credential = Self::encode_jwt(&vc)?;

        Ok((vc, json_credential))
    }

    pub fn verify_vc(vc: &Map<String, Value>, issuer_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let claims: &Map<String, Value> = Self::extract_claims(vc)?;
        let leaves: Vec<[u8; HASH_LEN]> = Self::convert_claim_to_leaves(claims);
        let computed_root: [u8; HASH_LEN] = Self::derive_root_from_leaves(&leaves)?;
        let vc_root: [u8; HASH_LEN] = Self::derive_root_from_leaves(&leaves)?;

        if computed_root != vc_root {
            return Err(format!("Root in vc and root computed do not match {:?} - {:?}", computed_root, vc_root))
        }

        Self::verify_root_signature(&vc, issuer_public_key)?;

        Ok(())
    }

    pub fn issue_vp(vc: &Map<String, Value>, disclosures: &Vec<String>, holder_private_key: &impl AsRef<[u8]>) -> Result<(Map<String, Value>, String), String> {

        let mut vp: Map<String, Value> = vc.clone();
        let leaves: Vec<[u8; HASH_LEN]> = Self::convert_claim_to_leaves(Self::extract_claims(&mut vp)?);
        let merkle_tree: MerkleTree<Sha256> = MerkleTree::from_leaves(leaves.as_slice());
        let disclosed_indices = Self::filter_claims_by_disclosure_and_insert(&mut vp, disclosures)?;
        let merkle_proof: MerkleProof<Sha256> = merkle_tree.proof(&disclosed_indices);
        let proof_bytes = merkle_proof.to_bytes();

        Self::serialize_and_insert(&mut vp, MERKLE_PROOF.to_string(), &proof_bytes)?;
        Self::serialize_and_insert(&mut vp, DISCLOSED_INDICES.to_string(), &disclosed_indices)?;
        let jwt = Self::encode_and_sign_jwt(&mut vp, &holder_private_key)?;

        Ok((vp, jwt))
    }

    pub fn verify_vp(jwt: &String, issuer_public_key: &impl AsRef<[u8]>, holder_public_key: &impl AsRef<[u8]>) -> Result<(), String> {

        let vp = Self::decode_and_verify_jwt(&jwt, &holder_public_key)?;
        let disclosed_claims = Self::extract_claims(&vp)?;

        let proof_bytes: Vec<u8> = Self::get_and_decode(&vp, MERKLE_PROOF.to_string())?;
        let proof: MerkleProof<Sha256> = match MerkleProof::from_bytes(proof_bytes.as_slice()) {
            Ok(proof) => { proof }
            Err(err) => { return Err(format!("Could not decode proof from bytes: [{err}]")) }
        };

        let disclosed_indices: Vec<usize> = Self::get_and_decode(&vp, DISCLOSED_INDICES.to_string())?;
        let leaves_len: usize = Self::get_and_decode(&vp, LEN.to_string())?;
        let disclosed_leaves = Self::convert_claim_to_leaves(&disclosed_claims);
        let merkle_root_vec: Vec<u8> = Self::verify_root_signature(&vp, issuer_public_key)?;
        let mut merkle_root: [u8; HASH_LEN] = [0u8; HASH_LEN];

        if merkle_root_vec.len() != HASH_LEN {
            return Err(format!("Merkle root array length is not {HASH_LEN}"));
        } else {
            for (i, byte) in merkle_root_vec.iter().enumerate() {
                merkle_root[i] = byte.clone();
            }
        }

        if proof.verify(merkle_root, disclosed_indices.as_slice(), disclosed_leaves.as_slice(), leaves_len) {
            Ok(())
        } else {
            Err("Proof verification failed.".to_string())
        }

    }
}


#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};

    use crate::common_data::{CommonData, VC};

    use super::*;

    #[test]
    fn merkle() -> Result<(), String> {

        let value_raw_vc: Value = match serde_json::from_str::<Value>(VC) {
            Ok(value_vc) => { value_vc }
            Err(err) => { return Err(format!("[Merkle] Failed to parse Raw Verifiable Credential from string. [{err}]")); }
        };

        let mut raw_vc: Map<String, Value> = match serde_json::from_value::<Map<String, Value>>(value_raw_vc) {
            Ok(vc) => { vc }
            Err(err) => { return Err(format!("[Merkle] Failed to parse Raw Verifiable Credential from Value. [{err}]")); }
        };

        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = CommonData::issuer_keys()?;

        let (vc, _jwt) = match MerkleTreeInstance::issue_vc(&mut raw_vc, &issuer_private_key) {
            Ok(result) => { result }
            Err(err) => { return Err(format!("[Merkle] Failed to issue vc [{err}]."))}
        };

        match MerkleTreeInstance::verify_vc(&vc, &issuer_public_key) {
            Ok(_) => { println!("[Merkle] Successfully verified vc.")}
            Err(err) => { return Err(format!("[Merkle] Failed to verify vc [{err}]."))}
        };

        let disclosures = vec!["name", "birthdate"].iter().map(|x| x.to_string()).collect();
        let (_vp, vp_jwt) = match MerkleTreeInstance::issue_vp(&vc, &disclosures, &holder_private_key) {
            Ok(result) => { result }
            Err(err) => { return Err(format!("[Merkle] Failed to issue verifiable presentation: [{err}].")) }
        };

        match MerkleTreeInstance::verify_vp(&vp_jwt, &issuer_public_key, &holder_public_key) {
            Ok(_) => { println!("[Merkle] Successfully verified vp.")}
            Err(err) => { return Err(format!("[Merkle] Failed to verify vp [{err}].")) }
        };

        Ok(())
    }
}