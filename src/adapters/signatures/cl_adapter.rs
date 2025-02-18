use serde_json::{Map, Value};
use zkryptium::cl03::ciphersuites::CL1024Sha256;
use zkryptium::cl03::keys::{CL03CommitmentPublicKey, CL03PublicKey, CL03SecretKey};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::CL03;

use crate::common_data::{CommonData};
use crate::adapters::adapter::Adapter;
use crate::sd_algorithms::signatures::cl::CLInstance;

pub struct CLAdapter {
    holder_public_key: Vec<u8>,
    holder_private_key: Vec<u8>,
    issuer_public_key: CL03PublicKey,
    issuer_private_key: CL03SecretKey,
    commitment_pk: CL03CommitmentPublicKey
}

impl Adapter for CLAdapter {
    fn sd_algorithm(&self) -> String {
        String::from("CL")
    }

    fn new(claims_len: usize) -> Result<Self, String> {

        let issuer_keypair = KeyPair::<CL03<CL1024Sha256>>::generate();
        let (issuer_sk, issuer_pk) = (issuer_keypair.private_key(), issuer_keypair.public_key());

        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = (issuer_pk.clone(), issuer_sk.clone());

        // Generation of a Commitment Public Key for the computation of the SPoK
        let commitment_pk = CL03CommitmentPublicKey::generate::<CL1024Sha256>(
            Some(issuer_pk.N.clone()),
            Some(claims_len),
        );

        Ok(CLAdapter {
            holder_public_key,
            holder_private_key,
            issuer_public_key,
            issuer_private_key,
            commitment_pk
        })
    }

    fn issue_vc(&self, raw_vc: &Map<String, Value>) -> Result<(Map<String, Value>, String), String> {
        CLInstance::issue_vc(raw_vc, &self.issuer_public_key, &self.issuer_private_key)
    }

    fn verify_vc(&self, vc: &Map<String, Value>) -> Result<(), String> {
        CLInstance::verify_vc(vc, &self.issuer_public_key)
    }

    fn issue_vp(&self, vc: &Map<String, Value>, disclosures: &Vec<String>) -> Result<(Map<String, Value>, String), String> {
        CLInstance::issue_vp(vc, disclosures, &self.issuer_public_key, &self.commitment_pk, &self.holder_private_key)
    }

    fn verify_vp(&self, vp_jwt: &String) -> Result<(), String> {
        CLInstance::verify_vp(vp_jwt, &self.issuer_public_key, &self.commitment_pk, &self.holder_public_key)
    }

    fn issuer_keypair(&self) -> Result<(String, String), String> {
        let issuer_public_key = match serde_json::to_string(&self.issuer_public_key) {
            Ok(ipk) => {ipk}
            Err(err) => { return Err(format!("Error in serializing issuer public key: [{err}]")) }
        };
        let issuer_private_key = match serde_json::to_string(&self.issuer_private_key) {
            Ok(ipk) => {ipk}
            Err(err) => { return Err(format!("Error in serializing issuer private key: [{err}]")) }
        };

        Ok((issuer_public_key, issuer_private_key))
    }
}