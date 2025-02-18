use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{Map, Value};
use zkryptium::bbsplus::ciphersuites::{BbsCiphersuite, Bls12381Sha256};
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BBSplus;
use crate::common_data::CommonData;
use crate::adapters::adapter::Adapter;
use crate::sd_algorithms::signatures::bbs_plus::BBSPlusInstance;

pub struct BBSPlusAdapter {
    holder_public_key: Vec<u8>,
    holder_private_key: Vec<u8>,
    issuer_public_key: BBSplusPublicKey,
    issuer_private_key: BBSplusSecretKey,
}

impl Adapter for BBSPlusAdapter {

    fn sd_algorithm(&self) -> String {
        String::from("BBSPlus")
    }

    fn new(_claims_len: usize) -> Result<Self, String> {

        let mut rng = StdRng::from_os_rng();
        let key_material: Vec<u8> = (0..Bls12381Sha256::IKM_LEN).map(|_| rng.random()).collect();

        let issuer_keypair = match KeyPair::<BBSplus<Bls12381Sha256>>::generate(&key_material, None, None) {
            Ok(keypair) => { keypair }
            Err(err) => { return Err(format!("Error in issuing BBS+ keypair [{err}]")) }
        };

        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = (
            issuer_keypair.public_key().clone(),
            issuer_keypair.private_key().clone()
        );

        Ok(BBSPlusAdapter {
            holder_public_key,
            holder_private_key,
            issuer_public_key,
            issuer_private_key,
        })
    }

    fn issue_vc(&self, raw_vc: &Map<String, Value>) -> Result<(Map<String, Value>, String), String> {
        BBSPlusInstance::issue_vc(raw_vc, &self.issuer_public_key, &self.issuer_private_key)
    }

    fn verify_vc(&self, vc: &Map<String, Value>) -> Result<(), String> {
        BBSPlusInstance::verify_vc(vc, &self.issuer_public_key)
    }

    fn issue_vp(&self, vc: &Map<String, Value>, disclosures: &Vec<String>) -> Result<(Map<String, Value>, String), String> {
        BBSPlusInstance::issue_vp(vc, disclosures, &self.issuer_public_key, &self.holder_private_key)
    }

    fn verify_vp(&self, vp_jwt: &String) -> Result<(), String> {
        BBSPlusInstance::verify_vp(vp_jwt, &self.issuer_public_key, &self.holder_public_key)
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