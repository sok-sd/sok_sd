use ark_std::rand::{SeedableRng};
use ark_std::rand::rngs::StdRng;
use serde_json::{Map, Value};

use crate::common_data::{CommonData};
use crate::adapters::adapter::Adapter;
use crate::our_impl::pointcheval_sanders::ps_private_key::PSPrivateKey;
use crate::our_impl::pointcheval_sanders::ps_public_key::PSPublicKey;
use crate::our_impl::pointcheval_sanders::ps_signature::PSSignature;
use crate::sd_algorithms::signatures::ps::PSInstance;

pub struct PSAdapter {
    holder_public_key: Vec<u8>,
    holder_private_key: Vec<u8>,
    issuer_public_key: PSPublicKey,
    issuer_private_key: PSPrivateKey,
    rng: StdRng,
}

impl Adapter for PSAdapter {
    fn sd_algorithm(&self) -> String {
        String::from("PS")
    }

    fn new(claims_len: usize) -> Result<Self, String> {

        let mut rng = StdRng::from_entropy();
        let (issuer_sk, issuer_pk) = PSSignature::keygen(claims_len, &mut rng)?;

        let (holder_public_key, holder_private_key) = CommonData::holder_keys()?;
        let (issuer_public_key, issuer_private_key) = (issuer_pk, issuer_sk);

        Ok(PSAdapter {
            holder_public_key,
            holder_private_key,
            issuer_public_key,
            issuer_private_key,
            rng
        })
    }

    fn issue_vc(&self, raw_vc: &Map<String, Value>) -> Result<(Map<String, Value>, String), String> {
        let mut clone = self.rng.clone();

        PSInstance::issue_vc(raw_vc, &self.issuer_private_key, &mut clone)
    }

    fn verify_vc(&self, vc: &Map<String, Value>) -> Result<(), String> {
        PSInstance::verify_vc(vc, &self.issuer_public_key)
    }

    fn issue_vp(&self, vc: &Map<String, Value>, disclosures: &Vec<String>) -> Result<(Map<String, Value>, String), String> {
        let mut clone = self.rng.clone();
        PSInstance::issue_vp(vc, disclosures, &self.issuer_public_key, &self.holder_private_key, &mut clone)
    }

    fn verify_vp(&self, vp_jwt: &String) -> Result<(), String> {
        PSInstance::verify_vp(vp_jwt, &self.issuer_public_key, &self.holder_public_key)
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