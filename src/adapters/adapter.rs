use serde_json::{Map, Value};

pub trait Adapter {

    fn sd_algorithm(&self) -> String;
    fn new(claims_len: usize) -> Result<Self, String> where Self: Sized;
    fn issue_vc(&self, raw_vc: &Map<String, Value>) -> Result<(Map<String, Value>, String), String>;
    fn verify_vc(&self, vc: &Map<String, Value>) -> Result<(), String>;
    fn issue_vp(&self, vc: &Map<String, Value>, disclosures: &Vec<String>) -> Result<(Map<String, Value>, String), String>;
    fn verify_vp(&self, vp_jwt: &String) -> Result<(), String>;
    fn issuer_keypair(&self,) -> Result<(String, String), String>;
}
