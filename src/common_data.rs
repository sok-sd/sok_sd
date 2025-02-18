use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jwk::{Jwk, KeyPair};

pub const ISSUER_PRIVATE_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/issuer_private.pem");
pub const HOLDER_PRIVATE_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/holder_private.pem");
pub const ISSUER_PUBLIC_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/issuer_public.pem");
pub const HOLDER_PUBLIC_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/holder_public.pem");
pub const HEADER: &str = "header";
pub const SIGNATURE: &str = "signature";
pub const CLAIMS: &str = "credentialSubject";

pub const VC: &str = r#"{
    "@context": [ "https://www.w3.org/ns/credentials/v2"],
    "type": [ "VerifiableCredential" ],
    "issuer": "https://vc.example/scientists/committee",
    "credentialSubject": {
        "name": "Albert Einstein",
        "birthdate": "1879-03-14",
        "field": "Theoretical Physics",
        "nationality": "German-Swiss-American",
        "school": "Polytechnic Institute of Zurich",
        "university": "University of Zurich",
        "nobel award": "Nobel Prize in Physics (1921)",
        "time award": "Time Person of the Century (1999)",
        "important work": "The Theory of Special Relativity (1905)",
        "other important work": "The Theory of General Relativity (1916)",
        "time award": "Time Person of the Century (1999)",
        "first quote": "Imagination is more important than knowledge.",
        "second quote": "I am enough of a scientist to know that whatever is not measurable is not real.",
        "image": "https://example.com/einstein.jpg"
    }
}"#;


pub struct CommonData;

impl CommonData {


    // Generate a private key for ES256
    //                  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private.pem
    // Generate a public key from the private key.
    //                  openssl pkey -in private.pem -pubout -out public.pem
    pub(crate) fn holder_keys() -> Result<(Vec<u8>, Vec<u8>), String> {
        let pk = match std::fs::read(HOLDER_PUBLIC_KEY) {
            Ok(public_key) => { public_key }
            Err(err) => { return Err(format!("Failed to read public key from {HOLDER_PUBLIC_KEY}. [{err}]")); }
        };
        let sk = match std::fs::read(HOLDER_PRIVATE_KEY) {
            Ok(private_key) => { private_key }
            Err(err) => { return Err(format!("Failed to read private key from {HOLDER_PRIVATE_KEY}. [{err}]")); }
        };

        Ok((pk, sk))
    }

    pub(crate) fn issuer_keys() -> Result<(Vec<u8>, Vec<u8>), String> {


        let jwk: Jwk = match Jwk::generate_ec_key(EcCurve::P256) {
            Ok(jwk) => { jwk }
            Err(err) => { return Err(format!("Error in generating Jwk: [{err}]")) }
        };


        let key_pair: EcKeyPair = EcKeyPair::from_jwk(&jwk).unwrap();

        let pk: Vec<u8> = key_pair.to_pem_public_key();
        let sk: Vec<u8> = key_pair.to_pem_private_key();

        /* let pk = match std::fs::read(ISSUER_PUBLIC_KEY) {
            Ok(public_key) => { public_key }
            Err(err) => { return Err(format!("Failed to read public key from {ISSUER_PUBLIC_KEY}. [{err}]")); }
        };
        let sk = match std::fs::read(ISSUER_PRIVATE_KEY) {
            Ok(private_key) => { private_key }
            Err(err) => { return Err(format!("Failed to read private key from {ISSUER_PRIVATE_KEY}. [{err}]")); }
        };*/

        Ok((pk, sk))
    }

}