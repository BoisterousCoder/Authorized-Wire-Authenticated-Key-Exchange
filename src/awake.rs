use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::{Uint8Array, Array};
use std::collections::HashMap;
use serde_json::Value;

use crate::utils::*;
use crate::transitable::Transitable;
use crate::forienAgent::ForienAgent;

const DID_KEY_PREFIX:&str = "did:key:";
const DID_KEY_PREFIX_NIST256:&str = "zDn";

#[wasm_bindgen]
pub struct Awake{
    crypto: SubtleCrypto,
    handshake_public: Option<CryptoKey>,
    handshake_private: Option<CryptoKey>,
    real_public: CryptoKey,
    real_private: CryptoKey,
    potential_partners: Option<Vec<ForienAgent>>,
    real_partner:Option<ForienAgent>
}

#[wasm_bindgen]
impl Awake{
    pub async fn new() -> Awake{
        let crypto = fetch_subtle_crypto();
        let (handshake_public, handshake_private) = gen_key_pair(&crypto).await;
        let (real_public, real_private) = gen_key_pair(&crypto).await;
        return Awake{
            handshake_public:Some(handshake_public),
            handshake_private:Some(handshake_private),
            real_public,
            real_private,
            potential_partners:Some(vec![]),
            real_partner:None,
            crypto
        };
    }
    // Part 3.2 from spec
    pub async fn handshake_request(&self, capabilities: Array) -> Transitable {
        //TODO: Add error handling
        let issuer_did:String = match &self.handshake_public {
            None => panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections."),
            Some(public_key) => crypto_key_to_did_key(&self.crypto, DID_KEY_PREFIX_NIST256, public_key).await
        };
        let cap_json = capabilities_to_value(capabilities);
        let mut payload = Transitable::from_readable(&format!("{{
            \"awv\": \"0.1.0\",
            \"type\": \"awake/handshake_request\",
            \"did\":\"{}\",
            \"caps\": {}
        }}", issuer_did, cap_json));
        payload.sign(&self.crypto, &self.real_private).await;
        return payload;
    }
    //Part 3.3 from spec
    pub async fn handshake_reponse(&mut self, handshake_request:Transitable, capabilities: Array) -> Transitable{
        //error if there haas already been a handshake conducted
        if self.has_conducted_handshake(){
            panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections.")
        }

        //get requestor's public key
        let request_str = match handshake_request.as_readable(){
            Some(x) => x,
            None => panic!("The handshake was not sent sent in plain text")
        };
        let ucan_request:Value = match serde_json::from_str(&request_str){
            Ok(x) => x,
            Err(_) => panic!("The handshake was not sent in the proper json format")
        };
        let forien_did_key = &ucan_request["did"].as_str().unwrap();

        //init agent
        let mut agent = ForienAgent::new(&self.handshake_private.as_ref().unwrap(), forien_did_key, forien_did_key.as_bytes().to_vec()).await;
        let self_did = crypto_key_to_did_key(&self.crypto, DID_KEY_PREFIX_NIST256, &self.real_public).await;
        let cap_json = capabilities_to_value(capabilities);
        let plain_message = Transitable::from_readable(&format!("{{
            \"awv\": \"0.1.0\",
            \"type\": \"awake/handshake_reponse\",
            \"aud\":\"{}\",
            \"iss\": \"{}\",
            \"caps\": {}
        }}", forien_did_key, self_did, cap_json));
        let (_, mut encrypted_message) = agent.encrypt_for(plain_message).await;
        encrypted_message.sign(&self.crypto, &self.real_private).await;
        match &mut self.potential_partners{
            Some(partners) => partners.push(agent),
            None => ()
        }
        return encrypted_message;
    }
    pub fn has_conducted_handshake(&self) -> bool {
        return !(self.handshake_private.is_some() && self.handshake_public.is_some() && self.potential_partners.is_some())
    }
}
async fn crypto_key_to_did_key(crypto:&SubtleCrypto, curve_prefix:&str, crypto_key:&CryptoKey) -> String{
    let key_data_promise = crypto.export_key("raw", crypto_key).unwrap();
    let key_data = Uint8Array::new(&JsFuture::from(key_data_promise).await.unwrap());
    let did_key_data = bs58::encode(key_data.to_vec()).into_string();
    return format!("{}{}{}", DID_KEY_PREFIX, curve_prefix, did_key_data)
}

fn capabilities_to_value(capabilities:Array) -> Value{
    let mut caps:Vec<UcanCapability> = vec![];
    for cap in capabilities.to_vec() {
        caps.push(UcanCapability::from_object(&cap.dyn_into().unwrap()));
    }
    return serde_json::to_value(&caps).unwrap();
}