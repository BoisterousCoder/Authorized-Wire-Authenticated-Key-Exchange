use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::{Uint8Array, Object, Array};
use std::collections::HashMap;
use serde_json::Value;
use web_sys::console;

use crate::ratchet::Ratchet;
use crate::utils::*;

const DID_KEY_PREFIX:&str = "did:key:";
const DID_KEY_PREFIX_NIST256:&str = "zDn";

#[wasm_bindgen]
pub struct Awake{
    handshake_algorithm: HashMap<String, JsValue>,
    crypto: SubtleCrypto,
    handshake_public: Option<CryptoKey>,
    handshake_private: Option<CryptoKey>,
    ratchet: Option<Ratchet>
}

#[wasm_bindgen]
impl Awake{
    pub async fn new() -> Awake{
        let crypto = fetch_subtle_crypto();
        let handshake_algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("ECDH")),
            ("namedCurve".to_string(), JsValue::from_str("P-256")),
        ]);
        let (public_key, private_key) = gen_key_pair(&crypto, &handshake_algorithm).await;
        return Awake{
            handshake_public:Some(public_key),
            handshake_private:Some(private_key),
            handshake_algorithm,
            ratchet: None,
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
        let mut caps:Vec<UcanCapability> = vec![];
        for cap in capabilities.to_vec() {
            caps.push(object_to_capability(&cap.dyn_into().unwrap()));
        }
        let cap_json =serde_json::to_string(&caps).unwrap();
        return Transitable::from_readable(&format!("{{
        \"awv\": \"0.1.0\",
        \"type\": \"awake/init\",
        \"did\": \"{}\",
        \"caps\": {}
        }}", issuer_did, cap_json));
    }
    //Part 3.3 from spec
    pub async fn handshake_reponse(&mut self, handshake_request:Transitable) -> Transitable{
        //get other agent's public key
        let ucan_request:Value = serde_json::from_str(&handshake_request.as_readable()).unwrap();
        let other_agent_did_key = &ucan_request["did"].as_str().unwrap();

        //start double ratchet
        self.initiate_ratchet(other_agent_did_key).await;

        //

        return Transitable::from_readable(other_agent_did_key);
    }
    //Part 1.5.1.1 from spec
    async fn initiate_ratchet(&mut self, other_agent_did_key:&str){
        //get your private key
        let (_, self_key):(CryptoKey, CryptoKey) = gen_key_pair(&self.crypto, &self.handshake_algorithm).await;
        if !(self.handshake_private.is_some() && self.handshake_public.is_some()){
            panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections.")
        }
        
        //get other agent's public key
        let other_agent_key = did_key_to_crypto_key(&self.crypto, DID_KEY_PREFIX_NIST256, other_agent_did_key, &self.handshake_algorithm).await;
        //get Ecdh shared secret
        let shared_secret = diffie_helman(&self.crypto, self_key, other_agent_key).await;
        //make ratchet
        self.ratchet = Some(Ratchet::new(
            shared_secret,
            false, 
            other_agent_did_key.as_bytes().to_vec()
        ).await);
        //Wipe handshake keys for security
        //self.handshake_private = None;
        //self.handshake_public = None;
    }
}
async fn crypto_key_to_did_key(crypto:&SubtleCrypto, curve_prefix:&str, crypto_key:&CryptoKey) -> String{
    let key_data_promise = crypto.export_key("raw", crypto_key).unwrap();
    let key_data = Uint8Array::new(&JsFuture::from(key_data_promise).await.unwrap());
    let did_key_data = bs58::encode(key_data.to_vec()).into_string();
    return format!("{}{}{}", DID_KEY_PREFIX, curve_prefix, did_key_data)
}
async fn did_key_to_crypto_key(crypto:&SubtleCrypto, curve_prefix:&str, did_key:&str, algorithm:&HashMap<String, JsValue>) -> CryptoKey{
    let key_first_prefix_length = String::from(DID_KEY_PREFIX).len();
    let key_prefix_length = String::from(curve_prefix).len();
    if &did_key[key_first_prefix_length..key_prefix_length-1] == curve_prefix {
        let key_byte_str = &did_key[key_prefix_length..];
        let key_byte_vec = bs58::decode(key_byte_str).into_vec().unwrap();
        let key_byte_array = Uint8Array::new_with_length(key_byte_vec.len() as u32);
        let mut i = 0;
        while i < key_byte_vec.len(){
            key_byte_array.set_index(i as u32, key_byte_vec[i]);
            i += 1;
        }

        let key_promise = crypto.import_key_with_object("raw", &key_byte_array, &js_objectify(algorithm), false, &JsValue::from_str("deriveKey")).unwrap();
        let key_future = JsFuture::from(key_promise);
        return key_future.await.unwrap().dyn_into().unwrap();
    }else{
        panic!("DID key is not Nist-256 or is improperly formatted")
    }
}