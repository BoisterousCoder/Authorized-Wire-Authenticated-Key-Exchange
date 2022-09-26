use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::{Uint8Array, Object, Array};
use std::collections::HashMap;
use serde_json::Value;

use crate::ratchet::Ratchet;
use crate::utils::{Transitable, UcanCapability, js_objectify, fetch_subtle_crypto};

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
        let key_pair_promise = crypto.generate_key_with_object(&js_objectify(&handshake_algorithm), false, &JsValue::from_str("derive")).unwrap();
        let key_pair_future = JsFuture::from(key_pair_promise);
        let key_pair_object:Object = key_pair_future.await.unwrap().dyn_into().unwrap();
        let (public_key, private_key) = object_to_keypair(&key_pair_object);
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

        return Transitable::from_readable(other_agent_did_key);
    }
    //Part 1.5.1.1 from spec
    async fn initiate_ratchet(&mut self, other_agent_did_key:&str){
        //get your private key
        let self_key:&CryptoKey = match &self.handshake_private {
            None => panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections."),
            Some(private_key) => private_key
        };
        //get other agent's public key
        let other_agent_key = did_key_to_crypto_key(&self.crypto, DID_KEY_PREFIX_NIST256, other_agent_did_key, &self.handshake_algorithm).await;
        //get Ecdh shared secret
        let shared_secret_algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("ECDH")),
            ("public".to_string(), JsValue::from(other_agent_key))
        ]);
        let shared_secret_params = HashMap::from([
            ("name".to_string(), JsValue::from_str("AES-GCM")),
            ("length".to_string(), JsValue::from(128))
        ]);
        let shared_secret_promise = self.crypto.derive_key_with_object_and_object(
            &js_objectify(&shared_secret_algorithm),
            self_key,
            &js_objectify(&shared_secret_params),
            false,
            &JsValue::from("deriveKey")
        );
        let shared_secret:CryptoKey = JsFuture::from(shared_secret_promise.unwrap()).await.unwrap().dyn_into().unwrap();
        //make ratchet
        self.ratchet = Some(Ratchet::new(
            shared_secret,
            false, 
            other_agent_did_key.as_bytes().to_vec()
        ).await);
        //Wipe handshake keys for security
        self.handshake_private = None;
        self.handshake_public = None;
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

        let key_promise = crypto.import_key_with_object("raw", &key_byte_array, &js_objectify(algorithm), false, &JsValue::from_str("derive")).unwrap();
        let key_future = JsFuture::from(key_promise);
        return key_future.await.unwrap().dyn_into().unwrap();
    }else{
        panic!("DID key is not Nist-256 or is improperly formatted")
    }
}

fn object_to_keypair(obj: &Object) -> (CryptoKey, CryptoKey){
    //TODO: add error handling
    let entries = Object::entries(obj);
    let mut public_key:Option<CryptoKey> = None;
    let mut private_key:Option<CryptoKey> = None;
    for js_entry in entries.to_vec(){
        let entry:Array = js_entry.dyn_into().unwrap();
        let prop = entry.get(0).as_string().unwrap();
        if prop == "publicKey".to_string(){
            public_key = Some(entry.get(1).dyn_into().unwrap());
        }else if prop == "privateKey".to_string(){
            private_key = Some(entry.get(1).dyn_into().unwrap());
        }
    };
    //TODO: add error handling
    return (public_key.unwrap(), private_key.unwrap());
}


fn object_to_capability(obj:&Object) -> UcanCapability{
    //TODO: add error handling
    let entries = Object::entries(obj);
    let mut with:Option<String> = None;
    let mut can:Option<String> = None;
    for js_entry in entries.to_vec(){
        let entry:Array = js_entry.dyn_into().unwrap();
        let prop = entry.get(0).as_string().unwrap();
        if prop == "with".to_string(){
            with = Some(entry.get(1).as_string().unwrap());
        }else if prop == "can".to_string(){
            can = Some(entry.get(1).as_string().unwrap());
        }
    }
    return UcanCapability{
        with:with.unwrap(),
        can:can.unwrap()
    };
}