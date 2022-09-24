use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, SubtleCrypto, CryptoKey};
use js_sys::{Uint8Array, Object, Array};
use std::collections::HashMap;
use serde_json::Value;

use crate::utils::{Transitable, UcanCapability};
use crate::utils::js_objectify;

const DID_KEY_PREFIX:&str = "did:key:";
const DID_KEY_PREFIX_NIST256:&str = "zDn";

#[wasm_bindgen]
pub struct Awake{
    algorithm: HashMap<String, JsValue>,
    curve_prefix: &'static str,
    crypto: Crypto,
    sublte_crypto: SubtleCrypto,
    handshake_public: Option<CryptoKey>,
    handshake_private: Option<CryptoKey>
}

#[wasm_bindgen]
impl Awake{
    pub async fn new() -> Awake{
        let window = web_sys::window().unwrap();
        let crypto = window.crypto().unwrap(); 
        let sublte_crypto = crypto.subtle();
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("ECDH")),
            ("namedCurve".to_string(), JsValue::from_str("P-256")),
        ]);
        let mut state = Awake{
            handshake_public:None,
            handshake_private:None,
            curve_prefix: DID_KEY_PREFIX_NIST256, 
            algorithm,
            crypto,
            sublte_crypto
        };

        let key_pair_promise = state.sublte_crypto.generate_key_with_object(&js_objectify(&state.algorithm), false, &JsValue::from_str("derive")).unwrap();
        let key_pair_future = JsFuture::from(key_pair_promise);
        let key_pair_object:Object = key_pair_future.await.unwrap().dyn_into().unwrap();
        let (public_key, private_key) = object_to_keypair(&key_pair_object);
        state.handshake_public = Some(public_key);
        state.handshake_private = Some(private_key);
        return state;
    }
    // Part 3.2 from spec
    pub async fn handshake_request(&self, capabilities: Array) -> Transitable {
        //TODO: Add error handling
        let issuer_did:String = match &self.handshake_public {
            None => panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections."),
            Some(public_key) => self.crypto_key_to_did_key(public_key).await
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
    pub async fn handshake(&mut self, handshake_request:Transitable) -> Transitable{
        let self_key:&CryptoKey = match &self.handshake_private {
            None => panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections."),
            Some(private_key) => private_key
        };
        //get other agent's public key
        let ucan_request:Value = serde_json::from_str(&handshake_request.as_readable()).unwrap();
        let other_key_did = &ucan_request["did"].as_str().unwrap();

        let other_key = self.did_key_to_crypto_key(other_key_did).await;

        //Wipe handshake keys for security
        self.handshake_private = None;
        self.handshake_public = None;

        return Transitable::from_readable(other_key_did);
    }

    async fn crypto_key_to_did_key(&self, crypto_key:&CryptoKey) -> String{
        let key_data_promise = self.sublte_crypto.export_key("raw", crypto_key).unwrap();
        let key_data = Uint8Array::new(&JsFuture::from(key_data_promise).await.unwrap());
        let did_key_data = bs58::encode(key_data.to_vec()).into_string();
        return format!("{}{}{}", DID_KEY_PREFIX, self.curve_prefix, did_key_data)
    }
    async fn did_key_to_crypto_key(&self, did_key:&str) -> CryptoKey{
        let key_first_prefix_length = String::from(DID_KEY_PREFIX).len();
        let key_prefix_length = String::from(self.curve_prefix).len();
        if &did_key[key_first_prefix_length..key_prefix_length-1] == self.curve_prefix {
            let key_byte_str = &did_key[key_prefix_length..];
            let key_byte_vec = bs58::decode(key_byte_str).into_vec().unwrap();
            let key_byte_array = Uint8Array::new_with_length(key_byte_vec.len() as u32);
            let mut i = 0;
            while i < key_byte_vec.len(){
                key_byte_array.set_index(i as u32, key_byte_vec[i]);
                i += 1;
            }
    
            let key_promise = self.sublte_crypto.import_key_with_object("raw", &key_byte_array, &js_objectify(&self.algorithm), false, &JsValue::from_str("derive")).unwrap();
            let key_future = JsFuture::from(key_promise);
            return key_future.await.unwrap().dyn_into().unwrap();
        }else{
            panic!("DID key is not Nist-256 or is improperly formatted")
        }
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