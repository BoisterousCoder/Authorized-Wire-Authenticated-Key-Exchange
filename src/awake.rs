use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, SubtleCrypto, Window, CryptoKey};
use js_sys::{Uint8Array, Object, Array};
use std::collections::HashMap;

use crate::utils::Transitable;
use crate::utils::js_objectify;

const DID_KEY_PREFIX:&str = "did:key:";
const DID_KEY_PREFIX_NIST256:&str = "zDn";

#[wasm_bindgen]
pub struct Awake{
    window:Window,
    crypto: Crypto,
    sublte_crypto: SubtleCrypto,
    handshake_public: CryptoKey,
    handshake_private: CryptoKey
}

#[wasm_bindgen]
impl Awake{
    pub async fn new() -> Awake{
        let window = web_sys::window().unwrap();
        let crypto = window.crypto().unwrap(); 
        let sublte_crypto = crypto.subtle();
        let algorithm = HashMap::from([
            ("name", JsValue::from_str("ECDH")),
            ("namedCurve", JsValue::from_str("P-256")),
        ]);

        let key_pair_promise = sublte_crypto.generate_key_with_object(&js_objectify(algorithm), false, &JsValue::from_str("derive")).unwrap();
        let key_pair_future = JsFuture::from(key_pair_promise);
        let key_pair_object:Object = key_pair_future.await.unwrap().dyn_into().unwrap();
        let (public_key, private_key) = object_to_keypair(&key_pair_object);
        return Awake{
            handshake_public:public_key,
            handshake_private:private_key,
            window,
            crypto,
            sublte_crypto
        };
    }
    pub async fn initiate_handshake(&self) -> Transitable {
        //TODO: Add error handling
        let key_data_promise = self.sublte_crypto.export_key("raw", &self.handshake_public).unwrap();
        let key_data = Uint8Array::new(&JsFuture::from(key_data_promise).await.unwrap());
        let did_key_data = bs58::encode(key_data.to_vec()).into_string();
        return Transitable::from_readable(&format!("{}{}{}", DID_KEY_PREFIX, DID_KEY_PREFIX_NIST256, did_key_data));
        //return self.hand_shake_key_pair.;
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