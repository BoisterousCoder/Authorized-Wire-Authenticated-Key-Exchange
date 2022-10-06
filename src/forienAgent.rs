use web_sys::{CryptoKey};

use wasm_bindgen_futures::JsFuture;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use std::collections::HashMap;
use web_sys::SubtleCrypto;
use js_sys::Uint8Array;

use crate::ratchet::Ratchet;
use crate::transitable::Transitable;
use crate::utils::{diffie_helman, js_objectify, fetch_subtle_crypto};

const DID_KEY_PREFIX:&str = "did:key:";
const DID_KEY_PREFIX_NIST256:&str = "zDn";

pub struct ForienAgent{
    pub did:String,
    next_send_id:usize,
    send_ratchet:Ratchet,
    recieve_ratchet:Ratchet
}
impl ForienAgent{
    pub async fn new(private_key:&CryptoKey, forien_did:&str, salt:Vec<u8>) -> ForienAgent{
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("ECDH")),
            ("namedCurve".to_string(), JsValue::from_str("P-256")),
        ]);
        let crypto = fetch_subtle_crypto();
        let forien_key = did_key_to_crypto_key(
            &crypto, DID_KEY_PREFIX_NIST256, 
            forien_did, 
            &algorithm
        ).await;
        let shared_secret = diffie_helman(&crypto, private_key, &forien_key).await;
        return ForienAgent{
            next_send_id: 0,
            did: forien_did.to_string(),
            send_ratchet: Ratchet::new(shared_secret.clone(), true, salt.clone()).await,
            recieve_ratchet: Ratchet::new(shared_secret, false, salt).await
        }
    }
    pub async fn set_new_shared_key(&mut self, id:usize, private_key:CryptoKey, forien_did:&str){
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("ECDH")),
            ("namedCurve".to_string(), JsValue::from_str("P-256")),
        ]);
        let crypto = fetch_subtle_crypto();
        let forien_key = did_key_to_crypto_key(
            &crypto, 
            DID_KEY_PREFIX_NIST256, 
            forien_did, 
            &algorithm
        ).await;
        self.did = forien_did.to_string();
        let shared_secret = diffie_helman(&crypto, &private_key, &forien_key).await;

        self.send_ratchet.set_new_shared_key(id, shared_secret.clone());
        self.recieve_ratchet.set_new_shared_key(id, shared_secret);
    }
    pub async fn encrypt_for(&mut self, payload:Transitable) -> (usize, Transitable){
        let future = self.send_ratchet.process_payload(self.next_send_id, payload);
        self.next_send_id += 1;
        return (self.next_send_id-1, future.await.unwrap());
    }
    pub async fn decrypt_for(&mut self, id:usize, payload:Transitable) -> Transitable{
        return self.recieve_ratchet.process_payload(id, payload).await.unwrap();
    }
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