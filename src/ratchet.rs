use wasm_bindgen::prelude::*;
use js_sys::{Uint8Array, Array};
use std::collections::HashMap;
use std::slice::Iter;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::CryptoKey;
use crate::utils::{js_objectify, fetch_subtle_crypto};

#[wasm_bindgen]
pub struct Ratchet{
    shared_secret:CryptoKey,
    is_encrypting:bool,
    secret_chain:Vec<RatchetElement>
}
impl Ratchet{
    pub async fn new(shared_secret:CryptoKey, is_encrypting:bool, salt:Vec<u8>) -> Ratchet{
        let mut ratchet = Ratchet{
            is_encrypting,
            shared_secret:shared_secret.clone(),
            secret_chain: vec![]
        };
        ratchet.secret_chain.push(RatchetElement::new(shared_secret, salt, 0, None).await);
        return ratchet;
    }
    pub async fn process_payload(&mut self, id:u64, payload:Vec<u8>) -> Result<Vec<u8>, String>{
        while (self.secret_chain.len() as u64) < id {
            let last = self.secret_chain.len()-1;
            let new_ele = self.secret_chain[last].next().await;
            self.secret_chain.push(new_ele);
        }
        return match self.is_encrypting{
            true => self.secret_chain[id as usize].encrypt(payload).await,
            false => self.secret_chain[id as usize].decrypt(payload).await
        }
    }
}

#[wasm_bindgen]
pub struct RatchetElement{
    id:Option<u64>,
    secret:Option<[u8; 32]>,
    aes_key:Option<[u8; 32]>,
    unique_iv:Option<[u8; 12]>,
    salt:Option<Vec<u8>>,
    shared_secret:Option<CryptoKey>
}
impl RatchetElement{
    pub async fn new(shared_secret:CryptoKey, salt:Vec<u8>, id:u64, last_secret:Option<&[u8]>) -> RatchetElement{
        let last_secret_array = match last_secret {
            Some(secret) => u8_iter_js_array(secret.iter()),
            None => Uint8Array::new_with_length(0)
        };
        let salt_array = u8_iter_js_array(salt.iter());
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("HKDF")),
            ("hash".to_string(), JsValue::from("SHA-512")),
            ("salt".to_string(), JsValue::from(salt_array)),
            ("info".to_string(), JsValue::from(last_secret_array))
        ]);
        let key_data_promise = fetch_subtle_crypto().derive_bits_with_object(
            &js_objectify(&algorithm),
            &shared_secret,
            608 as u32
        );
        let key_data_array:Array = JsFuture::from(key_data_promise.unwrap()).await.unwrap().dyn_into().unwrap();
        let key_data:Vec<JsValue> = key_data_array.to_vec();
        let mut secret:[u8; 32] = [0 as u8; 32];
        let mut aes_key:[u8; 32] = [0 as u8; 32];
        let mut unique_iv:[u8; 12] = [0 as u8; 12];
        let mut i = 0;
        for js_byte in key_data {
            let byte = js_byte.as_f64().unwrap() as u8;
            if i < secret.len(){
                secret[i] = byte;
            }else if i < secret.len() + aes_key.len(){
                aes_key[i] = byte;
            }else{
                unique_iv[i] = byte;
            }
            i += 1;
        }
        return RatchetElement{ 
            id:Some(id), 
            secret:Some(secret),
            aes_key:Some(aes_key), 
            unique_iv:Some(unique_iv), 
            salt:Some(salt),
            shared_secret:Some(shared_secret)
        }
    }
    pub async fn encrypt(&mut self, payload:Vec<u8>) -> Result<Vec<u8>, String> {
        if self.has_processed_message() {
            return Err("A message has already been proccessed with given id".to_string());
        }
        let iv_array = u8_iter_js_array(self.unique_iv.unwrap().iter());
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("AES-GCM")),
            ("iv".to_string(), JsValue::from(iv_array)),
        ]);
        let mut payload_copy = payload;
        let payload_promise = fetch_subtle_crypto().encrypt_with_object_and_u8_array(
            &js_objectify(&algorithm),
            self.shared_secret.as_ref().unwrap(),
            &mut payload_copy[..]
        ).unwrap();
        let payload_complete:Uint8Array = JsFuture::from(payload_promise).await.unwrap().dyn_into().unwrap();
        self.empty_msg_keys();
        return Ok(payload_complete.to_vec());
    }
    pub async fn decrypt(&mut self, payload:Vec<u8>) -> Result<Vec<u8>, String> {
        if self.has_processed_message() {
            return Err("A message has already been proccessed with given id".to_string());
        }
        let iv_array = u8_iter_js_array(self.unique_iv.unwrap().iter());
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("AES-GCM")),
            ("iv".to_string(), JsValue::from(iv_array)),
        ]);
        let mut payload_copy = payload;
        let payload_promise = fetch_subtle_crypto().decrypt_with_object_and_u8_array(
            &js_objectify(&algorithm),
            self.shared_secret.as_ref().unwrap(),
            &mut payload_copy[..]
        ).unwrap();
        let payload_complete:Uint8Array = JsFuture::from(payload_promise).await.unwrap().dyn_into().unwrap();
        self.empty_msg_keys();
        return Ok(payload_complete.to_vec());
    }
    fn empty_msg_keys(&mut self){
        self.aes_key = None;
        self.unique_iv = None;
    }
    fn has_created_next(&self) -> bool{
        return !(self.secret.is_some() 
            && self.shared_secret.is_some() 
            && self.salt.is_some() 
            && self.id.is_some());
    }
    fn has_processed_message(&self) -> bool{
        return !(self.aes_key.is_some() && self.unique_iv.is_some());
    }
    pub async fn next(&mut self) -> RatchetElement {
        if self.has_created_next() {
            panic!("This RatchetElement has already generated the next member in the chain and can not do so again");
        }
        let ele = RatchetElement::new(
            self.shared_secret.as_ref().unwrap().clone(), 
            self.salt.as_ref().unwrap().clone(),
            self.id.unwrap() + 1,
            Some(&self.secret.as_ref().unwrap().clone())
        ).await;
        self.secret = None;
        self.shared_secret = None;
        self.salt = None;
        self.id = None;
        return ele;
    }
}
fn u8_iter_js_array(bytes:Iter<u8>) -> Uint8Array{
    let array = Uint8Array::new_with_length(bytes.len() as u32);
    let mut i:u32 = 0;
    for byte in bytes {
        array.set_index(i, byte.clone());
        i += 1;
    }
    return array;
}