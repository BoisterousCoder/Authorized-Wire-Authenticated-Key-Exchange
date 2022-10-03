use js_sys::{Uint8Array, ArrayBuffer, Array};
use std::collections::HashMap;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::CryptoKey;
use crate::utils::{js_objectify, fetch_subtle_crypto, Transitable, u8_iter_js_array};

pub struct Ratchet{
    shared_secret:CryptoKey,
    is_encrypting:bool,
    secret_chain:Vec<PayloadHandler>
}
impl Ratchet{
    pub async fn new(shared_secret:CryptoKey, is_encrypting:bool, salt:Vec<u8>) -> Ratchet{
        let mut ratchet = Ratchet{
            is_encrypting,
            shared_secret:shared_secret.clone(),
            secret_chain: vec![]
        };
        ratchet.secret_chain.push(PayloadHandler::new(shared_secret, salt, None).await);
        return ratchet;
    }
    pub async fn process_payload(&mut self, id:usize, payload:Transitable) -> Result<Transitable, String>{
        self.gen_handlers_to(id).await;
        return self.secret_chain[id].proccess_payload(self.is_encrypting, payload).await;
    }
    pub async fn set_new_shared_key(&mut self, start_id:usize, shared_secret:CryptoKey){
        self.gen_handlers_to(start_id-1).await;
        if self.secret_chain[start_id-1].has_created_next() || self.secret_chain.len() > start_id{
            panic!("Note: PayloadHandlers have already been gennerated at or beyond the id {} and a new key set cannot be started", start_id);
        }
        let secret = self.secret_chain[start_id-1].secret.unwrap();
        let salt = self.secret_chain[start_id-1].salt.as_ref().unwrap().clone();
        self.secret_chain.push(PayloadHandler::new(shared_secret, salt, Some(&secret)).await);
    }
    async fn gen_handlers_to(&mut self, id:usize){
        while self.secret_chain.len() <= id {
            let last = self.secret_chain.len()-1;
            let new_handler = self.secret_chain[last].next().await;
            self.secret_chain.push(new_handler);
        }
    }
}

struct PayloadHandler{
    secret:Option<[u8; 32]>,
    aes_key:Option<[u8; 32]>,
    unique_iv:Option<[u8; 12]>,
    salt:Option<Vec<u8>>,
    shared_secret:Option<CryptoKey>
}
impl PayloadHandler{
    pub async fn new(shared_secret:CryptoKey, salt:Vec<u8>, last_secret:Option<&[u8]>) -> PayloadHandler{
        let last_secret_array = match last_secret {
            Some(secret) => u8_iter_js_array(secret.iter()),
            None => Uint8Array::new_with_length(0)
        };
        let salt_array = u8_iter_js_array(salt.iter());
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("HKDF")),
            ("hash".to_string(), JsValue::from("SHA-256")),
            ("salt".to_string(), JsValue::from(salt_array)),
            ("info".to_string(), JsValue::from(last_secret_array))
        ]);
        let key_data_promise = fetch_subtle_crypto().derive_bits_with_object(
            &js_objectify(&algorithm),
            &shared_secret,
            608 as u32
        ).unwrap();
        let key_data_js_value = JsFuture::from(key_data_promise).await.unwrap();
        let key_data_array_buffer:ArrayBuffer = key_data_js_value.dyn_into().unwrap();
        let key_data_array:Uint8Array = js_sys::Uint8Array::new(&key_data_array_buffer);
        let key_data = key_data_array.to_vec();
        let mut secret:[u8; 32] = [0 as u8; 32];
        let mut aes_key:[u8; 32] = [0 as u8; 32];
        let mut unique_iv:[u8; 12] = [0 as u8; 12];
        let mut i = 0;
        for byte in key_data {
            if i < secret.len(){
                secret[i] = byte;
            }else if i < secret.len() + aes_key.len(){
                aes_key[i - secret.len()] = byte;
            }else{
                unique_iv[i - secret.len() - aes_key.len()] = byte;
            }
            i += 1;
        }
        return PayloadHandler{ 
            secret:Some(secret),
            aes_key:Some(aes_key), 
            unique_iv:Some(unique_iv), 
            salt:Some(salt),
            shared_secret:Some(shared_secret)
        }
    }
    pub async fn proccess_payload(&mut self, is_encrypting:bool, payload:Transitable)-> Result<Transitable, String>{
        if self.has_processed_message() {
            return Err("A message has already been proccessed with given id".to_string());
        }
        let iv_array = u8_iter_js_array(self.unique_iv.unwrap().iter());
        let aes_key_array = u8_iter_js_array(self.aes_key.unwrap().iter());
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("AES-GCM")),
            ("iv".to_string(), JsValue::from(iv_array)),
        ]);
        let key_uses = Array::new_with_length(2);
        key_uses.set(0, "encrypt".into());
        key_uses.set(1, "decrypt".into());

        let payload_array = payload.as_bytes();
        let crypto =  fetch_subtle_crypto();
        let js_algoritm = js_objectify(&algorithm);
        let aes_key_promise = crypto.import_key_with_str("raw", &aes_key_array, "AES-GCM", false, &key_uses).unwrap();
        let aes_key_js = JsFuture::from(aes_key_promise).await.unwrap();
        let aes_key:CryptoKey = aes_key_js.dyn_into().unwrap();
        let payload_promise = match is_encrypting {
            true => crypto.encrypt_with_object_and_buffer_source(
                &js_algoritm,
                &aes_key,
                &payload_array
            ).unwrap(),
            false => crypto.decrypt_with_object_and_buffer_source(
                &js_algoritm,
                &aes_key,
                &payload_array
            ).unwrap()
        };
        let payload_js = JsFuture::from(payload_promise).await.unwrap();
        self.empty_msg_keys();
        let payload_vec = Uint8Array::new(&payload_js).to_vec();
        return Ok(Transitable::from_bytes(payload_vec.as_slice()));
    }
    fn empty_msg_keys(&mut self){
        self.aes_key = None;
        self.unique_iv = None;
    }
    pub fn has_created_next(&self) -> bool{
        return !(self.secret.is_some() 
            && self.shared_secret.is_some() 
            && self.salt.is_some());
    }
    fn has_processed_message(&self) -> bool{
        return !(self.aes_key.is_some() && self.unique_iv.is_some());
    }
    pub async fn next(&mut self) -> PayloadHandler {
        if self.has_created_next() {
            panic!("This PayloadHandler has already generated the next member in the chain and can not do so again");
        }
        let handler = PayloadHandler::new(
            self.shared_secret.as_ref().unwrap().clone(), 
            self.salt.as_ref().unwrap().clone(),
            Some(&self.secret.as_ref().unwrap().clone())
        ).await;
        self.secret = None;
        self.shared_secret = None;
        self.salt = None;
        return handler;
    }
}