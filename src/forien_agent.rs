use web_sys::{CryptoKey};

use wasm_bindgen_futures::JsFuture;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use std::collections::HashMap;
use web_sys::SubtleCrypto;
use js_sys::Uint8Array;

use crate::ratchet::Ratchet;
use crate::transitable::Transitable;
use crate::utils::{diffie_helman, js_objectify, fetch_subtle_crypto, did_key_to_crypto_key, crypto_key_to_did_key};

pub struct ForienAgent{
    pub did:String,
    next_send_id:usize,
    send_ratchet:Ratchet,
    recieve_ratchet:Ratchet
}
impl ForienAgent{
    pub async fn new(private_key:&CryptoKey, forien_did:&str, requestor_public_key:Option<&CryptoKey>) -> ForienAgent{
        let crypto = fetch_subtle_crypto();
        let salt = match requestor_public_key{
            Some(salt_key) => crypto_key_to_did_key(&crypto, salt_key).await.as_bytes().to_vec(),
            None => forien_did.as_bytes().to_vec()
        };
        let forien_key = did_key_to_crypto_key(&crypto, forien_did).await;
        let shared_secret = diffie_helman(&crypto, private_key, &forien_key).await;
        return ForienAgent{
            next_send_id: 0,
            did: forien_did.to_string(),
            send_ratchet: Ratchet::new(shared_secret.clone(), true, salt.clone()).await,
            recieve_ratchet: Ratchet::new(shared_secret, false, salt).await
        }
    }
    pub async fn is_sender_of(&self, payload:&Transitable) -> bool{
        let crypto = fetch_subtle_crypto();
        let key = did_key_to_crypto_key(&crypto, &self.did).await;
        return payload.verify(&crypto, &key).await;
    }
    pub async fn set_new_shared_key(&mut self, id:usize, private_key:CryptoKey, forien_did:&str){
        let crypto = fetch_subtle_crypto();
        let forien_key = did_key_to_crypto_key(&crypto, forien_did).await;
        self.did = forien_did.to_string();
        let shared_secret = diffie_helman(&crypto, &private_key, &forien_key).await;

        self.send_ratchet.set_new_shared_key(id, shared_secret.clone());
        self.recieve_ratchet.set_new_shared_key(id, shared_secret).await;
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