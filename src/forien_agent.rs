use web_sys::{CryptoKey};

use wasm_bindgen_futures::JsFuture;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use std::collections::HashMap;
use web_sys::SubtleCrypto;
use js_sys::Uint8Array;

use crate::ratchet::Ratchet;
use crate::transitable::Transitable;
use crate::utils::{hash, diffie_helman, js_objectify, fetch_subtle_crypto, did_key_to_crypto_key, crypto_key_to_did_key};

const MAX_MSGS: usize = 1000000;//One million should be enough

#[derive(Clone)]
pub struct ForienAgent{
    pub did:String,
    mid_prefix:Option<Vec<u8>>,
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
            mid_prefix: None,
            send_ratchet: Ratchet::new(shared_secret.clone(), true, salt.clone()).await,
            recieve_ratchet: Ratchet::new(shared_secret, false, salt).await
        }
    }
    pub async fn is_sender_of(&self, payload:&Transitable) -> bool{
        let crypto = fetch_subtle_crypto();
        let key = did_key_to_crypto_key(&crypto, &self.did).await;
        return payload.verify(&crypto, &key).await;
    }
    pub async fn finalize(&mut self, private_key:CryptoKey, forien_did:&str, mid_prefix:Vec<u8>){
        self.mid_prefix = Some(mid_prefix);
        
        let crypto = fetch_subtle_crypto();
        let forien_key = did_key_to_crypto_key(&crypto, forien_did).await;
        self.did = forien_did.to_string();
        let shared_secret = diffie_helman(&crypto, &private_key, &forien_key).await;

        self.send_ratchet.set_new_shared_key(1, shared_secret.clone());
        self.recieve_ratchet.set_new_shared_key(1, shared_secret).await;
    }
    pub async fn encrypt_for(&mut self, payload:Transitable) -> (String, Transitable){
        let encrypted = self.send_ratchet.process_payload(self.next_send_id, payload).await.unwrap();
        let mid = match &self.mid_prefix{
            Some(prefix) => self.get_mid(self.next_send_id).await,
            None => format!("{}", self.next_send_id)
        };
        self.next_send_id += 1;
        return (mid, encrypted);
    }
    pub async fn decrypt_for(&mut self, id:usize, payload:Transitable) -> Transitable{
        return self.recieve_ratchet.process_payload(id, payload).await.unwrap();
    }
    pub async fn decrypt_with_mid(&mut self, mid:String, payload:Transitable) -> Transitable{
        let mut i = 0;
        let mut id:Option<usize> = None;
        let start = self.recieve_ratchet.len();
        while (start+i < MAX_MSGS) || (start - i) > 0{
            if start+i < MAX_MSGS {
                if self.get_mid(start+i).await == mid{
                    id = Some(start+i);
                    break;
                }
            }
            if (start - i) > 0 {
                if self.get_mid(start-i).await == mid{
                    id = Some(start-i);
                    break;
                }
            }
            i += 1;
        }
        return self.decrypt_for(id.unwrap(), payload).await;
    }
    async fn get_mid(&self, id:usize) -> String {
        let crypto = fetch_subtle_crypto();
        let mut count = self.next_send_id.to_be_bytes().to_vec();
        let mut prefix_mut = self.mid_prefix.as_ref().unwrap().clone();
        let mut key_data = Vec::new();
        key_data.append(&mut prefix_mut);
        key_data.append(&mut count);
        let hash = hash(&crypto, &key_data).await;
        return base64::encode(hash)
    }
    pub fn empty_decryptor(&mut self, id:usize){
        self.recieve_ratchet.empty_decryptor(id);
    }
}