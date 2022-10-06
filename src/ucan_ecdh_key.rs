use wasm_bindgen_futures::JsFuture;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use std::collections::HashMap;
use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::Uint8Array;
use futures::Future;
use std::pin::Pin;
use std::error::Error;
use anyhow::anyhow;

use crate::utils::*;

pub struct UcanEcdhKey {
    key: CryptoKey
}
impl UcanEcdhKey {
    pub async fn from_did(crypto:&SubtleCrypto, did:&str) -> UcanEcdhKey{
        UcanEcdhKey::from_crypto_key(did_key_to_crypto_key(&crypto, did).await)
    }
    pub fn from_crypto_key(key: CryptoKey) -> UcanEcdhKey{
        return UcanEcdhKey{key}
    }
}
impl ucan::crypto::KeyMaterial for UcanEcdhKey {
    fn get_jwt_algorithm_name(&self) -> String {"ES256".to_string()}
    fn get_did<'life0, 'async_trait>(&'life0 self) 
        -> Pin<Box<dyn Future<Output = Result<String, anyhow::Error>> + 'async_trait>>
        where 'life0: 'async_trait,Self: 'async_trait {
        return Box::pin(async move {
            Ok::<String, anyhow::Error>(crypto_key_to_did_key(&fetch_subtle_crypto(), &self.key).await)
        });
    }
    fn sign<'life0, 'life1, 'async_trait>(&'life0 self, payload: &'life1 [u8]) 
        -> Pin<Box<dyn Future<Output = Result<Vec<u8>, anyhow::Error>> + 'async_trait>>
        where 'life0: 'async_trait, 'life1: 'async_trait,Self: 'async_trait{
        return Box::pin(async move {
            let crypto = fetch_subtle_crypto();
            let ecdsa_key = get_ecdsa_key(&crypto, &self.key, true).await;
            let algorithm = HashMap::from([
                ("name".to_string(), JsValue::from_str("ECDSA")),
                ("hash".to_string(), JsValue::from_str("SHA-512")),
            ]);
            let signature_promise = crypto.sign_with_object_and_buffer_source(
                &js_objectify(&algorithm), 
                &ecdsa_key,
                &u8_iter_js_array(payload.to_vec().iter())
            ).unwrap();
            let signature_js = JsFuture::from(signature_promise).await.unwrap();
            let signature_array = Uint8Array::new(&signature_js);
            Ok::<Vec<u8>, anyhow::Error>(signature_array.to_vec())
        });
    }
    fn verify<'life0, 'life1, 'life2, 'async_trait>(&'life0 self, payload: &'life1 [u8], signature: &'life2 [u8]) 
        -> Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + 'async_trait>>
        where 'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait{
        return Box::pin( async move {
            let crypto = fetch_subtle_crypto();
            let ecdsa_key = get_ecdsa_key(&crypto, &self.key, false).await;
            let algorithm = HashMap::from([
                ("name".to_string(), JsValue::from_str("ECDSA")),
                ("hash".to_string(), JsValue::from_str("SHA-512")),
            ]);
            let is_sender_future = crypto.verify_with_object_and_buffer_source_and_buffer_source(
                &js_objectify(&algorithm),
                &ecdsa_key,
                &u8_iter_js_array(signature.to_vec().iter()),
                &u8_iter_js_array(payload.to_vec().iter())
            ).unwrap();
            let is_sender_js = JsFuture::from(is_sender_future).await.unwrap();
            match is_sender_js.as_bool().unwrap() {
                true => Ok::<(), anyhow::Error>(()),
                false => Err::<(), anyhow::Error>(anyhow!("attempted to verrify but got an answer that wasn't a boolean"))
            }
        });
    }
}