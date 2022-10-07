use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::Uint8Array;

use std::collections::HashMap;
use std::str;

use crate::utils::*;

#[wasm_bindgen]
pub struct Transitable {
    data: Vec<u8>
}

#[wasm_bindgen]
impl Transitable {
    pub fn from_base58(input: &str) -> Transitable{
        return Transitable{
            //TODO: add error handling here
            data: bs58::decode(input).into_vec().unwrap()
        };
    }
    pub fn from_readable(input: &str) -> Transitable{
        return Transitable{
            data: input.as_bytes().to_vec()
        }
    }
    pub fn from_bytes(input: &[u8]) -> Transitable{
        return Transitable{
            data: input.to_vec()
        }
    }
    pub fn from_base64(input: &str) -> Transitable{
        return Transitable{
            data: base64::decode(input).unwrap()
        }
    }
    #[wasm_bindgen(getter)]
    pub fn as_base64(&self) -> String {
        return base64::encode(&self.data[..]);
    }
    #[wasm_bindgen(getter)]
    pub fn as_bytes(&self) -> js_sys::Uint8Array {
        return js_sys::Uint8Array::from(&self.data[..]);
    }
    #[wasm_bindgen(getter)]
    pub fn as_readable(&self) -> Option<String> {
        return match str::from_utf8(&self.data[..]) {
            Ok(readable) => Some(readable.to_string()),
            Err(_) => None
        };
    }
    #[wasm_bindgen(getter)]
    pub fn as_base58(&self) -> String {
        return bs58::encode(&self.data[..]).into_string();
    }
}
impl Transitable {
    pub async fn sign(&self, crypto:&SubtleCrypto, key:&CryptoKey) -> Transitable{
        let payload_str = match self.as_readable() {
            Some(x) => x,
            None => panic!("could not format as jwt as the data was not a string")
        };
        //let mut payload_bytes = payload_str.as_bytes().copy();
        let payload_b64 = base64::encode(payload_str.as_bytes());
        let header_text = "{{\"alg\": \"ES512\", \"typ\": \"JWT\" }}";
        let header_b64 = base64::encode(header_text.as_bytes());
    
        let signature_vec = sign(crypto, key, &self.data).await;
        let signature_b64 = base64::encode(signature_vec.as_slice());
    
        Transitable::from_readable(&format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }
    pub async fn verify(&self, crypto:&SubtleCrypto, key:&CryptoKey) -> bool{
        verify(
            crypto,
            key,
            &self.get_jwt_section(1),
            &self.get_jwt_section(2)
        ).await
    }
    fn get_jwt_section(&self, i:usize) -> Vec<u8>{
        let jwt_str = match self.as_readable() {
            Some(x) => x,
            None => panic!("Error: This transitable is either not a Json Web Token or is improperly formatted")
        };
        let sections:Vec<&str> =jwt_str.split(".").collect();
        if sections.len() != 3 {
            panic!("Error: This transitable is either not a Json Web Token or is improperly formatted")
        }
        return base64::decode(sections[i]).unwrap().to_vec();
    }
    pub fn unsign(&self) -> Transitable{
        Transitable::from_bytes(&self.get_jwt_section(1))
    }
}