//#[macro_use]
// use simple_error::bail;

use bs58;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsValue, JsCast};
use wasm_bindgen_futures::JsFuture;
use serde::{Serialize, Deserialize};
use web_sys::{SubtleCrypto};
use js_sys::{Object, Array, ArrayBuffer};
use std::collections::HashMap;
use web_sys::CryptoKey;
use std::str;

#[derive(Serialize, Deserialize)]
pub struct UcanCapability{
    pub with:String,
    pub can:String
}
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
    pub fn as_readable(&self) -> String { //Warning: This is will fail if data cannot be converted to utf8
        return str::from_utf8(&self.data[..]).unwrap().to_string();
    }
    #[wasm_bindgen(getter)]
    pub fn as_base58(&self) -> String {
        return bs58::encode(&self.data[..]).into_string();
    }
}

pub fn js_objectify(props:&HashMap<String, JsValue>) -> Object{
    let mut obj = Object::new();
    let obj_array = Array::new_with_length(props.len() as u32);
    let mut i:u32 = 0;
    for (prop, val) in props {
        let pair = Array::new_with_length(2 as u32);
        pair.set(0 as u32, JsValue::from(prop));
        pair.set(1 as u32, val.clone());
        obj_array.set(i, JsValue::from(pair));
        i += 1;
    }
    return Object::from_entries(&obj_array).unwrap();
}

pub fn fetch_subtle_crypto() -> SubtleCrypto{
    let window = web_sys::window().unwrap();
    return window.crypto().unwrap().subtle();
}

#[wasm_bindgen]
struct ObjectProperty {
    value:JsValue,
    writable:bool
}

pub async fn gen_key_pair(crypto:&SubtleCrypto, algorithm:&HashMap<String, JsValue>) -> (CryptoKey, CryptoKey){
    let key_uses_array:Array = Array::new_with_length(2);
    key_uses_array.set(0, JsValue::from("deriveBits"));
    key_uses_array.set(1, JsValue::from("deriveKey"));
    let js_algorithm = js_objectify(algorithm);
    //console::log_1(&js_algorithm);
    let key_pair_promise = crypto.generate_key_with_object(&js_algorithm, false, &key_uses_array).unwrap();
    let key_pair_future = JsFuture::from(key_pair_promise);
    let key_pair_object:Object = key_pair_future.await.unwrap().dyn_into().unwrap();
    return object_to_keypair(&key_pair_object);
}
pub async fn diffie_helman(crypto:&SubtleCrypto, self_key:CryptoKey, other_agent_key:CryptoKey) -> CryptoKey{
    let key_uses_array:Array = Array::new_with_length(2);
    key_uses_array.set(0, JsValue::from("deriveBits"));
    key_uses_array.set(1, JsValue::from("deriveKey"));
    let shared_secret_algorithm = HashMap::from([
        ("name".to_string(), JsValue::from_str("ECDH")),
        ("namedCurve".to_string(), JsValue::from_str("P-256")),
        ("public".to_string(), JsValue::from(other_agent_key))
    ]);
    let shared_secret_data_promise = crypto.derive_bits_with_object(
        &js_objectify(&shared_secret_algorithm),
        &self_key,
        256,
    ).unwrap();
    let shared_secret_data = JsFuture::from(shared_secret_data_promise).await.unwrap();
    let shared_secret_data_obj:Object  = shared_secret_data.dyn_into().unwrap();
    let shared_secret_promise = crypto.import_key_with_str(
        "raw",
        &shared_secret_data_obj,
        "HKDF",
        false,
        &key_uses_array
    ).unwrap();
    let shared_secret = JsFuture::from(shared_secret_promise).await.unwrap();
    return shared_secret.dyn_into().unwrap();
}
pub fn object_to_keypair(obj: &Object) -> (CryptoKey, CryptoKey){
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
pub fn object_to_capability(obj:&Object) -> UcanCapability{
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