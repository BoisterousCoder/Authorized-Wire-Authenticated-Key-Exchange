//#[macro_use]
// use simple_error::bail;

use bs58;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsValue, JsCast};
use wasm_bindgen_futures::JsFuture;

use serde::{Serialize, Deserialize};

use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::{Object, Array, JSON, Uint8Array};

use std::collections::HashMap;
use std::slice::Iter;

pub fn js_objectify(props:&HashMap<String, JsValue>) -> Object{
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

pub async fn gen_key_pair(crypto:&SubtleCrypto, is_extractable:bool) -> (CryptoKey, CryptoKey){
    let algorithm = HashMap::from([
        ("name".to_string(), JsValue::from_str("ECDH")),
        ("namedCurve".to_string(), JsValue::from_str("P-256")),
    ]);
    let key_uses_array:Array = Array::new_with_length(2);
    key_uses_array.set(0, JsValue::from("deriveBits"));
    key_uses_array.set(1, JsValue::from("deriveKey"));
    let js_algorithm = js_objectify(&algorithm);
    let key_pair_promise = crypto.generate_key_with_object(&js_algorithm, is_extractable, &key_uses_array).unwrap();
    let key_pair_future = JsFuture::from(key_pair_promise);
    let key_pair_object:Object = key_pair_future.await.unwrap().dyn_into().unwrap();
    return object_to_keypair(&key_pair_object);
}
pub async fn diffie_helman(crypto:&SubtleCrypto, self_key:&CryptoKey, other_agent_key:&CryptoKey) -> CryptoKey{
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
        self_key,
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

pub async fn get_ecdsa_key(crypto:&SubtleCrypto, ecdh_key:&CryptoKey, is_sign_key:bool) -> CryptoKey{
    let algorithm = HashMap::from([
        ("name".to_string(), JsValue::from_str("ECDSA")),
        ("namedCurve".to_string(), JsValue::from_str("P-256")),
    ]);
    
    let key_uses_array:Array = Array::new_with_length(1);
    if is_sign_key { key_uses_array.set(0, JsValue::from("sign")); }
    else {key_uses_array.set(0, JsValue::from("verify"));}

    let key_data_promise = crypto.export_key("jwk", ecdh_key).unwrap();
    let key_data_jwk = JsFuture::from(key_data_promise).await.unwrap();
    let mut key_data_map = obj_to_hash_map(&key_data_jwk.dyn_into().unwrap());
    let key_data_map_override:HashMap<String, JsValue> = HashMap::from([
        ("alg".to_string(), JsValue::from("ES256")),
        ("crv".to_string(), JsValue::from("P-256")),
        ("ext".to_string(), JsValue::from(true)),
        ("kty".to_string(), JsValue::from("EC")),
        ("key_ops".to_string(), JsValue::from(&key_uses_array))
    ]);
    let key_data_map = overwrite_hash_map(&key_data_map_override, &key_data_map);
    let key_data = hash_map_to_object(key_data_map);

    let ecdsa_key_promise = crypto.import_key_with_object(
        "jwk",
        &key_data,
        &js_objectify(&algorithm), 
        false,
        &key_uses_array
    ).unwrap();
    let ecdsa_key = JsFuture::from(ecdsa_key_promise).await.unwrap();
    return ecdsa_key.dyn_into().unwrap();
}

pub fn overwrite_hash_map<K, V>(top: &HashMap<K, V>, bot: &HashMap<K, V>) -> HashMap<K, V>
    where K: std::hash::Hash, K: std::cmp::Eq, K: Clone, V: Clone{
    let mut out = top.clone();
    for (key, value) in bot {
        if !out.contains_key(key){
            out.insert(key.clone(), value.clone());
        }
    }
    return out;
}

pub fn u8_iter_js_array(bytes:Iter<u8>) -> Uint8Array{
    let array = Uint8Array::new_with_length(bytes.len() as u32);
    let mut i:u32 = 0;
    for byte in bytes {
        array.set_index(i, byte.clone());
        i += 1;
    }
    return array;
}

fn obj_to_hash_map(obj:&Object) -> HashMap<String, JsValue>{
    let keys = array_to_vec(Object::keys(obj));
    let values = array_to_vec(Object::values(obj));

    let mut i = 0;
    let mut ret:HashMap<String, JsValue> = HashMap::new();
    for value in values{
        ret.insert(keys[i].as_string().unwrap(), value);
        i += 1;
    }
    return ret;
}

fn array_to_vec(array:Array) -> Vec<JsValue>{
    let mut vector:Vec<JsValue> = vec![];
    let length = array.length();
    let mut i:u32 = 0;
    while i < length {
        vector.push(array.get(i));
        i += 1;
    }
    return vector;
}
fn hash_map_to_object(map: HashMap<String, JsValue>) -> Object{
    let entries = Array::new_with_length(map.len() as u32);
    let mut i:u32 = 0;
    for (key, value) in map {
        let entry = Array::new_with_length(2);
        entry.set(0, JsValue::from(key));
        entry.set(1, value);
        entries.set(i, JsValue::from(entry));
        i += 1;
    }
    return Object::from_entries(&entries.dyn_into().unwrap()).unwrap();
}

#[derive(Serialize, Deserialize)]
pub struct UcanCapability{
    pub with:String,
    pub can:String,
    pub nb:Option<String>
}
impl UcanCapability{
    pub fn from_object(obj:&Object) -> UcanCapability{
        let entries = Object::entries(obj);
        let mut with:Option<String> = None;
        let mut can:Option<String> = None;
        let mut nb:Option<String> = None;
        for js_entry in entries.to_vec(){
            let entry:Array = js_entry.dyn_into().unwrap();
            let prop = entry.get(0).as_string().unwrap();
            if prop == "with".to_string(){
                with = match entry.get(1).as_string() {
                    Some(x) => Some(x),
                    None => panic!("the with property of a capibility must be a string value")
                };
            }else if prop == "can".to_string(){
                can = match entry.get(1).as_string() {
                    Some(x) => Some(x),
                    None => panic!("the can property of a capibility must be a string value")
                };
            }else if prop == "nb".to_string(){
                // let obj:Object = entry.get(1).dyn_into().unwrap();
                nb = match JSON::stringify(&entry.get(1)) {
                    Ok(x) => x.as_string(),
                    Err(_) => panic!("cannot convert nb to json value")
                };
                //TODO: Fix this
                // nb = Some("This does't work yet".to_string())
            }
        }
        if with.is_none() || can.is_none() {
            panic!("a capability must have the with and can properties");
        }
        return UcanCapability{with:with.unwrap(), can:can.unwrap(), nb}
    }
}