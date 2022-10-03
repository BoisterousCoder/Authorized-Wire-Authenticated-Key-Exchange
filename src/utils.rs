//#[macro_use]
// use simple_error::bail;

use bs58;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsValue, JsCast};
use wasm_bindgen_futures::JsFuture;

use serde::{Serialize, Deserialize};
use serde_json::Value;

use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::{Object, Array, JSON, Uint8Array};

use std::collections::HashMap;
use std::slice::Iter;
use std::str;

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
    pub async fn format_as_jwt(&mut self, crypto:&SubtleCrypto, ecdh_key:&CryptoKey){
        let payload_str = match self.as_readable() {
            Some(x) => x,
            None => panic!("could not format as jwt as the data was not a string")
        };
        //convert ecdh key to ecdsa key
        let ecdsa_key = get_ecdsa_key(crypto, ecdh_key).await;
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("ECDSA")),
            ("hash".to_string(), JsValue::from_str("SHA-512")),
        ]);
        
        //let mut payload_bytes = payload_str.as_bytes().copy();
        let payload_b64 = base64::encode(payload_str.as_bytes());
        let header_text = "{{\"alg\": \"ES512\", \"typ\": \"JWT\" }}";
        let header_b64 = base64::encode(header_text.as_bytes());
    
        let signature_promise = crypto.sign_with_object_and_buffer_source(
            &js_objectify(&algorithm), 
            &ecdsa_key,
            &u8_iter_js_array(payload_str.as_bytes().to_vec().iter())
        ).unwrap();
        let signature_js = JsFuture::from(signature_promise).await.unwrap();
        let signature_array = Uint8Array::new(&signature_js);
        let signature_vec = signature_array.to_vec();
        let signature = base64::encode(signature_vec.as_slice());
    
        self.data = format!("{}.{}.{}", header_b64, payload_b64, signature).as_bytes().to_vec();
    }
    pub async fn verify(&self, crypto:&SubtleCrypto, ecdh_key:&CryptoKey) -> bool{
        let ecdsa_key = get_ecdsa_key(crypto, ecdh_key).await;
        let algorithm = HashMap::from([
            ("name".to_string(), JsValue::from_str("ECDSA")),
            ("hash".to_string(), JsValue::from_str("SHA-512")),
        ]);
        let payload = u8_iter_js_array(self.get_jwt_section(2).iter());
        let signatute = u8_iter_js_array(self.get_jwt_section(3).iter());
        let is_sender_future = crypto.verify_with_object_and_buffer_source_and_buffer_source(
            &js_objectify(&algorithm),
            &ecdsa_key,
            &signatute,
            &payload
        ).unwrap();
        let is_sender_js = JsFuture::from(is_sender_future).await.unwrap();
        return is_sender_js.as_bool().unwrap()
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
    pub fn deformat_from_jwt(&mut self){
        self.data = self.get_jwt_section(2);
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
    let key_pair_promise = crypto.generate_key_with_object(&js_algorithm, false, &key_uses_array).unwrap();
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

pub async fn get_ecdsa_key(crypto:&SubtleCrypto, ecdh_key:&CryptoKey) -> CryptoKey{
    let algorithm = HashMap::from([
        ("name".to_string(), JsValue::from_str("ECDSA")),
        ("namedCurve".to_string(), JsValue::from_str("P-256")),
    ]);
    
    let key_uses_array:Array = Array::new_with_length(2);
    key_uses_array.set(0, JsValue::from("sign"));
    key_uses_array.set(1, JsValue::from("verify"));

    let ecdsa_key_data_promise = crypto.export_key("raw", ecdh_key).unwrap();
    let ecdsa_key_data = JsFuture::from(ecdsa_key_data_promise).await.unwrap();
    let ecdsa_key_data_obj:Object = ecdsa_key_data.dyn_into().unwrap();
    let ecdsa_key_promise = crypto.import_key_with_object(
        "raw",
        &ecdsa_key_data_obj,
        &js_objectify(&algorithm), 
        false,
        &key_uses_array
    ).unwrap();
    let ecdsa_key = JsFuture::from(ecdsa_key_promise).await.unwrap();
    return ecdsa_key.dyn_into().unwrap();
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
                let obj:Object = entry.get(1).dyn_into().unwrap();
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