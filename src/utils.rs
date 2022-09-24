//#[macro_use]
// use simple_error::bail;

use bs58;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsValue, JsCast};
use serde::{Serialize, Deserialize};
use js_sys::Object;
use std::collections::HashMap;
use std::str;

#[derive(Serialize, Deserialize)]
pub struct UcanCapability{
    pub with:String,
    pub can:String
}
#[wasm_bindgen]
pub struct Transitable {
    data: String,
}

#[wasm_bindgen]
impl Transitable {
    pub fn from_base58(input: &str) -> Transitable{
        let vec_bytes = bs58::decode(input).into_vec().unwrap();
        let bytes = vec_bytes.as_slice();
        return Transitable{
            //TODO: add error handling here
            data: str::from_utf8(bytes).unwrap().to_string()
        };
    }
    pub fn from_readable(input: &str) -> Transitable{
        return Transitable{
            data: input.to_string()
        }
    }
    pub fn from_bytes(input: &[u8]) -> Transitable{
        return Transitable{
            data: str::from_utf8(input).unwrap().to_string()
        }
    }
    #[wasm_bindgen(getter)]
    pub fn as_bytes(&self) -> js_sys::Uint8Array {
        return js_sys::Uint8Array::from(&self.data.as_bytes()[..]);
    }
    #[wasm_bindgen(getter)]
    pub fn as_readable(&self) -> String {
        return self.data.to_string();
    }
    #[wasm_bindgen(getter)]
    pub fn as_base58(&self) -> String {
        return bs58::encode(self.data.as_bytes()).into_string();
    }
}

pub fn js_objectify(props:&HashMap<String, JsValue>) -> Object{
    let mut obj = Object::new();
    for (prop, val) in props {
        let obj_val: Object= JsValue::from(ObjectProperty{value:val.clone(), writable:false}).dyn_into().unwrap();
        obj = Object::define_property(&obj, &JsValue::from_str(prop), &obj_val)
    }
    return obj;
}

#[wasm_bindgen]
struct ObjectProperty {
    value:JsValue,
    writable:bool
}