//#[macro_use]
// use simple_error::bail;

use base64;
use wasm_bindgen::prelude::wasm_bindgen;
use js_sys;
use std::str;

#[wasm_bindgen]
pub struct Transitable {
    data: String,
}

#[wasm_bindgen]
impl Transitable {
    pub fn from_base64(input: &str) -> Transitable{
        return Transitable{
            //TODO: add error handling here
            data: str::from_utf8(base64::decode(input).unwrap().as_slice()).unwrap().to_string()
        }
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
    pub fn as_base64(&self) -> String {
        return base64::encode(self.data.clone());
    }
}
#[cfg(test)]
mod tests {
    use quickcheck_macros::quickcheck;
    use wasm_bindgen_test::wasm_bindgen_test;
    use crate::utils::Transitable;

    #[wasm_bindgen_test]
    #[quickcheck]
    fn can_convert_transitable_base64(s:String) -> bool{
        // let s = "dklfjhlkdsjahffdsfkjhfdskjdaflshfkdjhfdsalkjhfkljdsahf";
        let base_64 = Transitable::from_readable(&s).as_base64();
        let s_mod = Transitable::from_base64(&base_64).as_readable();
        s == s_mod
    }
    #[wasm_bindgen_test]
    #[quickcheck]
    fn can_convert_transitable_bytes(s:String) -> bool{
        // let s = "dklfjhlkdsjahffdsfkjhfdskjdaflshfkdjhfdsalkjhfkljdsahf";
        let js_bytes = Transitable::from_readable(&s).as_bytes();
        let mut bytes = vec![];
        js_bytes.for_each(&mut |byte, i, _| bytes[i as usize] = byte);
        let s_mod = Transitable::from_bytes(bytes.as_slice()).as_readable();
        s == s_mod
    }
}