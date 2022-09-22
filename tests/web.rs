//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use awake::utils::Transitable;
use wasm_bindgen_test::*;
use quickcheck_macros::quickcheck;
wasm_bindgen_test_configure!(run_in_browser);

/*
Unit Tests
*/
#[wasm_bindgen_test]
#[quickcheck]
fn can_convert_transitable_base64(s:String) -> bool{
    let base_64 = Transitable::from_readable(&s).as_base64();
    let s_mod = Transitable::from_base64(&base_64).as_readable();
    s == s_mod
}
#[wasm_bindgen_test]
#[quickcheck]
fn can_convert_transitable_bytes(s:String) -> bool{
    let js_bytes = Transitable::from_readable(&s).as_bytes();
    let mut bytes = vec![];
    js_bytes.for_each(&mut |byte, _, _| bytes.push(byte));
    let s_mod = Transitable::from_bytes(bytes.as_slice()).as_readable();
    s == s_mod
}
/*
Integration Tests
*/