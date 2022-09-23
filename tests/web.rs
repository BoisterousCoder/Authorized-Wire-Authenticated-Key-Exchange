//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use std::{assert, print};
use futures::executor::block_on;

use awake::utils::Transitable;
use awake::awake::Awake;
use wasm_bindgen_test::*;
use quickcheck_macros::quickcheck;
wasm_bindgen_test_configure!(run_in_browser);

/*
Unit Tests
*/
#[wasm_bindgen_test]
#[quickcheck]
fn can_convert_transitable_base58(s:String) -> bool{
    let base_64 = Transitable::from_readable(&s).as_base58();
    let s_mod = Transitable::from_base58(&base_64).as_readable();
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
// */
//Note: blocking on async fuctions is not currently supported inside rust therefore testing of async function must be done within javascript
// #[wasm_bindgen_test]
// fn can_handshake(){
//     let state = block_on(Awake::new());
//     let key_future = state.initiate_handshake();
//     let did_key = block_on(key_future).as_readable();
//     //print!("{}", did_key);
//     assert!(did_key.contains("did:key:"));
// }
