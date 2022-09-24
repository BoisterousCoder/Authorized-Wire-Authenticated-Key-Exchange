//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use std::{assert, print};
use futures::executor::block_on;

use awake::utils::Transitable;
use awake::awake::Awake;
use wasm_bindgen_test::*;
use quickcheck_macros::quickcheck;
use web_sys::console;
wasm_bindgen_test_configure!(run_in_browser);

const ALLOW_LOGGING:bool = true;

fn log(msg:&str){
    if ALLOW_LOGGING {
        console::log_1(&msg.into());
    }
}

/*
Unit Tests
*/
#[wasm_bindgen_test]
#[quickcheck]
fn can_convert_transitable_base58(s:String) -> bool{
    log("Converting to base 58..");
    let base_58 = Transitable::from_readable(&s).as_base58();
    log("Converting from base 58..");
    let s_mod = Transitable::from_base58(&base_58).as_readable();
    log(&format!("Base 58 looks like:{} from {}", s, base_58));
    s == s_mod
}
#[wasm_bindgen_test]
#[quickcheck]
fn can_convert_transitable_bytes(s:String) -> bool{
    log("Converting to bytes..");
    let js_bytes = Transitable::from_readable(&s).as_bytes();
    log("Converting array to bytes..");
    let mut bytes = vec![];
    js_bytes.for_each(&mut |byte, _, _| bytes.push(byte));
    log("Converting from bytes..");
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
