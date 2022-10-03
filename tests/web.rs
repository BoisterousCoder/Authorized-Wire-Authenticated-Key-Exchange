//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use std::collections::HashMap;
use std::{assert, print, format};
use js_sys::Array;
use wasm_bindgen::JsValue;
use std::str;

use awake::utils::{Transitable, gen_key_pair, fetch_subtle_crypto, diffie_helman};
use awake::awake::Awake;
use awake::ratchet::Ratchet;
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
    //log("Converting to base 58..");
    let base_58 = Transitable::from_readable(&s).as_base58();
    //log("Converting from base 58..");
    let s_mod = Transitable::from_base58(&base_58).as_readable().unwrap();
    //log(&format!("Base 58 looks like:{} from {}", s, base_58));
    s == s_mod
}
#[wasm_bindgen_test]
#[quickcheck]
fn can_convert_transitable_base64(s:String) -> bool{
    let base_64 = Transitable::from_readable(&s).as_base64();
    let s_mod = Transitable::from_base64(&base_64).as_readable().unwrap();
    s == s_mod
}
#[wasm_bindgen_test]
#[quickcheck]
fn can_convert_transitable_bytes(s:String) -> bool{
    //log("Converting to bytes..");
    let js_bytes = Transitable::from_readable(&s).as_bytes();
    //log("Converting array to bytes..");
    let mut bytes = vec![];
    js_bytes.for_each(&mut |byte, _, _| bytes.push(byte));
    //log("Converting from bytes..");
    let s_mod = Transitable::from_bytes(bytes.as_slice()).as_readable().unwrap();
    s == s_mod
}
/*
Integration Tests
// */
#[wasm_bindgen_test]
async fn can_handshake(){
    let state = Awake::new().await;
    let did_key = state.handshake_request(Array::new_with_length(0 as u32)).await;
    let text = did_key.as_readable().unwrap();
    //log(&text);
    assert!(text.contains("did:key:"));
}
//#[wasm_bindgen_test]
//#[quickcheck] Note: Quick Check does not allow for futures so we'll have to do things for manually
async fn can_rachet_crypto_func(text_in:&str, id:usize, salt_str:&str) -> bool{
    let salt = salt_str.as_bytes().to_vec();

    let algorithm = HashMap::from([
        ("name".to_string(), JsValue::from_str("ECDH")),
        ("namedCurve".to_string(), JsValue::from_str("P-256")),
    ]);
    let crypto = fetch_subtle_crypto();

    let (sender_puiblic, sender_private) = gen_key_pair(&crypto, &algorithm).await;
    let (reciever_puiblic, reciever_private) = gen_key_pair(&crypto, &algorithm).await;

    let sender_key = diffie_helman(&crypto, &sender_private, &reciever_puiblic).await;
    let reciever_key = diffie_helman(&crypto, &reciever_private, &sender_puiblic).await;
    
    let mut sender_ratchet = Ratchet::new(sender_key, true, salt.clone()).await;
    let mut reciever_ratchet = Ratchet::new(reciever_key, false, salt.clone()).await;

    let text_in_vec = Transitable::from_readable(text_in);
    let sent_message = sender_ratchet.process_payload(id, text_in_vec).await.unwrap();
    let recieved_vec = reciever_ratchet.process_payload(id, sent_message).await.unwrap();
    let recieved_text = recieved_vec.as_readable();

    text_in == recieved_text.unwrap()
}

#[wasm_bindgen_test]
async fn can_rachet_crypto() {
    let tests:Vec<(&str, usize, &str)> = vec![
        ("This is a first test", 5, "this is a salt"),
        ("T8796543213251324658479876543421654687498324438927342234fodiu>?ASS/Fds/.df/D.,sf';[]pro[pww", 0, "T8796543213251324658479876543421654687498324438927342234fodiu>?ASS/Fds/.df/D.,sf';[]pro[pww"),
        ("!@#$%^&*(){}[]:\"';<>,.?\\|", 50, "!@#$%^&*(){}[]:\"';<>,.?\\|")
    ];
    for (text, id, salt) in tests{
        if !can_rachet_crypto_func(text, id, salt).await {
            panic!("failed with text:{} id:{} salt:{}", text, id, salt);
        }
    }
    assert!(true)
}