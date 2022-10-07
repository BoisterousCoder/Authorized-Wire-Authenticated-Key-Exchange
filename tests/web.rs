//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use std::collections::HashMap;
use std::{assert, print, format, vec};
use js_sys::{Array, Function};
use ucan::ucan::UcanPayload;
use wasm_bindgen::JsValue;
use std::str;

use awake::utils::*;
use awake::handshake::Handshake;
use awake::transitable::Transitable;
use awake::ratchet::Ratchet;
use wasm_bindgen_test::*;
use quickcheck_macros::quickcheck;
use web_sys::console;

wasm_bindgen_test_configure!(run_in_browser);


const ALLOW_LOGGING:bool = true;
//Note: While I do property based testing where it's possible the quickcheck library does not support async fuctions so I use normal tests everywhere else
static TEST_STRINGS: &'static [&'static str] = &[
    "This is a first test",
    "!@#$%^&*(){}[]:\"';<>,.?\\|", 
    "T8796543213251324658479876543421654687498324438927342234fodiu>?ASS/Fds/.df/D.,sf';[]pro[pww"
];

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
#[wasm_bindgen_test]
async fn can_convert_to_did(){
    let crypto = fetch_subtle_crypto();
    let (key, _) = gen_key_pair(&crypto, true).await;
    let did = crypto_key_to_did_key(&crypto, &key).await;
    let new_key = did_key_to_crypto_key(&crypto, &did).await;
    let new_did = crypto_key_to_did_key(&crypto, &new_key).await;
    assert!(did == new_did);
}
/*
Integration Tests
// */
#[wasm_bindgen_test]
async fn can_sign(){
    for payload in TEST_STRINGS {
        if !can_sign_func(payload).await {
            panic!("failed with payload:{}", payload);
        }
    }
    assert!(true);
}

async fn can_sign_func(payload:&str) -> bool{
    let crypto = fetch_subtle_crypto();
    let (public_key, private_key) = gen_key_pair(&crypto, true).await;

    let data = Transitable::from_readable(payload).sign(&crypto, &private_key).await;
    return data.verify(&crypto, &public_key).await;
}
#[wasm_bindgen_test]
async fn can_unsign(){
    for payload in TEST_STRINGS {
        if !can_unsign_func(payload).await {
            panic!("failed with payload:{}", payload);
        }
    }
    assert!(true);
}
async fn can_unsign_func(payload:&str) -> bool{
    let crypto = fetch_subtle_crypto();
    let (_, private_key) = gen_key_pair(&crypto, true).await;

    let data = Transitable::from_readable(payload).sign(&crypto, &private_key).await;
    return data.unsign().as_readable().unwrap() == payload.to_string();
}
#[wasm_bindgen_test]
async fn can_fail_sign(){
    for payload in TEST_STRINGS {
        if !can_fail_sign_func(payload).await {
            panic!("failed with payload:{}", payload);
        }
    }
    assert!(true);
}

async fn can_fail_sign_func(payload:&str) -> bool{
    let crypto = fetch_subtle_crypto();
    let (public_key_imposter, _) = gen_key_pair(&crypto, true).await;
    let (_, private_key) = gen_key_pair(&crypto, true).await;

    let data = Transitable::from_readable(payload).sign(&crypto, &private_key).await;
    return !data.verify(&crypto, &public_key_imposter).await;
}
async fn can_rachet_crypto_func(text_in:&str, id:usize, salt_str:&str) -> bool{
    let salt = salt_str.as_bytes().to_vec();
    let crypto = fetch_subtle_crypto();

    let (sender_public, sender_private) = gen_key_pair(&crypto, false).await;
    let (reciever_public, reciever_private) = gen_key_pair(&crypto, false).await;

    let sender_key = diffie_helman(&crypto, &sender_private, &reciever_public).await;
    let reciever_key = diffie_helman(&crypto, &reciever_private, &sender_public).await;
    
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

#[wasm_bindgen_test]
async fn can_handler_return(){
    let mut handshaker_requestor = Handshake::new().await;
    let mut handshaker_responder = Handshake::new().await;

    let request = handshaker_requestor.request(Array::new()).await;
    log(&request.as_readable().unwrap());
    let response = handshaker_responder.reponse(request, Array::new(), 60, Function::new_no_args("return true")).await.unwrap();
    log(&response.as_readable().unwrap());
    let challenge = handshaker_requestor.challenge_response(response, "Arbitrary Pin", Function::new_no_args("return true")).await.unwrap();
    log(&challenge.as_readable().unwrap());
    assert!(true);
}