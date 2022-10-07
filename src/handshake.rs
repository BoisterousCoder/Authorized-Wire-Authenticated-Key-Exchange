use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::{Array, Function, JSON};
use std::collections::HashMap;
use ucan::builder::UcanBuilder;
use serde_json::{Value, json};

use crate::utils::*;
use crate::ucan_ecdh_key::UcanEcdhKey;
use crate::transitable::Transitable;
use crate::forien_agent::ForienAgent;

#[wasm_bindgen]
pub struct Handshake{
    crypto: SubtleCrypto,
    pub is_done:bool,
    step_2_public: CryptoKey,
    step_2_private: CryptoKey,
    step_4_public: CryptoKey,
    step_4_private: CryptoKey,
    real_public: CryptoKey,
    real_private: CryptoKey,
    potential_partners: HashMap<String, ForienAgent>
}


/*
    TODOS:
        Current does not fail to failed awake message.
        Current only supports oob-pin for verification of requestor.
        More error handling is needed across the board
        More comments are needed everywher
        Utils could be split into multiple files
        There may be room small for performance imporvement moving around awaits
        more tests need to writen
        tests should be organised better
        an example of how to use it needs to be writen
        signatures on incomimng awake resquests probably need to be checked
        exposed methods and properties need to be allowed to be accessed more js friendly names
*/
#[wasm_bindgen]
impl Handshake{
    pub async fn new() -> Handshake{
        let crypto = fetch_subtle_crypto();
        let (step_2_public, step_2_private) = gen_key_pair(&crypto, false).await;
        let (step_4_public, step_4_private) = gen_key_pair(&crypto, false).await;
        let (real_public, real_private) = gen_key_pair(&crypto, true).await;
        return Handshake{
            step_2_public,
            step_2_private,
            step_4_public,
            step_4_private,
            real_public,
            real_private,
            potential_partners:HashMap::new(),
            is_done: false,
            crypto
        };
    }
    // Part 3.2 from spec
    pub async fn request(&self, capabilities: Array) -> Transitable {
        if self.is_done{
            panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections.")
        }

        //TODO: Add error handling
        let cap_json = capabilities_to_value(capabilities);
        return Transitable::from_readable(&format!("{{
                \"awv\": \"0.1.0\",
                \"type\": \"awake/init\",
                \"did\":\"{}\",
                \"caps\": {}
            }}", 
            &crypto_key_to_did_key(&self.crypto, &self.step_2_public).await, cap_json))
            .sign(&self.crypto, &self.real_private).await;
    }
    //Part 3.3 from spec
    pub async fn reponse(
        &mut self, 
        request_signed:Transitable, //The handshake request you are trying to respond to
        capabilities: Array, //The capabilities you have and are trying to prove to them
        lifetime: u64, //how long should the ucan be valid for
        are_capabilities_valid: Function //passes in the capabilities they want to prove and passes out a boolean on if you deem them valid
    ) -> Option<Transitable>{
        //error if there haas already been a handshake conducted
        if self.is_done{
            panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections.")
        }
        let self_did = crypto_key_to_did_key(&self.crypto, &self.step_2_public);

        //get requestor's data from request
        let request = request_signed.unsign();
        let request_str = match request.as_readable(){
            Some(x) => x,
            None => panic!("The handshake init was not sent properly or the transitable is not a handshake request")
        };
        let request_map:Value = match serde_json::from_str(&request_str){
            Ok(x) => x,
            Err(_) => panic!("The handshake was not sent in the proper json format")
        };

        //init agent
        let forien_did_key = &request_map["did"].as_str().unwrap();
        let mut agent = ForienAgent::new(&self.step_2_private, forien_did_key, None).await;

        //verify sender of the request
        //The forien agent's real public is not known yet so this is impossible
        // if !agent.is_sender_of(&request_signed).await {
        //     warn("Failed to verify sender's signature");
        //     return None;
        // }

        //verify the capabilities of the request
        //TODO: fix this
        let forien_caps_str = serde_json::to_string(&request_map["caps"]).unwrap();
        let forien_caps_js = JSON::parse(&forien_caps_str).unwrap();
        let is_sender_capable = are_capabilities_valid.call1(&forien_caps_js, &forien_caps_js).unwrap();
        if !is_sender_capable.as_bool().unwrap() { 
            warn("Failed to verify sender's capabilities");
            return None;
        }

        //create facts for verification
        let oob_pin_fact = json!({
            "awake/challenge": "oob-pin",
            "caps": capabilities_to_value(capabilities)
        });
        let next_did_fact = json!({
            "awake/nextdid": crypto_key_to_did_key(&self.crypto, &self.step_4_public).await
        });

        //build ucan message
        let ucan = UcanBuilder::default()
            .issued_by(&UcanEcdhKey::from(self.real_public.clone(), self.real_private.clone()))
            .for_audience(forien_did_key)
            .with_lifetime(lifetime)
            .with_fact(next_did_fact)
            .with_fact(oob_pin_fact)
            .build().unwrap()
            .sign().await.unwrap()
            .encode().unwrap();
        
        //encrypt the ucan and add agent to the list of potential agents
        let (_, encrypted_ucan) = agent.encrypt_for(Transitable::from_readable(&ucan)).await;
        self.potential_partners.insert(forien_did_key.to_string(), agent);

        //build the response 
        let response = Transitable::from_readable(&format!("{{
                \"awv\": \"0.1.0\",
                \"type\": \"awake/res\",
                \"aud\":\"{}\",
                \"iss\": \"{}\",
                \"msg\": \"{}\"
            }}", 
            forien_did_key, self_did.await, encrypted_ucan.as_base64()))
            .sign(&self.crypto, &self.real_private).await;
        return Some(response);
    }
    //part 3.4 from spec
    pub async fn challenge_response(&mut self, 
        response_signed:Transitable, //The handshake response you are trying to challenge
        oob_pin: &str, //The out of bounds pin to prove who you are
        is_ucan_valid: Function //passes in the capabilities they want to prove and passes out a boolean on if you deem them valid){
    )-> Option<Transitable> {
        if self.is_done{
            panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections.")
        }
        let self_did_future = crypto_key_to_did_key(&self.crypto, &self.real_public);

        //get requestor's data from request
        let response = response_signed.unsign();
        let response_str = match response.as_readable(){
            Some(x) => x,
            None => {
                warn("handshake response was not sent properly or the transitable is not a handshake request");
                return None
            }
        };
        let response_map:Value = match serde_json::from_str(&response_str){
            Ok(x) => x,
            Err(_) => {
                warn(&format!("handshake response was not sent in the proper json format: \n{}", response_str));
                return None;
            }
        };

        //init agent
        let forien_step_2_did = &response_map["iss"].as_str().unwrap();
        let mut agent = ForienAgent::new(&self.step_2_private, forien_step_2_did, Some(&self.step_2_public)).await;

        //get message id
        let forien_step_2_key = did_key_to_crypto_key(&self.crypto, forien_step_2_did).await;
        let mid_future = get_message_id(&self.crypto, &self.step_2_public, &forien_step_2_key, None);

        //get ucan serde
        let ucan_encrypted_str = match response_map["msg"].as_str(){
            Some(x) => x,
            None => {
                warn("handshake ucan was not sent in the proper json format");
                return None;
            }
        }.to_string();
        let ucan = process_encrypted_ucan(&mut agent, &ucan_encrypted_str, 0).await;

        //check if ucan is valid
        let ucan_str = serde_json::to_string(&ucan).unwrap();
        let ucan_js = JSON::parse(&ucan_str).unwrap();
        let is_sender_capable = is_ucan_valid.call1(&ucan_js, &ucan_js).unwrap();
        if !is_sender_capable.as_bool().unwrap() { 
            warn("Failed to verify sender's capabilities");
            return None;
        }

        //get signed hash for the payload
        let forein_real_did = ucan["iss"].as_str().unwrap();
        let mut hash_data:Vec<u8> = vec![];
        hash_data.append(&mut did_key_to_bytes(forein_real_did));
        hash_data.append(&mut oob_pin.as_bytes().to_vec());
        let hash = hash(&self.crypto, &hash_data).await;
        let signature = sign(&self.crypto, &self.real_private, &hash).await;

        //create the message field and encrypt it
        let msg_plain = format!("{{
            \"pin\":\"{}\"
            \"did\":\"{}\"
            \"sig\":\"{}\"
        }}", oob_pin, self_did_future.await, base64::encode(signature));
        let (_, msg_encrypted) = agent.encrypt_for(Transitable::from_readable(&msg_plain)).await;
        
        //add agent to potential partner list
        self.potential_partners.insert(forien_step_2_did.to_string(), agent);

        //return the final product, a response challange
        let challenge = Transitable::from_readable(&format!("{{
                \"awv\": \"0.1.0\",
                \"type\": \"awake/msg\",
                \"mid\":\"{}\",
                \"msg\": \"{}\"
            }}", 
            base64::encode(mid_future.await), msg_encrypted.as_base64()))
            .sign(&self.crypto, &self.real_private).await;

        return Some(challenge);
    }
}
async fn process_encrypted_ucan(agent:&mut ForienAgent, encrypted_ucan_str:&str, msg_count:usize) -> Value{
    let encrypted_ucan = Transitable::from_base64(encrypted_ucan_str);
    let ucan_signed = agent.decrypt_for(0, encrypted_ucan).await;
    let ucan_payload_str = ucan_signed.unsign().as_readable().unwrap();
    return serde_json::from_str(&ucan_payload_str).unwrap()
}
fn capabilities_to_value(capabilities:Array) -> Value{
    let mut caps:Vec<UcanCapability> = vec![];
    for cap in capabilities.to_vec() {
        caps.push(UcanCapability::from_object(&cap.dyn_into().unwrap()));
    }
    return serde_json::to_value(&caps).unwrap();
}
fn warn(msg:&str){
    web_sys::console::warn_1(&JsValue::from(msg));
}