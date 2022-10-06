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
        let self_did = crypto_key_to_did_key(&self.crypto, &self.real_public);

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
        let mut agent = ForienAgent::new(&self.real_private, forien_did_key, None).await;

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
        let mut response = Transitable::from_readable(&format!("{{
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
        oob_pin: JsValue, //The out of bounds pin to prove who you are
        is_ucan_valid: Function //passes in the capabilities they want to prove and passes out a boolean on if you deem them valid){
    )-> Option<Transitable> {
        if self.is_done{
            panic!("This awake object has already conducted a handshake. Please initialize a new awake object to conduct more conections.")
        }

        //get requestor's data from request
        let response = response_signed.unsign();
        let response_str = match response_signed.as_readable(){
            Some(x) => x,
            None => panic!("The handshake init was not sent properly or the transitable is not a handshake request")
        };
        let response_map:Value = match serde_json::from_str(&response_str){
            Ok(x) => x,
            Err(_) => panic!("The handshake was not sent in the proper json format")
        };

        //init agent
        let forien_iss_did_key = &response_map["did"].as_str().unwrap();
        let mut agent = ForienAgent::new(&self.real_private, forien_iss_did_key, None).await;

        //verify sender of the response
        if !agent.is_sender_of(&response_signed).await {
            warn("Failed to verify sender's signature");
            return None;
        }

        //get ucan string
        let encrypted_ucan = Transitable::from_readable(&response_map["msg"].as_str().unwrap());
        let ucan_signed_str = agent.decrypt_for(0, encrypted_ucan).await.as_readable().unwrap();


        //check if ucan is valid
        // let ucan_js = JSON::parse(ucan_str).unwrap();
        // let is_sender_capable = is_ucan_valid.call1(&ucan_js, &ucan_js).unwrap();
        // if !is_sender_capable.as_bool().unwrap() { 
        //     warn("Failed to verify sender's capabilities");
        //     return None;
        // }
        return Some(Transitable::from_readable(""));

        //let mid_future = get_message_id(&self.crypto, );
    }
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