use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{SubtleCrypto, CryptoKey};
use js_sys::{Uint8Array, Array, Function};
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
    step_1_public: CryptoKey,
    step_1_private: CryptoKey,
    step_4_public: CryptoKey,
    step_4_private: CryptoKey,
    real_public: CryptoKey,
    real_private: CryptoKey,
    potential_partners: Vec<ForienAgent>
}

#[wasm_bindgen]
impl Handshake{
    pub async fn new() -> Handshake{
        let crypto = fetch_subtle_crypto();
        let (step_1_public, step_1_private) = gen_key_pair(&crypto, false).await;
        let (step_4_public, step_4_private) = gen_key_pair(&crypto, false).await;
        let (real_public, real_private) = gen_key_pair(&crypto, true).await;
        return Handshake{
            step_1_public,
            step_1_private,
            step_4_public,
            step_4_private,
            real_public,
            real_private,
            potential_partners:vec![],
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
            &crypto_key_to_did_key(&self.crypto, &self.step_1_public).await, cap_json))
            .sign(&self.crypto, &self.real_private).await;
    }
    //Part 3.3 from spec
    pub async fn reponse(
        &mut self, 
        request_signed:Transitable, //The handshake request you are trying to respond to
        capabilities: Array, //The capabilities you have and are trying to prove to them
        lifetime: u64, //how long should the ucan be valid for
        are_capabilities_valid: Function //passes in the capabilities they want to prove and passes out a boolean on if you deem them valid
    ) -> Transitable{
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
        let mut agent = ForienAgent::new(&self.step_1_private, forien_did_key, None).await;

        //verify sender of the request
        if !agent.is_sender_of(&request_signed).await { panic!("Failed to verify sender's signature")}

        //verify the capabilities of the request
        let caps_map:HashMap<String, String> = serde_json::from_value(request_map["caps"].clone()).unwrap();
        let caps_map_js:HashMap<String, JsValue> = caps_map.iter()
            .map(|(prop, val)| (prop.clone(), JsValue::from(val))).collect();

        let is_sender_sender = are_capabilities_valid.call1(&capabilities, &hash_map_to_object(caps_map_js)).unwrap();
        if !is_sender_sender.as_bool().unwrap() { panic!("Failed to verify sender's capabilities")}

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
            .issued_by(&UcanEcdhKey::from_crypto_key(self.real_public.clone()))
            .for_audience(forien_did_key)
            .with_lifetime(lifetime)
            .with_fact(next_did_fact)
            .with_fact(oob_pin_fact)
            .build().unwrap()
            .sign().await.unwrap()
            .encode().unwrap();
        
        //encrypt the ucan and add agent to the list of potential agents
        let (_, encrypted_ucan) = agent.encrypt_for(Transitable::from_readable(&ucan)).await;
        self.potential_partners.push(agent);

        //build the response 
        let mut response = Transitable::from_readable(&format!("{{
            \"awv\": \"0.1.0\",
            \"type\": \"awake/res\",
            \"aud\":\"{}\",
            \"iss\": \"{}\",
            \"msg\": {}
        }}", forien_did_key, self_did.await, encrypted_ucan.as_base64()));
        response.sign(&self.crypto, &self.real_private).await;
        return response;
    }
    //part 3.4 from spec
    pub async fn challenge_response(){

    }
}

fn capabilities_to_value(capabilities:Array) -> Value{
    let mut caps:Vec<UcanCapability> = vec![];
    for cap in capabilities.to_vec() {
        caps.push(UcanCapability::from_object(&cap.dyn_into().unwrap()));
    }
    return serde_json::to_value(&caps).unwrap();
}