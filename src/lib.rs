#![cfg(target_arch = "wasm32")]

pub mod utils;
pub mod awake;
pub mod ratchet;

use wasm_bindgen::prelude::*;
use crate::awake::Awake;

#[wasm_bindgen]
pub async fn initiate() -> Awake{
    return Awake::new().await;
}