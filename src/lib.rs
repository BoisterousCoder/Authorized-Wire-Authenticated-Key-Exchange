use utils::Transitable;

pub mod utils;
pub mod awake;

use wasm_bindgen::prelude::*;
use crate::awake::Awake;

#[wasm_bindgen]
pub async fn initiate() -> Awake{
    return Awake::new().await;
}