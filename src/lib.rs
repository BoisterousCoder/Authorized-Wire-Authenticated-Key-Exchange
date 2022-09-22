pub mod utils;

use utils::Transitable;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn handshake_initiate(text:&str) -> Transitable {
    return Transitable::from_readable(text);
}