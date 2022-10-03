#![cfg(target_arch = "wasm32")]

pub mod utils;
pub mod awake;
pub mod ratchet;
pub mod forienAgent;

use wasm_bindgen::prelude::*;
use crate::awake::Awake;
