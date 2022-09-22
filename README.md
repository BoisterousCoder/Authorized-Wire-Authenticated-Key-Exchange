# Authorized Wire Authenticated Key Exchange (AWAKE)
This repo is an implimentation of the Awake Protocol Specification (https://github.com/ucan-wg/awake)

## About:
"AWAKE bootstraps a secure session on top of a public channel. Key exchanges for point-to-point communication are plentiful, but in open, trustless protocols, rooting trust can be a barrier for ad hoc communications channels. Two common approaches are to use a trusted certificate authority, or ignore the principal and "merely" establish a point-to-point channel.

Capability-based systems have a helpful philosophy towards a third path. By emphasizing authorization over authentication, they provide a way to know something provable about what the other party "can do", even if they have no sure way of knowing "who they are". One way of phrasing this is that such an agent is "functionally equivalent to the principal in this context". AWAKE makes use of authorization to bootstrap point-to-point sessions that are both secure and mutually trusted." ~Introduction to AWAKE from (https://github.com/ucan-wg/awake)

## How do you use it:

This app depends on the Rust programming language, and the Wasm-Pack tools to build.

### To build:
  
#### From source
1. Clone this repository
1. ensure Rust (https://www.rust-lang.org/learn/get-started) and Wasm-pack (https://rustwasm.github.io/wasm-pack/installer/) are installed
1. Run `$ wasm build --target web` to install libraries and build the prograam

To rust tests use `wasm-pack test --headless --firefox`

### How to Use
This is a TODO

## License
Licensed under Mozzilla Public License 2.0