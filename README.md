# Authorized Wire Authenticated Key Exchange (AWAKE)
This repo is an implimentation of the Awake Protocol Specification (https://github.com/ucan-wg/awake)

## About:
"AWAKE bootstraps a secure session on top of a public channel. Key exchanges for point-to-point communication are plentiful, but in open, trustless protocols, rooting trust can be a barrier for ad hoc communications channels. Two common approaches are to use a trusted certificate authority, or ignore the principal and "merely" establish a point-to-point channel.

Capability-based systems have a helpful philosophy towards a third path. By emphasizing authorization over authentication, they provide a way to know something provable about what the other party "can do", even if they have no sure way of knowing "who they are". One way of phrasing this is that such an agent is "functionally equivalent to the principal in this context". AWAKE makes use of authorization to bootstrap point-to-point sessions that are both secure and mutually trusted." ~Introduction to AWAKE from (https://github.com/ucan-wg/awake)

## How do you use it:

This app depends on the Rust programming language, and the Wasm-Pack tools to build.

### To build source:
1. Clone this repository
1. ensure Rust (https://www.rust-lang.org/learn/get-started) and Wasm-pack (https://rustwasm.github.io/wasm-pack/installer/) are installed
1. Run `$ wasm build --target web` to install libraries and build the prograam

To rust tests use `wasm-pack test --headless --firefox`

### How to Use
This is a TODO

## Known Issue
    - does not fail to failed awake message when it is required.
    - only supports oob-pin for verification of requestor.
    - more error handling is needed in most places
    - more comments are needed in most place
    - utils could be split into multiple files
    - there may be room for small performance imporvements moving around awaits
    - more tests need to writen
    - tests should be organised better
    - an example of how to use the library needs to be writen
    - signatures on incomimng awake resquests probably need to be checked
    - exposed methods and properties need to be allowed to be accessed more js friendly names
    - the acknoledge step of the handshake needs to be finished
    - a *Messages* struct needs to be created to handle using the *final_agent* to encrypt/decrypt messages between agents
    - there needs a wrapper around *Handshake* and *Message* inorder to sort messages based on what part of the handshake proccess they are apart of
    - unused imports and other compiler warnings need to be taken care of
## License
Licensed under Mozzilla Public License 2.0