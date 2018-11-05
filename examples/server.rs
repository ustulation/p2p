#![allow(deprecated)]

#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate mio;
extern crate mio_extras;
extern crate p2p;
extern crate safe_crypto;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate socket_collection;
#[macro_use]
extern crate unwrap;

pub use server_impl::{entry_point, Overlay, Peer};

mod common;
mod server_impl;

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));
    entry_point();
}
