#![allow(deprecated)]

#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate mio;
extern crate p2p;
extern crate rust_sodium as sodium;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate socket_collection;
#[macro_use]
extern crate unwrap;

pub use peer_impl::{entry_point, Event, OverlayConnect};

mod common;
mod peer_impl;

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));
    entry_point();
}
