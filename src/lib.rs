#[macro_use]
extern crate lazy_static;
extern crate tokio_io;
extern crate tokio_core;
extern crate futures;
extern crate rust_sodium as sodium;
extern crate get_if_addrs;
#[macro_use]
extern crate unwrap;
extern crate rand;
extern crate bytes;
extern crate net2;
#[macro_use]
extern crate net_literals;
extern crate rust_sodium;
extern crate bincode;
extern crate future_utils;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate env_logger;
extern crate void;
#[macro_use]
extern crate log;
#[macro_use]
extern crate quick_error;
extern crate igd;
extern crate tokio_shared_udp_socket;
#[cfg(test)]
#[macro_use]
extern crate maplit;

mod priv_prelude;
mod prelude;

mod protocol;
mod ip_addr;
mod socket_addr;
mod tcp;
mod udp;
mod util;
mod server_set;
mod mc;
mod igd_async;
mod open_addr;
mod rendezvous_addr;
mod filter_addrs;

pub use prelude::*;

pub const ECHO_REQ: [u8; 8] = [b'E', b'C', b'H', b'O', b'A', b'D', b'D', b'R'];
