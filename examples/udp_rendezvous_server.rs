//! This example runs a demo rendezvous server listening on UDP port.
//! Randezvous server listens for echo requests and responds with clients address.
//!
//! Use `udp_reendezvous_client` example to test this server.

extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate net_literals;
extern crate p2p;
extern crate serde_json;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

use futures::{future, Future};
use p2p::UdpRendezvousServer;

fn main() {
    unwrap!(env_logger::init());

    let mut core = unwrap!(tokio_core::reactor::Core::new());
    let handle = core.handle();
    let mc = p2p::P2p::default();
    let res = core.run({
        UdpRendezvousServer::bind_public(&addr!("0.0.0.0:0"), &handle, &mc)
            .map_err(|e| panic!("Error binding server publicly: {}", e))
            .and_then(|(server, public_addr)| {
                println!("listening on public socket address {}", public_addr);
                println!(
                    "our public key is: {}",
                    unwrap!(serde_json::to_string(&server.public_key()))
                );

                future::empty().map(|()| drop(server))
            })
    });
    unwrap!(res);
}
