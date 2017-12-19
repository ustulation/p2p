//! This example runs a demo rendezvous server listening on UDP port.
//! Randezvous server listens for echo requests and responds with clients address.
//! For example you can test this example with `netcat`:
//!
//! ```
//! echo -n "ECHOADDR" | nc -u $addr $port
//! 85.102.203.141:54824
//! ```
//!
//! where `$addr` and `$port` are printed to stdout when you run this example.
//! The second line is public address of the peer that called `nc`.

#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate net_literals;
extern crate tokio_core;
extern crate p2p;
extern crate futures;

use futures::{Future, future};
use p2p::UdpRendezvousServer;

fn main() {
    let mut core = unwrap!(tokio_core::reactor::Core::new());
    let handle = core.handle();
    let mc = p2p::P2p::default();
    let res = core.run({
        UdpRendezvousServer::bind_public(&addr!("0.0.0.0:0"), &handle, &mc)
            .map_err(|e| panic!("Error binding server publicly: {}", e))
            .and_then(|(server, public_addr)| {
                println!("listening on public socket address {}", public_addr);

                future::empty()
            .map(|()| drop(server))
            })
    });
    unwrap!(res);
}
