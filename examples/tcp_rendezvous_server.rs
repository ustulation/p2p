#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate net_literals;
extern crate tokio_core;
extern crate p2p;
extern crate futures;
extern crate serde_json;

use futures::{Future, future};
use p2p::TcpRendezvousServer;

fn main() {
    let mut core = unwrap!(tokio_core::reactor::Core::new());
    let handle = core.handle();
    let mc = p2p::P2p::default();
    let res = core.run({
        TcpRendezvousServer::bind_public(&addr!("0.0.0.0:0"), &handle, &mc)
            .map_err(|e| panic!("Error binding server publicly: {}", e))
            .and_then(|(server, public_addr)| {
                println!("listening on public socket address {}", public_addr);
                println!(
                    "our public key is: {}",
                    unwrap!(serde_json::to_string(&server.public_key()))
                );

                future::empty()
            .map(|()| drop(server))
            })
    });
    unwrap!(res);
}
