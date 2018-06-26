extern crate futures;
#[macro_use]
extern crate net_literals;
extern crate p2p;
extern crate serde_json;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

use futures::{future, Future};
use p2p::{crypto::P2pSecretId, TcpRendezvousServer};

fn main() {
    let mut core = unwrap!(tokio_core::reactor::Core::new());
    let handle = core.handle();
    let mc = p2p::P2p::<P2pSecretId>::default();
    let res = core.run({
        TcpRendezvousServer::bind_public(&addr!("0.0.0.0:0"), &handle, &mc)
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
