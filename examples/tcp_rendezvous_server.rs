#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate net_literals;
extern crate tokio_core;
extern crate p2p;
extern crate futures;

use futures::{future, Future};
use p2p::TcpRendezvousServer;

fn main() {
    let mut core = unwrap!(tokio_core::reactor::Core::new());
    let handle = core.handle();
    let res = core.run({
        TcpRendezvousServer::bind_public(&addr!("0.0.0.0:0"), &handle)
        .map_err(|e| panic!("Error binding server publicly: {}", e))
        .and_then(|(server, public_addr)| {
            println!("listening on public socket address {}", public_addr);

            future::empty()
            .map(|()| drop(server))
        })
    });
    unwrap!(res);
}


