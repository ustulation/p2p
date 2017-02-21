extern crate mio;
extern crate p2p;
extern crate rust_sodium as sodium;
#[macro_use]
extern crate unwrap;

use self::event_loop::spawn_event_loop;
use p2p::{NatMsg, UdpRendezvousServer};
use std::sync::mpsc;

mod event_loop;

fn main() {
    let el = spawn_event_loop();
    unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
        unwrap!(UdpRendezvousServer::start(ifc, poll));
    })));

    let (_tx, rx) = mpsc::channel();
    println!("Server started. Blocking main thread indefinitely");
    unwrap!(rx.recv())
}
