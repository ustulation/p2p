extern crate mio;
extern crate p2p;
extern crate rust_sodium as sodium;
#[macro_use]
extern crate unwrap;

use self::event_loop::{El, spawn_event_loop};
use mio::Poll;
use p2p::{Handle, HolePunchMediator, Interface, RendezvousInfo};
use std::sync::mpsc;

mod event_loop;

fn get_rendezvous_info(el: &El) -> (Handle, RendezvousInfo) {
    let (tx, rx) = mpsc::channel();
    let mut tx = Some(tx);
    unwrap!(el.nat_tx.send(Box::new(move |ifc, poll| {
        let tx = unwrap!(tx.take());
        let get_info = move |_: &mut Interface, _: &Poll, res| {
            let (handle, info) = unwrap!(res);
            unwrap!(tx.send((handle, info)));
        };
        unwrap!(HolePunchMediator::start(ifc, poll, Box::new(get_info)));
    })));

    unwrap!(rx.recv())
}

fn main() {
    let el = spawn_event_loop();
    let (_handle, rendezvous_info) = get_rendezvous_info(&el);
    println!("Our RendezvousInfo: {:?}", rendezvous_info);
}
