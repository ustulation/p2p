extern crate mio;
extern crate p2p;
extern crate rust_sodium as sodium;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

use self::event_loop::{El, spawn_event_loop};
use mio::Poll;
use p2p::{Handle, HolePunchMediator, Interface, NatMsg, RendezvousInfo, Res};
use std::io;
use std::sync::mpsc;

mod event_loop;

fn get_rendezvous_info(el: &El) -> Res<(Handle, RendezvousInfo)> {
    let (tx, rx) = mpsc::channel();
    unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
        let get_info = move |_: &mut Interface, _: &Poll, res| {
            unwrap!(tx.send(res));
        };
        unwrap!(HolePunchMediator::start(ifc, poll, Box::new(get_info)));
    })));

    unwrap!(rx.recv())
}

fn main() {
    let el = spawn_event_loop();
    let (handle, rendezvous_info) = match get_rendezvous_info(&el) {
        Ok((h, r)) => (h, r),
        Err(e) => {
            println!("Could not obtain rendezvous info: {:?}", e);
            println!("[Check if the rendezvous server addresses are correct and publicly \
                      reachable and that they are running].");
            return;
        }
    };
    let our_info = unwrap!(serde_json::to_string(&rendezvous_info));
    println!("Our rendezvous info:\n{}", our_info);

    println!("Enter peer rendezvous info:");
    let mut peer_info = String::new();
    unwrap!(io::stdin().read_line(&mut peer_info));
    let peers = unwrap!(serde_json::from_str(&peer_info));

    let (tx, rx) = mpsc::channel();
    handle.fire_hole_punch(peers,
                           Box::new(move |_, _, res| {
                               unwrap!(tx.send(res.is_ok()));
                           }));

    if unwrap!(rx.recv()) {
        println!("Successfully traversed NAT and established peer to peer communication :)");
    } else {
        println!("Could not traverse NAT to establish peer to peer communication :(");
    }
}
