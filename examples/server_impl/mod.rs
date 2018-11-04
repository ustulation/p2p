pub use self::overlay::Overlay;
pub use self::peer::Peer;

use common::event_loop::{spawn_event_loop, CoreMsg};
use p2p::{NatMsg, TcpRendezvousServer, UdpRendezvousServer};
use std::io;
use std::sync::mpsc;

mod overlay;
mod peer;

const OVERLAY_PORT: u16 = 31567;

pub fn entry_point() {
    let el = spawn_event_loop();

    {
        let (tx, rx) = mpsc::channel();
        unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
            let _token_udp = unwrap!(UdpRendezvousServer::start(ifc, poll));
            let _token_tcp = unwrap!(TcpRendezvousServer::start(ifc, poll));
            unwrap!(tx.send(()));
        })));
        unwrap!(rx.recv());
    }

    println!("Rendezvous servers started successfully.");
    println!("Should this node also be the overlay [y/n] ?");

    let mut answer = String::new();
    unwrap!(io::stdin().read_line(&mut answer));
    answer = answer.trim().to_string().to_lowercase();

    if answer == "y" || answer == "yes" {
        let (tx, rx) = mpsc::channel();
        unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
            Overlay::start(core, poll, OVERLAY_PORT);
            unwrap!(tx.send(()));
        })));
        unwrap!(rx.recv());
        println!("Overlay started successfully.");
    }

    println!("Everything done. Blocking main thread until user quits.");
    let mut quit = String::new();
    loop {
        println!("Enter 'q' to quit");
        unwrap!(io::stdin().read_line(&mut quit));
        quit = quit.trim().to_string().to_lowercase();
        if quit == "q" || quit == "quit" {
            break;
        }
        quit.clear();
    }
}
