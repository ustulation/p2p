pub use self::overlay::Overlay;
pub use self::peer::Peer;

use common::event_loop::{spawn_event_loop, CoreMsg};
use common::read_config;
use p2p::{Config, NatMsg, TcpRendezvousServer, UdpRendezvousServer};
use std::io;
use std::sync::mpsc;

mod overlay;
mod peer;

#[derive(Serialize, Deserialize)]
pub struct FullConfig {
    pub server_cfg: ServerConfig,
    pub p2p_cfg: Config,
}

#[derive(Serialize, Deserialize)]
pub struct ServerConfig {
    overlay_port: u16,
}

pub fn entry_point() {
    let cfg: FullConfig = read_config("./server-config");

    let el = spawn_event_loop(cfg.p2p_cfg);
    let server_cfg = cfg.server_cfg;

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
            Overlay::start(core, poll, server_cfg.overlay_port);
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
