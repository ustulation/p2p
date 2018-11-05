pub use self::event::Event;
pub use self::overlay_connect::OverlayConnect;

use common::event_loop::{spawn_event_loop, CoreMsg};
use common::read_config;
use p2p::Config;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc;

mod event;
mod overlay_connect;

#[derive(Serialize, Deserialize)]
pub struct FullConfig {
    pub peer_cfg: PeerConfig,
    pub p2p_cfg: Config,
}

#[derive(Serialize, Deserialize)]
pub struct PeerConfig {
    overlay_addr: SocketAddr,
}

pub fn entry_point() {
    let cfg: FullConfig = read_config("./peer-config");

    let el = spawn_event_loop(cfg.p2p_cfg);
    let peer_cfg = cfg.peer_cfg;

    println!("Enter Name [Name must be unique and cannot contain spaces]:");

    let mut name = String::new();
    loop {
        unwrap!(io::stdin().read_line(&mut name));
        name = name.trim().to_string();
        if name.is_empty() || name.contains(" ") {
            println!("Invalid Name. Choose a valid Name:");
            name.clear();
        } else {
            break;
        }
    }

    let (event_tx, event_rx) = mpsc::channel();

    {
        let tx = event_tx.clone();
        let name = name.clone();
        unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
            // FIXME: Give proper address
            let overlay = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
            OverlayConnect::start(core, poll, &overlay, name, tx);
        })));
    }
}
