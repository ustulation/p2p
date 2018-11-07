pub use self::event::Event;
pub use self::overlay_connect::OverlayConnect;

use common::event_loop::{spawn_event_loop, CoreMsg};
use common::read_config;
use common::types::PlainTextMsg;
use maidsafe_utilities::serialisation::serialise;
use mio::Token;
use p2p::{Config, Handle, RendezvousInfo};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

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

#[derive(Debug)]
pub enum PeerState {
    Discovered,
    CreatingRendezvousInfo {
        mediator_token: Token,
        peer_info: Option<RendezvousInfo>,
    },
    AwaitingRendezvousResp {
        p2p_handle: Handle,
    },
    AwaitingHolePunchResult,
    Connected(Token),
}

impl Default for PeerState {
    fn default() -> Self {
        PeerState::Discovered
    }
}

const MENU: &str = "
 ---------------------------------------
|  ======
| | Menu |
|  ======
| 0) Show Online & Connected (*) Peers
| 1) Refresh Online Peers List
| 2) Quit/Exit
 ---------------------------------------
";

pub fn entry_point() {
    let cfg: FullConfig = read_config("./peer-config");

    let el = spawn_event_loop(cfg.p2p_cfg);
    let peer_cfg = cfg.peer_cfg;

    println!("Enter Name [Name must be unique (preferably) and cannot contain spaces]:");

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
    let peers = Arc::new(Mutex::new(Default::default()));

    {
        let tx = event_tx.clone();
        let name = name.clone();
        let peers = peers.clone();
        let overlay = peer_cfg.overlay_addr;
        unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
            OverlayConnect::start(core, poll, &overlay, name, peers, tx);
        })));
    }

    let event = unwrap!(event_rx.recv_timeout(Duration::from_secs(5)));
    let overlay_token = match event {
        Event::OverlayConnected(t) => t,
        x => panic!("Unexpected event: {:?}", x),
    };

    let mut choice = String::new();
    loop {
        println!("\n{}\nChoose an option:", MENU);
        unwrap!(io::stdin().read_line(&mut choice));
        choice = choice.trim().to_string();

        if choice == "0" {
            let mut list = String::new();
            unwrap!(peers.lock())
                .iter()
                .for_each(|(ref id, ref peer_state)| {
                    list.push_str(&format!(
                        "{} {}\n",
                        id,
                        if let PeerState::Connected(_) = peer_state {
                            "*"
                        } else {
                            ""
                        }
                    ))
                });
            if list.is_empty() {
                list = "List is empty. Try refreshing.".to_string();
            }
            println!("List:\n{}", list);
        } else if choice == "1" {
            print!("Refreshing... ");
            unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
                if let Some(overlay) = core.peer_state(overlay_token) {
                    let m = unwrap!(serialise(&PlainTextMsg::ReqOnlinePeers));
                    overlay.borrow_mut().write(core, poll, m);
                }
            })));
            match unwrap!(event_rx.recv_timeout(Duration::from_secs(5))) {
                Event::PeersRefreshed => (),
                x => panic!("Unexpected event: {:?}", x),
            }
            println!("Done !");
        } else if choice == "2" {
            break;
        } else {
            println!("Invalid option !");
        }

        choice.clear();
    }
}
