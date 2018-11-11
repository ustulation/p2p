pub use self::active_peer::ActivePeer;
pub use self::event::Event;
pub use self::overlay_connect::OverlayConnect;

use common::event_loop::{spawn_event_loop, CoreMsg, El};
use common::read_config;
use common::types::PlainTextMsg;
use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::{self, Joiner};
use mio::Token;
use p2p::{Config, Handle, RendezvousInfo};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

mod active_peer;
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
    AwaitingPeerRendezvous {
        since: Instant,
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
 -------------------------------------------
|  ======
| | Menu |
|  ======
| 1) Show Online & Connected (*) Peers
| 2) Refresh Online Peers List
| 3) Connect to
| 4) Chat with
| 5) Information about inputs to (2) and (3)
| 0) Quit/Exit
 -------------------------------------------
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
    println!("{}", event);
    let overlay_token = match event {
        Event::OverlayConnected(t) => t,
        x => panic!("Unexpected event: {:?}", x),
    };

    let _j = print_events(event_rx);

    let mut choice = String::new();
    loop {
        println!("\n{}\nChoose an option:", MENU);
        unwrap!(io::stdin().read_line(&mut choice));
        choice = choice.trim().to_string();

        if choice == "1" {
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
        } else if choice == "2" {
            print!("Refreshing... ");
            unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
                if let Some(overlay) = core.peer_state(overlay_token) {
                    let m = unwrap!(serialise(&PlainTextMsg::ReqOnlinePeers));
                    overlay.borrow_mut().write(core, poll, m);
                }
            })));
        } else if choice == "3" {
            println!("Enter peer id. Partial id/name can be given:");

            let mut peer_choice = String::new();
            unwrap!(io::stdin().read_line(&mut peer_choice));
            peer_choice = peer_choice.trim().to_string();

            let mut found_peer = None;
            {
                let peers_guard = unwrap!(peers.lock());
                for (id, peer_state) in &*peers_guard {
                    let peer_fmt = format!("{}", id);
                    if peer_fmt.contains(&peer_choice) {
                        if let PeerState::Discovered = peer_state {
                            if found_peer.is_some() {
                                println!(
                                    "Ambiguous, multiple matches found. More qualification needed."
                                );
                                found_peer = None;
                                break;
                            } else {
                                found_peer = Some(id.clone());
                            }
                        } else {
                            println!(
                                "Peer is either in the process of being connected or is already \
                                 connected. Check status after sometime and retry if necessary."
                            );
                            found_peer = None;
                            break;
                        }
                    }
                }
            }

            if let Some(peer_id) = found_peer {
                unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
                    let overlay = unwrap!(core.peer_state(overlay_token));
                    let mut overlay = overlay.borrow_mut();
                    let overlay_connect =
                        unwrap!(overlay.as_any().downcast_mut::<OverlayConnect>());
                    overlay_connect.start_connect_with_peer(core, poll, peer_id.clone());
                })));
            } else {
                println!("Aborting due to previous errors (if printed) or due to peer not found.");
            }
        } else if choice == "4" {
            println!("Enter peer id. Partial id/name can be given:");

            let mut peer_choice = String::new();
            unwrap!(io::stdin().read_line(&mut peer_choice));
            peer_choice = peer_choice.trim().to_string();

            let mut found_peer = None;
            {
                let peers_guard = unwrap!(peers.lock());
                for (id, peer_state) in &*peers_guard {
                    let peer_fmt = format!("{}", id);
                    if peer_fmt.contains(&peer_choice) {
                        if let PeerState::Connected(token) = peer_state {
                            if found_peer.is_some() {
                                println!(
                                    "Ambiguous, multiple matches found. More qualification needed."
                                );
                                found_peer = None;
                                break;
                            } else {
                                found_peer = Some(*token);
                            }
                        } else {
                            println!(
                                "Peer is not connected. Check status after sometime and retry if \
                                 necessary."
                            );
                            found_peer = None;
                            break;
                        }
                    }
                }
            }

            if let Some(token) = found_peer {
                let (tx, rx) = mpsc::channel();
                let tx_clone = tx.clone();
                unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
                    let peer = unwrap!(core.peer_state(token));
                    let mut peer = peer.borrow_mut();
                    let active_peer = unwrap!(peer.as_any().downcast_mut::<ActivePeer>());
                    active_peer.flush_and_stop_buffering();

                    unwrap!(tx_clone.send(()));
                })));

                unwrap!(rx.recv());
                let disconnected = start_chat(&el, token);

                if !disconnected {
                    unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
                        let peer = unwrap!(core.peer_state(token));
                        let mut peer = peer.borrow_mut();
                        let active_peer = unwrap!(peer.as_any().downcast_mut::<ActivePeer>());
                        active_peer.start_buffering();

                        unwrap!(tx.send(()));
                    })));
                    unwrap!(rx.recv());
                }
            } else {
                println!("Aborting due to previous errors (if printed) or due to peer not found.");
            }
        } else if choice == "5" {
            println!(
                "E.g. if the list has a peer id as \"Blah (1baf3e..)\" you may enter the \
                 whole thing as is, or just \"Blah\" or just \"lah\" or just \"af3e\" etc. all \
                 without quotes. However if the list also contains someone else like \"Blah-blah\" \
                 then \"lah\" will match that too and return error for non unique match. In such \
                 cases qualify more until you have a unique match, giving the whole ID in the worst \
                 case."
            );
        } else if choice == "0" {
            break;
        } else {
            println!("Invalid option !");
        }

        choice.clear();
    }

    unwrap!(event_tx.send(Event::Quit));
}

fn start_chat(el: &El, peer: Token) -> bool {
    println!("Enter (without quotes) \"<quit>\" to exit this chat.");

    let mut disconnected = false;
    let (tx, rx) = mpsc::channel();
    loop {
        let mut input = String::new();
        let _ = unwrap!(io::stdin().read_line(&mut input));
        input = input.trim().to_owned();

        if input == "<quit>" {
            break;
        }

        let m = unwrap!(serialise(&PlainTextMsg::Chat(input)));

        let tx = tx.clone();
        unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
            if let Some(active_peer) = core.peer_state(peer) {
                active_peer.borrow_mut().write(core, poll, m);
                unwrap!(tx.send(true));
            } else {
                unwrap!(tx.send(false));
            }
        })));

        if !unwrap!(rx.recv()) {
            println!("Peer is now disconnected. Try reconnecting to chat again.");
            disconnected = true;
            break;
        }
    }

    disconnected
}

fn print_events(rx: mpsc::Receiver<Event>) -> Joiner {
    thread::named("Event-Rx", move || {
        for event in rx.iter() {
            match event {
                Event::Quit => break,
                e => println!("{}", e),
            }
        }
    })
}
