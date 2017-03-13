extern crate mio;
extern crate p2p;
extern crate rust_sodium as sodium;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

use self::event_loop::{Core, CoreMsg, CoreState, El, spawn_event_loop};
use mio::{Poll, PollOpt, Ready, Token};
use mio::udp::UdpSocket;
use p2p::{Handle, HolePunchMediator, Interface, NatMsg, RendezvousInfo, Res};
use p2p::HolePunchInfo;
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::rc::Rc;
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

struct ChatEngine {
    token: Token,
    write_queue: VecDeque<Vec<u8>>,
    read_buf: [u8; 1024],
    sock: UdpSocket,
    peer: SocketAddr,
    key: box_::PrecomputedKey,
}

impl ChatEngine {
    fn start(core: &mut Core,
             poll: &Poll,
             token: Token,
             sock: UdpSocket,
             peer: SocketAddr,
             peer_enc_pk: &box_::PublicKey)
             -> Token {
        unwrap!(poll.reregister(&sock,
                                token,
                                Ready::readable() | Ready::error() | Ready::hup(),
                                PollOpt::edge()));
        let engine = Rc::new(RefCell::new(ChatEngine {
                                              token: token,
                                              write_queue: VecDeque::with_capacity(5),
                                              read_buf: [0; 1024],
                                              sock: sock,
                                              peer: peer,
                                              key: box_::precompute(peer_enc_pk, core.enc_sk()),
                                          }));

        if let Err(e) = core.insert_peer_state(token, engine) {
            panic!("{}", e.1);
        }
        token
    }

    fn read(&mut self, _core: &mut Core, _poll: &Poll) {
        let bytes_rxd = match self.sock.recv_from(&mut self.read_buf) {
            Ok(Some((bytes_rxd, _))) => bytes_rxd,
            Ok(None) => return,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => return,
            Err(e) => panic!("Error in chat engine read: {:?}", e),

        };

        let msg = unwrap!(String::from_utf8(unwrap!(p2p::msg_to_read(&self.read_buf
                                                                          [..bytes_rxd],
                                                                     &self.key))));
        println!("======================\nPEER: {}\n======================",
                 msg);
    }

    fn write(&mut self, _core: &mut Core, poll: &Poll, m: Option<String>) {
        let m = match m {
            Some(m) => {
                let cipher_text = unwrap!(p2p::msg_to_send(m.as_bytes(), &self.key));
                if self.write_queue.is_empty() {
                    cipher_text
                } else {
                    self.write_queue.push_back(cipher_text);
                    return;
                }
            }
            None => {
                match self.write_queue.pop_front() {
                    Some(cipher_text) => cipher_text,
                    None => return,
                }
            }
        };

        match self.sock.send_to(&m, &self.peer) {
            Ok(Some(bytes_txd)) => assert!(bytes_txd == m.len()),
            Ok(None) => self.write_queue.push_front(m),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => self.write_queue.push_front(m),
            Err(e) => panic!("Error in chat engine write: {:?}", e),
        }

        let interest = if self.write_queue.is_empty() {
            Ready::readable() | Ready::error() | Ready::hup()
        } else {
            Ready::writable() | Ready::readable() | Ready::error() | Ready::hup()
        };

        unwrap!(poll.reregister(&self.sock, self.token, interest, PollOpt::edge()));
    }
}

impl CoreState for ChatEngine {
    fn ready(&mut self, core: &mut Core, poll: &Poll, event: Ready) {
        assert!(!(event.is_error() || event.is_hup()));
        if event.is_readable() {
            self.read(core, poll)
        } else if event.is_writable() {
            self.write(core, poll, None)
        } else {
            panic!("Unhandled event: {:?}", event);
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, m: String) {
        self.write(core, poll, Some(m))
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.sock);
    }
}

fn start_chatting(el: &El, token: Token) {
    println!("Begin chatting with peer (type \"quit\" to quit)");

    loop {
        let mut input = String::new();
        let _ = unwrap!(io::stdin().read_line(&mut input));
        input = input.trim().to_owned();

        if input == "quit" {
            break;
        }

        unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
                                                 let chat_engine = unwrap!(core.peer_state(token));
                                                 chat_engine.borrow_mut().write(core, poll, input);
                                             })));
    }
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

    println!("\n[NOTE: For unfriendlier routers/NATs, timming can play a big role. It's \
              recommended that once the rendezvous info is exchanged, both parties hit \"Enter\" \
              as closely in time as possible. Usually with an overlay network to exchange this \
              info there won't be a problem, but when doing it manually it could be of benefit \
              to do it as simultaneously as possible.]\n");

    println!("Enter peer rendezvous info:");
    let mut peer_info = String::new();
    unwrap!(io::stdin().read_line(&mut peer_info));
    let peers = unwrap!(serde_json::from_str(&peer_info));

    let (tx, rx) = mpsc::channel();
    handle.fire_hole_punch(peers,
                           Box::new(move |_, _, res| {
                                        unwrap!(tx.send(res));
                                    }));

    let HolePunchInfo { tcp, udp, enc_pk } = match unwrap!(rx.recv()) {
        Ok(info) => {
            println!("Successfully traversed NAT and established peer to peer communication :)\n");
            info
        }
        Err(e) => {
            println!("Could not traverse NAT to establish peer to peer communication: {:?}",
                     e);
            return;
        }
    };

    let (sock, peer, token) = match (udp, tcp) {
        (Some(info), Some(_)) => {
            println!("Connected via both, TCP and UDP. Choosing UDP...\n");
            info
        }
        (Some(info), None) => {
            println!("Connected only via UDP\n");
            info
        }
        (None, Some(_)) => {
            println!("Connected only via TCP. This example only supports communicating via \
                      udp-socket but it seems it's tcp hole punching that has succeeded instead. \
                      It is trivial to implement tcp communication for the chat engine and is \
                      left for future scope. Terminating for the moment.");
            return;
        }
        (None, None) => {
            unreachable!("This condition should not have been passed over to the user \
                                     code!")
        }
    };

    unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
        let _token = ChatEngine::start(core, poll, token, sock, peer, &enc_pk);
    })));

    start_chatting(&el, token);
}
