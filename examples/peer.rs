#![allow(deprecated)]

extern crate env_logger;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate mio;
extern crate p2p;
extern crate rust_sodium as sodium;
extern crate serde_json;
#[macro_use]
extern crate unwrap;
extern crate socket_collection;

use self::event_loop::{spawn_event_loop, Core, CoreMsg, CoreState, El};
use mio::{Poll, PollOpt, Ready, Token};
use p2p::{Handle, HolePunchInfo, HolePunchMediator, Interface, NatMsg, RendezvousInfo, Res};
use socket_collection::{UdpSock, UdtSock};
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};

#[cfg(target_family = "unix")]
use std::process::Command;

mod event_loop;

fn get_rendezvous_info(el: &El) -> Res<(Handle, RendezvousInfo)> {
    let (tx, rx) = mpsc::channel();
    unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
        let get_info = move |_: &mut Interface, _: &Poll, _nat_info, res| {
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
    sock: UdtSock,
    peer: SocketAddr,
    key: box_::PrecomputedKey,
    waiting_for_connect: bool,
    tx: mpsc::Sender<()>,
}

impl ChatEngine {
    fn start(
        core: &mut Core,
        poll: &Poll,
        token: Token,
        sock: UdpSock,
        peer: SocketAddr,
        peer_enc_pk: &box_::PublicKey,
        tx: mpsc::Sender<()>,
    ) -> Token {
        let _ = unwrap!(poll.deregister(&sock));

        let sock = unwrap!(UdtSock::wrap_udp_sock(sock, core.udt_epoll_handle()));

        unwrap!(sock.connect(&peer));

        unwrap!(poll.reregister(
            &sock,
            token,
            Ready::writable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        ));

        let engine = Rc::new(RefCell::new(ChatEngine {
            token: token,
            write_queue: VecDeque::with_capacity(5),
            read_buf: [0; 1024],
            sock: sock,
            peer: peer,
            key: box_::precompute(peer_enc_pk, core.enc_sk()),
            waiting_for_connect: true,
            tx,
        }));

        if let Err(e) = core.insert_peer_state(token, engine) {
            panic!("{}", e.1);
        }
        token
    }

    fn read(&mut self, core: &mut Core, poll: &Poll) {
        loop {
            match self.sock.read::<Vec<u8>>() {
                Ok(Some(cipher_text)) => {
                    let msg = unwrap!(String::from_utf8(unwrap!(p2p::msg_to_read(
                        &cipher_text,
                        &self.key
                    ))));
                    println!(
                        "======================\nPEER: {}\n======================",
                        msg
                    );
                }
                Ok(None) => return,
                Err(e) => {
                    debug!("Error in chat engine read: {:?}", e);
                    return self.terminate(core, poll);
                }
            }
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, m: Option<String>) {
        let cipher_text = m.map(|msg| (unwrap!(p2p::msg_to_send(msg.as_bytes(), &self.key)), 0));
        if let Err(e) = self.sock.write(cipher_text) {
            debug!("Chat engine failed to write socket: {:?}", e);
            return self.terminate(core, poll);
        }
    }
}

impl CoreState for ChatEngine {
    fn ready(&mut self, core: &mut Core, poll: &Poll, event: Ready) {
        assert!(!(event.is_error() || event.is_hup()));
        if event.is_readable() {
            self.read(core, poll)
        } else if event.is_writable() {
            if self.waiting_for_connect {
                self.waiting_for_connect = false;
                unwrap!(poll.reregister(
                    &self.sock,
                    self.token,
                    Ready::readable() | Ready::error() | Ready::hup(),
                    PollOpt::edge(),
                ));

                println!("We are UDT connected !");
                unwrap!(self.tx.send(()));
                return;
            }
            self.write(core, poll, None)
        } else {
            panic!("Unhandled event: {:?}", event);
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, m: String) {
        self.write(core, poll, Some(m))
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        println!("\nTerminating Chat Engine!");
        let _ = core.remove_state(self.token);
        let _ = poll.deregister(&self.sock);
    }
}

fn start_chatting(el: &El, token: Token, rx: mpsc::Receiver<()>) {
    println!("Waiting for a UDT connection...");
    unwrap!(rx.recv());
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

#[cfg(target_family = "unix")]
fn copy_to_clipboard(our_info: &str) {
    let xclip = format!("xclip -i -selection clipboard <<< '{}'", our_info);
    if let Ok(mut cmd) = Command::new("sh").arg("-c").arg(xclip).spawn() {
        let _ = cmd.wait();
    }
}

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let el = spawn_event_loop();
    let (handle, rendezvous_info) = match get_rendezvous_info(&el) {
        Ok((h, r)) => (h, r),
        Err(e) => {
            println!("Could not obtain rendezvous info: {:?}", e);
            println!(
                "[Check if the rendezvous server addresses are correct and publicly \
                 reachable and that they are running]."
            );
            return;
        }
    };

    let our_info = unwrap!(serde_json::to_string(&rendezvous_info));

    #[cfg(target_family = "unix")]
    copy_to_clipboard(&our_info);

    println!(
        "Our rendezvous info (Copied to clipboard on Linux if xclip's there):\n{}",
        our_info
    );

    println!(
        "\n[NOTE: For unfriendlier routers/NATs, timming can play a big role. It's \
         recommended that once the rendezvous info is exchanged, both parties hit \"Enter\" \
         as closely in time as possible. Usually with an overlay network to exchange this \
         info there won't be a problem, but when doing it manually it could be of benefit \
         to do it as simultaneously as possible.]\n"
    );

    println!("Enter peer rendezvous info:");
    let mut peer_info = String::new();
    unwrap!(io::stdin().read_line(&mut peer_info));
    let peers = unwrap!(serde_json::from_str(&peer_info));

    let (tx, rx) = mpsc::channel();
    handle.fire_hole_punch(
        peers,
        Box::new(move |_, _, res| {
            unwrap!(tx.send(res));
        }),
    );

    let HolePunchInfo { tcp, udp, enc_pk } = match unwrap!(rx.recv()) {
        Ok(info) => {
            println!("Successfully traversed NAT and established peer to peer communication :)\n");
            info
        }
        Err(e) => {
            println!(
                "Could not traverse NAT to establish peer to peer communication: {:?}",
                e
            );
            return;
        }
    };

    let (sock, peer, token) = match (udp, tcp) {
        (Some(udp_hp_info), Some(tcp_hp_info)) => {
            println!(
                "Connected via both, TCP and UDP.\nTCP details: {:?}\nUDP details: {:?}\n\n
                     Choosing UDP...\n",
                tcp_hp_info, udp_hp_info
            );
            (udp_hp_info.sock, udp_hp_info.peer, udp_hp_info.token)
        }
        (Some(udp_hp_info), None) => {
            println!("Connected only via UDP.\nUDP details: {:?}\n", udp_hp_info);
            (udp_hp_info.sock, udp_hp_info.peer, udp_hp_info.token)
        }
        (None, Some(tcp_hp_info)) => {
            println!(
                "Connected only via TCP.\nTCP details: {:?}\n\nThis example only supports \
                 communicating via udp-socket but it seems it's tcp hole punching that has \
                 succeeded instead. It is trivial to implement tcp communication for the chat \
                 engine and is left for future scope. Terminating for the moment.",
                tcp_hp_info
            );
            return;
        }
        (None, None) => unreachable!(
            "This condition should not have been passed over to the user \
             code!"
        ),
    };

    if false {
        let (tx, rx) = mpsc::channel();
        unwrap!(el.core_tx.send(CoreMsg::new(move |core, poll| {
            let _token = ChatEngine::start(core, poll, token, sock, peer, &enc_pk, tx);
        })));

        start_chatting(&el, token, rx);
    } else {
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}
