use common::event_loop::{Core, CoreState};
use mio::net::TcpListener;
use mio::{Poll, PollOpt, Ready, Token};
use p2p::Interface;
use socket_collection::TcpSock;
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;
use Peer;

pub struct Overlay {
    token: Token,
    l: TcpListener,
    peers: Rc<RefCell<BTreeMap<String, (box_::PublicKey, Token)>>>,
}

impl Overlay {
    pub fn start(core: &mut Core, poll: &Poll, overlay_port: u16) {
        let local_ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), overlay_port);
        let l = unwrap!(TcpListener::bind(&local_ep));

        let token = core.new_token();

        unwrap!(poll.register(
            &l,
            token,
            Ready::readable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        ));

        let state = Self {
            token,
            l,
            peers: Rc::new(RefCell::new(Default::default())),
        };

        if core
            .insert_peer_state(token, Rc::new(RefCell::new(state)))
            .is_err()
        {
            panic!("Could not start Overlay !");
        }
    }

    fn accept(&self, core: &mut Core, poll: &Poll) {
        loop {
            match self.l.accept() {
                Ok((socket, _)) => {
                    unwrap!(socket.set_keepalive(Some(Duration::from_secs(10))));
                    let peers = Rc::downgrade(&self.peers);
                    Peer::start(core, poll, TcpSock::wrap(socket), peers);
                }
                Err(e) => {
                    if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::Interrupted {
                        warn!("Failed to accept new socket: {:?}", e);
                    }
                    break;
                }
            }
        }
    }
}

impl CoreState for Overlay {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_error() || kind.is_hup() {
            warn!("Overlay errored out");
            self.terminate(core, poll);
        } else if kind.is_readable() {
            self.accept(core, poll);
        }
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = poll.deregister(&self.l);
        let _ = core.remove_peer_state(self.token);
    }
}
