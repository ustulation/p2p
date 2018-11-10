use common::event_loop::{Core, CoreState};
use common::types::{PeerId, PeerMsg, PlainTextMsg};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use mio::{Poll, Ready, Token};
use p2p::{msg_to_read, msg_to_send, Interface};
use socket_collection::UdpSock;
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use {Event, PeerState};

pub struct ActivePeer {
    token: Token,
    sock: UdpSock,
    peer: PeerId,
    key: box_::PrecomputedKey,
    peers: Arc<Mutex<BTreeMap<PeerId, PeerState>>>,
    should_buffer: bool,
    chat_buf: Vec<String>,
    tx: Sender<Event>,
}

impl ActivePeer {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        token: Token,
        sock: UdpSock,
        peer: PeerId,
        peers: Arc<Mutex<BTreeMap<PeerId, PeerState>>>,
        tx: Sender<Event>,
    ) {
        let state = Rc::new(RefCell::new(ActivePeer {
            token,
            sock,
            peer: peer.clone(),
            key: box_::precompute(&peer.pk, core.enc_sk()),
            peers: peers.clone(),
            should_buffer: true,
            chat_buf: Default::default(),
            tx: tx.clone(),
        }));

        if let Err(e) = core.insert_peer_state(token, state) {
            info!("Could not insert peer-state: {:?}", e.1);
            unwrap!(tx.send(Event::PeerConnectFailed(peer.name)));
            return;
        }

        let peer_name = peer.name.clone();

        let mut peers_guard = unwrap!(peers.lock());
        let stored_state = peers_guard.entry(peer).or_insert(Default::default());
        *stored_state = PeerState::Connected(token);

        unwrap!(tx.send(Event::PeerConnected(peer_name, token)));
    }

    pub fn start_buffering(&mut self) {
        self.should_buffer = true;
    }

    pub fn flush_and_stop_buffering(&mut self) {
        self.should_buffer = false;
        for m in self.chat_buf.drain(..) {
            println!("{}: {}", self.peer, m);
        }
    }

    fn read(&mut self, core: &mut Core, poll: &Poll) {
        loop {
            match self.sock.read() {
                Ok(Some(PeerMsg::CipherText(ct))) => {
                    if !self.handle_ciphertext(core, poll, &ct) {
                        return self.terminate(core, poll);
                    }
                }
                Ok(Some(_)) => {
                    debug!("Invalid peer-chat message");
                    return self.terminate(core, poll);
                }
                Ok(None) => return,
                Err(e) => {
                    // TODO Make this debug better as such:
                    // debug!("{:?} - Failed to read from sock: {:?}", self.our_id, e);
                    debug!("Failed to read from sock: {:?}", e);
                    return self.terminate(core, poll);
                }
            }
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, m: Option<PeerMsg>) {
        if let Err(e) = self.sock.write(m.map(|m| (m, 0))) {
            debug!("Failed to write to sock: {:?}", e);
            self.terminate(core, poll);
        }
    }

    fn handle_ciphertext(&mut self, core: &mut Core, poll: &Poll, ciphertext: &[u8]) -> bool {
        let plaintext_ser = match msg_to_read(ciphertext, &self.key) {
            Ok(pt) => pt,
            Err(e) => {
                debug!("Error decrypting: {:?}", e);
                return true;
            }
        };

        let plaintext = match deserialise(&plaintext_ser) {
            Ok(pt) => pt,
            Err(e) => {
                info!("Error deserialising: {:?}", e);
                return false;
            }
        };

        let chat = match plaintext {
            PlainTextMsg::Chat(m) => m,
            x => {
                info!("Invalid PlainTextMsg: {:?}", x);
                return false;
            }
        };

        if self.should_buffer {
            self.chat_buf.push(chat);
        } else {
            println!("{}: {}", self.peer, chat);
        }

        true
    }
}

impl CoreState for ActivePeer {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_readable() {
            self.read(core, poll);
        } else if kind.is_writable() {
            self.write(core, poll, None)
        } else {
            warn!("Unknown kind: {:?}", kind);
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, data: Vec<u8>) {
        let ciphertext = unwrap!(msg_to_send(&data, &self.key));
        self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let mut peers_guard = unwrap!(self.peers.lock());
        if let Some(stored_state) = peers_guard.get_mut(&self.peer) {
            *stored_state = Default::default();
        }

        let _ = core.remove_peer_state(self.token);
        let _ = poll.deregister(&self.sock);
    }
}
