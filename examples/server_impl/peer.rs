use common::event_loop::{Core, CoreState};
use common::types::{PeerId, PeerMsg, PlainTextMsg};
use maidsafe_utilities::serialisation::serialise;
use mio::{Poll, PollOpt, Ready, Token};
use p2p::{Interface, RendezvousInfo};
use safe_crypto::{PublicEncryptKey, SharedSecretKey};
use socket_collection::TcpSock;
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::{Rc, Weak};
use std::{fmt, mem};

pub struct Peer {
    token: Token,
    sock: TcpSock,
    state: CurrentState,
    peers: Weak<RefCell<BTreeMap<PeerId, Token>>>,
}

enum CurrentState {
    AwaitingPeerPk,
    AwaitingPeerName {
        pk: PublicEncryptKey,
        key: SharedSecretKey,
    },
    PeerActivated {
        id: PeerId,
        key: SharedSecretKey,
    },
}

impl Default for CurrentState {
    fn default() -> Self {
        CurrentState::AwaitingPeerPk
    }
}

impl fmt::Debug for CurrentState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CurrentState::AwaitingPeerPk => write!(f, "CurrentState::AwaitingPeerPk"),
            CurrentState::AwaitingPeerName { .. } => write!(f, "CurrentState::AwaitingPeerName"),
            CurrentState::PeerActivated { .. } => write!(f, "CurrentState::PeerActivated"),
        }
    }
}

impl Peer {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        sock: TcpSock,
        peers: Weak<RefCell<BTreeMap<PeerId, Token>>>,
    ) {
        let token = core.new_token();

        unwrap!(poll.register(
            &sock,
            token,
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        ));

        let state = Self {
            token,
            sock,
            state: Default::default(),
            peers,
        };

        if core
            .insert_peer_state(token, Rc::new(RefCell::new(state)))
            .is_err()
        {
            panic!("Could not start Overlay !");
        }
    }

    fn read(&mut self, core: &mut Core, poll: &Poll) {
        loop {
            match self.sock.read() {
                Ok(Some(PeerMsg::PubKey(pk))) => {
                    if !self.handle_peer_pk(core, poll, pk) {
                        return self.terminate(core, poll);
                    }
                }
                Ok(Some(PeerMsg::CipherText(ct))) => {
                    if !self.handle_ciphertext(core, poll, &ct) {
                        return self.terminate(core, poll);
                    }
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

    fn handle_peer_pk(&mut self, core: &mut Core, poll: &Poll, pk: PublicEncryptKey) -> bool {
        match self.state {
            CurrentState::AwaitingPeerPk => (),
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return false;
            }
        }

        self.state = CurrentState::AwaitingPeerName {
            pk,
            key: core.enc_sk().shared_secret(&pk),
        };
        let overlay_pk = *core.enc_pk();

        self.write(core, poll, Some(PeerMsg::PubKey(overlay_pk)));

        true
    }

    fn handle_ciphertext(&mut self, core: &mut Core, poll: &Poll, ciphertext: &[u8]) -> bool {
        let plaintext = match self.state {
            CurrentState::AwaitingPeerName { ref key, .. }
            | CurrentState::PeerActivated { ref key, .. } => match key.decrypt(ciphertext) {
                Ok(pt) => pt,
                Err(e) => {
                    info!("Error decrypting: {:?}", e);
                    return false;
                }
            },
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return false;
            }
        };

        match plaintext {
            PlainTextMsg::ReqUpdateName(name) => self.handle_update_name(core, poll, name),
            PlainTextMsg::ReqOnlinePeers => self.handle_req_online_peers(core, poll),
            PlainTextMsg::ExchgRendezvousInfo { src_info, dst_peer } => {
                self.forward_rendezvous_impl(core, poll, src_info, dst_peer)
            }
            x => {
                info!("Invalid PlainTextMsg: {:?}", x);
                return false;
            }
        }
    }

    fn handle_update_name(&mut self, core: &mut Core, poll: &Poll, name: String) -> bool {
        let peers = match self.peers.upgrade() {
            Some(peers) => peers,
            None => {
                warn!("Peer list unexpectedly unavailable !");
                return false;
            }
        };

        match mem::replace(&mut self.state, Default::default()) {
            CurrentState::AwaitingPeerName { pk, key } => {
                let id = PeerId::new(name, pk);
                let ciphertext = if id.name.is_empty()
                    || id.name.contains(" ")
                    || peers.borrow().contains_key(&id)
                {
                    trace!("Invalid name or identity already taken - choose a different one");
                    let resp = PlainTextMsg::UpdateNameResp(false);
                    let ciphertext = unwrap!(key.encrypt(&resp));

                    self.state = CurrentState::AwaitingPeerName { pk, key };

                    ciphertext
                } else {
                    let resp = PlainTextMsg::UpdateNameResp(true);
                    let ciphertext = unwrap!(key.encrypt(&resp));

                    self.state = CurrentState::PeerActivated {
                        id: id.clone(),
                        key,
                    };
                    if peers.borrow_mut().insert(id, self.token).is_some() {
                        panic!("Logic Error in updating name: id existed and is now displaced !");
                    }

                    ciphertext
                };

                self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));
                true
            }
            x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                false
            }
        }
    }

    fn handle_req_online_peers(&mut self, core: &mut Core, poll: &Poll) -> bool {
        let ciphertext = match self.state {
            CurrentState::PeerActivated { ref key, .. } => {
                let peers = match self.peers.upgrade() {
                    Some(peers) => peers,
                    None => {
                        warn!("Peer list unexpectedly unavailable !");
                        return false;
                    }
                };

                let peers: Vec<PeerId> = peers.borrow().keys().cloned().collect();
                let peers = PlainTextMsg::OnlinePeersResp(peers);
                unwrap!(key.encrypt(&peers))
            }
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return false;
            }
        };

        self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));

        true
    }

    fn forward_rendezvous_impl(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        src_info: RendezvousInfo,
        dst_peer: PeerId,
    ) -> bool {
        let src_peer = match self.state {
            CurrentState::PeerActivated { ref id, .. } => id.clone(),
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return false;
            }
        };

        let peers = match self.peers.upgrade() {
            Some(peers) => peers,
            None => {
                warn!("Peer list unexpectedly unavailable !");
                return false;
            }
        };

        let dst_token = match peers.borrow().get(&dst_peer) {
            Some(&t) => t,
            None => {
                trace!("Destination Peer is no longer online.");
                return true;
            }
        };

        let dst_peer_state = match core.peer_state(dst_token) {
            Some(ps) => ps,
            None => {
                warn!("Destination Peer is online but does not have a peer-state.");
                return true;
            }
        };

        let fwd_info = PlainTextMsg::FwdRendezvousInfo { src_info, src_peer };

        let fwd_info_ser = unwrap!(serialise(&fwd_info));
        dst_peer_state.borrow_mut().write(core, poll, fwd_info_ser);

        true
    }
}

impl CoreState for Peer {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_readable() {
            self.read(core, poll)
        } else if kind.is_writable() {
            self.write(core, poll, None)
        } else {
            warn!("Unknown kind: {:?}", kind);
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, data: Vec<u8>) {
        let ciphertext = match self.state {
            CurrentState::PeerActivated { ref key, .. } => unwrap!(key.encrypt_bytes(&data)),
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return;
            }
        };
        self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        if let Some(peers) = self.peers.upgrade() {
            if let CurrentState::PeerActivated { ref id, .. } = self.state {
                let _ = peers.borrow_mut().remove(&id);
            }
        }
        let _ = poll.deregister(&self.sock);
        let _ = core.remove_peer_state(self.token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
