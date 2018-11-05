use common::event_loop::{Core, CoreState};
use common::types::{PeerMsg, PlainTextMsg};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use mio::{Poll, PollOpt, Ready, Token};
use p2p::{msg_to_read, msg_to_send, Interface, RendezvousInfo};
use socket_collection::TcpSock;
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::{Rc, Weak};
use std::{fmt, mem};

pub struct Peer {
    token: Token,
    sock: TcpSock,
    state: CurrentState,
    peers: Weak<RefCell<BTreeMap<String, (box_::PublicKey, Token)>>>,
}

enum CurrentState {
    AwaitingPeerPk,
    AwaitingPeerName {
        pk: box_::PublicKey,
        key: box_::PrecomputedKey,
    },
    PeerActivated {
        pk: box_::PublicKey,
        key: box_::PrecomputedKey,
        name: String,
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
        peers: Weak<RefCell<BTreeMap<String, (box_::PublicKey, Token)>>>,
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

    fn handle_peer_pk(&mut self, core: &mut Core, poll: &Poll, pk: box_::PublicKey) -> bool {
        match self.state {
            CurrentState::AwaitingPeerPk => (),
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return false;
            }
        }

        self.state = CurrentState::AwaitingPeerName {
            pk,
            key: box_::precompute(&pk, core.enc_sk()),
        };
        let overlay_pk = *core.enc_pk();

        self.write(core, poll, Some(PeerMsg::PubKey(overlay_pk)));

        true
    }

    fn handle_ciphertext(&mut self, core: &mut Core, poll: &Poll, ciphertext: &[u8]) -> bool {
        let plaintext_ser = match self.state {
            CurrentState::AwaitingPeerName { ref key, .. }
            | CurrentState::PeerActivated { ref key, .. } => match msg_to_read(ciphertext, key) {
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

        let plaintext = match deserialise::<PlainTextMsg>(&plaintext_ser) {
            Ok(pt) => pt,
            Err(e) => {
                info!("Error deserialising: {:?}", e);
                return false;
            }
        };

        match plaintext {
            PlainTextMsg::ReqUpdateName(name) => self.handle_update_name(core, poll, name),
            PlainTextMsg::ReqOnlinePeers => self.handle_req_online_peers(core, poll),
            PlainTextMsg::ReqRendezvousInfo {
                src_info,
                dst_peer,
                dst_pk,
            } => self.forward_rendezvous_impl(core, poll, src_info, dst_peer, dst_pk, true),
            PlainTextMsg::RendezvousInfoResp {
                src_info,
                dst_peer,
                dst_pk,
            } => self.forward_rendezvous_impl(core, poll, src_info, dst_peer, dst_pk, false),
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
                let ciphertext = if name.is_empty()
                    || name.contains(" ")
                    || peers.borrow().contains_key(&name)
                {
                    trace!("Invalid name or name already taken - choose a different one");
                    let resp_ser = unwrap!(serialise(&PlainTextMsg::UpdateNameResp(false)));
                    unwrap!(msg_to_send(&resp_ser, &key))
                } else {
                    let resp_ser = unwrap!(serialise(&PlainTextMsg::UpdateNameResp(true)));
                    let ciphertext = unwrap!(msg_to_send(&resp_ser, &key));

                    self.state = CurrentState::PeerActivated {
                        pk,
                        key,
                        name: name.clone(),
                    };
                    if peers.borrow_mut().insert(name, (pk, self.token)).is_some() {
                        panic!("Logic Error in updating name: name existed and is now displaced !");
                    }

                    ciphertext
                };

                self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));
                true
            }
            x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return false;
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

                let peers: Vec<(String, box_::PublicKey)> = peers
                    .borrow()
                    .iter()
                    .map(|elt| (elt.0.clone(), (elt.1).0))
                    .collect();

                let peers_ser = unwrap!(serialise(&PlainTextMsg::OnlinePeersResp(peers)));
                unwrap!(msg_to_send(&peers_ser, key))
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
        dst_peer: String,
        dst_pk: box_::PublicKey,
        is_request: bool,
    ) -> bool {
        let src_peer = match self.state {
            CurrentState::PeerActivated { ref name, .. } => name.clone(),
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
            Some(&(pk, t)) => if pk != dst_pk {
                trace!("Destination Peer is no longer the same.");
                return true;
            } else {
                t
            },
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

        let fwd_info = if is_request {
            PlainTextMsg::ForwardedRendezvousReq { src_info, src_peer }
        } else {
            PlainTextMsg::ForwardedRendezvousResp { src_info, src_peer }
        };

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
            CurrentState::PeerActivated { ref key, .. } => unwrap!(msg_to_send(&data, key)),
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return;
            }
        };
        self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        if let Some(peers) = self.peers.upgrade() {
            if let CurrentState::PeerActivated { ref name, .. } = self.state {
                let _ = peers.borrow_mut().remove(name);
            }
        }
        let _ = poll.deregister(&self.sock);
        let _ = core.remove_peer_state(self.token);
    }
}
