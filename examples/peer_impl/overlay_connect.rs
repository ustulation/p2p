use common::event_loop::{Core, CoreState};
use common::types::{PeerId, PeerMsg, PlainTextMsg};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use mio::{Poll, PollOpt, Ready, Token};
use p2p::{msg_to_read, msg_to_send, Interface, RendezvousInfo};
use socket_collection::TcpSock;
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::{fmt, mem};
use Event;

pub struct OverlayConnect {
    token: Token,
    sock: TcpSock,
    our_name: String,
    state: CurrentState,
    peers: Arc<Mutex<BTreeMap<PeerId, Option<Token>>>>,
    tx: Sender<Event>,
}

enum CurrentState {
    Init,
    AwaitingOverlayPk,
    AwaitingUpdateNameResp {
        pk: box_::PublicKey,
        key: box_::PrecomputedKey,
    },
    OverlayActivated {
        pk: box_::PublicKey,
        key: box_::PrecomputedKey,
    },
}

impl Default for CurrentState {
    fn default() -> Self {
        CurrentState::Init
    }
}

impl fmt::Debug for CurrentState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CurrentState::Init => write!(f, "CurrentState::Init"),
            CurrentState::AwaitingOverlayPk => write!(f, "CurrentState::AwaitingOverlayPk"),
            CurrentState::AwaitingUpdateNameResp { .. } => {
                write!(f, "CurrentState::AwaitingUpdateNameResp")
            }
            CurrentState::OverlayActivated { .. } => write!(f, "CurrentState::OverlayActivated"),
        }
    }
}

impl OverlayConnect {
    pub fn start(
        core: &mut Core,
        poll: &Poll,
        overlay: &SocketAddr,
        our_name: String,
        peers: Arc<Mutex<BTreeMap<PeerId, Option<Token>>>>,
        tx: Sender<Event>,
    ) {
        let token = core.new_token();
        let sock = unwrap!(TcpSock::connect(overlay));

        unwrap!(poll.register(
            &sock,
            token,
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        ));

        let state = Rc::new(RefCell::new(OverlayConnect {
            token,
            sock,
            our_name,
            state: Default::default(),
            peers: peers,
            tx,
        }));

        if core.insert_peer_state(token, state).is_err() {
            panic!("Could not start Overlay !");
        }
    }

    fn read(&mut self, core: &mut Core, poll: &Poll) {
        loop {
            match self.sock.read() {
                Ok(Some(PeerMsg::PubKey(pk))) => {
                    if !self.handle_overlay_pk(core, poll, pk) {
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

    fn handle_overlay_pk(&mut self, core: &mut Core, poll: &Poll, pk: box_::PublicKey) -> bool {
        match self.state {
            CurrentState::AwaitingOverlayPk => (),
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return false;
            }
        }

        let key = box_::precompute(&pk, core.enc_sk());

        let update_name = unwrap!(serialise(&PlainTextMsg::ReqUpdateName(
            self.our_name.clone()
        )));
        let ciphertext = unwrap!(msg_to_send(&update_name, &key));

        self.state = CurrentState::AwaitingUpdateNameResp { pk, key };

        self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));

        true
    }

    fn handle_ciphertext(&mut self, core: &mut Core, poll: &Poll, ciphertext: &[u8]) -> bool {
        let plaintext_ser = match self.state {
            CurrentState::AwaitingUpdateNameResp { ref key, .. }
            | CurrentState::OverlayActivated { ref key, .. } => {
                match msg_to_read(ciphertext, key) {
                    Ok(pt) => pt,
                    Err(e) => {
                        info!("Error decrypting: {:?}", e);
                        return false;
                    }
                }
            }
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
            PlainTextMsg::UpdateNameResp(is_updated) => {
                self.handle_update_name_resp(core, poll, is_updated)
            }
            PlainTextMsg::OnlinePeersResp(online_peers) => {
                self.handle_online_peers_resp(core, poll, online_peers)
            }
            PlainTextMsg::ForwardedRendezvousReq { src_info, src_peer } => {
                self.handle_rendezvous_req(core, poll, src_info, src_peer)
            }
            PlainTextMsg::ForwardedRendezvousResp { src_info, src_peer } => {
                self.handle_rendezvous_resp(core, poll, src_info, src_peer)
            }
            x => {
                info!("Invalid PlainTextMsg: {:?}", x);
                return false;
            }
        }
    }

    fn handle_update_name_resp(&mut self, core: &mut Core, poll: &Poll, is_updated: bool) -> bool {
        match mem::replace(&mut self.state, Default::default()) {
            CurrentState::AwaitingUpdateNameResp { pk, key } => {
                if is_updated {
                    if let Err(e) = self.tx.send(Event::OverlayConnected(self.token)) {
                        debug!("Error sending event: {:?}", e);
                        return false;
                    }

                    self.state = CurrentState::OverlayActivated { pk, key };

                    true
                } else {
                    if let Err(e) = self.tx.send(Event::OverlayConnectFailed) {
                        debug!("Error sending event: {:?}", e);
                    }
                    self.terminate(core, poll);

                    false
                }
            }
            x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                false
            }
        }
    }

    fn handle_online_peers_resp(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        online_peers: Vec<PeerId>,
    ) -> bool {
        {
            let mut peers_guard = unwrap!(self.peers.lock());
            let mut current_peers = mem::replace(&mut *peers_guard, Default::default());

            online_peers.into_iter().for_each(|id| {
                let token = current_peers.remove(&id).and_then(|t| t);
                let _ = peers_guard.insert(id, token);
            });

            current_peers.into_iter().for_each(|(id, token)| {
                if token.is_some() {
                    let _ = peers_guard.insert(id, token);
                }
            });
        }

        if let Err(e) = self.tx.send(Event::PeersRefreshed) {
            debug!("Error sending event: {:?}", e);
            false
        } else {
            true
        }
    }

    fn handle_rendezvous_req(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        src_info: RendezvousInfo,
        src_peer: PeerId,
    ) -> bool {
        unimplemented!()
    }

    fn handle_rendezvous_resp(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        src_info: RendezvousInfo,
        src_peer: PeerId,
    ) -> bool {
        unimplemented!()
    }
}

impl CoreState for OverlayConnect {
    fn ready(&mut self, core: &mut Core, poll: &Poll, kind: Ready) {
        if kind.is_readable() {
            self.read(core, poll)
        } else if kind.is_writable() {
            let m = if let CurrentState::Init = self.state {
                self.state = CurrentState::AwaitingOverlayPk;
                Some(PeerMsg::PubKey(*core.enc_pk()))
            } else {
                None
            };
            self.write(core, poll, m)
        } else {
            warn!("Unknown kind: {:?}", kind);
        }
    }

    fn write(&mut self, core: &mut Core, poll: &Poll, data: Vec<u8>) {
        let ciphertext = match self.state {
            CurrentState::OverlayActivated { ref key, .. } => unwrap!(msg_to_send(&data, key)),
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return;
            }
        };
        self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        // if let Some(peers) = self.peers.upgrade() {
        //     if let CurrentState::OverlayActivated { ref name, .. } = self.state {
        //         let _ = peers.borrow_mut().remove(name);
        //     }
        // }
        let _ = poll.deregister(&self.sock);
        let _ = core.remove_peer_state(self.token);
    }
}
