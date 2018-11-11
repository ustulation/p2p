use common::event_loop::{Core, CoreState, CoreTimer};
use common::types::{PeerId, PeerMsg, PlainTextMsg};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use mio::timer::Timeout;
use mio::{Poll, PollOpt, Ready, Token};
use p2p::{
    msg_to_read, msg_to_send, Handle, HolePunchInfo, HolePunchMediator, Interface, NatInfo,
    RendezvousInfo, Res,
};
use socket_collection::TcpSock;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fmt, mem};
use {ActivePeer, Event, PeerState};

const PURGE_EXPIRED_AWAITS_SECS: u64 = 60;
const TIMER_ID: u8 = 0;

pub struct OverlayConnect {
    token: Token,
    sock: TcpSock,
    our_name: String,
    state: CurrentState,
    peers: Arc<Mutex<BTreeMap<PeerId, PeerState>>>,
    tx: Sender<Event>,
    timeout: Timeout,
    self_weak: Weak<RefCell<OverlayConnect>>,
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
        peers: Arc<Mutex<BTreeMap<PeerId, PeerState>>>,
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
            timeout: unwrap!(core.set_core_timeout(
                Duration::from_secs(PURGE_EXPIRED_AWAITS_SECS),
                CoreTimer::new(token, TIMER_ID)
            )),
            self_weak: Default::default(),
        }));
        state.borrow_mut().self_weak = Rc::downgrade(&state);

        if core.insert_peer_state(token, state).is_err() {
            panic!("Could not start Overlay !");
        }
    }

    pub fn start_connect_with_peer(&mut self, core: &mut Core, poll: &Poll, peer: PeerId) {
        let mut peers_guard = unwrap!(self.peers.lock());
        let stored_state = match peers_guard.get_mut(&peer) {
            Some(peer_state) => peer_state,
            None => {
                info!("Peer no longer online for connection.");
                return;
            }
        };

        if let PeerState::Discovered = *stored_state {
            let weak = self.self_weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, nat_info, res| {
                if let Some(overlay_connect) = weak.upgrade() {
                    if let Some(core) = ifc.as_any().downcast_mut::<Core>() {
                        overlay_connect.borrow_mut().handle_rendezvous_res(
                            core,
                            poll,
                            peer.clone(),
                            nat_info,
                            res,
                        );
                    } else {
                        warn!("Failed to conver Interface to Core");
                    }
                }
            };

            let next_state = match HolePunchMediator::start(core, poll, Box::new(handler)) {
                Ok(mediator_token) => PeerState::CreatingRendezvousInfo {
                    mediator_token,
                    peer_info: None,
                },
                Err(e) => {
                    info!("Could not initialise p2p mediator: {:?}", e);
                    return;
                }
            };

            *stored_state = next_state;
        } else {
            info!("Peer already in the process of being connected to.");
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

        let plaintext = match deserialise(&plaintext_ser) {
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
            PlainTextMsg::FwdRendezvousInfo { src_info, src_peer } => {
                self.handle_peer_rendezvous(core, poll, src_info, src_peer)
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
                let peer_state = current_peers.remove(&id).unwrap_or(Default::default());
                let _ = peers_guard.insert(id, peer_state);
            });

            current_peers
                .into_iter()
                .for_each(|(id, peer_state)| match peer_state {
                    PeerState::AwaitingHolePunchResult | PeerState::Connected(_) => {
                        let _ = peers_guard.insert(id, peer_state);
                    }
                    PeerState::CreatingRendezvousInfo { mediator_token, .. } => {
                        if let Some(state) = core.state(mediator_token) {
                            state.borrow_mut().terminate(core, poll);
                        }
                    }
                    _ => (),
                });
        }

        if let Err(e) = self.tx.send(Event::PeersRefreshed) {
            debug!("Error sending event: {:?}", e);
            false
        } else {
            true
        }
    }

    fn handle_peer_rendezvous(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        src_info: RendezvousInfo,
        src_peer: PeerId,
    ) -> bool {
        let mut peers_guard = unwrap!(self.peers.lock());

        let stored_state = peers_guard
            .entry(src_peer.clone())
            .or_insert(Default::default());

        let prev_peer_state = mem::replace(stored_state, Default::default());

        let next_state = match prev_peer_state {
            PeerState::AwaitingHolePunchResult | PeerState::Connected(_) => {
                info!(
                    "Got connection request from a connected (or being holepunched to) peer: \
                     {}",
                    src_peer
                );
                prev_peer_state
            }
            PeerState::CreatingRendezvousInfo {
                mediator_token,
                mut peer_info,
            } => {
                if peer_info.is_some() {
                    info!(
                        "Got RendezvousInfo from a peer we already have an info for: {}",
                        src_peer
                    );
                } else {
                    peer_info = Some(src_info);
                }
                PeerState::CreatingRendezvousInfo {
                    mediator_token,
                    peer_info,
                }
            }
            PeerState::AwaitingPeerRendezvous { p2p_handle, .. } => {
                let mediator_token = p2p_handle.mediator_token();
                let weak = self.self_weak.clone();
                let handler = move |ifc: &mut Interface, poll: &Poll, res| {
                    if let Some(overlay_connect) = weak.upgrade() {
                        if let Some(core) = ifc.as_any().downcast_mut::<Core>() {
                            overlay_connect.borrow_mut().handle_holepunch_res(
                                core,
                                poll,
                                src_peer.clone(),
                                res,
                            );
                        } else {
                            warn!("Failed to conver Interface to Core");
                        }
                    }
                };
                Handle::start_hole_punch(core, mediator_token, src_info, Box::new(handler));
                PeerState::AwaitingHolePunchResult
            }
            PeerState::Discovered => {
                let weak = self.self_weak.clone();
                let handler = move |ifc: &mut Interface, poll: &Poll, nat_info, res| {
                    if let Some(overlay_connect) = weak.upgrade() {
                        if let Some(core) = ifc.as_any().downcast_mut::<Core>() {
                            overlay_connect.borrow_mut().handle_rendezvous_res(
                                core,
                                poll,
                                src_peer.clone(),
                                nat_info,
                                res,
                            );
                        } else {
                            warn!("Failed to conver Interface to Core");
                        }
                    }
                };
                match HolePunchMediator::start(core, poll, Box::new(handler)) {
                    Ok(mediator_token) => PeerState::CreatingRendezvousInfo {
                        mediator_token,
                        peer_info: Some(src_info),
                    },
                    Err(e) => {
                        debug!("Could not initialise p2p mediator: {:?}", e);
                        prev_peer_state
                    }
                }
            }
        };

        *stored_state = next_state;

        true
    }

    fn handle_rendezvous_res(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        for_peer: PeerId,
        _nat_info: NatInfo,
        res: Res<(Handle, RendezvousInfo)>,
    ) -> bool {
        let (p2p_handle, our_info) = match res {
            Ok(r) => r,
            Err(e) => {
                debug!("Rendezvous failed for peer: {}", for_peer);
                let mut peers_guard = unwrap!(self.peers.lock());
                if let Some(stored_state) = peers_guard.get_mut(&for_peer) {
                    *stored_state = Default::default();
                }
                return true;
            }
        };

        let ciphertext = match self.state {
            CurrentState::OverlayActivated { ref key, .. } => {
                let plaintext_ser = unwrap!(serialise(&PlainTextMsg::ExchgRendezvousInfo {
                    src_info: our_info,
                    dst_peer: for_peer.clone()
                }));
                match msg_to_send(&plaintext_ser, key) {
                    Ok(ct) => ct,
                    Err(e) => {
                        info!("Error encrypting: {:?}", e);
                        return false;
                    }
                }
            }
            ref x => {
                info!("Message cannot be handled in the current state: {:?}", x);
                return false;
            }
        };

        {
            let mut peers_guard = unwrap!(self.peers.lock());
            let stored_state = match peers_guard.get_mut(&for_peer) {
                Some(peer_state) => peer_state,
                None => {
                    trace!(
                        "Rendezvous created for peer who is no longer online: {}",
                        for_peer
                    );
                    return true;
                }
            };

            let prev_peer_state = mem::replace(stored_state, Default::default());
            let next_state = match prev_peer_state {
                PeerState::CreatingRendezvousInfo { peer_info, .. } => {
                    if let Some(peer_info) = peer_info {
                        let mediator_token = p2p_handle.mediator_token();
                        let weak = self.self_weak.clone();
                        let handler = move |ifc: &mut Interface, poll: &Poll, res| {
                            if let Some(overlay_connect) = weak.upgrade() {
                                if let Some(core) = ifc.as_any().downcast_mut::<Core>() {
                                    overlay_connect.borrow_mut().handle_holepunch_res(
                                        core,
                                        poll,
                                        for_peer.clone(),
                                        res,
                                    );
                                } else {
                                    warn!("Failed to conver Interface to Core");
                                }
                            }
                        };
                        Handle::start_hole_punch(
                            core,
                            mediator_token,
                            peer_info,
                            Box::new(handler),
                        );
                        PeerState::AwaitingHolePunchResult
                    } else {
                        PeerState::AwaitingPeerRendezvous {
                            since: Instant::now(),
                            p2p_handle,
                        }
                    }
                }
                x => {
                    warn!(
                    "Logic Error. handle_rendezvous_res() should not get called when at state: \
                     {:?}",
                    x
                );
                    return true;
                }
            };

            *stored_state = next_state;
        }

        self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));

        true
    }

    fn handle_holepunch_res(
        &mut self,
        core: &mut Core,
        poll: &Poll,
        for_peer: PeerId,
        res: Res<HolePunchInfo>,
    ) {
        let holepunch_info = match res {
            Ok(info) => info,
            Err(e) => {
                debug!("Could not holepunch to {}: {:?}", for_peer, e);
                let mut peers_guard = unwrap!(self.peers.lock());
                if let Some(stored_state) = peers_guard.get_mut(&for_peer) {
                    *stored_state = Default::default();
                }
                return;
            }
        };

        if for_peer.pk != holepunch_info.enc_pk {
            info!("Keys mismatch. Unexpected behaviour.");
            return;
        }

        if holepunch_info.tcp.is_some() {
            trace!(
                "Successfully Holepunched via TCP. This example however only continues if UDP \
                 Holepunch is successful."
            );
        } else {
            trace!("Could not HolePunch via TCP");
        }

        let udp = match holepunch_info.udp {
            Some(udp) => {
                trace!("Successfully Holepunched via UDP: {:?}", udp);
                udp
            }
            None => {
                debug!(
                    "Could not HolePunch via UDP. This example however only continues if UDP \
                     Holepunch is successful."
                );
                return;
            }
        };

        ActivePeer::start(
            core,
            poll,
            udp.token,
            udp.sock,
            for_peer,
            self.peers.clone(),
            self.tx.clone(),
        );
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

    fn timeout(&mut self, core: &mut Core, poll: &Poll, timer_id: u8) {
        assert_eq!(timer_id, TIMER_ID);

        {
            let mut peers_guard = unwrap!(self.peers.lock());
            peers_guard.values_mut().for_each(|peer_state| {
                let mut purge = false;
                if let PeerState::AwaitingPeerRendezvous { ref since, .. } = peer_state {
                    purge = since.elapsed() >= Duration::from_secs(PURGE_EXPIRED_AWAITS_SECS);
                }

                if purge {
                    *peer_state = Default::default();
                }
            });
        }

        self.timeout = unwrap!(core.set_core_timeout(
            Duration::from_secs(PURGE_EXPIRED_AWAITS_SECS),
            CoreTimer::new(self.token, TIMER_ID)
        ));
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let _ = poll.deregister(&self.sock);
        let _ = core.cancel_core_timeout(&self.timeout);
        let _ = core.remove_peer_state(self.token);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
