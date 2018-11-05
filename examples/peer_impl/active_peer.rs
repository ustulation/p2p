use common::event_loop::{Core, CoreState, CoreTimer};
use common::types::{PeerId, PeerMsg, PlainTextMsg};
use mio::{Poll, Ready, Token};
use mio_extras::timer::Timeout;
use p2p::Interface;
use safe_crypto::SharedSecretKey;
use socket_collection::UdpSock;
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use {Event, PeerState};

const INACTIVITY_TIMEOUT_ID: u8 = 0;
const TOLERATE_READ_ERRS_ID: u8 = 1;

const INACTIVITY_TIMEOUT_SECS: u64 = 180;
const TOLERATE_READ_ERRS_SECS: u64 = 60;

pub struct ActivePeer {
    token: Token,
    sock: UdpSock,
    peer: PeerId,
    key: SharedSecretKey,
    peers: Arc<Mutex<BTreeMap<PeerId, PeerState>>>,
    should_buffer: bool,
    chat_buf: Vec<String>,
    tolerate_read_errs: bool,
    timeout_inactivity: Timeout,
    _timeout_tolerate_read_errs: Timeout,
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
            key: core.enc_sk().shared_secret(&peer.pk),
            peers: peers.clone(),
            should_buffer: true,
            chat_buf: Default::default(),
            tolerate_read_errs: true,
            timeout_inactivity: core.set_core_timeout(
                Duration::from_secs(INACTIVITY_TIMEOUT_SECS),
                CoreTimer::new(token, INACTIVITY_TIMEOUT_ID),
            ),
            _timeout_tolerate_read_errs: core.set_core_timeout(
                Duration::from_secs(TOLERATE_READ_ERRS_SECS),
                CoreTimer::new(token, TOLERATE_READ_ERRS_ID),
            ),
            tx: tx.clone(),
        }));

        if let Err((state, e)) = core.insert_peer_state(token, state) {
            info!("Could not insert peer-state: {:?}", e);
            state.borrow_mut().terminate(core, poll);
            unwrap!(tx.send(Event::PeerConnectFailed(peer)));
            return;
        }

        let mut peers_guard = unwrap!(peers.lock());
        let stored_state = peers_guard
            .entry(peer.clone())
            .or_insert(Default::default());
        *stored_state = PeerState::Connected(token);

        unwrap!(tx.send(Event::PeerConnected(peer, token)));
    }

    pub fn start_buffering(&mut self) {
        self.should_buffer = true;
    }

    pub fn flush_and_stop_buffering(&mut self) {
        self.should_buffer = false;
        for m in self.chat_buf.drain(..) {
            println!("{} --> {}", self.peer, m);
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
                    if self.tolerate_read_errs {
                        trace!("Tolerating read error: {:?}", e);
                    } else {
                        debug!("Failed to read from sock: {:?}", e);
                        return self.terminate(core, poll);
                    }
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

    fn handle_ciphertext(&mut self, core: &mut Core, _poll: &Poll, ciphertext: &[u8]) -> bool {
        let plaintext = match self.key.decrypt(ciphertext) {
            Ok(pt) => pt,
            Err(e) => {
                return if self.tolerate_read_errs {
                    trace!("Tolerating error decrypting: {:?}", e);
                    true
                } else {
                    debug!("Error decrypting: {:?}", e);
                    false
                };
            }
        };

        let chat = match plaintext {
            PlainTextMsg::Chat(m) => m,
            x => {
                return if self.tolerate_read_errs {
                    trace!("Tolerating invalid PlainTextMsg: {:?}", x);
                    true
                } else {
                    info!("Invalid PlainTextMsg: {:?}", x);
                    false
                };
            }
        };

        if self.should_buffer {
            self.chat_buf.push(chat);
        } else {
            println!("{} --> {}", self.peer, chat);
        }

        let _ = core.cancel_core_timeout(&self.timeout_inactivity);
        self.timeout_inactivity = core.set_core_timeout(
            Duration::from_secs(INACTIVITY_TIMEOUT_SECS),
            CoreTimer::new(self.token, INACTIVITY_TIMEOUT_ID),
        );

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
        let ciphertext = unwrap!(self.key.encrypt_bytes(&data));
        self.write(core, poll, Some(PeerMsg::CipherText(ciphertext)));
    }

    fn timeout(&mut self, core: &mut Core, poll: &Poll, timer_id: u8) {
        if timer_id == INACTIVITY_TIMEOUT_ID {
            trace!(
                "Peer inactive for {} secs. Terminating..",
                INACTIVITY_TIMEOUT_SECS
            );
            return self.terminate(core, poll);
        }

        assert_eq!(timer_id, TOLERATE_READ_ERRS_ID);
        self.tolerate_read_errs = false;
    }

    fn terminate(&mut self, core: &mut Core, poll: &Poll) {
        let mut peers_guard = unwrap!(self.peers.lock());
        if let Some(stored_state) = peers_guard.get_mut(&self.peer) {
            *stored_state = Default::default();
        }

        let _ = core.remove_peer_state(self.token);
        let _ = poll.deregister(&self.sock);

        let _ = self.tx.send(Event::PeerDisconnected(self.peer.clone()));
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
