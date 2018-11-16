use config::{HOLE_PUNCH_TIMEOUT_SEC, HOLE_PUNCH_WAIT_FOR_OTHER, RENDEZVOUS_TIMEOUT_SEC};
use mio::{Poll, Token};
use mio_extras::channel::Sender;
use mio_extras::timer::Timeout;
use socket_collection::{TcpSock, UdpSock};
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::rc::{Rc, Weak};
use std::time::Duration;
use tcp::TcpHolePunchMediator;
use udp::UdpHolePunchMediator;
use {Interface, NatError, NatMsg, NatState, NatTimer};

/// Callback to receive the result of rendezvous
pub type GetInfo = Box<FnMut(&mut Interface, &Poll, NatInfo, ::Res<(Handle, RendezvousInfo)>)>;
/// Callback to receive the result of hole punching in a different thread
pub type HolePunchFinsihCrossThread =
    Box<FnMut(&mut Interface, &Poll, ::Res<HolePunchInfo>) + Send + 'static>;
/// Callback to receive the result of hole punching in the same thread
pub type HolePunchFinsih = Box<FnMut(&mut Interface, &Poll, ::Res<HolePunchInfo>)>;

/// Detected NAT Type
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum NatType {
    /// Endpoint Independent Mapping NAT
    EIM,
    /// Predictable Endpoint dependent Mapping NAT. Contains the detected delta.
    EDM(i32),
    /// Unpredictable Endpoint dependent Mapping NAT. Contains the detected IPs.
    EDMRandomIp(Vec<IpAddr>),
    /// Unpredictable Endpoint dependent Mapping NAT. Contains the detected ports.
    EDMRandomPort(Vec<u16>),
    /// Unknown or could not be determined
    Unknown,
}

impl Default for NatType {
    fn default() -> Self {
        NatType::Unknown
    }
}

/// NAT Details
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct NatInfo {
    /// Detected NAT Type for TCP
    pub nat_type_for_tcp: NatType,
    /// Detected NAT Type for UDP
    pub nat_type_for_udp: NatType,
}

/// A rendezvous packet.
///
/// This is supposed to be exchanged out of band between the peers to allow them to hole-punch to
/// each other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousInfo {
    /// UDP addresses in order. This is not to be re-ordered becuase we want to match our ttl
    /// runners with peer's (so our slowest will correspond to their slowest etc.) and also make
    /// sure that we are not mis-matching the our-to-peer socket-mapping. Hence not a
    /// Hash/BTreeSet.
    pub udp: Vec<SocketAddr>,
    /// TCP addresses in order
    pub tcp: Option<SocketAddr>,
    /// Encrypting Asymmetric PublicKey. Peer will use our public key to encrypt and their secret
    /// key to authenticate the message. We will use our secret key to decrypt and peer public key
    /// to validate authenticity of the message.
    pub enc_pk: [u8; box_::PUBLICKEYBYTES],
}

impl RendezvousInfo {
    fn with_key(enc_pk: &box_::PublicKey) -> Self {
        RendezvousInfo {
            udp: vec![],
            tcp: None,
            enc_pk: enc_pk.0,
        }
    }
}

impl Default for RendezvousInfo {
    fn default() -> Self {
        RendezvousInfo {
            udp: vec![],
            tcp: None,
            enc_pk: [0; box_::PUBLICKEYBYTES],
        }
    }
}

/// A successful result of TCP hole punch will be bundled in this structure
#[derive(Debug)]
pub struct TcpHolePunchInfo {
    /// Hole punched socket
    pub sock: TcpSock,
    /// Token the udp socket is registered with mio
    pub token: Token,
    /// Duration it took to successfull forge a NAT hole - intended for debugging/stats purposes
    pub dur: Duration,
}

impl TcpHolePunchInfo {
    /// Construct a new `TcpHolePunchInfo`
    pub fn new(sock: TcpSock, token: Token, dur: Duration) -> Self {
        Self { sock, token, dur }
    }
}

/// A successful result of UDP hole punch will be bundled in this structure
#[derive(Debug)]
pub struct UdpHolePunchInfo {
    /// Hole punched socket
    pub sock: UdpSock,
    /// Peer hole punched to
    pub peer: SocketAddr,
    /// Token the udp socket is registered with mio
    pub token: Token,
    /// Starting TTL of the socket - intended for debugging/stats purposes
    pub starting_ttl: u32,
    /// TTL of the socket when concluding we have been reached by the peer - intended for
    /// debugging/stats purposes
    pub ttl_on_being_reached: u32,
    /// Duration it took to successfull forge a NAT hole - intended for debugging/stats purposes
    pub dur: Duration,
}

impl UdpHolePunchInfo {
    /// Construct a new `UdpHolePunchInfo`
    pub fn new(
        sock: UdpSock,
        peer: SocketAddr,
        token: Token,
        starting_ttl: u32,
        ttl_on_being_reached: u32,
        dur: Duration,
    ) -> Self {
        Self {
            sock,
            peer,
            token,
            starting_ttl,
            ttl_on_being_reached,
            dur,
        }
    }
}

/// A successful result of hole punch will be bundled in this structure
#[derive(Debug)]
pub struct HolePunchInfo {
    /// TCP socket that successfully managed to hole punch
    pub tcp: Option<TcpHolePunchInfo>,
    /// UDP socket that successfully managed to hole punch
    pub udp: Option<UdpHolePunchInfo>,
    /// Encrypting Asymmetric PublicKey. Peer will use our public key to encrypt and their secret
    /// key to authenticate the message. We will use our secret key to decrypt and peer public key
    /// to validate authenticity of the message.
    pub enc_pk: box_::PublicKey,
}

impl HolePunchInfo {
    fn with_key(enc_pk: box_::PublicKey) -> Self {
        HolePunchInfo {
            tcp: None,
            udp: None,
            enc_pk,
        }
    }
}

impl Default for HolePunchInfo {
    fn default() -> Self {
        HolePunchInfo {
            tcp: None,
            udp: None,
            enc_pk: box_::PublicKey([0; box_::PUBLICKEYBYTES]),
        }
    }
}

const TIMER_ID: u8 = 0;

enum State {
    None,
    Rendezvous {
        info: RendezvousInfo,
        nat_info: NatInfo,
        timeout: Timeout,
        f: GetInfo,
    },
    ReadyToHolePunch,
    HolePunching {
        info: HolePunchInfo,
        timeout: Timeout,
        f: HolePunchFinsih,
    },
}

impl Debug for State {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            State::None => write!(f, "State::None"),
            State::Rendezvous { .. } => write!(f, "State::Rendezvous"),
            State::ReadyToHolePunch => write!(f, "State::ReadyToHolePunch"),
            State::HolePunching { .. } => write!(f, "State::HolePunching"),
        }
    }
}

/// The main hole punch mediator engine.
///
/// This is responsible for managing all the hole punching details. It has child states to mediate
/// UDP and TCP rendezvous as well as UDP and TCP hole punching. The result will be published to
/// the user via accepted callbacks.
pub struct HolePunchMediator {
    token: Token,
    state: State,
    udp_child: Option<Rc<RefCell<UdpHolePunchMediator>>>,
    tcp_child: Option<Rc<RefCell<TcpHolePunchMediator>>>,
    self_weak: Weak<RefCell<HolePunchMediator>>,
}

impl HolePunchMediator {
    /// Start the mediator engine. This will prepare it for the rendezvous. Once rendezvous
    /// information is obtained via the given callback, the user is expected to exchange it out of
    /// band with the peer and begin hole punching by giving the peer's rendezvous information.
    pub fn start(ifc: &mut Interface, poll: &Poll, f: GetInfo) -> ::Res<Token> {
        let token = ifc.new_token();
        let dur = ifc
            .config()
            .rendezvous_timeout_sec
            .unwrap_or(RENDEZVOUS_TIMEOUT_SEC);
        let timeout = ifc.set_timeout(Duration::from_secs(dur), NatTimer::new(token, TIMER_ID));

        let mediator = Rc::new(RefCell::new(HolePunchMediator {
            token,
            state: State::None,
            udp_child: None,
            tcp_child: None,
            self_weak: Weak::new(),
        }));
        let weak = Rc::downgrade(&mediator);
        let weak_cloned = weak.clone();
        mediator.borrow_mut().self_weak = weak.clone();

        let handler = move |ifc: &mut Interface, poll: &Poll, nat_type, res| {
            if let Some(mediator) = weak.upgrade() {
                mediator
                    .borrow_mut()
                    .handle_udp_rendezvous(ifc, poll, nat_type, res);
            }
        };

        let udp_child = match UdpHolePunchMediator::start(ifc, poll, Box::new(handler)) {
            Ok(child) => Some(child),
            Err(e) => {
                debug!("Udp Hole Punch Mediator failed to initialise: {:?}", e);
                None
            }
        };

        let handler = move |ifc: &mut Interface, poll: &Poll, nat_type, res| {
            if let Some(mediator) = weak_cloned.upgrade() {
                mediator
                    .borrow_mut()
                    .handle_tcp_rendezvous(ifc, poll, nat_type, res);
            }
        };

        let tcp_child = match TcpHolePunchMediator::start(ifc, poll, Box::new(handler)) {
            Ok(child) => Some(child),
            Err(e) => {
                debug!("Tcp Hole Punch Mediator failed to initialise: {:?}", e);
                None
            }
        };

        if udp_child.is_none() && tcp_child.is_none() {
            Err(NatError::RendezvousFailed)
        } else {
            {
                let mut m = mediator.borrow_mut();
                m.state = State::Rendezvous {
                    info: RendezvousInfo::with_key(ifc.enc_pk()),
                    nat_info: Default::default(),
                    timeout: timeout,
                    f: f,
                };
                m.udp_child = udp_child;
                m.tcp_child = tcp_child;
            }

            if let Err((nat_state, e)) = ifc.insert_state(token, mediator) {
                // TODO Handle properly
                error!("To be handled properly: {}", e);
                nat_state.borrow_mut().terminate(ifc, poll);
                return Err(NatError::HolePunchMediatorFailedToStart);
            }

            Ok(token)
        }
    }

    fn handle_udp_rendezvous(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        nat_type: NatType,
        res: ::Res<Vec<SocketAddr>>,
    ) {
        if let State::Rendezvous {
            ref mut info,
            ref mut nat_info,
            ..
        } = self.state
        {
            if let Ok(ext_addrs) = res {
                // We assume that udp_child does not return an empty list here - rather it
                // should error out on such case (i.e. call us with an error)
                info.udp = ext_addrs;
            } else {
                self.udp_child = None;
            }
            nat_info.nat_type_for_udp = nat_type;
        }

        self.handle_rendezvous_impl(ifc, poll);
    }

    fn handle_tcp_rendezvous(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        nat_type: NatType,
        res: ::Res<SocketAddr>,
    ) {
        if let State::Rendezvous {
            ref mut info,
            ref mut nat_info,
            ..
        } = self.state
        {
            if let Ok(ext_addr) = res {
                info.tcp = Some(ext_addr);
            } else {
                self.tcp_child = None;
            }
            nat_info.nat_type_for_tcp = nat_type;
        }

        self.handle_rendezvous_impl(ifc, poll);
    }

    fn handle_rendezvous_impl(&mut self, ifc: &mut Interface, poll: &Poll) {
        let r = match self.state {
            State::Rendezvous {
                ref mut info,
                ref mut nat_info,
                ref mut f,
                ref timeout,
            } => {
                if (self.udp_child.is_none() || !info.udp.is_empty())
                    && (self.tcp_child.is_none() || info.tcp.is_some())
                {
                    if self.udp_child.is_none() && self.tcp_child.is_none() {
                        let nat_info = mem::replace(nat_info, Default::default());
                        f(ifc, poll, nat_info, Err(NatError::RendezvousFailed));
                        Err(NatError::RendezvousFailed)
                    } else {
                        let _ = ifc.cancel_timeout(timeout);
                        let info = mem::replace(info, Default::default());
                        let nat_info = mem::replace(nat_info, Default::default());
                        let handle = Handle {
                            token: self.token,
                            tx: ifc.sender().clone(),
                        };
                        f(ifc, poll, nat_info, Ok((handle, info)));
                        Ok(true)
                    }
                } else {
                    Ok(false)
                }
            }
            ref x => {
                warn!(
                    "Logic Error in state book-keeping - Pls report this as a bug. Expected \
                     state: State::Rendezvous ;; Found: {:?}",
                    x
                );
                Err(NatError::InvalidState)
            }
        };

        match r {
            Ok(true) => self.state = State::ReadyToHolePunch,
            Ok(false) => (),
            Err(e @ NatError::RendezvousFailed) => {
                // This is reached only if children is empty. So no chance of borrow violation for
                // children in terminate()
                debug!("Terminating due to: {:?}", e);
                self.terminate(ifc, poll);
            }
            // Don't call terminate as that can lead to child being borrowed twice
            Err(e) => debug!("Ignoring error in handle hole-punch: {:?}", e),
        }
    }

    fn punch_hole(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        peer: RendezvousInfo,
        mut f: HolePunchFinsih,
    ) {
        match self.state {
            State::ReadyToHolePunch => (),
            ref x => {
                debug!("Improper state for this operation: {:?}", x);
                return f(ifc, poll, Err(NatError::HolePunchFailed));
            }
        };

        let dur = ifc
            .config()
            .hole_punch_timeout_sec
            .unwrap_or(HOLE_PUNCH_TIMEOUT_SEC);
        let timeout = ifc.set_timeout(
            Duration::from_secs(dur),
            NatTimer::new(self.token, TIMER_ID),
        );

        let peer_enc_pk = box_::PublicKey(peer.enc_pk);

        if let Some(udp_child) = self.udp_child.as_ref().cloned() {
            let weak = self.self_weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, res| {
                if let Some(mediator) = weak.upgrade() {
                    mediator.borrow_mut().handle_udp_hole_punch(ifc, poll, res);
                }
            };
            if let Err(e) = udp_child.borrow_mut().punch_hole(
                ifc,
                poll,
                peer.udp,
                &peer_enc_pk,
                Box::new(handler),
            ) {
                debug!("Udp punch hole failed to start: {:?}", e);
                self.udp_child = None;
            }
        }

        if let Some(tcp_child) = self.tcp_child.as_ref().cloned() {
            let weak = self.self_weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, res| {
                if let Some(mediator) = weak.upgrade() {
                    mediator.borrow_mut().handle_tcp_hole_punch(ifc, poll, res);
                }
            };
            if let Some(tcp_peer) = peer.tcp {
                if let Err(e) = tcp_child.borrow_mut().punch_hole(
                    ifc,
                    poll,
                    tcp_peer,
                    &peer_enc_pk,
                    Box::new(handler),
                ) {
                    debug!("Tcp punch hole failed to start: {:?}", e);
                    self.tcp_child = None;
                }
            } else {
                tcp_child.borrow_mut().terminate(ifc, poll);
                self.tcp_child = None;
            }
        }

        if self.udp_child.is_none() && self.tcp_child.is_none() {
            debug!("Failure: Not even one valid child even managed to start hole punching");
            self.terminate(ifc, poll);
            return f(ifc, poll, Err(NatError::HolePunchFailed));
        }

        self.state = State::HolePunching {
            info: HolePunchInfo::with_key(peer_enc_pk),
            timeout: timeout,
            f: f,
        };
    }

    fn handle_udp_hole_punch(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        res: ::Res<UdpHolePunchInfo>,
    ) {
        if let State::HolePunching { ref mut info, .. } = self.state {
            self.udp_child = None;
            if let Ok(udp_hp_info) = res {
                trace!("UDP has successfully hole punched");
                info.udp = Some(udp_hp_info);
            }
        }

        self.handle_hole_punch_impl(ifc, poll);
    }

    fn handle_tcp_hole_punch(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        res: ::Res<TcpHolePunchInfo>,
    ) {
        if let State::HolePunching { ref mut info, .. } = self.state {
            self.tcp_child = None;
            if let Ok(tcp_hp_info) = res {
                trace!("TCP has successfully hole punched");
                info.tcp = Some(tcp_hp_info);
            }
        }

        self.handle_hole_punch_impl(ifc, poll);
    }

    fn handle_hole_punch_impl(&mut self, ifc: &mut Interface, poll: &Poll) {
        let r = match self.state {
            State::HolePunching {
                ref mut info,
                ref mut f,
                ..
            } => {
                if self.tcp_child.is_none() && self.udp_child.is_none() {
                    if info.tcp.is_none() && info.udp.is_none() {
                        f(ifc, poll, Err(NatError::HolePunchFailed));
                        Err(NatError::HolePunchFailed)
                    } else {
                        let info = mem::replace(info, Default::default());
                        f(ifc, poll, Ok(info));
                        Ok(true)
                    }
                } else if info.tcp.is_none() && info.udp.is_none() {
                    // None has succeeded yet so continue waiting
                    Ok(false)
                } else {
                    // At-least one has succeeded
                    let wait = ifc
                        .config()
                        .hole_punch_wait_for_other
                        .unwrap_or(HOLE_PUNCH_WAIT_FOR_OTHER);
                    if wait {
                        Ok(false)
                    } else {
                        let info = mem::replace(info, Default::default());
                        f(ifc, poll, Ok(info));
                        Ok(true)
                    }
                }
            }
            ref x => {
                warn!(
                    "Logic Error in state book-keeping - Pls report this as a bug. Expected \
                     state: State::HolePunching ;; Found: {:?}",
                    x
                );
                Err(NatError::InvalidState)
            }
        };

        match r {
            Ok(true) => self.terminate(ifc, poll),
            Ok(false) => (),
            Err(e @ NatError::HolePunchFailed) => {
                // This is reached only if children is empty. So no chance of borrow violation for
                // children in terminate()
                debug!("Terminating due to: {:?}", e);
                self.terminate(ifc, poll);
            }
            // Don't call terminate as that can lead to child being borrowed twice
            Err(e) => debug!("Ignoring error in handle hole-punch: {:?}", e),
        }
    }
}

impl NatState for HolePunchMediator {
    fn timeout(&mut self, ifc: &mut Interface, poll: &Poll, timer_id: u8) {
        if timer_id != TIMER_ID {
            debug!("Invalid Timer ID: {}", timer_id);
        }

        let terminate = match self.state {
            State::Rendezvous { .. } => {
                if let Some(udp_child) = self.udp_child.as_ref().cloned() {
                    let mut nat_type = Default::default();
                    match udp_child.borrow_mut().rendezvous_timeout(ifc, poll).map(
                        |(our_addrs, nat)| {
                            nat_type = nat;
                            our_addrs
                        },
                    ) {
                        // It has already gone to the next state, ignore it
                        Err(NatError::InvalidState) => (),
                        r @ Ok(_) | r @ Err(_) => {
                            debug!("Extracted results after time out for UDP Rendezvous reached");
                            self.handle_udp_rendezvous(ifc, poll, nat_type, r)
                        }
                    }
                }
                if let Some(tcp_child) = self.tcp_child.as_ref().cloned() {
                    match tcp_child.borrow_mut().rendezvous_timeout(ifc, poll) {
                        // It has already gone to the next state, ignore it
                        NatError::InvalidState => (),
                        e => self.handle_tcp_rendezvous(ifc, poll, Default::default(), Err(e)),
                    }
                }

                false
            }
            State::HolePunching {
                ref mut info,
                ref mut f,
                ..
            } => {
                debug!("Timeout fired for Holepunch");
                if info.tcp.is_none() && info.udp.is_none() {
                    f(ifc, poll, Err(NatError::HolePunchFailed));
                } else {
                    let info = mem::replace(info, Default::default());
                    f(ifc, poll, Ok(info));
                }

                true
            }
            ref x => {
                warn!(
                    "Logic error, report bug: terminating due to invalid state for a timeout: \
                     {:?}",
                    x
                );
                true
            }
        };

        if terminate {
            self.terminate(ifc, poll);
        }
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        match self.state {
            State::Rendezvous { ref timeout, .. } => {
                let _ = ifc.cancel_timeout(timeout);
            }
            State::HolePunching {
                ref mut info,
                ref timeout,
                ..
            } => {
                let _ = ifc.cancel_timeout(timeout);

                if let Some(ref tcp_hp_info) = info.tcp {
                    let _ = poll.deregister(&tcp_hp_info.sock);
                }
                if let Some(ref udp_hp_info) = info.udp {
                    let _ = poll.deregister(&udp_hp_info.sock);
                }
            }
            _ => (),
        }
        if let Some(udp_child) = self.udp_child.take() {
            udp_child.borrow_mut().terminate(ifc, poll);
        }
        if let Some(tcp_child) = self.tcp_child.take() {
            tcp_child.borrow_mut().terminate(ifc, poll);
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

/// Handle to the [`HolePunchMediator`].
///
/// Using this handle, the user can provide peer rendezvous information to begin hole punching. The
/// handle is flexible enough to invoke hole punching either from another thread or from the event
/// loop thread. The choice is up to the user.
///
/// Dropping this handle will clean up all the internal states associated with this handle and the
/// entire [`HolePunchMediator`] for this handle will terminate gracefully.
///
/// [`HolePunchMediator`]: ../p2p/hole_punch/struct.HolePunchMediator.html
pub struct Handle {
    token: Token,
    tx: Sender<NatMsg>,
}

impl Handle {
    /// Fire hole punch request from a non-event loop thread.
    pub fn fire_hole_punch(self, peer: RendezvousInfo, f: HolePunchFinsihCrossThread) {
        let token = self.token;
        if let Err(e) = self.tx.send(NatMsg::new(move |ifc, _| {
            Handle::start_hole_punch(ifc, token, peer, f)
        })) {
            debug!("Could not fire hole punch request: {:?}", e);
        } else {
            mem::forget(self);
        }
    }

    /// Request hole punch from within the event loop thread.
    pub fn start_hole_punch(
        ifc: &mut Interface,
        hole_punch_mediator: Token,
        peer: RendezvousInfo,
        f: HolePunchFinsih,
    ) {
        QueueReq::start(ifc, hole_punch_mediator, peer, f);
    }

    /// Obtain the token associated with the HolePunchMediator to which this is a handle.
    pub fn mediator_token(self) -> Token {
        let token = self.token;
        mem::forget(self);
        token
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let token = self.token;
        let _ = self.tx.send(NatMsg::new(move |ifc, poll| {
            if let Some(nat_state) = ifc.state(token) {
                nat_state.borrow_mut().terminate(ifc, poll);
            }
        }));
    }
}

impl Debug for Handle {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Handle {{ token: {:?} }}", self.token)
    }
}

struct QueueReq {
    token: Token,
    inner: Option<QueueReqInner>,
}

struct QueueReqInner {
    hole_punch_mediator: Token,
    peer: RendezvousInfo,
    f: HolePunchFinsih,
}

impl QueueReq {
    fn start(
        ifc: &mut Interface,
        hole_punch_mediator: Token,
        peer: RendezvousInfo,
        f: HolePunchFinsih,
    ) {
        let token = ifc.new_token();
        let state = Rc::new(RefCell::new(Self {
            token,
            inner: Some(QueueReqInner {
                hole_punch_mediator,
                peer,
                f,
            }),
        }));

        if let Err((_, e)) = ifc.insert_state(token, state) {
            // Cannot terminate mediator as it could be already borrowed - must be queued but the
            // queuing has failed.
            warn!("Could not insert state: {:?}. This will leak mediator.", e);
        }

        let _ = ifc.sender().send(NatMsg::new(move |ifc, poll| {
            if let Some(state) = ifc.state(token) {
                state.borrow_mut().terminate(ifc, poll);
            } else {
                warn!("No QueueReq state found. This will leak mediator.");
            }
        }));
    }
}

impl NatState for QueueReq {
    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);

        let QueueReqInner {
            hole_punch_mediator,
            peer,
            mut f,
        } = if let Some(i) = self.inner.take() {
            i
        } else {
            info!("Logic Error! Callback must be stored.");
            if let Some(nat_state) = ifc.state(self.token) {
                nat_state.borrow_mut().terminate(ifc, poll);
            }

            return;
        };

        if let Some(nat_state) = ifc.state(hole_punch_mediator) {
            let mut state = nat_state.borrow_mut();
            let mediator = match state.as_any().downcast_mut::<HolePunchMediator>() {
                Some(m) => m,
                None => {
                    debug!("Token has some other state mapped, not HolePunchMediator");
                    return f(ifc, poll, Err(NatError::InvalidState));
                }
            };
            mediator.punch_hole(ifc, poll, peer, f);
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
