use self::puncher::Puncher;
pub use self::rendezvous_client::UdpRendezvousClient;
use mio::Poll;
use mio::Token;
use socket_collection::UdpSock;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::{Rc, Weak};
use std::time::Duration;
use {Interface, NatError, NatState, NatType, UdpHolePunchInfo};

mod puncher;
mod rendezvous_client;

pub type RendezvousFinsih = Box<FnMut(&mut Interface, &Poll, NatType, ::Res<Vec<SocketAddr>>)>;
pub type HolePunchFinsih = Box<FnMut(&mut Interface, &Poll, ::Res<UdpHolePunchInfo>)>;

enum State {
    None,
    Rendezvous {
        children: HashSet<Token>,
        info: (Vec<(UdpSock, Token)>, Vec<SocketAddr>),
        nat_type: NatType,
        f: RendezvousFinsih,
    },
    ReadyToHolePunch(Vec<(UdpSock, Token)>),
    HolePunching {
        children: HashSet<Token>,
        f: HolePunchFinsih,
    },
}
impl Debug for State {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            State::None => write!(f, "State::None"),
            State::Rendezvous { .. } => write!(f, "State::Rendezvous"),
            State::ReadyToHolePunch(..) => write!(f, "State::ReadyToHolePunch"),
            State::HolePunching { .. } => write!(f, "State::HolePunching"),
        }
    }
}

pub struct UdpHolePunchMediator {
    state: State,
    self_weak: Weak<RefCell<UdpHolePunchMediator>>,
}

impl UdpHolePunchMediator {
    pub fn start(
        ifc: &mut Interface,
        poll: &Poll,
        f: RendezvousFinsih,
    ) -> ::Res<Rc<RefCell<Self>>> {
        let mut socks = Vec::with_capacity(ifc.config().udp_hole_punchers.len());
        let addr_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        for _ in 0..ifc.config().udp_hole_punchers.len() {
            socks.push(UdpSock::bind(&addr_any)?);
        }

        let mediator = Rc::new(RefCell::new(UdpHolePunchMediator {
            state: State::None,
            self_weak: Weak::new(),
        }));
        mediator.borrow_mut().self_weak = Rc::downgrade(&mediator);
        let weak = mediator.borrow().self_weak.clone();

        let mut rendezvous_children = HashSet::with_capacity(socks.len());

        for sock in socks {
            let weak_cloned = weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, child, nat_type, res| {
                if let Some(mediator) = weak_cloned.upgrade() {
                    mediator
                        .borrow_mut()
                        .handle_rendezvous(ifc, poll, child, nat_type, res);
                }
            };

            if let Ok(child) = UdpRendezvousClient::start(ifc, poll, sock, Box::new(handler)) {
                let _ = rendezvous_children.insert(child);
            }
        }

        if rendezvous_children.is_empty() {
            Err(NatError::UdpHolePunchMediatorFailedToStart)
        } else {
            let n = rendezvous_children.len();
            mediator.borrow_mut().state = State::Rendezvous {
                children: rendezvous_children,
                info: (Vec::with_capacity(n), Vec::with_capacity(n)),
                nat_type: Default::default(),
                f,
            };

            Ok(mediator)
        }
    }

    // The NatType report will only be considered for the 1st successful child to report a known NAT
    // type. This assumes that router does not appear as NatType::EDM to one and NatType::EIM to
    // another etc. Just one caveat though: It can appear as EDM to one and
    // EDMRandomIp/EDMRandomPort to another if the port at delta/port_prediction_offset happens to
    // be occupied by some other socket. We don't want to make the code bloat to handle this rare
    // case and it's going to be reported by TCP correctly anyway given that similar thing happening
    // with TCP at the same time too is even rarer.
    fn handle_rendezvous(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        child: Token,
        deduced_nat_type: NatType,
        res: ::Res<(UdpSock, SocketAddr)>,
    ) {
        let r = match self.state {
            State::Rendezvous {
                ref mut children,
                ref mut info,
                ref mut nat_type,
                ref mut f,
            } => {
                let _ = children.remove(&child);
                if *nat_type == Default::default() {
                    *nat_type = deduced_nat_type;
                }
                if let Ok((sock, ext_addr)) = res {
                    info.0.push((sock, child));
                    info.1.push(ext_addr);
                }
                if children.is_empty() {
                    let mut socks = mem::replace(&mut info.0, vec![]);
                    let ext_addrs = mem::replace(&mut info.1, vec![]);
                    let nat_type = mem::replace(nat_type, Default::default());
                    if socks.is_empty() || ext_addrs.is_empty() {
                        UdpHolePunchMediator::dereg_socks(poll, &mut socks);
                        f(ifc, poll, nat_type, Err(NatError::UdpRendezvousFailed));
                        Err(NatError::UdpRendezvousFailed)
                    } else {
                        f(ifc, poll, nat_type, Ok(ext_addrs));
                        Ok(Some(socks))
                    }
                } else {
                    Ok(None)
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
            Ok(Some(socks)) => self.state = State::ReadyToHolePunch(socks),
            Ok(None) => (),
            Err(e @ NatError::UdpRendezvousFailed) => {
                // This is reached only if children is empty. So no chance of borrow violation for
                // children in terminate()
                debug!("Terminating due to: {:?}", e);
                self.terminate(ifc, poll);
            }
            // Don't call terminate as that can lead to child being borrowed twice
            Err(e) => debug!("Ignoring error in handle rendezvous: {:?}", e),
        }
    }

    // Do not use callback to return success/errors in these functions. They are directly called so
    // give the result back asap, else there will be multiple borrows of the caller
    pub fn rendezvous_timeout(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
    ) -> ::Res<(Vec<SocketAddr>, NatType)> {
        debug!("Timeout for UDP Rendezvous");
        let r = match self.state {
            State::Rendezvous {
                ref mut children,
                ref mut info,
                ref mut nat_type,
                ..
            } => {
                UdpHolePunchMediator::terminate_children(ifc, poll, children);
                let mut socks = mem::replace(&mut info.0, vec![]);
                let ext_addrs = mem::replace(&mut info.1, vec![]);
                let nat_type = mem::replace(nat_type, Default::default());
                if socks.is_empty() || ext_addrs.is_empty() {
                    UdpHolePunchMediator::dereg_socks(poll, &mut socks);
                    Err(NatError::UdpRendezvousFailed)
                } else {
                    Ok((socks, ext_addrs, nat_type))
                }
            }
            ref x => {
                trace!(
                    "Already proceeded to the next state. Invalid state for executing a \
                     rendezvous timeout: {:?}",
                    x
                );
                Err(NatError::InvalidState)
            }
        };

        let r = r.map(|(socks, ext_addrs, nat_type)| {
            self.state = State::ReadyToHolePunch(socks);
            (ext_addrs, nat_type)
        });

        match r {
            Ok(_) | Err(NatError::InvalidState) => (),
            Err(ref e) => {
                debug!("Terminating due to: {:?}", e);
                self.terminate(ifc, poll);
            }
        }

        r
    }

    pub fn punch_hole(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        peers: Vec<SocketAddr>,
        peer_enc_pk: &box_::PublicKey,
        f: HolePunchFinsih,
    ) -> ::Res<()> {
        let info = match self.state {
            State::ReadyToHolePunch(ref mut info) => mem::replace(info, vec![]),
            ref x => {
                debug!("Improper state for this operation: {:?}", x);
                return Err(NatError::InvalidState);
            }
        };

        let cap = info.len();
        let hole_punchers_cfg = ifc.config().udp_hole_punchers.clone();

        let mut children = HashSet::with_capacity(cap);
        for (((sock, token), peer), puncher_config) in info
            .into_iter()
            .zip(peers.into_iter())
            .zip(hole_punchers_cfg.into_iter())
        {
            let weak = self.self_weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, token, res| {
                if let Some(mediator) = weak.upgrade() {
                    mediator
                        .borrow_mut()
                        .handle_hole_punch(ifc, poll, token, res);
                }
            };
            match Puncher::start(
                ifc,
                poll,
                token,
                sock,
                puncher_config.starting_ttl,
                puncher_config.ttl_increment_delay_ms,
                peer,
                peer_enc_pk,
                Box::new(handler),
            ) {
                Ok(()) => {
                    let _ = children.insert(token);
                }
                Err(e) => debug!("Error: Could not start UDP Puncher: {:?}", e),
            }
        }

        if children.is_empty() {
            info!("Failure: Not even one valid child even managed to start hole punching");
            self.terminate(ifc, poll);
            return Err(NatError::UdpHolePunchFailed);
        }

        self.state = State::HolePunching { children, f };

        Ok(())
    }

    fn handle_hole_punch(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        child: Token,
        res: ::Res<(UdpSock, SocketAddr, u32, u32, Duration)>,
    ) {
        let r = match self.state {
            State::HolePunching {
                ref mut children,
                ref mut f,
            } => {
                let _ = children.remove(&child);
                if let Ok((sock, peer, starting_ttl, ttl_on_being_reached, dur)) = res {
                    f(
                        ifc,
                        poll,
                        Ok(UdpHolePunchInfo::new(
                            sock,
                            peer,
                            child,
                            starting_ttl,
                            ttl_on_being_reached,
                            dur,
                        )),
                    );
                    Ok(true)
                } else if children.is_empty() {
                    f(ifc, poll, Err(NatError::UdpHolePunchFailed));
                    Err(NatError::UdpHolePunchFailed)
                } else {
                    Ok(false)
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
            Err(e @ NatError::UdpHolePunchFailed) => {
                // This is reached only if children is empty, or we have removed the child that
                // called us. So no chance of borrow violation for children in terminate()
                debug!("Terminating due to: {:?}", e);
                self.terminate(ifc, poll);
            }
            // Don't call terminate as that can lead to child being borrowed twice
            Err(e) => debug!("Ignoring error in handle hole-punch: {:?}", e),
        }
    }

    fn terminate_children(ifc: &mut Interface, poll: &Poll, children: &mut HashSet<Token>) {
        for child in children.drain() {
            let child = match ifc.state(child) {
                Some(state) => state,
                None => continue,
            };

            child.borrow_mut().terminate(ifc, poll);
        }
    }

    fn dereg_socks(poll: &Poll, socks: &mut Vec<(UdpSock, Token)>) {
        for (sock, _) in socks.drain(..) {
            let _ = poll.deregister(&sock);
        }
    }
}

impl NatState for UdpHolePunchMediator {
    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        match self.state {
            State::Rendezvous {
                ref mut children,
                ref mut info,
                ..
            } => {
                UdpHolePunchMediator::terminate_children(ifc, poll, children);
                UdpHolePunchMediator::dereg_socks(poll, &mut info.0);
            }
            State::ReadyToHolePunch(ref mut socks) => {
                UdpHolePunchMediator::dereg_socks(poll, socks)
            }
            State::HolePunching {
                ref mut children, ..
            } => {
                UdpHolePunchMediator::terminate_children(ifc, poll, children);
            }
            State::None => (),
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
