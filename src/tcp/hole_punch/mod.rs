use self::listener::Listener;
use self::puncher::{Puncher, Via};
use self::rendezvous_client::TcpRendezvousClient;
use mio::tcp::{TcpListener, TcpStream};
use mio::Poll;
use mio::Token;
use rand::{self, Rng};
use socket_collection::TcpSock;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::{Rc, Weak};
use tcp::new_reusably_bound_tcp_sockets;
use {Interface, NatError, NatState, NatType};

mod listener;
mod puncher;
mod rendezvous_client;

pub type RendezvousFinsih = Box<FnMut(&mut Interface, &Poll, NatType, ::Res<SocketAddr>)>;
pub type HolePunchFinsih = Box<FnMut(&mut Interface, &Poll, ::Res<(TcpSock, Token)>)>;

const LISTENER_BACKLOG: i32 = 100;

enum State {
    None,
    Rendezvous {
        children: HashSet<Token>,
        info: (SocketAddr, Vec<SocketAddr>),
        f: RendezvousFinsih,
    },
    ReadyToHolePunch(SocketAddr),
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

pub struct TcpHolePunchMediator {
    state: State,
    self_weak: Weak<RefCell<TcpHolePunchMediator>>,
}

impl TcpHolePunchMediator {
    pub fn start(
        ifc: &mut Interface,
        poll: &Poll,
        f: RendezvousFinsih,
    ) -> ::Res<Rc<RefCell<Self>>> {
        let mut servers = ifc.config().remote_tcp_rendezvous_servers.clone();
        let num_servers = servers.len();

        if num_servers == 0 {
            return Err(NatError::TcpHolePunchMediatorFailedToStart);
        } else if num_servers < 2 {
            info!(
                "Tcp: Symmetric NAT detection and port prediction will not be possible using \
                 less than 2 Rendezvous Servers. Use at-least 2. Recommended is 3."
            );
        } else if num_servers > 3 {
            let mut rng = rand::thread_rng();
            rng.shuffle(&mut servers);
            servers = servers[..3].to_owned();
        }

        let addr_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        let (builders, addr) = new_reusably_bound_tcp_sockets(&addr_any, num_servers)?;

        let mediator = Rc::new(RefCell::new(TcpHolePunchMediator {
            state: State::None,
            self_weak: Weak::new(),
        }));
        mediator.borrow_mut().self_weak = Rc::downgrade(&mediator);
        let weak = mediator.borrow().self_weak.clone();

        let mut rendezvous_children = HashSet::with_capacity(builders.len());

        for (builder, server) in builders.iter().zip(servers.iter()) {
            let sock = {
                let s = builder.to_tcp_stream()?;
                TcpSock::wrap(TcpStream::connect_stream(s, server)?)
            };

            let weak_cloned = weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, child, res| {
                if let Some(mediator) = weak_cloned.upgrade() {
                    mediator
                        .borrow_mut()
                        .handle_rendezvous(ifc, poll, child, res);
                }
            };

            if let Ok(child) = TcpRendezvousClient::start(ifc, poll, sock, Box::new(handler)) {
                let _ = rendezvous_children.insert(child);
            }
        }

        if rendezvous_children.is_empty() {
            Err(NatError::TcpHolePunchMediatorFailedToStart)
        } else {
            let n = rendezvous_children.len();
            mediator.borrow_mut().state = State::Rendezvous {
                children: rendezvous_children,
                info: (addr, Vec::with_capacity(n)),
                f: f,
            };

            Ok(mediator)
        }
    }

    fn handle_rendezvous(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        child: Token,
        res: ::Res<SocketAddr>,
    ) {
        let r = match self.state {
            State::Rendezvous {
                ref mut children,
                ref mut info,
                ref mut f,
            } => {
                let _ = children.remove(&child);
                if let Ok(ext_addr) = res {
                    info.1.push(ext_addr);
                }
                if children.is_empty() {
                    let ext_addrs = mem::replace(&mut info.1, vec![]);

                    if ext_addrs.is_empty() {
                        f(
                            ifc,
                            poll,
                            NatType::Unknown,
                            Err(NatError::TcpRendezvousFailed),
                        );
                        Err(NatError::TcpRendezvousFailed)
                    } else {
                        let mut nat_type = NatType::Unknown;
                        match TcpHolePunchMediator::port_prediction(ext_addrs, &mut nat_type) {
                            Ok(ext_addr) => {
                                f(ifc, poll, nat_type, Ok(ext_addr));
                                Ok(Some(info.0))
                            }
                            _ => {
                                f(ifc, poll, nat_type, Err(NatError::TcpRendezvousFailed));
                                Err(NatError::TcpRendezvousFailed)
                            }
                        }
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
            Ok(Some(our_addr)) => self.state = State::ReadyToHolePunch(our_addr),
            Ok(None) => (),
            Err(e @ NatError::TcpRendezvousFailed) => {
                // This is reached only if children is empty. So no chance of borrow violation for
                // children in terminate()
                debug!("Terminating due to: {:?}", e);
                self.terminate(ifc, poll);
            }
            // Don't call terminate as that can lead to child being borrowed twice
            Err(e) => debug!("Ignoring error in handle rendezvous: {:?}", e),
        }
    }

    fn port_prediction(
        mut ext_addrs: Vec<SocketAddr>,
        nat_type: &mut NatType,
    ) -> ::Res<SocketAddr> {
        let mut ext_addr = match ext_addrs.pop() {
            Some(addr) => addr,
            None => return Err(NatError::TcpRendezvousFailed),
        };

        let mut addrs = vec![ext_addr];
        let mut port_prediction_offset = 0i32;
        let mut is_err = false;
        for addr in ext_addrs {
            addrs.push(addr);

            if ext_addr.ip() != addr.ip() {
                info!(
                    "Symmetric NAT with variable IP mapping detected. No logic for Tcp \
                     external address prediction for these circumstances!"
                );
                *nat_type = NatType::EDMRandomIp(addrs.into_iter().map(|s| s.ip()).collect());
                is_err = true;
                break;
            } else if port_prediction_offset == 0 {
                port_prediction_offset = addr.port() as i32 - ext_addr.port() as i32;
            } else if port_prediction_offset != addr.port() as i32 - ext_addr.port() as i32 {
                info!(
                    "Symmetric NAT with non-uniformly changing port mapping detected. No logic \
                     for Tcp external address prediction for these circumstances!"
                );
                *nat_type = NatType::EDMRandomPort(addrs.into_iter().map(|s| s.port()).collect());
                is_err = true;
                break;
            }

            ext_addr = addr;
        }

        if is_err {
            return Err(NatError::TcpRendezvousFailed);
        }

        let port = ext_addr.port();
        ext_addr.set_port((port as i32 + port_prediction_offset) as u16);
        trace!("Our ext addr by Tcp Rendezvous Client: {}", ext_addr);

        *nat_type = if port_prediction_offset == 0 {
            NatType::EIM
        } else {
            NatType::EDM(port_prediction_offset)
        };

        Ok(ext_addr)
    }

    pub fn rendezvous_timeout(&mut self, ifc: &mut Interface, poll: &Poll) -> NatError {
        let e = match self.state {
            State::Rendezvous { .. } => NatError::TcpRendezvousFailed,
            _ => NatError::InvalidState,
        };

        match e {
            NatError::InvalidState => (),
            ref x => {
                debug!("Terminating due to: {:?}", x);
                self.terminate(ifc, poll);
            }
        }

        e
    }

    pub fn punch_hole(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        peer: SocketAddr,
        peer_enc_pk: &box_::PublicKey,
        f: HolePunchFinsih,
    ) -> ::Res<()> {
        let our_addr = match self.state {
            State::ReadyToHolePunch(our_addr) => our_addr,
            ref x => {
                debug!("Improper state for this operation: {:?}", x);
                return Err(NatError::InvalidState);
            }
        };

        let l = new_reusably_bound_tcp_sockets(&our_addr, 1)?.0[0].listen(LISTENER_BACKLOG)?;
        let listener = TcpListener::from_listener(l, &our_addr)?;

        let mut children = HashSet::with_capacity(2);

        let weak = self.self_weak.clone();
        let handler = move |ifc: &mut Interface, poll: &Poll, token, res| {
            if let Some(mediator) = weak.upgrade() {
                mediator
                    .borrow_mut()
                    .handle_hole_punch(ifc, poll, token, res);
            }
        };
        let via = Via::Connect {
            our_addr: our_addr,
            peer_addr: peer,
        };
        if let Ok(child) = Puncher::start(ifc, poll, via, peer_enc_pk, Box::new(handler)) {
            let _ = children.insert(child);
        }

        let weak = self.self_weak.clone();
        let handler = move |ifc: &mut Interface, poll: &Poll, token, res| {
            if let Some(mediator) = weak.upgrade() {
                mediator
                    .borrow_mut()
                    .handle_hole_punch(ifc, poll, token, res);
            }
        };
        if let Ok(child) = Listener::start(ifc, poll, listener, peer_enc_pk, Box::new(handler)) {
            let _ = children.insert(child);
        }

        if children.is_empty() {
            debug!("Failure: Not even one valid child even managed to start hole punching");
            self.terminate(ifc, poll);
            return Err(NatError::TcpHolePunchFailed);
        }

        self.state = State::HolePunching {
            children: children,
            f: f,
        };

        Ok(())
    }

    fn handle_hole_punch(
        &mut self,
        ifc: &mut Interface,
        poll: &Poll,
        child: Token,
        res: ::Res<TcpSock>,
    ) {
        let r = match self.state {
            State::HolePunching {
                ref mut children,
                ref mut f,
            } => {
                let _ = children.remove(&child);
                if let Ok(sock) = res {
                    f(ifc, poll, Ok((sock, child)));
                    Ok(true)
                } else if children.is_empty() {
                    f(ifc, poll, Err(NatError::TcpHolePunchFailed));
                    Err(NatError::TcpHolePunchFailed)
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
            Err(e @ NatError::TcpHolePunchFailed) => {
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
}

impl NatState for TcpHolePunchMediator {
    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        match self.state {
            State::Rendezvous {
                ref mut children, ..
            }
            | State::HolePunching {
                ref mut children, ..
            } => {
                TcpHolePunchMediator::terminate_children(ifc, poll, children);
            }
            State::None | State::ReadyToHolePunch(_) => (),
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
