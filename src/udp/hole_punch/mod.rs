use self::puncher::Puncher;
use self::rendezvous_client::UdpRendezvousClient;
use {Interface, NatError, NatState};
use mio::Poll;
use mio::Token;
use mio::udp::UdpSocket;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::{Rc, Weak};

mod puncher;
mod rendezvous_client;

pub type RendezvousFinsih = Box<FnMut(&mut Interface, &Poll, ::Res<Vec<SocketAddr>>)>;
pub type HolePunchFinsih = Box<FnMut(&mut Interface, &Poll, ::Res<Vec<(UdpSocket, Token)>>)>;

enum State {
    None,
    Rendezvous {
        children: HashSet<Token>,
        info: (Vec<(UdpSocket, Token)>, Vec<SocketAddr>),
        f: RendezvousFinsih,
    },
    ReadyToHolePunch(Vec<(UdpSocket, Token)>),
    HolePunching {
        children: HashSet<Token>,
        info: Vec<(UdpSocket, Token)>,
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
    token: Token,
    state: State,
    self_weak: Weak<RefCell<UdpHolePunchMediator>>,
}

impl UdpHolePunchMediator {
    pub fn start(ifc: &mut Interface,
                 poll: &Poll,
                 f: RendezvousFinsih)
                 -> ::Res<Weak<RefCell<Self>>> {
        let mut socks = Vec::with_capacity(ifc.config().udp_hole_punchers.len());
        let addr_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        for _ in 0..ifc.config().udp_hole_punchers.len() {
            socks.push(UdpSocket::bind(&addr_any)?);
        }

        let token = ifc.new_token();
        let mediator = Rc::new(RefCell::new(UdpHolePunchMediator {
            token: token,
            state: State::None,
            self_weak: Weak::new(),
        }));
        mediator.borrow_mut().self_weak = Rc::downgrade(&mediator);
        let weak = mediator.borrow().self_weak.clone();

        let mut rendezvous_children = HashSet::with_capacity(socks.len());

        for sock in socks {
            let weak_cloned = weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, child, res| {
                if let Some(mediator) = weak_cloned.upgrade() {
                    mediator.borrow_mut().handle_rendezvous(ifc, poll, child, res);
                }
            };

            if let Ok(child) = UdpRendezvousClient::start(ifc, poll, sock, Box::new(handler)) {
                let _ = rendezvous_children.insert(child);
            }
        }

        if rendezvous_children.is_empty() {
            Err(NatError::UdpRendezvousFailed)
        } else {
            let n = rendezvous_children.len();
            mediator.borrow_mut().state = State::Rendezvous {
                children: rendezvous_children,
                info: (Vec::with_capacity(n), Vec::with_capacity(n)),
                f: f,
            };

            if let Err((nat_state, e)) = ifc.insert_state(token, mediator) {
                // TODO Handle properly
                error!("To be handled properly: {}", e);
                nat_state.borrow_mut().terminate(ifc, poll);
                return Err(NatError::UdpHolePunchMediatorFailedToStart);
            }

            Ok(weak)
        }
    }

    fn handle_rendezvous(&mut self,
                         ifc: &mut Interface,
                         poll: &Poll,
                         child: Token,
                         res: ::Res<(UdpSocket, SocketAddr)>) {
        let r = match self.state {
            State::Rendezvous { ref mut children, ref mut info, ref mut f } => {
                let _ = children.remove(&child);
                if let Ok((sock, ext_addr)) = res {
                    info.0.push((sock, child));
                    info.1.push(ext_addr);
                }
                if children.is_empty() {
                    let socks = mem::replace(&mut info.0, vec![]);
                    let ext_addrs = mem::replace(&mut info.1, vec![]);
                    f(ifc, poll, Ok(ext_addrs));
                    Ok(Some(socks))
                } else {
                    Ok(None)
                }
            }
            ref x => {
                warn!("Logic Error in state book-keeping - Pls report this as a bug. Expected \
                       state: State::Rendezvous ;; Found: {:?}",
                      x);
                Err(NatError::InvalidState)
            }
        };

        match r {
            Ok(Some(socks)) => self.state = State::ReadyToHolePunch(socks),
            Ok(None) => (),
            Err(e) => debug!("{:?}", e),
        }
    }

    pub fn punch_hole(&mut self,
                      ifc: &mut Interface,
                      poll: &Poll,
                      peers: Vec<SocketAddr>,
                      f: HolePunchFinsih)
                      -> ::Res<()> {
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
        for (((sock, token), peer), puncher_config) in
            info.into_iter()
                .zip(peers.into_iter())
                .zip(hole_punchers_cfg.into_iter()) {
            let weak = self.self_weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, token, res| {
                if let Some(mediator) = weak.upgrade() {
                    mediator.borrow_mut().handle_hole_punch(ifc, poll, token, res);
                }
            };
            if Puncher::start(ifc,
                              poll,
                              token,
                              sock,
                              puncher_config.starting_ttl,
                              puncher_config.ttl_increment_delay_ms,
                              peer,
                              Box::new(handler))
                .is_ok() {
                let _ = children.insert(token);
            }
        }

        if children.is_empty() {
            debug!("Failure: Not even one valid child even managed to start hole punching");
            self.terminate(ifc, poll);
            return Err(NatError::UdpHolePunchFailed);
        }

        self.state = State::HolePunching {
            children: children,
            info: Vec::with_capacity(cap),
            f: f,
        };

        Ok(())
    }

    fn handle_hole_punch(&mut self,
                         ifc: &mut Interface,
                         poll: &Poll,
                         child: Token,
                         res: ::Res<UdpSocket>) {
        let r = match self.state {
            State::HolePunching { ref mut children, ref mut info, ref mut f } => {
                let _ = children.remove(&child);
                if let Ok(sock) = res {
                    info.push((sock, child));
                }
                if children.is_empty() {
                    let socks = mem::replace(info, vec![]);
                    f(ifc, poll, Ok(socks));
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ref x => {
                warn!("Logic Error in state book-keeping - Pls report this as a bug. Expected \
                       state: State::HolePunching ;; Found: {:?}",
                      x);
                Err(NatError::InvalidState)
            }
        };

        match r {
            Ok(true) => self.terminate(ifc, poll),
            Ok(false) => (),
            Err(e) => {
                debug!("Terminating due to: {:?}", e);
                self.terminate(ifc, poll);
            }
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

    fn dereg_socks(poll: &Poll, socks: &mut Vec<(UdpSocket, Token)>) {
        for (sock, _) in socks.drain(..) {
            let _ = poll.deregister(&sock);
        }
    }
}

impl NatState for UdpHolePunchMediator {
    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        match self.state {
            State::Rendezvous { ref mut children, ref mut info, .. } => {
                UdpHolePunchMediator::terminate_children(ifc, poll, children);
                UdpHolePunchMediator::dereg_socks(poll, &mut info.0);
            }
            State::HolePunching { ref mut children, ref mut info, .. } => {
                UdpHolePunchMediator::terminate_children(ifc, poll, children);
                UdpHolePunchMediator::dereg_socks(poll, info);
            }
            _ => (),
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
