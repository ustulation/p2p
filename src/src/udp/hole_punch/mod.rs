use self::rendezvous_client::UdpRendezvousClient;
use {Interface, NatError, NatState};
use mio::Poll;
use mio::Token;
use mio::udp::UdpSocket;
use std::cell::RefCell;
use std::collections::HashSet;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::{Rc, Weak};

mod puncher;
mod rendezvous_client;

pub type RendezvousFinsih = Box<FnMut(&mut Interface, &Poll, ::Res<Vec<SocketAddr>>)>;

enum State {
    None,
    Rendezvous {
        children: HashSet<Token>,
        udp_info: (Vec<(UdpSocket, Token)>, Vec<SocketAddr>),
        f: RendezvousFinsih,
    },
    RendezvousDone(Vec<(UdpSocket, Token)>),
    HolePunch,
}

pub struct UdpHolePunchMediator {
    state: State,
    self_weak: Weak<RefCell<UdpHolePunchMediator>>,
}

impl UdpHolePunchMediator {
    pub fn start(ifc: &mut Interface, poll: &Poll, f: RendezvousFinsih) -> ::Res<Token> {
        let mut socks = Vec::with_capacity(ifc.config().udp_hole_punchers.len());
        let addr_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        for _ in 0..ifc.config().udp_hole_punchers.len() {
            socks.push(UdpSocket::bind(&addr_any)?);
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
                udp_info: (Vec::with_capacity(n), Vec::with_capacity(n)),
                f: f,
            };

            let token = ifc.new_token();
            if let Err(e) = ifc.insert_state(token, mediator) {
                // TODO Handle properly
                error!("To be handled properly: {}", e);
            }

            Ok(token)
        }
    }

    fn handle_rendezvous(&mut self,
                         ifc: &mut Interface,
                         poll: &Poll,
                         child: Token,
                         res: ::Res<(UdpSocket, SocketAddr)>) {
        let r = match self.state {
            State::Rendezvous { ref mut children, ref mut udp_info, ref mut f } => {
                let _ = children.remove(&child);
                if let Ok((sock, ext_addr)) = res {
                    udp_info.0.push((sock, child));
                    udp_info.1.push(ext_addr);
                }
                if children.is_empty() {
                    let socks = mem::replace(&mut udp_info.0, vec![]);
                    let ext_addrs = mem::replace(&mut udp_info.1, vec![]);
                    f(ifc, poll, Ok(ext_addrs));
                    Ok(Some(socks))
                } else {
                    Ok(None)
                }
            }
            State::None => {
                warn!("Logic Error in state book-keeping - Pls report this as a bug. Expected \
                       state: State::Rendezvous ;; Found: State::None");
                Err(NatError::UdpRendezvousFailed)
            }
            State::RendezvousDone(_) => {
                warn!("Logic Error in state book-keeping - Pls report this as a bug. Expected \
                       state: State::Rendezvous ;; Found: State::RendezvousDone(_)");
                Err(NatError::UdpRendezvousFailed)
            }
            State::HolePunch => {
                warn!("Logic Error in state book-keeping - Pls report this as a bug. Expected \
                       state: State::Rendezvous ;; Found: State::HolePunch");
                Err(NatError::UdpRendezvousFailed)
            }
        };

        match r {
            Ok(Some(socks)) => self.state = State::RendezvousDone(socks),
            Ok(None) => (),
            Err(e) => {
                debug!("{:?}", e);
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
}

impl NatState for UdpHolePunchMediator {
    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        match self.state {
            State::Rendezvous { ref mut children, ref mut udp_info, ref mut f } => {
                UdpHolePunchMediator::terminate_children(ifc, poll, children);
            }
            _ => (),
        }
        Ok(())
    }
}
