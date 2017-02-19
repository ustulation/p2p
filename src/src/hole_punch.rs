use {Interface, NatMsg, NatState};
use mio::{Poll, Token};
use mio::channel::Sender;
use std::cell::RefCell;
use std::mem;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use udp::UdpHolePunchMediator;

pub type GetInfo = Box<FnMut(&mut Interface, &Poll, ::Res<(Handle, HolePunchInfo)>)>;

pub struct HolePunchInfo {
    pub udp_info: Vec<SocketAddr>,
    pub tcp_info: Vec<SocketAddr>,
}
impl Default for HolePunchInfo {
    fn default() -> Self {
        HolePunchInfo {
            udp_info: vec![],
            tcp_info: vec![],
        }
    }
}

// enum State {
//     None,
//     Rendezvous(GetInfo),
//     HolePunch(GetSocket),
// }

pub struct HolePunchMediator {
    token: Token,
    udp_mediator: Token,
    hole_punch_info: HolePunchInfo,
    f: GetInfo,
}

impl HolePunchMediator {
    pub fn new(ifc: &mut Interface, poll: &Poll, f: GetInfo) -> ::Res<()> {
        let token = ifc.new_token();
        let mediator = Rc::new(RefCell::new(HolePunchMediator {
            token: token,
            udp_mediator: Token(0),
            hole_punch_info: Default::default(),
            f: f,
        }));
        let weak = Rc::downgrade(&mediator);

        let handler = move |ifc: &mut Interface, poll: &Poll, res| if let Some(mediator) =
            weak.upgrade() {
            mediator.borrow_mut().handle_udp_rendezvous(ifc, poll, res);
        };

        match UdpHolePunchMediator::start(ifc, poll, Box::new(handler)) {
            Ok(child) => mediator.borrow_mut().udp_mediator = child,
            Err(e) => debug!("Udp Hole Punch Mediator failed to initialise: {:?}", e),
        }

        if let Err(e) = ifc.insert_state(token, mediator) {
            // TODO Handle properly
            error!("To be handled properly: {}", e);
        }

        Ok(())
    }

    fn handle_udp_rendezvous(&mut self,
                             ifc: &mut Interface,
                             poll: &Poll,
                             res: ::Res<Vec<SocketAddr>>) {
        match res {
            Ok(udp_info) => {
                self.hole_punch_info.udp_info = udp_info;
                let hole_punch_info = mem::replace(&mut self.hole_punch_info, Default::default());
                let handle = Handle {
                    token: Some(self.token),
                    tx: ifc.sender().clone(),
                };
                (*self.f)(ifc, poll, Ok((handle, hole_punch_info)))
            }
            Err(e) => {
                debug!("{:?}", e);
                (*self.f)(ifc, poll, Err(e))
            }
        }
    }
}

impl NatState for HolePunchMediator {}

pub struct Handle {
    token: Option<Token>,
    tx: Sender<NatMsg>,
}
impl Handle {
    pub fn start_hole_punch(&mut self, peer_info: HolePunchInfo) {
        if let Some(token) = self.token.take() {
            self.tx.send(Box::new(move |ifc, poll| if let Some(mediator) = ifc.state(token) {
                mediator.borrow_mut().terminate(ifc, poll);
            }));
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(token) = self.token {
            self.tx.send(Box::new(move |ifc, poll| if let Some(mediator) = ifc.state(token) {
                mediator.borrow_mut().terminate(ifc, poll);
            }));
        }
    }
}
