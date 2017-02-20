use {Interface, NatError, NatMsg, NatState, NatTimer};
use config::{HOLE_PUNCH_TIMEOUT_SEC, RENDEZVOUS_TIMEOUT_SEC};
use mio::{Poll, Token};
use mio::channel::Sender;
use mio::tcp::TcpStream;
use mio::timer::Timeout;
use mio::udp::UdpSocket;
use std::any::Any;
use std::cell::RefCell;
use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::time::Duration;
use tcp::TcpHolePunchMediator;
use udp::UdpHolePunchMediator;

pub type GetInfo = Box<FnMut(&mut Interface, &Poll, ::Res<(Handle, RendezvousInfo)>)>;
pub type HolePunchFinsih = Box<FnMut(&mut Interface, &Poll, ::Res<HolePunchInfo>)>;

#[derive(Debug)]
pub struct RendezvousInfo {
    pub udp: Vec<SocketAddr>,
    pub tcp: Vec<SocketAddr>,
}
impl Default for RendezvousInfo {
    fn default() -> Self {
        RendezvousInfo {
            udp: vec![],
            tcp: vec![],
        }
    }
}

#[derive(Debug)]
pub struct HolePunchInfo {
    pub tcp: Vec<(TcpStream, Token)>,
    pub udp: Vec<(UdpSocket, Token)>,
}
impl Default for HolePunchInfo {
    fn default() -> Self {
        HolePunchInfo {
            tcp: vec![],
            udp: vec![],
        }
    }
}

const TIMER_ID: u8 = 0;

enum State {
    None,
    Rendezvous {
        info: RendezvousInfo,
        _timeout: Timeout,
        f: GetInfo,
    },
    ReadyToHolePunch,
    HolePunching {
        info: HolePunchInfo,
        _timeout: Timeout,
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


pub struct HolePunchMediator {
    token: Token,
    state: State,
    udp_child: Weak<RefCell<UdpHolePunchMediator>>,
    tcp_child: Weak<RefCell<TcpHolePunchMediator>>,
    self_weak: Weak<RefCell<HolePunchMediator>>,
}

impl HolePunchMediator {
    pub fn start(ifc: &mut Interface, poll: &Poll, f: GetInfo) -> ::Res<()> {
        let token = ifc.new_token();
        let secs = ifc.config().rendezvous_timeout_sec.unwrap_or(RENDEZVOUS_TIMEOUT_SEC);
        let timeout = ifc.set_timeout(Duration::from_secs(secs), NatTimer::new(token, TIMER_ID))?;

        let mediator = Rc::new(RefCell::new(HolePunchMediator {
            token: token,
            state: State::None,
            udp_child: Weak::new(),
            tcp_child: Weak::new(),
            self_weak: Weak::new(),
        }));
        let weak = Rc::downgrade(&mediator);
        mediator.borrow_mut().self_weak = weak.clone();

        let handler = move |ifc: &mut Interface, poll: &Poll, res| if let Some(mediator) =
            weak.upgrade() {
            mediator.borrow_mut().handle_udp_rendezvous(ifc, poll, res);
        };

        let udp_child = match UdpHolePunchMediator::start(ifc, poll, Box::new(handler)) {
            Ok(child) => child,
            Err(e) => {
                debug!("Udp Hole Punch Mediator failed to initialise: {:?}", e);
                Weak::new()
            }
        };

        let tcp_child = Weak::new(); // TODO when Tcp is coded

        if udp_child.upgrade().is_none() && tcp_child.upgrade().is_none() {
            Err(NatError::RendezvousFailed)
        } else {
            {
                let mut m = mediator.borrow_mut();
                m.state = State::Rendezvous {
                    info: Default::default(),
                    _timeout: timeout,
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

            Ok(())
        }
    }

    fn handle_udp_rendezvous(&mut self,
                             ifc: &mut Interface,
                             poll: &Poll,
                             res: ::Res<Vec<SocketAddr>>) {
        let r = match self.state {
            State::Rendezvous { ref mut info, ref mut f, .. } => {
                if let Ok(ext_addrs) = res {
                    info.udp = ext_addrs;
                }
                if self.tcp_child.upgrade().is_none() || !info.tcp.is_empty() {
                    let info = mem::replace(info, Default::default());
                    let handle = Handle {
                        token: self.token,
                        tx: ifc.sender().clone(),
                    };
                    f(ifc, poll, Ok((handle, info)));
                    Ok(true)
                } else {
                    Ok(false)
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
            Ok(true) => self.state = State::ReadyToHolePunch,
            Ok(false) => (),
            Err(e) => debug!("{:?}", e),
        }
    }

    fn punch_hole(&mut self,
                  ifc: &mut Interface,
                  poll: &Poll,
                  peers: RendezvousInfo,
                  mut f: HolePunchFinsih) {
        match self.state {
            State::ReadyToHolePunch => (),
            ref x => {
                debug!("Improper state for this operation: {:?}", x);
                return f(ifc, poll, Err(NatError::HolePunchFailed));
            }
        };

        if let Some(udp_child) = self.udp_child.upgrade() {
            let weak = self.self_weak.clone();
            let handler = move |ifc: &mut Interface, poll: &Poll, res| if let Some(mediator) =
                weak.upgrade() {
                mediator.borrow_mut().handle_udp_hole_punch(ifc, poll, res);
            };
            if let Err(e) = udp_child.borrow_mut()
                .punch_hole(ifc, poll, peers.udp, Box::new(handler)) {
                debug!("Udp punch hole failed to start: {:?}", e);
                self.udp_child = Weak::new();
            }
        }

        if self.udp_child.upgrade().is_none() && self.tcp_child.upgrade().is_none() {
            debug!("Failure: Not even one valid child even managed to start hole punching");
            self.terminate(ifc, poll);
            return f(ifc, poll, Err(NatError::HolePunchFailed));
        }

        let secs = ifc.config().hole_punch_timeout_sec.unwrap_or(HOLE_PUNCH_TIMEOUT_SEC);
        let timeout = ifc.set_timeout(Duration::from_secs(secs),
                         NatTimer::new(self.token, TIMER_ID))
            .unwrap();
        self.state = State::HolePunching {
            info: Default::default(),
            _timeout: timeout,
            f: f,
        };
    }

    fn handle_udp_hole_punch(&mut self,
                             ifc: &mut Interface,
                             poll: &Poll,
                             res: ::Res<Vec<(UdpSocket, Token)>>) {

        let r = match self.state {
            State::HolePunching { ref mut info, ref mut f, .. } => {
                if let Ok(socks) = res {
                    info.udp = socks;
                }
                if self.tcp_child.upgrade().is_none() || !info.tcp.is_empty() {
                    let info = mem::replace(info, Default::default());
                    f(ifc, poll, Ok(info));
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
}

impl NatState for HolePunchMediator {
    fn timeout(&mut self, _ifc: &mut Interface, _poll: &Poll, timer_id: u8) {
        if timer_id != TIMER_ID {
            debug!("Invalid Timer ID: {}", timer_id);
        }

        // match self.state {
        //     State::Rendezvous { ref mut info, ref mut f, .. } => {}
        //     State::HolePunching { ref mut info, ref mut f, .. } => {}
        //     ref x => debug!("Invalid state for a timeout: {:?}", x),
        // }
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        if let Some(udp_child) = self.udp_child.upgrade() {
            udp_child.borrow_mut().terminate(ifc, poll);
        }
        if let Some(tcp_child) = self.tcp_child.upgrade() {
            tcp_child.borrow_mut().terminate(ifc, poll);
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

pub struct Handle {
    token: Token,
    tx: Sender<NatMsg>,
}

impl Handle {
    // TODO see why this does not work
    // pub fn fire_hole_punch(&self, peers: RendezvousInfo, f: HolePunchFinsih) {
    //     let token = self.token;
    //     let mut f = Some(move |ifc: &mut Interface, poll: &Poll| {
    //         Handle::start_hole_punch(ifc, poll, token, peers, f)
    //     });
    //     if let Err(e) = self.tx.send(Box::new(move |ifc, poll| if let Some(f) = f.take() {
    //         f(ifc, poll)
    //     })) {
    //         debug!("Could not fire hole punch request: {:?}", e);
    //     }
    // }

    pub fn start_hole_punch(ifc: &mut Interface,
                            poll: &Poll,
                            hole_punch_mediator: Token,
                            peers: RendezvousInfo,
                            mut f: HolePunchFinsih) {
        if let Some(nat_state) = ifc.state(hole_punch_mediator) {
            let mut state = nat_state.borrow_mut();
            let mediator = match state.as_any().downcast_mut::<HolePunchMediator>() {
                Some(m) => m,
                None => {
                    debug!("Token has some other state mapped, not HolePunchMediator");
                    return f(ifc, poll, Err(NatError::InvalidState));
                }
            };
            mediator.punch_hole(ifc, poll, peers, f);

        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let token = self.token;
        let _ = self.tx.send(Box::new(move |ifc, poll| if let Some(nat_state) =
            ifc.state(token) {
            nat_state.borrow_mut().terminate(ifc, poll);
        }));
    }
}
