use {Interface, NatError, NatState};
use mio::{Poll, PollOpt, Ready, Token};
use sodium::crypto::sealedbox;
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::{self, FromStr};
use tcp::{TcpEchoReq, TcpEchoResp};
use tcp::Socket;

pub type Finish = Box<FnMut(&mut Interface, &Poll, Token, ::Res<SocketAddr>)>;

pub struct TcpRendezvousClient {
    token: Token,
    sock: Socket,
    req: Option<TcpEchoReq>,
    f: Finish,
}

impl TcpRendezvousClient {
    pub fn start(ifc: &mut Interface, poll: &Poll, sock: Socket, f: Finish) -> ::Res<Token> {
        let token = ifc.new_token();

        poll.register(&sock,
                      token,
                      Ready::writable() | Ready::error() | Ready::hup(),
                      PollOpt::edge())?;

        let client = Rc::new(RefCell::new(TcpRendezvousClient {
            token: token,
            sock: sock,
            req: Some(TcpEchoReq(ifc.enc_pk().0)),
            f: f,
        }));

        if ifc.insert_state(token, client.clone()).is_err() {
            debug!("Unable to insert TcpRendezvousClient State!");
            client.borrow_mut().terminate(ifc, poll);
            Err(NatError::TcpRendezvousFailed)
        } else {
            Ok(token)
        }
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) {
        let utf8 = match self.sock.read() {
            Ok(Some(TcpEchoResp(r))) => {
                match sealedbox::open(&r, ifc.enc_pk(), ifc.enc_sk()) {
                    Ok(utf8) => utf8,
                    Err(()) => return self.handle_err(ifc, poll),
                }
            }
            Ok(None) => return,
            Err(e) => {
                debug!("Tcp Rendezvous client errored out in read: {:?}", e);
                return self.handle_err(ifc, poll);
            }
        };

        match str::from_utf8(&utf8) {
            Ok(our_ext_addr_str) => {
                match SocketAddr::from_str(our_ext_addr_str) {
                    Ok(addr) => self.done(ifc, poll, addr),
                    Err(e) => {
                        debug!("Error: UdpEchoResp which contained non-parsable address: {:?}",
                               e);
                        self.handle_err(ifc, poll)
                    }
                }
            }
            Err(e) => {
                debug!("Error: UdpEchoResp which contained non-utf8 address: {:?}",
                       e);
                self.handle_err(ifc, poll)
            }
        }
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll, m: Option<TcpEchoReq>) {
        if let Err(e) = self.sock.write(poll, self.token, m) {
            debug!("Tcp Rendezvous client errored out in write: {:?}", e);
            self.handle_err(ifc, poll);
        }
    }

    fn done(&mut self, ifc: &mut Interface, poll: &Poll, ext_addr: SocketAddr) {
        self.terminate(ifc, poll);
        (*self.f)(ifc, poll, self.token, Ok(ext_addr));
    }

    fn handle_err(&mut self, ifc: &mut Interface, poll: &Poll) {
        self.terminate(ifc, poll);
        (*self.f)(ifc, poll, self.token, Err(NatError::TcpRendezvousFailed));
    }
}

impl NatState for TcpRendezvousClient {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_error() {
            let e = match self.sock.take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            debug!("Error in TcpRendezvousClient readiness: {:?}", e);
            self.handle_err(ifc, poll)
        } else if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            let m = self.req.take();
            self.write(ifc, poll, m)
        } else if event.is_hup() {
            debug!("Shutdown in Tcp Rendezvous Client readiness");
            self.handle_err(ifc, poll)
        } else {
            trace!("Ignoring unknown event kind: {:?}", event);
        }
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let _ = poll.deregister(&self.sock);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
