use super::{TcpEchoReq, TcpEchoResp};
use {Interface, NatError, NatState, NatTimer};
use mio::{Poll, PollOpt, Ready, Token};
use mio::timer::Timeout;
use sodium::crypto::box_;
use sodium::crypto::sealedbox;
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;
use tcp::Socket;

const TIMER_ID: u8 = 0;
const RENDEZVOUS_EXCHG_TIMEOUT_SEC: u64 = 10;

pub struct ExchangeMsg {
    token: Token,
    sock: Socket,
    peer: SocketAddr,
    timeout: Timeout,
}

impl ExchangeMsg {
    pub fn start(ifc: &mut Interface, poll: &Poll, peer: SocketAddr, sock: Socket) -> ::Res<()> {
        let token = ifc.new_token();

        let timeout = ifc.set_timeout(Duration::from_secs(RENDEZVOUS_EXCHG_TIMEOUT_SEC),
                         NatTimer::new(token, TIMER_ID))?;

        poll.register(&sock,
                      token,
                      Ready::readable() | Ready::error() | Ready::hup(),
                      PollOpt::edge())?;

        let exchg_msg = Rc::new(RefCell::new(ExchangeMsg {
            token: token,
            sock: sock,
            peer: peer,
            timeout: timeout,
        }));

        if ifc.insert_state(token, exchg_msg.clone()).is_err() {
            debug!("Unable to start TCP rendezvous exchanger!");
            exchg_msg.borrow_mut().terminate(ifc, poll);
            Err(NatError::TcpRendezvousExchangerStartFailed)
        } else {
            Ok(())
        }
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) {
        let pk = match self.sock.read::<TcpEchoReq>() {
            Ok(Some(TcpEchoReq(pk))) => box_::PublicKey(pk),
            Ok(None) => return,
            Err(e) => {
                debug!("Error in read: {:?}", e);
                return self.terminate(ifc, poll);
            }
        };

        let resp = TcpEchoResp(sealedbox::seal(format!("{}", self.peer).as_bytes(), &pk));
        self.write(ifc, poll, Some(resp))
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll, m: Option<TcpEchoResp>) {
        match self.sock.write(poll, self.token, m) {
            Ok(true) => (),
            Ok(false) => return,
            Err(e) => debug!("Error in write for tcp exchanger: {:?}", e),
        }

        self.terminate(ifc, poll);
    }
}

impl NatState for ExchangeMsg {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_error() {
            let e = match self.sock.take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            debug!("Error in TcpRendezvousServer readiness: {:?}", e);
            self.terminate(ifc, poll)
        } else if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            self.write(ifc, poll, None)
        } else if event.is_hup() {
            debug!("Shutdown in TcpRendezvousServer readiness");
            self.terminate(ifc, poll)
        } else {
            trace!("Ignoring unknown event kind: {:?}", event);
        }
    }

    fn timeout(&mut self, ifc: &mut Interface, poll: &Poll, timer_id: u8) {
        if timer_id != TIMER_ID {
            debug!("Invalid Timer ID: {}", timer_id);
        }
        debug!("Timeout in tcp rendezvous exchanger. Terminating session.");
        self.terminate(ifc, poll)
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.cancel_timeout(&self.timeout);
        let _ = ifc.remove_state(self.token);
        let _ = poll.deregister(&self.sock);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
