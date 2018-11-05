use super::{TcpEchoReq, TcpEchoResp};
use mio::{Poll, PollOpt, Ready, Token};
use mio_extras::timer::Timeout;
use socket_collection::{SocketError, TcpSock};
use sodium::crypto::box_;
use sodium::crypto::sealedbox;
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;
use {Interface, NatError, NatState, NatTimer};

const TIMER_ID: u8 = 0;
const RENDEZVOUS_EXCHG_TIMEOUT_SEC: u64 = 5;

pub struct ExchangeMsg {
    token: Token,
    sock: TcpSock,
    peer: SocketAddr,
    timeout: Timeout,
}

impl ExchangeMsg {
    pub fn start(ifc: &mut Interface, poll: &Poll, peer: SocketAddr, sock: TcpSock) -> ::Res<()> {
        let token = ifc.new_token();

        let timeout = ifc.set_timeout(
            Duration::from_secs(RENDEZVOUS_EXCHG_TIMEOUT_SEC),
            NatTimer::new(token, TIMER_ID),
        );

        poll.register(
            &sock,
            token,
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        )?;

        let exchg_msg = Rc::new(RefCell::new(ExchangeMsg {
            token,
            sock,
            peer,
            timeout,
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
        let mut pk = None;
        loop {
            match self.sock.read() {
                Ok(Some(TcpEchoReq(raw))) => pk = Some(box_::PublicKey(raw)),
                Ok(None) => if pk.is_some() {
                    break;
                } else {
                    return;
                },
                Err(e) => {
                    match e {
                        SocketError::ZeroByteRead => (), // Expected of a well behave client
                        _ => debug!("Error in read: {:?}", e),
                    }
                    return self.terminate(ifc, poll);
                }
            }
        }

        if let Some(pk) = pk.take() {
            let resp = TcpEchoResp(sealedbox::seal(format!("{}", self.peer).as_bytes(), &pk));
            self.write(ifc, poll, Some(resp))
        } else {
            warn!("Error: Logic error in Tcp Rendezvous Server - Please report.");
            return self.terminate(ifc, poll);
        }
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll, m: Option<TcpEchoResp>) {
        match self.sock.write(m.map(|m| (m, 0))) {
            Ok(true) => (),
            Ok(false) => return,
            Err(e) => {
                debug!("Error in write for tcp exchanger: {:?}", e);
                self.terminate(ifc, poll);
            }
        }
    }
}

impl NatState for ExchangeMsg {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            self.write(ifc, poll, None)
        } else {
            warn!("Investigate: Ignoring unknown event kind: {:?}", event);
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
