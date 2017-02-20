use {Interface, NatError, NatState, NatTimer};
use bincode::{SizeLimit, deserialize, serialize};
use mio::{Poll, PollOpt, Ready, Token};
use mio::timer::Timeout;
use mio::udp::UdpSocket;
use sodium::crypto::sealedbox;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::{self, FromStr};
use std::time::Duration;
use udp::{UdpEchoReq, UdpEchoResp};

pub type Finish = Box<FnMut(&mut Interface, &Poll, Token, ::Res<UdpSocket>)>;

const TIMER_ID: u8 = 0;
const SYN: &'static [u8] = b"SYN";
const SYN_ACK: &'static [u8] = b"SYN-ACK";

enum Sending {
    Syn,
    SynAck,
}

pub struct Puncher {
    token: Token,
    sock: Option<UdpSocket>,
    peer: SocketAddr,
    os_ttl: u32,
    current_ttl: u32,
    ttl_inc_interval_ms: u64,
    timeout: Timeout,
    sending: Sending,
    syn_ack_rxd: bool,
    syn_ack_txd: bool,
    f: Finish,
}

impl Puncher {
    pub fn start(ifc: &mut Interface,
                 poll: &Poll,
                 token: Token,
                 (sock, ttl, ttl_inc_interval_ms): (UdpSocket, u8, u64),
                 peer: SocketAddr,
                 f: Finish)
                 -> ::Res<()> {
        let os_ttl = sock.ttl()?;
        sock.set_ttl(ttl as u32)?;
        let timeout = ifc.set_timeout(Duration::from_millis(ttl_inc_interval_ms),
                         NatTimer::new(token, TIMER_ID))?;
        poll.reregister(&sock,
                        token,
                        Ready::writable() | Ready::readable() | Ready::error() | Ready::hup(),
                        PollOpt::edge())?;

        let puncher = Rc::new(RefCell::new(Puncher {
            token: token,
            sock: Some(sock),
            peer: peer,
            os_ttl: os_ttl,
            current_ttl: ttl as u32,
            ttl_inc_interval_ms: ttl_inc_interval_ms,
            timeout: timeout,
            sending: Sending::Syn,
            syn_ack_rxd: false,
            syn_ack_txd: false,
            f: f,
        }));

        ifc.insert_state(token, puncher).unwrap();
        Ok(())
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        let mut buf = [0; 512];
        // FIXME will need to be done in a loop until wouldblock or Ok(None) - Same for rendezvous
        // server
        let bytes_rxd = match self.sock.as_ref().unwrap().recv_from(&mut buf) {
            Ok(Some((bytes, _))) => bytes,
            Ok(None) => return Ok(()),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => return Ok(()),
            Err(e) => {
                debug!("Udp Hole Puncher has errored out in read: {:?}", e);
                return Ok(self.handle_err(ifc, poll));
            }
        };

        if &buf[..bytes_rxd] == SYN {
            self.sending = Sending::SynAck;
        } else if &buf[..bytes_rxd] == SYN_ACK {
            if self.syn_ack_txd {
                self.done(ifc, poll);
                return Ok(());
            }
            self.sending = Sending::SynAck;
            self.syn_ack_rxd = true;
        }

        Ok(())
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        match self.write_impl(ifc, poll) {
            Ok(()) => Ok(()),
            Err(e) => {
                debug!("Udp Hole Puncher has errored out in write: {:?}", e);
                Ok(self.handle_err(ifc, poll))
            }
        }
    }

    fn write_impl(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        let m = match self.sending {
            Sending::Syn => SYN,
            Sending::SynAck => SYN_ACK,
        };

        let sent = match self.sock.as_ref().unwrap().send_to(m, &self.peer) {
            Ok(Some(bytes_txd)) => {
                if bytes_txd != m.len() {
                    debug!("Partial datagram sent - datagram will be treated as corrupted. \
                            Actual size: {} B, sent size: {} B.",
                           m.len(),
                           bytes_txd);
                    false
                } else {
                    true
                }
            }
            Ok(None) => false,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => false,
            Err(e) => return Err(From::from(e)),
        };

        if sent {
            if let Sending::SynAck = self.sending {
                self.syn_ack_txd = true;
            }
            if self.syn_ack_txd && self.syn_ack_rxd {
                self.done(ifc, poll);
                return Ok(());
            }
            Ok(poll.reregister(self.sock.as_ref().unwrap(),
                            self.token,
                            Ready::readable() | Ready::error() | Ready::hup(),
                            PollOpt::edge())?)
        } else {
            Ok(poll.reregister(self.sock.as_ref().unwrap(),
                            self.token,
                            Ready::readable() | Ready::writable() | Ready::error() | Ready::hup(),
                            PollOpt::edge())?)
        }
    }

    fn done(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let _ = ifc.cancel_timeout(&self.timeout);
        let sock = self.sock.take().unwrap();
        (*self.f)(ifc, poll, self.token, Ok(sock));
    }

    fn handle_err(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = self.terminate(ifc, poll);
        (*self.f)(ifc, poll, self.token, Err(NatError::UdpHolePunchError));
    }
}

impl NatState for Puncher {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) -> ::Res<()> {
        if event.is_error() || event.is_hup() {
            let e = match self.sock.as_ref().unwrap().take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            debug!("Error in Udp Puncher readiness: {:?}", e);
            self.terminate(ifc, poll)
        } else if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            self.write(ifc, poll)
        } else {
            trace!("Ignoring unknown event kind: {:?}", event);
            Ok(())
        }
    }

    fn timeout(&mut self, ifc: &mut Interface, poll: &Poll, timer_id: u8) -> ::Res<()> {
        if timer_id != TIMER_ID {
            debug!("Invalid Timer ID: {}", timer_id);
            return Err(NatError::InvalidTimerId);
        }
        self.timeout = ifc.set_timeout(Duration::from_millis(self.ttl_inc_interval_ms),
                         NatTimer::new(self.token, TIMER_ID))?;
        self.current_ttl += 1;
        if self.current_ttl >= self.os_ttl {
            debug!("OS TTL reached and still could not hole punch - giving up");
            self.handle_err(ifc, poll);
        }
        if let Err(e) = self.sock.as_ref().unwrap().set_ttl(self.current_ttl) {
            self.handle_err(ifc, poll);
        }

        Ok(())
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        let _ = ifc.remove_state(self.token);
        let _ = ifc.cancel_timeout(&self.timeout);
        Ok(poll.deregister(self.sock.as_ref().unwrap())?)
    }
}
