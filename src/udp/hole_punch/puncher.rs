use {Interface, NatError, NatState, NatTimer};
use mio::{Poll, PollOpt, Ready, Token};
use mio::timer::Timeout;
use mio::udp::UdpSocket;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

pub type Finish = Box<FnMut(&mut Interface, &Poll, Token, ::Res<(UdpSocket, SocketAddr)>)>;

const TIMER_ID: u8 = 0;
const SYN: &'static [u8] = b"SYN";
const SYN_ACK: &'static [u8] = b"SYN-ACK";
const ACK: &'static [u8] = b"ACK";

#[derive(Debug)]
enum Sending {
    Syn,
    SynAck,
    Ack,
    None,
}

pub struct Puncher {
    token: Token,
    sock: Option<UdpSocket>,
    peer: SocketAddr,
    key: box_::PrecomputedKey,
    connection_chooser: bool,
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
                 sock: UdpSocket,
                 ttl: u8,
                 ttl_inc_interval_ms: u64,
                 peer: SocketAddr,
                 peer_enc_pk: &box_::PublicKey,
                 f: Finish)
                 -> ::Res<()> {
        let os_ttl = sock.ttl()?;
        sock.set_ttl(ttl as u32)?;

        let timeout = match ifc.set_timeout(Duration::from_millis(ttl_inc_interval_ms),
                                            NatTimer::new(token, TIMER_ID)) {
            Ok(timeout) => timeout,
            Err(e) => {
                let _ = poll.deregister(&sock);
                return Err(From::from(e));
            }
        };

        if let Err(e) = poll.reregister(&sock,
                                        token,
                                        Ready::writable() | Ready::readable() | Ready::error() |
                                        Ready::hup(),
                                        PollOpt::edge()) {
            let _ = poll.deregister(&sock);
            return Err(From::from(e));
        }

        let puncher = Rc::new(RefCell::new(Puncher {
            token: token,
            sock: Some(sock),
            peer: peer,
            key: box_::precompute(peer_enc_pk, ifc.enc_sk()),
            connection_chooser: ifc.enc_pk() > peer_enc_pk,
            os_ttl: os_ttl,
            current_ttl: ttl as u32,
            ttl_inc_interval_ms: ttl_inc_interval_ms,
            timeout: timeout,
            sending: Sending::Syn,
            syn_ack_rxd: false,
            syn_ack_txd: false,
            f: f,
        }));

        if let Err((nat_state, e)) = ifc.insert_state(token, puncher) {
            debug!("Error inserting state: {:?}", e);
            nat_state.borrow_mut().terminate(ifc, poll);
            return Err(NatError::UdpHolePunchFailed);
        }

        Ok(())
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) {
        let mut buf = [0; 512];
        // FIXME will need to be done in a loop until wouldblock or Ok(None) - Same for rendezvous
        // server
        let r = match self.sock.as_ref() {
            Some(s) => s.recv_from(&mut buf),
            None => return,
        };
        let bytes_rxd = match r {
            Ok(Some((bytes, _))) => bytes,
            Ok(None) => return,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => return,
            Err(e) => {
                debug!("Udp Hole Puncher has errored out in read: {:?}", e);
                return self.handle_err(ifc, poll);
            }
        };

        let msg = match ::msg_to_read(&buf[..bytes_rxd], &self.key) {
            Ok(m) => m,
            Err(e) => {
                debug!("Udp Hole Puncher has errored out in read: {:?}", e);
                return self.handle_err(ifc, poll);
            }
        };

        if msg == SYN {
            self.sending = Sending::SynAck;
        } else if msg == SYN_ACK {
            if self.syn_ack_txd {
                self.sending = if self.connection_chooser {
                    Sending::Ack
                } else {
                    let _ = ifc.cancel_timeout(&self.timeout);
                    Sending::None
                };
            } else {
                self.sending = Sending::SynAck;
                self.syn_ack_rxd = true;
            }
        } else if msg == ACK {
            if self.connection_chooser {
                debug!("No tolerance for a non chooser giving us an ACK - terminating");
                return self.handle_err(ifc, poll);
            } else {
                return self.done(ifc, poll);
            }
        }
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll) {
        if let Err(e) = self.write_impl(ifc, poll) {
            debug!("Udp Hole Puncher has errored out in write: {:?}", e);
            self.handle_err(ifc, poll)
        }
    }

    fn write_impl(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        let msg = {
            let m = match self.sending {
                Sending::Syn => SYN,
                Sending::SynAck => SYN_ACK,
                Sending::Ack => ACK,
                Sending::None => {
                    let _ = ifc.cancel_timeout(&self.timeout);
                    return Ok(());
                }
            };

            ::msg_to_send(m, &self.key)?
        };

        let r = match self.sock.as_ref() {
            Some(s) => s.send_to(&msg, &self.peer),
            None => return Err(NatError::UnregisteredSocket),
        };
        let sent = match r {
            Ok(Some(bytes_txd)) => {
                if bytes_txd != msg.len() {
                    debug!("Partial datagram sent - datagram will be treated as corrupted. \
                            Actual size: {} B, sent size: {} B.",
                           msg.len(),
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
            match self.sending {
                Sending::SynAck => self.syn_ack_txd = true,
                Sending::Ack => return Ok(self.done(ifc, poll)),
                _ => (),
            }
            if self.syn_ack_txd && self.syn_ack_rxd {
                self.sending = if self.connection_chooser {
                    Sending::Ack
                } else {
                    let _ = ifc.cancel_timeout(&self.timeout);
                    Sending::None
                };
            }
            Ok(poll.reregister(self.sock.as_ref().ok_or(NatError::UnregisteredSocket)?,
                            self.token,
                            Ready::readable() | Ready::error() | Ready::hup(),
                            PollOpt::edge())?)
        } else {
            Ok(poll.reregister(self.sock.as_ref().ok_or(NatError::UnregisteredSocket)?,
                            self.token,
                            Ready::readable() | Ready::writable() | Ready::error() | Ready::hup(),
                            PollOpt::edge())?)
        }
    }

    fn done(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let _ = ifc.cancel_timeout(&self.timeout);
        match self.sock.take() {
            Some(s) => (*self.f)(ifc, poll, self.token, Ok((s, self.peer))),
            None => (*self.f)(ifc, poll, self.token, Err(NatError::UdpHolePunchFailed)),
        }
    }

    fn handle_err(&mut self, ifc: &mut Interface, poll: &Poll) {
        self.terminate(ifc, poll);
        (*self.f)(ifc, poll, self.token, Err(NatError::UdpHolePunchFailed));
    }
}

impl NatState for Puncher {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_error() || event.is_hup() {
            let e = match self.sock
                .as_ref()
                .ok_or(NatError::UnregisteredSocket)
                .and_then(|s| s.take_error().map_err(From::from)) {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            debug!("Error in Udp Puncher readiness: {:?}", e);
            self.handle_err(ifc, poll)
        } else if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            self.write(ifc, poll)
        } else {
            trace!("Ignoring unknown event kind: {:?}", event);
        }
    }

    fn timeout(&mut self, ifc: &mut Interface, poll: &Poll, timer_id: u8) {
        if timer_id != TIMER_ID {
            debug!("Invalid Timer ID: {}", timer_id);
        }
        self.timeout = match ifc.set_timeout(Duration::from_millis(self.ttl_inc_interval_ms),
                                             NatTimer::new(self.token, TIMER_ID)) {
            Ok(t) => t,
            Err(e) => {
                debug!("Error in setting timeout: {:?}", e);
                return self.handle_err(ifc, poll);
            }

        };
        self.current_ttl += 1;
        if self.current_ttl >= self.os_ttl {
            debug!("OS TTL reached and still could not hole punch - giving up");
            return self.handle_err(ifc, poll);
        }
        let r = match self.sock.as_ref() {
            Some(sock) => sock.set_ttl(self.current_ttl).map_err(From::from),
            None => Err(NatError::UnregisteredSocket),
        };
        if let Err(e) = r {
            debug!("Error setting ttl: {:?}", e);
            return self.handle_err(ifc, poll);
        }

        self.write(ifc, poll)
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let _ = ifc.cancel_timeout(&self.timeout);
        if let Some(sock) = self.sock.take() {
            let _ = poll.deregister(&sock);
        }
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
