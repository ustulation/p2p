use mio::timer::Timeout;
use mio::{Poll, PollOpt, Ready, Token};
use socket_collection::UdpSock;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};
use std::{fmt, mem};
use {Interface, NatError, NatState, NatTimer};

// Result of (UdpSock, peer, starting_ttl, ttl_on_being_reached, duration-of-hole-punch)
pub type Finish =
    Box<FnMut(&mut Interface, &Poll, Token, ::Res<(UdpSock, SocketAddr, u32, u32, Duration)>)>;

const TIMER_ID: u8 = 0;
const SYN: &[u8] = b"SYN";
const SYN_ACK: &[u8] = b"SYN-ACK";
const ACK: &[u8] = b"ACK";
const ACK_ACK: &[u8] = b"ACK_ACK"; // Fire and forget optimistic case to release ACK-sender
const MAX_ACK_RETRANSMISSIONS: u8 = 3;

#[derive(Debug, Eq, PartialEq)]
enum Sending {
    Syn,
    SynAck,
    Ack,
    AckAck,
}

pub struct Puncher {
    token: Token,
    sock: UdpSock,
    peer: SocketAddr,
    key: box_::PrecomputedKey,
    connection_chooser: bool,
    os_ttl: u32,
    starting_ttl: u32,
    current_ttl: u32,
    ttl_on_being_reached: u32,
    ttl_inc_interval_ms: u64,
    timeout: Timeout,
    sending: Sending,
    num_acks_transmitted: u8,
    commenced_at: Instant,
    f: Finish,
}

impl Puncher {
    pub fn start(
        ifc: &mut Interface,
        poll: &Poll,
        token: Token,
        mut sock: UdpSock,
        starting_ttl: u8,
        ttl_inc_interval_ms: u64,
        peer: SocketAddr,
        peer_enc_pk: &box_::PublicKey,
        f: Finish,
    ) -> ::Res<()> {
        let os_ttl = sock.ttl()?;
        let starting_ttl = starting_ttl as u32;
        sock.set_ttl(starting_ttl)?;
        sock.connect(&peer).map_err(|e| {
            debug!("Error: Failed to connect UDP Puncher: {:?}", e);
            e
        })?;

        let timeout = match ifc.set_timeout(
            Duration::from_millis(ttl_inc_interval_ms),
            NatTimer::new(token, TIMER_ID),
        ) {
            Ok(timeout) => timeout,
            Err(e) => {
                debug!("Error: UdpPuncher errored in setting timeout: {:?}", e);
                let _ = poll.deregister(&sock);
                return Err(From::from(e));
            }
        };

        if let Err(e) = poll.reregister(
            &sock,
            token,
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        ) {
            debug!("Error: UdpPuncher errored in registeration: {:?}", e);
            let _ = poll.deregister(&sock);
            return Err(From::from(e));
        }

        let puncher = Rc::new(RefCell::new(Puncher {
            token: token,
            sock,
            peer,
            key: box_::precompute(peer_enc_pk, ifc.enc_sk()),
            connection_chooser: ifc.enc_pk() > peer_enc_pk,
            os_ttl,
            starting_ttl,
            current_ttl: starting_ttl,
            ttl_on_being_reached: 0,
            ttl_inc_interval_ms,
            timeout,
            sending: Sending::Syn,
            num_acks_transmitted: 0,
            commenced_at: Instant::now(),
            f,
        }));

        if let Err((nat_state, e)) = ifc.insert_state(token, puncher) {
            debug!("Error inserting state: {:?}", e);
            nat_state.borrow_mut().terminate(ifc, poll);
            return Err(NatError::UdpHolePunchFailed);
        }

        Ok(())
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) {
        let mut cipher_text = Vec::new();
        loop {
            match self.sock.read() {
                Ok(Some(m)) => cipher_text = m,
                Ok(None) => if cipher_text.is_empty() {
                    return;
                } else {
                    break;
                },
                Err(e) => {
                    trace!(
                        "{} Ignoring Error Read: {:?} - These are likely caused by ICMP errors for \
                        timeout/ttl-drops or unreachable-peer/port. Continue with ttl-runners.",
                        self, e);
                    if cipher_text.is_empty() {
                        return;
                    } else {
                        break;
                    }
                }
            }
        }

        let msg = match ::msg_to_read(&cipher_text, &self.key) {
            Ok(m) => m,
            Err(e) => {
                debug!("{} Errored while deciphering incoming data: {:?}", self, e);
                return self.handle_err(ifc, poll);
            }
        };

        if msg == SYN {
            if let Sending::Syn = self.sending {
                self.sending = Sending::SynAck;
            }
        } else if msg == SYN_ACK {
            if self.connection_chooser {
                self.sending = Sending::Ack
            } else if let Sending::Syn = self.sending {
                self.sending = Sending::SynAck;
            }
        } else if msg == ACK {
            if self.connection_chooser {
                info!(
                    "{} No tolerance for a non chooser giving us an ACK - terminating",
                    self
                );
                return self.handle_err(ifc, poll);
            }
            self.sending = Sending::AckAck;
        } else if msg == ACK_ACK {
            if !self.connection_chooser {
                info!(
                    "{} No tolerance for a chooser giving us an ACK_ACK - terminating",
                    self
                );
                return self.handle_err(ifc, poll);
            }
            trace!("{} Rxd ACK_ACK - we are done", self);
            return self.done(ifc, poll);
        }

        // Since we have read something, revert back to OS default TTL
        if self.current_ttl != self.os_ttl {
            if let Err(e) = self.sock.set_ttl(self.os_ttl) {
                debug!("{} Error: Could not set OS Default TTL: {:?}", self, e);
                return self.handle_err(ifc, poll);
            } else {
                self.ttl_on_being_reached = self.current_ttl;
                self.current_ttl = self.os_ttl;
            }
        }

        // Do a premature-handshake since we have received something. This will hasten things up.
        self.continue_handshake(ifc, poll);
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll, m: Option<Vec<u8>>) {
        match self.sock.write(m.map(|m| (m, 0))) {
            Ok(true) => self.on_successful_send(ifc, poll),
            Ok(false) => (),
            Err(e) => trace!(
                "{} Ignoring Error in Write: {:?} - These are likely caused by ICMP errors for \
                 timeout/ttl-drops or unreachable-peer/port. Continue with ttl-runners.",
                self,
                e
            ),
        }
    }

    fn continue_handshake(&mut self, ifc: &mut Interface, poll: &Poll) {
        let msg = {
            let m = match self.sending {
                Sending::Syn => SYN,
                Sending::SynAck => SYN_ACK,
                Sending::Ack => {
                    if self.num_acks_transmitted < MAX_ACK_RETRANSMISSIONS {
                        self.num_acks_transmitted += 1;
                    }
                    if self.num_acks_transmitted == MAX_ACK_RETRANSMISSIONS {
                        let _ = ifc.cancel_timeout(&self.timeout);
                    }
                    ACK
                }
                Sending::AckAck => {
                    let _ = ifc.cancel_timeout(&self.timeout);
                    ACK_ACK
                }
            };

            match ::msg_to_send(m, &self.key) {
                Ok(m) => m,
                Err(e) => {
                    debug!("{} Error: while encrypting: {:?}", self, e);
                    return self.handle_err(ifc, poll);
                }
            }
        };

        self.write(ifc, poll, Some(msg));
    }

    fn on_successful_send(&mut self, ifc: &mut Interface, poll: &Poll) {
        match self.sending {
            Sending::Ack => if self.num_acks_transmitted == MAX_ACK_RETRANSMISSIONS {
                trace!("{} Sent all ACKs - we are done", self);
                self.done(ifc, poll);
            },
            Sending::AckAck => {
                trace!("{} Sent ACK_ACK - we are done", self);
                self.done(ifc, poll);
            }
            _ => (),
        }
    }

    fn done(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let _ = ifc.cancel_timeout(&self.timeout);
        let s = mem::replace(&mut self.sock, Default::default());
        (*self.f)(
            ifc,
            poll,
            self.token,
            Ok((
                s,
                self.peer,
                self.starting_ttl,
                self.ttl_on_being_reached,
                self.commenced_at.elapsed(),
            )),
        );
    }

    fn handle_err(&mut self, ifc: &mut Interface, poll: &Poll) {
        self.terminate(ifc, poll);
        (*self.f)(ifc, poll, self.token, Err(NatError::UdpHolePunchFailed));
    }
}

impl NatState for Puncher {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            self.write(ifc, poll, None)
        } else {
            warn!(
                "{} Investigate: Ignoring unknown event kind: {:?}",
                self, event
            );
        }
    }

    fn timeout(&mut self, ifc: &mut Interface, poll: &Poll, timer_id: u8) {
        if timer_id != TIMER_ID {
            warn!("{} Invalid Timer ID: {}", self, timer_id);
        }

        self.timeout = match ifc.set_timeout(
            Duration::from_millis(self.ttl_inc_interval_ms),
            NatTimer::new(self.token, TIMER_ID),
        ) {
            Ok(t) => t,
            Err(e) => {
                debug!("{} Error in setting timeout: {:?}", self, e);
                return self.handle_err(ifc, poll);
            }
        };

        // If we have got an incoming message we would have had set current to the os value so
        // keep it at that, else do the usual incrementing.
        if self.current_ttl < self.os_ttl {
            self.current_ttl += 1;
            if self.current_ttl == self.os_ttl {
                debug!(
                    "{} OS TTL reached and still peer did not reach us - giving up",
                    self
                );
                return self.handle_err(ifc, poll);
            }
            if let Err(e) = self.sock.set_ttl(self.current_ttl) {
                debug!("{} Error setting ttl: {:?}", self, e);
                return self.handle_err(ifc, poll);
            }
        }

        self.continue_handshake(ifc, poll)
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let _ = ifc.cancel_timeout(&self.timeout);
        let _ = poll.deregister(&self.sock);

        trace!("{} terminated", self);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

impl fmt::Display for Puncher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ttl_on_being_reached = if self.ttl_on_being_reached == 0 {
            "N/A".to_string()
        } else {
            format!("{}", self.ttl_on_being_reached)
        };
        write!(
            f,
            "UdpPuncher [peer=({:02x}{:02x}{:02x}../{}) ;; os_ttl={}, starting_ttl={}, current_ttl={}
            , ttl_on_being_reached={} ;; state={:?} ;; chooser={}]",
            self.key.0[0],
            self.key.0[1],
            self.key.0[2],
            self.peer,
            self.os_ttl,
            self.starting_ttl,
            self.current_ttl,
            ttl_on_being_reached,
            self.sending,
            self.connection_chooser
        )
    }
}
