use mio::tcp::TcpStream;
use mio::timer::Timeout;
use mio::{Poll, PollOpt, Ready, Token};
use net2::TcpStreamExt;
use socket_collection::TcpSock;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};
use tcp::new_reusably_bound_tcp_sockets;
use {Interface, NatError, NatState, NatTimer};

pub type Finish = Box<FnMut(&mut Interface, &Poll, Token, ::Res<(TcpSock, Duration)>)>;

pub enum Via {
    Connect {
        our_addr: SocketAddr,
        peer_addr: SocketAddr,
    },
    Accept(TcpSock, Token, Instant),
}

const TIMER_ID: u8 = 0;
const RE_CONNECT_MS: u64 = 100;
const CHOOSE_CONN: &[u8] = b"Choose this connection";

enum ConnectionChooser {
    Choose(Option<Vec<u8>>),
    Wait(box_::PrecomputedKey),
}

pub struct Puncher {
    token: Token,
    sock: TcpSock,
    our_addr: SocketAddr,
    peer_addr: SocketAddr,
    via_accept: bool,
    connection_chooser: ConnectionChooser,
    timeout: Option<Timeout>,
    commenced_at: Instant,
    f: Finish,
}

impl Puncher {
    pub fn start(
        ifc: &mut Interface,
        poll: &Poll,
        via: Via,
        peer_enc_pk: &box_::PublicKey,
        f: Finish,
    ) -> ::Res<Token> {
        let (sock, token, via_accept, our_addr, peer_addr, commenced_at) = match via {
            Via::Accept(sock, t, commenced_at) => {
                let our_addr = sock.local_addr()?;
                let peer_addr = sock.peer_addr()?;
                (sock, t, true, our_addr, peer_addr, commenced_at)
            }
            Via::Connect {
                our_addr,
                peer_addr,
            } => {
                let stream = new_reusably_bound_tcp_sockets(&our_addr, 1)?.0[0].to_tcp_stream()?;
                stream.set_linger(Some(Duration::from_secs(0)))?;
                let sock = TcpSock::wrap(TcpStream::connect_stream(stream, &peer_addr)?);
                (
                    sock,
                    ifc.new_token(),
                    false,
                    our_addr,
                    peer_addr,
                    Instant::now(),
                )
            }
        };

        poll.register(
            &sock,
            token,
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        )?;

        let key = box_::precompute(peer_enc_pk, ifc.enc_sk());
        let chooser = if ifc.enc_pk() > peer_enc_pk {
            ConnectionChooser::Choose(Some(::msg_to_send(CHOOSE_CONN, &key)?))
        } else {
            ConnectionChooser::Wait(key)
        };

        let puncher = Rc::new(RefCell::new(Puncher {
            token,
            sock,
            our_addr,
            peer_addr,
            via_accept,
            connection_chooser: chooser,
            timeout: None,
            commenced_at,
            f,
        }));

        if let Err((nat_state, e)) = ifc.insert_state(token, puncher) {
            debug!("Error inserting state: {:?}", e);
            nat_state.borrow_mut().terminate(ifc, poll);
            return Err(NatError::TcpHolePunchFailed);
        }

        Ok(token)
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) {
        let mut ok = false;
        loop {
            match self.sock.read::<Vec<u8>>() {
                Ok(Some(cipher_text)) => {
                    if let ConnectionChooser::Wait(ref key) = self.connection_chooser {
                        match ::msg_to_read(&cipher_text, key) {
                            Ok(ref plain_text) if plain_text == &CHOOSE_CONN => ok = true,
                            _ => {
                                debug!("Error: Failed to decrypt a connection-choose order");
                                ok = false;
                                break;
                            }
                        }
                    } else {
                        debug!("Error: A chooser TcpPucher got a choose order");
                        ok = false;
                        break;
                    }
                }
                Ok(None) => {
                    if ok {
                        break;
                    } else {
                        return;
                    }
                }
                Err(e) => {
                    debug!("Tcp Puncher errored out in read: {:?}", e);
                    ok = false;
                    break;
                }
            }
        }

        if ok {
            self.done(ifc, poll)
        } else {
            self.handle_err(ifc, poll)
        }
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll, m: Option<Vec<u8>>) {
        match self.sock.write(m.map(|m| (m, 0))) {
            Ok(true) => self.done(ifc, poll),
            Ok(false) => (),
            Err(e) => {
                debug!("Tcp Puncher errored out in write: {:?}", e);
                self.handle_err(ifc, poll);
            }
        }
    }

    fn done(&mut self, ifc: &mut Interface, poll: &Poll) {
        if let Some(t) = self.timeout.take() {
            let _ = ifc.cancel_timeout(&t);
        }
        let _ = ifc.remove_state(self.token);
        let sock = mem::replace(&mut self.sock, Default::default());
        let dur = self.commenced_at.elapsed();
        (*self.f)(ifc, poll, self.token, Ok((sock, dur)));
    }

    fn handle_err(&mut self, ifc: &mut Interface, poll: &Poll) {
        if self.via_accept {
            self.terminate(ifc, poll);
            (*self.f)(ifc, poll, self.token, Err(NatError::TcpHolePunchFailed));
        } else {
            // NOTE: Windows Fix. Edge trigger on error works like Level trigger on Windows and
            // instead of not notifying the error again, it actually notifies it immediately going
            // into an infinite loop. So deregister the socket immediately.
            let _ = poll.deregister(&self.sock);
            let _ = mem::replace(&mut self.sock, Default::default());

            // If read/write both fire one after another and error out for some reason, good idea
            // to cancel any set timers before to not have zombie timers around. Although this
            // should not happen because we have deregistered the socket above, still do it for
            // defensive programming because mio is not clear if `deregister` will prevent the
            // already accumulated events from firing or not. Since our state is still `alive` if
            // it does fire for the discarded socket, we will reach here.
            if let Some(t) = self.timeout.take() {
                let _ = ifc.cancel_timeout(&t);
            }
            match ifc.set_timeout(
                Duration::from_millis(RE_CONNECT_MS),
                NatTimer::new(self.token, TIMER_ID),
            ) {
                Ok(t) => self.timeout = Some(t),
                Err(e) => {
                    debug!("Error setting timeout: {:?}", e);
                    self.terminate(ifc, poll);
                    (*self.f)(ifc, poll, self.token, Err(NatError::TcpHolePunchFailed));
                }
            }
        }
    }
}

impl NatState for Puncher {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            if !self.via_accept {
                let r = || -> ::Res<TcpSock> {
                    let sock = mem::replace(&mut self.sock, Default::default());
                    sock.set_linger(None)?;
                    Ok(sock)
                }();

                match r {
                    Ok(s) => self.sock = s,
                    Err(e) => {
                        debug!("Terminating due to error: {:?}", e);
                        self.terminate(ifc, poll);
                        (*self.f)(ifc, poll, self.token, Err(NatError::TcpHolePunchFailed));
                    }
                }
            }
            let m = if let ConnectionChooser::Choose(ref mut m) = self.connection_chooser {
                m.take()
            } else {
                return;
            };
            self.write(ifc, poll, m)
        } else {
            warn!("Investigate: Ignoring unknown event kind: {:?}", event);
        }
    }

    fn timeout(&mut self, ifc: &mut Interface, poll: &Poll, timer_id: u8) {
        if timer_id != TIMER_ID {
            debug!("Invalid timer id: {}", timer_id);
        }

        let r = || -> ::Res<TcpSock> {
            let stream = new_reusably_bound_tcp_sockets(&self.our_addr, 1)?.0[0].to_tcp_stream()?;
            stream.set_linger(Some(Duration::from_secs(0)))?;
            let sock = TcpSock::wrap(TcpStream::connect_stream(stream, &self.peer_addr)?);
            poll.register(
                &sock,
                self.token,
                Ready::readable() | Ready::writable(),
                PollOpt::edge(),
            )?;
            Ok(sock)
        }();

        match r {
            Ok(s) => self.sock = s,
            Err(e) => {
                debug!("Aborting connection attempt due to: {:?}", e);
                self.terminate(ifc, poll);
                (*self.f)(ifc, poll, self.token, Err(NatError::TcpHolePunchFailed));
            }
        }
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        if let Some(t) = self.timeout.take() {
            let _ = ifc.cancel_timeout(&t);
        }
        let _ = ifc.remove_state(self.token);
        let _ = poll.deregister(&self.sock);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
