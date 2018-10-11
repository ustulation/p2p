use mio::tcp::TcpStream;
use mio::timer::Timeout;
use mio::{Poll, PollOpt, Ready, Token};
use net2::TcpStreamExt;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;
use tcp::{new_reusably_bound_tcp_sockets, Socket};
use {Interface, NatError, NatState, NatTimer};

pub type Finish = Box<FnMut(&mut Interface, &Poll, Token, ::Res<TcpStream>)>;

pub enum Via {
    Connect {
        our_addr: SocketAddr,
        peer_addr: SocketAddr,
    },
    Accept(Socket, Token),
}

const TIMER_ID: u8 = 0;
const RE_CONNECT_MS: u64 = 100;
const CHOOSE_CONN: &'static [u8] = b"Choose this connection";

enum ConnectionChooser {
    Choose(Option<Vec<u8>>),
    Wait(box_::PrecomputedKey),
}

pub struct Puncher {
    token: Token,
    sock: Socket,
    our_addr: SocketAddr,
    peer_addr: SocketAddr,
    via_accept: bool,
    connection_chooser: ConnectionChooser,
    timeout: Option<Timeout>,
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
        let (sock, token, via_accept, our_addr, peer_addr) = match via {
            Via::Accept(sock, t) => {
                let our_addr = sock.local_addr()?;
                let peer_addr = sock.peer_addr()?;
                (sock, t, true, our_addr, peer_addr)
            }
            Via::Connect {
                our_addr,
                peer_addr,
            } => {
                let stream = new_reusably_bound_tcp_sockets(&our_addr, 1)?.0[0].to_tcp_stream()?;
                stream.set_linger(Some(Duration::from_secs(0)))?;
                let sock = Socket::wrap(TcpStream::connect_stream(stream, &peer_addr)?);
                (sock, ifc.new_token(), false, our_addr, peer_addr)
            }
        };

        poll.register(
            &sock,
            token,
            Ready::readable() | Ready::writable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        )?;

        let key = box_::precompute(peer_enc_pk, ifc.enc_sk());
        let chooser = if ifc.enc_pk() > peer_enc_pk {
            ConnectionChooser::Choose(Some(::msg_to_send(CHOOSE_CONN, &key)?))
        } else {
            ConnectionChooser::Wait(key)
        };

        let puncher = Rc::new(RefCell::new(Puncher {
            token: token,
            sock: sock,
            our_addr: our_addr,
            peer_addr: peer_addr,
            via_accept: via_accept,
            connection_chooser: chooser,
            timeout: None,
            f: f,
        }));

        if let Err((nat_state, e)) = ifc.insert_state(token, puncher) {
            debug!("Error inserting state: {:?}", e);
            nat_state.borrow_mut().terminate(ifc, poll);
            return Err(NatError::TcpHolePunchFailed);
        }

        Ok(token)
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) {
        let ok = match self.sock.read::<Vec<u8>>() {
            Ok(Some(cipher_text)) => {
                if let ConnectionChooser::Wait(ref key) = self.connection_chooser {
                    match ::msg_to_read(&cipher_text, key) {
                        Ok(ref plain_text) if plain_text == &CHOOSE_CONN => true,
                        _ => false,
                    }
                } else {
                    false
                }
            }
            Ok(None) => return,
            Err(e) => {
                debug!("Tcp Rendezvous client errored out in read: {:?}", e);
                false
            }
        };

        if ok {
            self.done(ifc, poll)
        } else {
            self.handle_err(ifc, poll)
        }
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll, m: Option<Vec<u8>>) {
        match self.sock.write(poll, self.token, m) {
            Ok(true) => self.done(ifc, poll),
            Ok(false) => (),
            Err(e) => {
                debug!("Tcp Puncher errored out in write: {:?}", e);
                self.handle_err(ifc, poll);
            }
        }
    }

    fn done(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let sock = mem::replace(&mut self.sock, Default::default());
        if let Ok(stream) = sock.into_stream() {
            (*self.f)(ifc, poll, self.token, Ok(stream));
        } else {
            (*self.f)(ifc, poll, self.token, Err(NatError::TcpHolePunchFailed));
        }
    }

    fn handle_err(&mut self, ifc: &mut Interface, poll: &Poll) {
        self.terminate(ifc, poll);
        (*self.f)(ifc, poll, self.token, Err(NatError::TcpHolePunchFailed));
    }
}

impl NatState for Puncher {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_error() {
            let e = match self.sock.take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            if self.via_accept {
                debug!("Error in Tcp Puncher readiness: {:?}", e);
                self.handle_err(ifc, poll)
            } else {
                trace!("Error in Tcp Puncher connector readiness: {:?}", e);
                match ifc.set_timeout(
                    Duration::from_millis(RE_CONNECT_MS),
                    NatTimer::new(self.token, TIMER_ID),
                ) {
                    Ok(t) => self.timeout = Some(t),
                    Err(e) => {
                        debug!("Error setting timeout: {:?}", e);
                        self.handle_err(ifc, poll)
                    }
                }
            }
        } else if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            if let Some(t) = self.timeout.take() {
                let _ = ifc.cancel_timeout(&t);
            }
            if !self.via_accept {
                let r = || -> ::Res<Socket> {
                    let sock = mem::replace(&mut self.sock, Default::default());
                    let stream = sock.into_stream()?;
                    stream.set_linger(None)?;
                    Ok(Socket::wrap(stream))
                }();

                match r {
                    Ok(s) => self.sock = s,
                    Err(e) => {
                        debug!("Terminating due to error: {:?}", e);
                        return self.handle_err(ifc, poll);
                    }
                }
            }
            let m = if let ConnectionChooser::Choose(ref mut m) = self.connection_chooser {
                m.take()
            } else {
                return;
            };
            self.write(ifc, poll, m)
        } else if event.is_hup() {
            debug!("Shutdown in Tcp Puncher readiness");
            self.handle_err(ifc, poll)
        } else {
            trace!("Ignoring unknown event kind: {:?}", event);
        }
    }

    fn timeout(&mut self, ifc: &mut Interface, poll: &Poll, timer_id: u8) {
        if timer_id != TIMER_ID {
            debug!("Invalid timer id: {}", timer_id);
        }
        let _ = poll.deregister(&self.sock);
        let _ = mem::replace(&mut self.sock, Default::default());

        let r = || -> ::Res<Socket> {
            let stream = new_reusably_bound_tcp_sockets(&self.our_addr, 1)?.0[0].to_tcp_stream()?;
            stream.set_linger(Some(Duration::from_secs(0)))?;
            let sock = Socket::wrap(TcpStream::connect_stream(stream, &self.peer_addr)?);
            poll.register(
                &sock,
                self.token,
                Ready::readable() | Ready::writable() | Ready::error() | Ready::hup(),
                PollOpt::edge(),
            )?;
            Ok(sock)
        }();

        match r {
            Ok(s) => self.sock = s,
            Err(e) => {
                debug!("Aborting connection attempt due to: {:?}", e);
                self.handle_err(ifc, poll)
            }
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
