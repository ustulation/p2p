use {Interface, NatError, NatState};
use mio::{Poll, PollOpt, Ready, Token};
use mio::tcp::TcpStream;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::mem;
use std::rc::Rc;
use tcp::Socket;

pub type Finish = Box<FnMut(&mut Interface, &Poll, Token, ::Res<TcpStream>)>;

const CHOOSE_CONN: &'static [u8] = b"Choose this connection";

enum ConnectionChooser {
    Choose(Option<Vec<u8>>),
    Wait(box_::PrecomputedKey),
}

pub struct Puncher {
    token: Token,
    sock: Socket,
    connection_chooser: ConnectionChooser,
    f: Finish,
}

impl Puncher {
    pub fn start(ifc: &mut Interface,
                 poll: &Poll,
                 sock: Socket,
                 token: Option<Token>,
                 peer_enc_pk: &box_::PublicKey,
                 f: Finish)
                 -> ::Res<Token> {
        let token = token.unwrap_or_else(|| ifc.new_token());

        poll.register(&sock,
                      token,
                      Ready::readable() | Ready::writable() | Ready::readable() |
                      Ready::error() | Ready::hup(),
                      PollOpt::edge())?;

        let key = box_::precompute(peer_enc_pk, ifc.enc_sk());
        let chooser = if ifc.enc_pk() > peer_enc_pk {
            ConnectionChooser::Choose(Some(::msg_to_send(CHOOSE_CONN, &key)?))
        } else {
            ConnectionChooser::Wait(key)
        };

        let puncher = Rc::new(RefCell::new(Puncher {
            token: token,
            sock: sock,
            connection_chooser: chooser,
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
        if let Err(e) = self.sock.write(poll, self.token, m) {
            debug!("Tcp Puncher errored out in write: {:?}", e);
            self.handle_err(ifc, poll);
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
        if event.is_error() || event.is_hup() {
            let e = match self.sock.take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            debug!("Error in TcpRendezvousServer readiness: {:?}", e);
            self.handle_err(ifc, poll)
        } else if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            let m = if let ConnectionChooser::Choose(ref mut m) = self.connection_chooser {
                m.take()
            } else {
                return self.handle_err(ifc, poll);
            };
            self.write(ifc, poll, m)
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
