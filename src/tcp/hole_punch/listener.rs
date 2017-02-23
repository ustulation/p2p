use super::puncher::{Finish, Puncher};
use {Interface, NatError, NatState};
use mio::{Poll, PollOpt, Ready, Token};
use mio::tcp::TcpListener;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use tcp::Socket;

pub struct Listener {
    token: Token,
    listener: TcpListener,
    peer_enc_key: box_::PublicKey,
    f: Option<Finish>,
}

impl Listener {
    pub fn start(ifc: &mut Interface,
                 poll: &Poll,
                 l: TcpListener,
                 peer_enc_key: &box_::PublicKey,
                 f: Finish)
                 -> ::Res<Token> {
        let token = ifc.new_token();

        poll.register(&l,
                      token,
                      Ready::readable() | Ready::error() | Ready::hup(),
                      PollOpt::edge())?;

        let listener = Rc::new(RefCell::new(Listener {
            token: token,
            listener: l,
            peer_enc_key: *peer_enc_key,
            f: Some(f),
        }));

        if ifc.insert_state(token, listener.clone()).is_err() {
            warn!("Unable to start Listener!");
            listener.borrow_mut().terminate(ifc, poll);
            Err(NatError::TcpHolePunchFailed)
        } else {
            Ok(token)
        }
    }

    fn accept(&mut self, ifc: &mut Interface, poll: &Poll) {
        match self.listener.accept() {
            Ok((socket, _)) => {
                self.terminate(ifc, poll);
                let f = match self.f.take() {
                    Some(f) => f,
                    None => return,
                };
                if let Err(e) = Puncher::start(ifc,
                                               poll,
                                               Socket::wrap(socket),
                                               Some(self.token),
                                               &self.peer_enc_key,
                                               f) {
                    debug!("Error accepting direct puncher connection: {:?}", e);
                }
            }
            Err(e) => debug!("Failed to accept new socket: {:?}", e),
        }
    }

    fn handle_err(&mut self, ifc: &mut Interface, poll: &Poll) {
        self.terminate(ifc, poll);
        if let Some(ref mut f) = self.f {
            f(ifc, poll, self.token, Err(NatError::TcpHolePunchFailed));
        }
    }
}

impl NatState for Listener {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_error() || event.is_hup() {
            let e = match self.listener.take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            warn!("Error in Listener readiness: {:?}", e);
            self.handle_err(ifc, poll)
        } else if event.is_readable() {
            self.accept(ifc, poll)
        } else {
            trace!("Ignoring unknown event kind: {:?}", event);
        }
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let _ = poll.deregister(&self.listener);
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
