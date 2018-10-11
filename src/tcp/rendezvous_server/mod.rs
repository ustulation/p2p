use self::exchange_msg::ExchangeMsg;
use config::TCP_RENDEZVOUS_PORT;
use mio::tcp::TcpListener;
use mio::{Poll, PollOpt, Ready, Token};
use net2::TcpBuilder;
use std::any::Any;
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;
use tcp::{Socket, TcpEchoReq, TcpEchoResp};
use {Interface, NatError, NatState};

mod exchange_msg;

const LISTENER_BACKLOG: i32 = 100;

/// TCP Rendezvous server.
///
/// This is intended to be kept running on some publicly reachable endpoint so that peers can
/// obtain their rendezvous information. The information provided back to the peer is encrypted
/// with peer-supplied asymmetric key. Certain router and firewalls scan the packet and if they
/// find an IP address belonging to their pool that they use to do the NAT mapping/translation,
/// they take it as a STUN attempt or similar and mangle the information or even discard it.
/// Encrypting makes sure no such thing happens.
pub struct TcpRendezvousServer {
    token: Token,
    listener: TcpListener,
}

impl TcpRendezvousServer {
    /// Boot the TCP Rendezvous server. This should normally be called only once.
    pub fn start(ifc: &mut Interface, poll: &Poll) -> ::Res<Token> {
        let listener = {
            let port = ifc
                .config()
                .tcp_rendezvous_port
                .unwrap_or(TCP_RENDEZVOUS_PORT);
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
            let builder = TcpBuilder::new_v4()?;
            let _ = builder.bind(addr)?;
            let l = builder.listen(LISTENER_BACKLOG)?;
            TcpListener::from_listener(l, &addr)?
        };

        let token = ifc.new_token();

        poll.register(
            &listener,
            token,
            Ready::readable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        )?;

        let server = Rc::new(RefCell::new(TcpRendezvousServer {
            token: token,
            listener: listener,
        }));

        if ifc.insert_state(token, server.clone()).is_err() {
            warn!("Unable to start TcpRendezvousServer!");
            server.borrow_mut().terminate(ifc, poll);
            Err(NatError::TcpRendezvousServerStartFailed)
        } else {
            Ok(token)
        }
    }

    fn accept(&mut self, ifc: &mut Interface, poll: &Poll) {
        loop {
            match self.listener.accept() {
                Ok((socket, peer)) => {
                    if let Err(e) = ExchangeMsg::start(ifc, poll, peer, Socket::wrap(socket)) {
                        debug!("Error accepting direct connection: {:?}", e);
                    }
                }
                Err(e) => {
                    debug!("Failed to accept new socket: {:?}", e);
                    return;
                }
            }
        }
    }
}

impl NatState for TcpRendezvousServer {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_error() || event.is_hup() {
            let e = match self.listener.take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            warn!("Error in TcpRendezvousServer readiness: {:?}", e);
            self.terminate(ifc, poll)
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
