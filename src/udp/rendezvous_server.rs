use super::{UdpEchoReq, UdpEchoResp};
use config::UDP_RENDEZVOUS_PORT;
use mio::{Poll, PollOpt, Ready, Token};
use socket_collection::UdpSock;
use sodium::crypto::box_;
use sodium::crypto::sealedbox;
use std::any::Any;
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;
use {Interface, NatError, NatState};

/// UDP Rendezvous server.
///
/// This is intended to be kept running on some publicly reachable endpoint so that peers can
/// obtain their rendezvous information. The information provided back to the peer is encrypted
/// with peer-supplied asymmetric key. Certain router and firewalls scan the packet and if they
/// find an IP address belonging to their pool that they use to do the NAT mapping/translation,
/// they take it as a STUN attempt or similar and mangle the information or even discard it.
/// Encrypting makes sure no such thing happens.
pub struct UdpRendezvousServer {
    sock: UdpSock,
    token: Token,
}

impl UdpRendezvousServer {
    /// Boot the UDP Rendezvous server. This should normally be called only once.
    pub fn start(ifc: &mut Interface, poll: &Poll) -> ::Res<Token> {
        let port = ifc
            .config()
            .udp_rendezvous_port
            .unwrap_or(UDP_RENDEZVOUS_PORT);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
        let sock = UdpSock::bind(&addr)?;

        let token = ifc.new_token();

        poll.register(
            &sock,
            token,
            Ready::readable() | Ready::writable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        )?;

        let server = Rc::new(RefCell::new(UdpRendezvousServer { sock, token }));

        if ifc.insert_state(token, server.clone()).is_err() {
            warn!("Unable to start UdpRendezvousServer!");
            server.borrow_mut().terminate(ifc, poll);
            Err(NatError::UdpRendezvousServerStartFailed)
        } else {
            Ok(token)
        }
    }

    fn read_frm(&mut self, ifc: &mut Interface, poll: &Poll) {
        let mut pk = None;
        loop {
            match self.sock.read_frm() {
                Ok(Some((UdpEchoReq(raw), peer))) => pk = Some((box_::PublicKey(raw), peer)),
                Ok(None) => if pk.is_some() {
                    break;
                } else {
                    return;
                },
                Err(e) => {
                    debug!("Error in read: {:?}", e);
                    return self.terminate(ifc, poll);
                }
            }
        }

        if let Some((pk, peer)) = pk.take() {
            let resp = UdpEchoResp(sealedbox::seal(format!("{}", peer).as_bytes(), &pk));
            self.write_to(ifc, poll, Some((resp, peer)))
        } else {
            debug!("Error: Logic error in Udp Rendezvous Server - Please report.");
            return self.terminate(ifc, poll);
        }
    }

    fn write_to(&mut self, ifc: &mut Interface, poll: &Poll, m: Option<(UdpEchoResp, SocketAddr)>) {
        match self.sock.write_to(m.map(|(m, s)| (m, s, 0))) {
            Ok(_) => (),
            Err(e) => {
                warn!("Udp Rendezvous Server has errored out in write: {:?}", e);
                self.terminate(ifc, poll);
            }
        }
    }
}

impl NatState for UdpRendezvousServer {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_error() || event.is_hup() {
            let e = match self.sock.take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            warn!("Error in UdpRendezvousServer readiness: {:?}", e);
            self.terminate(ifc, poll)
        } else if event.is_readable() {
            self.read_frm(ifc, poll)
        } else if event.is_writable() {
            self.write_to(ifc, poll, None)
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
