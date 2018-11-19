use super::{UdpEchoReq, UdpEchoResp};
use config::UDP_RENDEZVOUS_PORT;
use mio::{Poll, PollOpt, Ready, Token};
use safe_crypto::PublicEncryptKey;
use socket_collection::UdpSock;
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
    terminated: bool,
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
            Ready::readable() | Ready::writable(),
            PollOpt::edge(),
        )?;

        let server = Rc::new(RefCell::new(UdpRendezvousServer {
            sock,
            token,
            terminated: false,
        }));

        if ifc.insert_state(token, server.clone()).is_err() {
            warn!("Unable to start UdpRendezvousServer!");
            server.borrow_mut().terminate(ifc, poll);
            Err(NatError::UdpRendezvousServerStartFailed)
        } else {
            Ok(token)
        }
    }

    fn read_frm(&mut self, ifc: &mut Interface, poll: &Poll) {
        let mut peers = Vec::new();
        loop {
            match self.sock.read_frm() {
                Ok(Some((UdpEchoReq(pk), peer))) => {
                    peers.push((PublicEncryptKey::from_bytes(pk), peer))
                }
                Ok(None) => if peers.is_empty() {
                    return;
                } else {
                    break;
                },
                Err(e) => {
                    debug!("Error in read: {:?}", e);
                    return self.terminate(ifc, poll);
                }
            }
        }

        for (pk, peer) in peers {
            let resp = UdpEchoResp(pk.anonymously_encrypt_bytes(format!("{}", peer).as_bytes()));
            self.write_to(ifc, poll, Some((resp, peer)));
            // Errored while writting
            if self.terminated {
                break;
            }
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
        if event.is_readable() {
            self.read_frm(ifc, poll)
        } else if event.is_writable() {
            self.write_to(ifc, poll, None)
        } else {
            warn!("Investigate: Ignoring unknown event kind: {:?}", event);
        }
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);
        let _ = poll.deregister(&self.sock);
        self.terminated = true;
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}
