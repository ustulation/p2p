use super::{UdpEchoReq, UdpEchoResp};
use {Interface, NatError, NatState};
use bincode::{SizeLimit, deserialize, serialize};
use config::UDP_RENDEZVOUS_PORT;
use mio::{Poll, PollOpt, Ready, Token};
use mio::udp::UdpSocket;
use sodium::crypto::box_::PublicKey;
use sodium::crypto::sealedbox;
use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;

/// UDP Rendezvous server.
///
/// This is intended to be kept running on some publicly reachable endpoint so that peers can
/// obtain their rendezvous information. The information provided back to the peer is encrypted
/// with peer-supplied asymmetric key. Certain router and firewalls scan the packet and if they
/// find an IP address belonging to their pool that they use to do the NAT mapping/translation,
/// they take it as a STUN attempt or similar and mangle the information or even discard it.
/// Encrypting makes sure no such thing happens.
pub struct UdpRendezvousServer {
    sock: UdpSocket,
    token: Token,
    write_queue: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl UdpRendezvousServer {
    /// Boot the UDP Rendezvous server. This should normally be called only once.
    pub fn start(ifc: &mut Interface, poll: &Poll) -> ::Res<Token> {
        let port = ifc.config().udp_rendezvous_port.unwrap_or(UDP_RENDEZVOUS_PORT);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
        let sock = UdpSocket::bind(&addr)?;

        let token = ifc.new_token();

        poll.register(&sock,
                      token,
                      Ready::readable() | Ready::error() | Ready::hup(),
                      PollOpt::edge())?;

        let server = Rc::new(RefCell::new(UdpRendezvousServer {
                                              sock: sock,
                                              token: token,
                                              write_queue: VecDeque::with_capacity(3),
                                          }));

        if ifc.insert_state(token, server.clone()).is_err() {
            warn!("Unable to start UdpRendezvousServer!");
            server.borrow_mut().terminate(ifc, poll);
            Err(NatError::UdpRendezvousServerStartFailed)
        } else {
            Ok(token)
        }
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) {
        let mut buf = [0; 512];
        let (bytes_rxd, peer) = match self.sock.recv_from(&mut buf) {
            Ok(Some((bytes, peer))) => (bytes, peer),
            Ok(None) => return,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => return,
            Err(e) => {
                warn!("Udp Rendezvous Server has errored out in read: {:?}", e);
                return self.terminate(ifc, poll);
            }
        };

        let UdpEchoReq(peer_pk) = match deserialize(&buf[..bytes_rxd]) {
            Ok(req) => req,
            Err(e) => {
                trace!("Unknown msg rxd by Udp Rendezvous Server: {:?}", e);
                return;
            }
        };

        let resp = UdpEchoResp(sealedbox::seal(format!("{}", peer).as_bytes(),
                                               &PublicKey(peer_pk)));
        let ser_resp = match serialize(&resp, SizeLimit::Infinite) {
            Ok(s) => s,
            Err(e) => {
                warn!("Error in serialization: {:?}", e);
                return;
            }
        };

        self.write_queue.push_back((peer, ser_resp));
        self.write(ifc, poll)
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll) {
        if let Err(e) = self.write_impl(poll) {
            warn!("Udp Rendezvous Server has errored out in write: {:?}", e);
            self.terminate(ifc, poll)
        }
    }

    fn write_impl(&mut self, poll: &Poll) -> ::Res<()> {
        let (peer, resp) = match self.write_queue.pop_front() {
            Some((peer, resp)) => (peer, resp),
            None => return Ok(()),
        };

        match self.sock.send_to(&resp, &peer) {
            Ok(Some(bytes_txd)) => {
                if bytes_txd != resp.len() {
                    debug!("Partial datagram sent - datagram will be treated as corrupted. \
                            Actual size: {} B, sent size: {} B.",
                           resp.len(),
                           bytes_txd);
                }
            }
            Ok(None) => self.write_queue.push_front((peer, resp)),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => {
                self.write_queue.push_front((peer, resp))
            }
            Err(e) => return Err(From::from(e)),
        }

        if self.write_queue.is_empty() {
            Ok(poll.reregister(&self.sock,
                               self.token,
                               Ready::readable() | Ready::error() | Ready::hup(),
                               PollOpt::edge())?)
        } else {
            Ok(poll.reregister(&self.sock,
                               self.token,
                               Ready::readable() | Ready::writable() | Ready::error() |
                               Ready::hup(),
                               PollOpt::edge())?)
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
            self.read(ifc, poll)
        } else if event.is_writable() {
            self.write(ifc, poll)
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
