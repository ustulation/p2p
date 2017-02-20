use {Interface, NatError, NatState};
use bincode::{SizeLimit, deserialize, serialize};
use mio::{Poll, PollOpt, Ready, Token};
use mio::udp::UdpSocket;
use sodium::crypto::sealedbox;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::{self, FromStr};
use udp::{UdpEchoReq, UdpEchoResp};

pub type Finish = Box<FnMut(&mut Interface, &Poll, Token, ::Res<(UdpSocket, SocketAddr)>)>;

pub struct UdpRendezvousClient {
    sock: Option<UdpSocket>,
    token: Token,
    servers: Vec<SocketAddr>,
    // Note: DO NOT convert to Hash/BTreeSet - strict ordering is required to pair with peer
    our_ext_addrs: Vec<SocketAddr>,
    port_prediction_offset: u16,
    write_queue: Option<(SocketAddr, Vec<u8>)>,
    req: Vec<u8>,
    f: Finish,
}

impl UdpRendezvousClient {
    pub fn start(ifc: &mut Interface, poll: &Poll, sock: UdpSocket, f: Finish) -> ::Res<Token> {
        let token = ifc.new_token();
        let req = serialize(&UdpEchoReq(ifc.enc_pk().0), SizeLimit::Infinite)?;
        let mut servers = ifc.config().remote_udp_rendezvous_servers.clone();
        let num_servers = servers.len();
        if num_servers < 2 {
            info!("Udp: Symmetric NAT detection and port prediction will not be possible using \
                   less than 2 Rendezvous Servers. Use at-least 2. Recommended is 3.");
        }

        let server = match servers.pop() {
            Some(server) => server,
            None => return Err(NatError::UdpRendezvousFailed),
        };

        poll.register(&sock,
                      token,
                      Ready::writable() | Ready::error() | Ready::hup(),
                      PollOpt::edge())?;

        let client = Rc::new(RefCell::new(UdpRendezvousClient {
            sock: Some(sock),
            token: token,
            servers: servers,
            our_ext_addrs: Vec::with_capacity(num_servers),
            port_prediction_offset: 0,
            write_queue: Some((server, req.clone())),
            req: req,
            f: f,
        }));

        if ifc.insert_state(token, client.clone()).is_err() {
            debug!("Unable to insert UdpRendezvousClient State!");
            client.borrow_mut().terminate(ifc, poll)?;
            Err(NatError::UdpRendezvousFailed)
        } else {
            Ok(token)
        }
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        let mut buf = [0; 512];
        // FIXME will need to be done in a loop until wouldblock or Ok(None) - Same for rendezvous
        // server
        let bytes_rxd = match self.sock.as_ref().unwrap().recv_from(&mut buf) {
            Ok(Some((bytes, _))) => bytes,
            Ok(None) => return Ok(()),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => return Ok(()),
            Err(e) => {
                debug!("Udp Rendezvous Client has errored out in read: {:?}", e);
                return self.terminate(ifc, poll);
            }
        };

        let UdpEchoResp(cipher_text) = match deserialize(&buf[..bytes_rxd]) {
            Ok(req) => req,
            Err(e) => {
                trace!("Unknown msg rxd by Udp Rendezvous Client: {:?}", e);
                return Ok(());
            }
        };

        if let Ok(our_ext_addr_bytes) = sealedbox::open(&cipher_text, ifc.enc_pk(), ifc.enc_sk()) {
            match str::from_utf8(&our_ext_addr_bytes) {
                Ok(our_ext_addr_str) => {
                    match SocketAddr::from_str(&our_ext_addr_str) {
                        Ok(addr) => self.our_ext_addrs.push(addr),
                        Err(e) => {
                            debug!("Ignoring UdpEchoResp which contained non-parsable address: \
                                    {:?}",
                                   e);
                        }
                    }
                }
                Err(e) => {
                    debug!("Ignoring UdpEchoResp which contained non-utf9 address: {:?}",
                           e)
                }
            }
        } else {
            debug!("Ignoring UdpEchoResp which could not be decrypted.");
        }

        if let Some(server) = self.servers.pop() {
            self.write_queue = Some((server, self.req.clone()));
            self.write(ifc, poll)
        } else {
            Ok(self.done(ifc, poll))
        }
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        match self.write_impl(ifc, poll) {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("Udp Rendezvous Client has errored out in write: {:?}", e);
                self.terminate(ifc, poll)
            }
        }
    }

    fn write_impl(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        let (server, resp) = match self.write_queue.take() {
            Some((server, resp)) => (server, resp),
            None => return Ok(()),
        };

        match self.sock.as_ref().unwrap().send_to(&resp, &server) {
            Ok(Some(bytes_txd)) => {
                if bytes_txd != resp.len() {
                    debug!("Partial datagram sent - datagram will be treated as corrupted. \
                            Actual size: {} B, sent size: {} B.",
                           resp.len(),
                           bytes_txd);
                }
            }
            Ok(None) => self.write_queue = Some((server, resp)),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock ||
                          e.kind() == ErrorKind::Interrupted => {
                self.write_queue = Some((server, resp))
            }
            Err(e) => return Err(From::from(e)),
        }

        if self.write_queue.is_none() {
            Ok(poll.reregister(self.sock.as_ref().unwrap(),
                            self.token,
                            Ready::readable() | Ready::error() | Ready::hup(),
                            PollOpt::edge())?)
        } else {
            Ok(poll.reregister(self.sock.as_ref().unwrap(),
                            self.token,
                            Ready::readable() | Ready::writable() | Ready::error() | Ready::hup(),
                            PollOpt::edge())?)
        }
    }

    fn done(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);

        let mut ext_addr = match self.our_ext_addrs.pop() {
            Some(addr) => addr,
            None => return (*self.f)(ifc, poll, self.token, Err(NatError::UdpRendezvousFailed)),
        };

        let mut port_prediction_offset = 0i32;
        for addr in &self.our_ext_addrs {
            if ext_addr.ip() != addr.ip() {
                info!("Symmetric NAT with variable IP mapping detected. No logic for Udp \
                       external address prediction for these circumstances!");
                return (*self.f)(ifc, poll, self.token, Err(NatError::UdpRendezvousFailed));
            } else if port_prediction_offset == 0 {
                port_prediction_offset = addr.port() as i32 - ext_addr.port() as i32;
            } else if port_prediction_offset != addr.port() as i32 - ext_addr.port() as i32 {
                info!("Symmetric NAT with non-uniformly changing port mapping detected. No logic \
                       for Udp external address prediction for these circumstances!");
                return (*self.f)(ifc, poll, self.token, Err(NatError::UdpRendezvousFailed));
            }

            ext_addr = *addr;
        }

        let port = ext_addr.port();
        ext_addr.set_port((port as i32 + port_prediction_offset) as u16);
        trace!("Our ext addr by Udp Rendezvous Client: {}", ext_addr);

        let sock = self.sock.take().unwrap();
        (*self.f)(ifc, poll, self.token, Ok((sock, ext_addr)))
    }
}

impl NatState for UdpRendezvousClient {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) -> ::Res<()> {
        if event.is_error() || event.is_hup() {
            let e = match self.sock.as_ref().unwrap().take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            debug!("Error in UdpRendezvousClient readiness: {:?}", e);
            self.terminate(ifc, poll);
            (*self.f)(ifc, poll, self.token, Err(e));

            Ok(())
        } else if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            self.write(ifc, poll)
        } else {
            trace!("Ignoring unknown event kind: {:?}", event);
            Ok(())
        }
    }

    fn terminate(&mut self, ifc: &mut Interface, poll: &Poll) -> ::Res<()> {
        let _ = ifc.remove_state(self.token);
        Ok(poll.deregister(self.sock.as_ref().unwrap())?)
    }
}
