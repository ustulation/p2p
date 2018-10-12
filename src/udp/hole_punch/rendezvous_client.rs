use mio::{Poll, PollOpt, Ready, Token};
use rand::{self, Rng};
use socket_collection::UdpSock;
use sodium::crypto::sealedbox;
use std::any::Any;
use std::cell::RefCell;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::{self, FromStr};
use udp::{UdpEchoReq, UdpEchoResp};
use {Interface, NatError, NatState, NatType};

pub type Finish = Box<FnMut(&mut Interface, &Poll, Token, NatType, ::Res<(UdpSock, SocketAddr)>)>;

pub struct UdpRendezvousClient {
    sock: UdpSock,
    token: Token,
    servers: Vec<SocketAddr>,
    on_first_write_triggered: Option<SocketAddr>,
    // Note: DO NOT convert to Hash/BTreeSet - strict ordering is required to pair with peer
    our_ext_addrs: Vec<SocketAddr>,
    f: Finish,
}

impl UdpRendezvousClient {
    pub fn start(ifc: &mut Interface, poll: &Poll, sock: UdpSock, f: Finish) -> ::Res<Token> {
        let token = ifc.new_token();
        let mut servers = ifc.config().remote_udp_rendezvous_servers.clone();
        let num_servers = servers.len();
        if num_servers < 2 {
            info!(
                "Udp: Symmetric NAT detection and port prediction will not be possible using \
                 less than 2 Rendezvous Servers. Use at-least 2. Recommended is 3."
            );
        } else if num_servers > 3 {
            let mut rng = rand::thread_rng();
            rng.shuffle(&mut servers);
            servers = servers[..3].to_owned();
        }

        let server = match servers.pop() {
            Some(server) => server,
            None => return Err(NatError::UdpRendezvousFailed),
        };

        poll.register(
            &sock,
            token,
            Ready::readable() | Ready::writable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        )?;

        let client = Rc::new(RefCell::new(UdpRendezvousClient {
            sock: sock,
            token: token,
            servers: servers,
            on_first_write_triggered: Some(server),
            our_ext_addrs: Vec::with_capacity(num_servers),
            f,
        }));

        if ifc.insert_state(token, client.clone()).is_err() {
            debug!("Unable to insert UdpRendezvousClient State!");
            client.borrow_mut().terminate(ifc, poll);
            Err(NatError::UdpRendezvousFailed)
        } else {
            Ok(token)
        }
    }

    fn read(&mut self, ifc: &mut Interface, poll: &Poll) {
        let mut cipher_text = Vec::new();
        loop {
            match self.sock.read() {
                Ok(Some(UdpEchoResp(m))) => cipher_text = m,
                Ok(None) => if cipher_text.is_empty() {
                    return;
                } else {
                    break;
                },
                Err(e) => {
                    debug!(
                        "Error: Udp Rendezvous Client has errored out in read: {:?}",
                        e
                    );
                    return self.terminate(ifc, poll);
                }
            }
        }

        if let Ok(our_ext_addr_bytes) = sealedbox::open(&cipher_text, ifc.enc_pk(), ifc.enc_sk()) {
            match str::from_utf8(&our_ext_addr_bytes) {
                Ok(our_ext_addr_str) => match SocketAddr::from_str(our_ext_addr_str) {
                    Ok(addr) => self.our_ext_addrs.push(addr),
                    Err(e) => {
                        debug!(
                            "Ignoring UdpEchoResp which contained non-parsable address: \
                             {:?}",
                            e
                        );
                    }
                },
                Err(e) => debug!(
                    "Ignoring UdpEchoResp which contained non-utf8 address: {:?}",
                    e
                ),
            }
        } else {
            debug!("Ignoring UdpEchoResp which could not be decrypted.");
        }

        if let Some(server) = self.servers.pop() {
            if let Err(e) = self.sock.connect(&server) {
                debug!(
                    "Error: Udp Rendezvous Client could not connect to server: {:?}",
                    e
                );
                return self.handle_err(ifc, poll, None);
            }
            let pk = ifc.enc_pk().0;
            self.write(ifc, poll, Some(UdpEchoReq(pk)));
        } else {
            self.done(ifc, poll)
        }
    }

    fn write(&mut self, ifc: &mut Interface, poll: &Poll, m: Option<UdpEchoReq>) {
        if let Err(e) = self.sock.write(m.map(|m| (m, 0))) {
            debug!("Udp Rendezvous Client has errored out in write: {:?}", e);
            self.handle_err(ifc, poll, None)
        }
    }

    fn done(&mut self, ifc: &mut Interface, poll: &Poll) {
        let _ = ifc.remove_state(self.token);

        let mut ext_addr = match self.our_ext_addrs.pop() {
            Some(addr) => addr,
            None => return self.handle_err(ifc, poll, None),
        };

        let mut nat_type = NatType::Unknown;

        let mut addrs = vec![ext_addr];
        let mut port_prediction_offset = 0i32;
        let mut is_err = false;
        for addr in &self.our_ext_addrs {
            addrs.push(*addr);

            if ext_addr.ip() != addr.ip() {
                warn!(
                    "Symmetric NAT with variable IP mapping detected. No logic for Udp \
                     external address prediction for these circumstances!"
                );
                nat_type = NatType::EDMRandomIp(addrs.into_iter().map(|s| s.ip()).collect());
                is_err = true;
                break;
            } else if port_prediction_offset == 0 {
                port_prediction_offset = addr.port() as i32 - ext_addr.port() as i32;
            } else if port_prediction_offset != addr.port() as i32 - ext_addr.port() as i32 {
                warn!(
                    "Symmetric NAT with non-uniformly changing port mapping detected. No logic \
                     for Udp external address prediction for these circumstances!"
                );
                nat_type = NatType::EDMRandomPort(addrs.into_iter().map(|s| s.port()).collect());
                is_err = true;
                break;
            }

            ext_addr = *addr;
        }

        if is_err {
            return self.handle_err(ifc, poll, Some(nat_type));
        }

        let port = ext_addr.port();
        ext_addr.set_port((port as i32 + port_prediction_offset) as u16);
        trace!("Our ext addr by Udp Rendezvous Client: {}", ext_addr);

        nat_type = if port_prediction_offset == 0 {
            NatType::EIM
        } else {
            NatType::EDM(port_prediction_offset)
        };

        let s = mem::replace(&mut self.sock, Default::default());
        (*self.f)(ifc, poll, self.token, nat_type, Ok((s, ext_addr)));
    }

    fn handle_err(&mut self, ifc: &mut Interface, poll: &Poll, nat_type: Option<NatType>) {
        self.terminate(ifc, poll);
        (*self.f)(
            ifc,
            poll,
            self.token,
            nat_type.unwrap_or(NatType::Unknown),
            Err(NatError::UdpRendezvousFailed),
        );
    }
}

impl NatState for UdpRendezvousClient {
    fn ready(&mut self, ifc: &mut Interface, poll: &Poll, event: Ready) {
        if event.is_error() || event.is_hup() {
            let e = match self.sock.take_error() {
                Ok(err) => err.map_or(NatError::Unknown, NatError::from),
                Err(e) => From::from(e),
            };
            debug!("Error in UdpRendezvousClient readiness: {:?}", e);
            self.handle_err(ifc, poll, None);
        } else if event.is_readable() {
            self.read(ifc, poll)
        } else if event.is_writable() {
            if let Some(server) = self.on_first_write_triggered.take() {
                // FIXME: Check if UDP connect requires to wait for an event
                if let Err(e) = self.sock.connect(&server) {
                    debug!(
                        "Error: Udp Rendezvous Client could not connect to server: {:?}",
                        e
                    );
                    self.handle_err(ifc, poll, None);
                }
                let pk = ifc.enc_pk().0;
                self.write(ifc, poll, Some(UdpEchoReq(pk)));
            } else {
                self.write(ifc, poll, None);
            }
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
