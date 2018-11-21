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
    terminated: bool,
}

impl UdpRendezvousServer {
    /// Boot the UDP Rendezvous server. This should normally be called only once.
    /// Uses the bind port specified by `Interface::config()`. If port is 0, OS chooses a random
    /// available port, which you can find out by checking the return value.
    ///
    /// # Returns
    ///
    /// A tuple of mio token associated with the rendezvous server and local listen address.
    pub fn start(ifc: &mut Interface, poll: &Poll) -> ::Res<(Token, SocketAddr)> {
        let port = ifc
            .config()
            .udp_rendezvous_port
            .unwrap_or(UDP_RENDEZVOUS_PORT);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
        let sock = UdpSock::bind(&addr)?;
        let server_addr = sock.local_addr()?;

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
            Ok((token, server_addr))
        }
    }

    fn read_frm(&mut self, ifc: &mut Interface, poll: &Poll) {
        let mut peers = Vec::new();
        loop {
            match self.sock.read_frm() {
                Ok(Some((UdpEchoReq(pk), peer))) => peers.push((box_::PublicKey(pk), peer)),
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
            let resp = UdpEchoResp(sealedbox::seal(format!("{}", peer).as_bytes(), &pk));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::mpsc;
    use test_utils::spawn_event_loop;
    use udp::hole_punch::UdpRendezvousClient;
    use {Config, NatMsg};

    /// Creates config for tests with all values zeroed.
    fn p2p_test_cfg() -> Config {
        Config {
            rendezvous_timeout_sec: None,
            hole_punch_timeout_sec: None,
            hole_punch_wait_for_other: None,
            udp_rendezvous_port: None,
            tcp_rendezvous_port: None,
            remote_udp_rendezvous_servers: Vec::new(),
            remote_tcp_rendezvous_servers: Vec::new(),
            udp_hole_punchers: Vec::new(),
        }
    }

    #[test]
    fn it_responds_with_client_address() {
        let mut config = p2p_test_cfg();
        config.udp_rendezvous_port = Some(0);
        let server_el = spawn_event_loop(config);
        let (server_port_tx, server_port_rx) = mpsc::channel();
        unwrap!(server_el.nat_tx.send(NatMsg::new(move |ifc, poll| {
            let (_token, addr) = unwrap!(UdpRendezvousServer::start(ifc, poll));
            unwrap!(server_port_tx.send(addr.port()));
        })));

        let server_port = unwrap!(server_port_rx.recv());
        let server_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), server_port));
        let (addr_tx, addr_rx) = mpsc::channel();
        let mut config = p2p_test_cfg();
        config.remote_udp_rendezvous_servers = vec![server_addr];
        let client_el = spawn_event_loop(config);
        let addr = unwrap!("127.0.0.1:0".parse());
        let sock = unwrap!(UdpSock::bind(&addr));
        let exp_client_addr = unwrap!(sock.local_addr());

        unwrap!(client_el.nat_tx.send(NatMsg::new(move |ifc, poll| {
            let on_done = Box::new(
                move |_ifc: &mut Interface,
                      _poll: &Poll,
                      _child,
                      _nat_type,
                      res: ::Res<(UdpSock, SocketAddr)>| {
                    let client_addr = unwrap!(res).1;
                    unwrap!(addr_tx.send(client_addr));
                },
            );
            let _ = unwrap!(UdpRendezvousClient::start(ifc, poll, sock, on_done));
        })));

        let client_addr = unwrap!(addr_rx.recv());
        assert_eq!(client_addr, exp_client_addr);
    }
}
