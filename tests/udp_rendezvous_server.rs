extern crate maidsafe_utilities;
extern crate mio;
extern crate mio_extras;
extern crate p2p;
extern crate rust_sodium as sodium;
extern crate serde_json;
#[macro_use]
extern crate unwrap;
extern crate net2;
extern crate socket_collection;

mod utils;

use mio::Poll;
use p2p::{Config, Interface, NatMsg, Res, UdpRendezvousClient, UdpRendezvousServer};
use socket_collection::UdpSock;
use std::net::SocketAddr;
use std::sync::mpsc;
use utils::spawn_event_loop;

#[test]
fn it_responds_with_client_address() {
    let server_sock = unwrap!(UdpSock::bind(&unwrap!("127.0.0.1:0".parse())));
    let server_addr = unwrap!(server_sock.local_addr());
    let mut config = Config::default();
    config.udp_rendezvous_port = Some(server_addr.port());
    let server_el = spawn_event_loop(config);
    unwrap!(server_el.nat_tx.send(NatMsg::new(move |ifc, poll| {
        let _ = unwrap!(UdpRendezvousServer::start_with_sock(server_sock, ifc, poll));
    })));

    let (addr_tx, addr_rx) = mpsc::channel();
    let mut config = Config::default();
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
