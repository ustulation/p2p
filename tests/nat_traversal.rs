extern crate maidsafe_utilities;
extern crate mio;
extern crate mio_extras;
extern crate p2p;
extern crate rust_sodium as sodium;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

mod utils;

use mio::Poll;
use p2p::{
    Handle, HolePunchMediator, Interface, NatInfo, NatMsg, NatType, QueuedNotifier, RendezvousInfo,
    Res, TcpRendezvousServer, UdpRendezvousServer,
};
use std::sync::mpsc;
use utils::{read_config, spawn_event_loop, EventLoop};

fn start_rendezvous_servers() -> Vec<EventLoop> {
    const NUM_RENDEZVOUS_SERVERS: usize = 3;

    let mut els = Vec::new();

    for i in 0..NUM_RENDEZVOUS_SERVERS {
        let el = spawn_event_loop(read_config(&format!(
            "./tests/nat-traversal-test-resources/config-rendezvous-server-{}",
            i,
        )));

        let (tx, rx) = mpsc::channel();
        unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
            let udp_server_token = unwrap!(UdpRendezvousServer::start(ifc, poll));
            let tcp_server_token = unwrap!(TcpRendezvousServer::start(ifc, poll));
            unwrap!(tx.send((udp_server_token, tcp_server_token)));
        })));

        let (_udp_server_token, _tcp_server_token) = unwrap!(rx.recv());

        els.push(el);
    }

    els
}

fn get_rendezvous_info(el: &EventLoop) -> mpsc::Receiver<(NatInfo, Res<(Handle, RendezvousInfo)>)> {
    let (tx, rx) = mpsc::channel();
    unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
        let handler = move |_: &mut Interface, _: &Poll, (nat_info, res)| {
            unwrap!(tx.send((nat_info, res)));
        };
        let _mediator_token = unwrap!(HolePunchMediator::start(
            ifc,
            poll,
            QueuedNotifier::new(handler)
        ));
    })));

    rx
}

#[test]
fn nat_traverse_among_3_peers() {
    unwrap!(maidsafe_utilities::log::init(true));

    let _els_rendezvous_servers = start_rendezvous_servers();

    let peer_config_path = "./tests/nat-traversal-test-resources/config-peers".to_string();
    let el_peer0 = spawn_event_loop(read_config(&peer_config_path));
    let el_peer1 = spawn_event_loop(read_config(&peer_config_path));
    let el_peer2 = spawn_event_loop(read_config(&peer_config_path));

    // Get `RendezvousInfo` in parallel
    let rendezvous_rx01 = get_rendezvous_info(&el_peer0);
    let rendezvous_rx02 = get_rendezvous_info(&el_peer0);
    let rendezvous_rx10 = get_rendezvous_info(&el_peer1);
    let rendezvous_rx12 = get_rendezvous_info(&el_peer1);
    let rendezvous_rx20 = get_rendezvous_info(&el_peer2);
    let rendezvous_rx21 = get_rendezvous_info(&el_peer2);

    let (nat_info01, (handle01, rendezvous_info01)) = {
        let (nat_info, res) = unwrap!(rendezvous_rx01.recv());
        (nat_info, unwrap!(res))
    };
    let (nat_info02, (handle02, rendezvous_info02)) = {
        let (nat_info, res) = unwrap!(rendezvous_rx02.recv());
        (nat_info, unwrap!(res))
    };
    let (nat_info10, (handle10, rendezvous_info10)) = {
        let (nat_info, res) = unwrap!(rendezvous_rx10.recv());
        (nat_info, unwrap!(res))
    };
    let (nat_info12, (handle12, rendezvous_info12)) = {
        let (nat_info, res) = unwrap!(rendezvous_rx12.recv());
        (nat_info, unwrap!(res))
    };
    let (nat_info20, (handle20, rendezvous_info20)) = {
        let (nat_info, res) = unwrap!(rendezvous_rx20.recv());
        (nat_info, unwrap!(res))
    };
    let (nat_info21, (handle21, rendezvous_info21)) = {
        let (nat_info, res) = unwrap!(rendezvous_rx21.recv());
        (nat_info, unwrap!(res))
    };

    // The localhost is very likely to be EIM unless someone's changed it deliberately for e.g., in
    // iptables on Linux etc. In that case change the assertion accordingly.
    assert_eq!(nat_info01.nat_type_for_tcp, NatType::EIM);
    assert_eq!(nat_info02.nat_type_for_tcp, NatType::EIM);
    assert_eq!(nat_info10.nat_type_for_tcp, NatType::EIM);
    assert_eq!(nat_info12.nat_type_for_tcp, NatType::EIM);
    assert_eq!(nat_info20.nat_type_for_tcp, NatType::EIM);
    assert_eq!(nat_info21.nat_type_for_tcp, NatType::EIM);

    // The localhost is very likely to be EIM unless someone's changed it deliberately for e.g., in
    // iptables on Linux etc. In that case change the assertion accordingly.
    assert_eq!(nat_info01.nat_type_for_udp, NatType::EIM);
    assert_eq!(nat_info02.nat_type_for_udp, NatType::EIM);
    assert_eq!(nat_info10.nat_type_for_udp, NatType::EIM);
    assert_eq!(nat_info12.nat_type_for_udp, NatType::EIM);
    assert_eq!(nat_info20.nat_type_for_udp, NatType::EIM);
    assert_eq!(nat_info21.nat_type_for_udp, NatType::EIM);

    // NAT Traverse in parallel
    let (hole_punch_tx01, hole_punch_rx01) = mpsc::channel();
    handle01.fire_hole_punch(rendezvous_info10, move |_, _, res| {
        unwrap!(hole_punch_tx01.send(res));
    });
    let (hole_punch_tx02, hole_punch_rx02) = mpsc::channel();
    handle02.fire_hole_punch(rendezvous_info20, move |_, _, res| {
        unwrap!(hole_punch_tx02.send(res));
    });
    let (hole_punch_tx10, hole_punch_rx10) = mpsc::channel();
    handle10.fire_hole_punch(rendezvous_info01, move |_, _, res| {
        unwrap!(hole_punch_tx10.send(res));
    });
    let (hole_punch_tx12, hole_punch_rx12) = mpsc::channel();
    handle12.fire_hole_punch(rendezvous_info21, move |_, _, res| {
        unwrap!(hole_punch_tx12.send(res));
    });
    let (hole_punch_tx20, hole_punch_rx20) = mpsc::channel();
    handle20.fire_hole_punch(rendezvous_info02, move |_, _, res| {
        unwrap!(hole_punch_tx20.send(res));
    });
    let (hole_punch_tx21, hole_punch_rx21) = mpsc::channel();
    handle21.fire_hole_punch(rendezvous_info12, move |_, _, res| {
        unwrap!(hole_punch_tx21.send(res));
    });

    let hole_punch_info01 = unwrap!(unwrap!(hole_punch_rx01.recv()));
    let hole_punch_info02 = unwrap!(unwrap!(hole_punch_rx02.recv()));
    let hole_punch_info10 = unwrap!(unwrap!(hole_punch_rx10.recv()));
    let hole_punch_info12 = unwrap!(unwrap!(hole_punch_rx12.recv()));
    let hole_punch_info20 = unwrap!(unwrap!(hole_punch_rx20.recv()));
    let hole_punch_info21 = unwrap!(unwrap!(hole_punch_rx21.recv()));

    assert!(hole_punch_info01.tcp.is_some());
    assert!(hole_punch_info02.tcp.is_some());
    assert!(hole_punch_info10.tcp.is_some());
    assert!(hole_punch_info12.tcp.is_some());
    assert!(hole_punch_info20.tcp.is_some());
    assert!(hole_punch_info21.tcp.is_some());

    assert!(hole_punch_info01.udp.is_some());
    assert!(hole_punch_info02.udp.is_some());
    assert!(hole_punch_info10.udp.is_some());
    assert!(hole_punch_info12.udp.is_some());
    assert!(hole_punch_info20.udp.is_some());
    assert!(hole_punch_info21.udp.is_some());
}
