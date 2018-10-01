//! This is a demo of `rendezvous_addr()` function that tries to detect our NAT type and an IP
//! address for hole punching.
//!
//! This example requires at least 3 STUN(rendezvous) servers. Run 3 `udp_rendezvous_server`
//! example instances of different servers that have public addresses and put the printed info
//! of each server into `stun_servers` vector. Then run this example:
//! `cargo run --example udp_rendezvous_addr`
//!
//! and you should see smth like:
//! ```
//! Rendezvous address and NAT type: Ok((V4(78.62.228.8:43953), EIM))
//! ```

extern crate env_logger;
#[macro_use]
extern crate net_literals;
extern crate p2p;
extern crate safe_crypto;
extern crate serde_json;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

use p2p::{rendezvous_addr, Protocol, RemoteUdpRendezvousServer, UdpSocketExt};
use safe_crypto::PublicEncryptKey;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Core;

fn main() {
    unwrap!(env_logger::init());

    // Change these servers with your own.
    let stun_servers = vec![
        ("167.99.199.159:60182", "{\"encrypt\":[76,243,119,61,134,238,221,239,60,113,196,19,130,40,185,71,146,68,156,248,151,103,235,248,92,168,209,201,146,60,65,5]}"),
        ("206.189.6.25:38437", "{\"encrypt\":[13,116,0,205,58,220,139,66,50,16,81,84,114,186,127,244,177,69,33,183,118,231,0,13,114,86,92,26,156,168,189,118]}"),
        ("142.93.101.173:39027", "{\"encrypt\":[10,0,222,183,11,166,51,123,38,244,105,95,112,228,183,153,22,30,210,5,139,250,242,185,165,226,92,75,7,165,226,117]}"),
    ];

    let p2p_conf = p2p::P2p::default();
    p2p_conf.disable_igd();
    p2p_conf.disable_igd_for_rendezvous();
    for server in stun_servers {
        let server_pub_key: PublicEncryptKey = unwrap!(serde_json::from_str(&server.1));
        let server_addr = unwrap!(SocketAddr::from_str(server.0));
        let addr_querier = RemoteUdpRendezvousServer::new(server_addr, server_pub_key);
        p2p_conf.add_udp_addr_querier(addr_querier);
    }

    let mut evloop = unwrap!(Core::new());
    let handle = evloop.handle();

    let socket = unwrap!(UdpSocket::bind_reusable(&addr!("0.0.0.0:0"), &handle));
    let bind_addr = unwrap!(socket.local_addr());
    let task = rendezvous_addr(Protocol::Udp, &bind_addr, &handle, &p2p_conf);
    let res = evloop.run(task);

    println!("Rendezvous address and NAT type: {:?}", res);
}
