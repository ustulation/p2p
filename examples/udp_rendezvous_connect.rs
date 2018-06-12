extern crate bytes;
extern crate docopt;
extern crate env_logger;
extern crate future_utils;
extern crate futures;
extern crate p2p;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate safe_crypto;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_io;
/// To use this, use a server with publicly accessible ports to act as a relay server between two
/// connecting udp sockets. This relay server will act as the channel when negotiating the
/// rendezvous connect.
///
/// For example, log into a VPS and run:
/// ```
/// $ socat TCP-LISTEN:45666 TCP-LISTEN:45667
/// ```
///
/// The run this example on two machines, on seperate networks, both hidden behind NATs:
/// ```
/// $ cargo run --example udp_rendezvous_connect -- <address of your vps>:45666 blah blah blah
/// $ cargo run --example udp_rendezvous_connect -- <address of your vps>:45667 blah blah blah
/// ```
///
/// If successful, the peers should be able to communicate directly with each other over UDP.
#[macro_use]
extern crate unwrap;
extern crate void;

use docopt::Docopt;
use futures::future::Loop;
use futures::{future, Async, AsyncSink, Future, Sink, Stream};
use p2p::{RemoteUdpRendezvousServer, UdpSocketExt};
use safe_crypto::PublicId;
use std::net::SocketAddr;
use std::{env, fmt};
use tokio_core::net::{TcpStream, UdpSocket};
use tokio_io::codec::length_delimited::Framed;
use void::ResultVoidExt;

// TODO: figure out how to not need this.
struct DummyDebug<S>(S);

impl<S> fmt::Debug for DummyDebug<S> {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        Ok(())
    }
}

impl<S: Stream> Stream for DummyDebug<S> {
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        self.0.poll()
    }
}

impl<S: Sink> Sink for DummyDebug<S> {
    type SinkItem = S::SinkItem;
    type SinkError = S::SinkError;

    fn start_send(
        &mut self,
        item: Self::SinkItem,
    ) -> Result<AsyncSink<Self::SinkItem>, Self::SinkError> {
        self.0.start_send(item)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, Self::SinkError> {
        self.0.poll_complete()
    }
}

const USAGE: &str = "
udp_rendezvous_connect

Usage:
    udp_rendezvous_connect --relay=<address> \
                           [--disable-igd] \
                           [--traversal-server=<address>] \
                           [--traversal-server-key=<public_key>] \
                           <message>
    udp_rendezvous_connect (-h | --help)
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_relay: SocketAddr,
    flag_disable_igd: bool,
    flag_traversal_server: Option<SocketAddr>,
    flag_traversal_server_key: Option<String>,
    arg_message: String,
}

fn main() {
    unwrap!(env_logger::init());

    let args = env::args().collect::<Vec<_>>();
    println!("args == {:?}", args);

    let args: Args = {
        Docopt::new(USAGE)
            .and_then(|d| d.deserialize())
            .unwrap_or_else(|e| e.exit())
    };

    let mc = p2p::P2p::default();
    if args.flag_disable_igd {
        mc.disable_igd();
    }

    if let Some(server_addr) = args.flag_traversal_server {
        let server_pub_key = unwrap!(
            args.flag_traversal_server_key,
            "If echo address server is specified, it's public key must be given too.",
        );
        let server_pub_key: PublicId = unwrap!(serde_json::from_str(&server_pub_key));
        let addr_querier = RemoteUdpRendezvousServer::new(server_addr, server_pub_key);
        mc.add_udp_addr_querier(addr_querier);
    }

    let relay_addr = args.flag_relay;
    let message: Vec<u8> = args.arg_message.into();

    let mut core = unwrap!(tokio_core::reactor::Core::new());
    let handle = core.handle();
    let res = core.run({
        TcpStream::connect(&relay_addr, &handle)
            .map_err(|e| panic!("error connecting to relay server: {}", e))
            .and_then(move |relay_stream| {
                let relay_channel =
                    DummyDebug(Framed::new(relay_stream).map(|bytes| bytes.freeze()));
                UdpSocket::rendezvous_connect(relay_channel, &handle, &mc)
                    .map_err(|e| panic!("rendezvous connect failed: {}", e))
                    .and_then(|(socket, addr)| {
                        println!("connected!");
                        socket
                            .send_dgram(message, addr)
                            .map_err(|e| panic!("error writing to udp socket: {}", e))
                            .and_then(move |(socket, _)| {
                                future::loop_fn(socket, move |socket| {
                                    let buffer = vec![0u8; 64 * 1024];
                                    socket
                                        .recv_dgram(buffer)
                                        .map_err(|e| panic!("error receiving on udp socket: {}", e))
                                        .map(move |(socket, buffer, len, recv_addr)| {
                                            if recv_addr == addr {
                                                let recv_message =
                                                    String::from_utf8_lossy(&buffer[..len]);
                                                println!("got message: {}", recv_message);
                                            }
                                            Loop::Continue(socket)
                                        })
                                })
                            })
                    })
            })
    });
    res.void_unwrap()
}
