use priv_prelude::*;
use bincode;
use tokio_io;
use ECHO_REQ;

use futures::future::Loop;
use server_set::{ServerSet, Servers};
use protocol::Protocol;

lazy_static! {
    static ref MC: Mutex<Mc> = Mutex::new(Mc::default());
}

#[derive(Default)]
struct Mc {
    tcp_server_set: ServerSet,
    udp_server_set: ServerSet,
    igd_disabled: bool,
}

impl Mc {
    fn server_set(&mut self, protocol: Protocol) -> &mut ServerSet {
        match protocol {
            Protocol::Udp => &mut self.udp_server_set,
            Protocol::Tcp => &mut self.tcp_server_set,
        }
    }

    fn add_server(&mut self, protocol: Protocol, addr: &SocketAddr) {
        self.server_set(protocol).add_server(addr)
    }

    fn remove_server(&mut self, protocol: Protocol, addr: &SocketAddr) {
        self.server_set(protocol).remove_server(addr)
    }

    fn iter_servers(&mut self, protocol: Protocol) -> Servers {
        self.server_set(protocol).iter_servers()
    }
}

/// Tell the library about a `TcpTraversalServer` than can be used to help use perform rendezvous
/// connects and hole punching.
pub fn add_tcp_traversal_server(addr: &SocketAddr) {
    let mut mc = unwrap!(MC.lock());
    mc.add_server(Protocol::Tcp, addr)
}

/// Tells the library to forget a `TcpTraversalServer` previously added with
/// `add_tcp_traversal_server`.
pub fn remove_tcp_traversal_server(addr: &SocketAddr) {
    let mut mc = unwrap!(MC.lock());
    mc.remove_server(Protocol::Tcp, addr)
}

/// Returns an iterator over all tcp traversal server addresses added with
/// `add_tcp_traversal_server`.
pub fn tcp_traversal_servers() -> Servers {
    let mut mc = unwrap!(MC.lock());
    mc.iter_servers(Protocol::Tcp)
}

/// Tell the library about a `UdpTraversalServer` than can be used to help use perform rendezvous
/// connects and hole punching.
pub fn add_udp_traversal_server(addr: &SocketAddr) {
    let mut mc = unwrap!(MC.lock());
    mc.add_server(Protocol::Udp, addr)
}

/// Tells the library to forget a `UdpTraversalServer` previously added with
/// `add_udp_traversal_server`.
pub fn remove_udp_traversal_server(addr: &SocketAddr) {
    let mut mc = unwrap!(MC.lock());
    mc.remove_server(Protocol::Udp, addr)
}

/// Returns an iterator over all udp traversal server addresses added with
/// `add_tcp_traversal_server`.
pub fn udp_traversal_servers() -> Servers {
    let mut mc = unwrap!(MC.lock());
    mc.iter_servers(Protocol::Udp)
}

pub fn traversal_servers(protocol: Protocol) -> Servers {
    let mut mc = unwrap!(MC.lock());
    mc.iter_servers(protocol)
}

pub fn query_public_addr(
    protocol: Protocol,
    bind_addr: &SocketAddr,
    server_addr: &SocketAddr,
    handle: &Handle,
) -> BoxFuture<SocketAddr, QueryPublicAddrError> {
    match protocol {
        Protocol::Tcp => tcp_query_public_addr(bind_addr, server_addr, handle),
        Protocol::Udp => udp_query_public_addr(bind_addr, server_addr, handle),
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum QueryPublicAddrError {
        Bind(e: io::Error) {
            description("error binding to socket address")
            display("error binding to socket address: {}", e)
            cause(e)
        }
        Connect(e: io::Error) {
            description("error connecting to echo server")
            display("error connecting to echo server: {}", e)
            cause(e)
        }
        ConnectTimeout {
            description("timed out contacting server")
        }
        SendRequest(e: io::Error) {
            description("error sending request to echo server")
            display("error sending request to echo server: {}", e)
            cause(e)
        }
        ReadResponse(e: io::Error) {
            description("error reading response from echo server")
            display("error reading response from echo server: {}", e)
            cause(e)
        }
        Deserialize(e: bincode::Error) {
            description("error deserializing response from echo server")
            display("error deserializing response from echo server: {}", e)
            cause(e)
        }
        ResponseTimeout {
            description("timed out waiting for response from echo server")
        }
    }
}

pub fn tcp_query_public_addr(
    bind_addr: &SocketAddr,
    server_addr: &SocketAddr,
    handle: &Handle,
) -> BoxFuture<SocketAddr, QueryPublicAddrError> {
    let bind_addr = *bind_addr;
    let server_addr = *server_addr;
    let handle = handle.clone();
    TcpStream::connect_reusable(&bind_addr, &server_addr, &handle)
    .map_err(|err| match err {
        ConnectReusableError::Connect(e) => QueryPublicAddrError::Connect(e),
        ConnectReusableError::Bind(e) => QueryPublicAddrError::Bind(e),
    })
    .with_timeout(Duration::from_secs(3), &handle)
    .and_then(|opt| opt.ok_or(QueryPublicAddrError::ConnectTimeout))
    .and_then(|stream| {
        tokio_io::io::write_all(stream, ECHO_REQ)
        .map(|(stream, _buf)| stream)
        .map_err(QueryPublicAddrError::SendRequest)
    })
    .and_then(move |stream| {
        tokio_io::io::read_to_end(stream, Vec::new())
        .map_err(QueryPublicAddrError::ReadResponse)
        .and_then(|(_stream, data)| {
            bincode::deserialize(&data)
            .map_err(QueryPublicAddrError::Deserialize)
        })
        .with_timeout(Duration::from_secs(2), &handle)
        .and_then(|opt| opt.ok_or(QueryPublicAddrError::ResponseTimeout))
    })
    .into_boxed()
}

pub fn udp_query_public_addr(
    bind_addr: &SocketAddr,
    server_addr: &SocketAddr,
    handle: &Handle,
) -> BoxFuture<SocketAddr, QueryPublicAddrError> {
    let try = || {
        let bind_addr = *bind_addr;
        let server_addr = *server_addr;
        let handle = handle.clone();
        let socket = {
            UdpSocket::bind_reusable(&bind_addr, &handle)
            .map_err(QueryPublicAddrError::Bind)
        }?;

        Ok({
            socket.send_dgram(ECHO_REQ, server_addr)
            .map(|(socket, _buf)| socket)
            .map_err(QueryPublicAddrError::SendRequest)
            .and_then(move |socket| {
                future::loop_fn(socket, move |socket| {
                    socket
                    .recv_dgram(vec![0u8; 256])
                    .map_err(QueryPublicAddrError::ReadResponse)
                    .and_then(move |(socket, data, len, addr)| {
                        if addr == server_addr {
                            let data = {
                                trace!("server responded with: {:?}", &data[..len]);
                                bincode::deserialize(&data[..len])
                                .map_err(QueryPublicAddrError::Deserialize)
                            }?;
                            Ok(Loop::Break(data))
                        } else {
                            Ok(Loop::Continue(socket))
                        }
                    })
                })
                .with_timeout(Duration::from_secs(2), &handle)
                .and_then(|opt| opt.ok_or(QueryPublicAddrError::ResponseTimeout))
            })
        })
    };
    future::result(try()).flatten().into_boxed()
}

pub fn is_igd_enabled() -> bool {
    let mc = unwrap!(MC.lock());
    !mc.igd_disabled
}

pub fn disable_igd() {
    let mut mc = unwrap!(MC.lock());
    mc.igd_disabled = true;
}

pub fn enable_igd() {
    let mut mc = unwrap!(MC.lock());
    mc.igd_disabled = false;
}

