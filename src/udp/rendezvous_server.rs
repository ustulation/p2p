

use ECHO_REQ;
use bincode::{self, Infinite};
use bytes::Bytes;
use open_addr::BindPublicError;
pub use priv_prelude::*;
use tokio_shared_udp_socket::{SharedUdpSocket, WithAddress};
use udp::socket;

pub struct UdpRendezvousServer {
    local_addr: SocketAddr,
    _drop_tx: DropNotify,
}

impl UdpRendezvousServer {
    pub fn from_socket(socket: UdpSocket, handle: &Handle) -> io::Result<UdpRendezvousServer> {
        let local_addr = socket.local_addr()?;
        Ok(from_socket_inner(socket, &local_addr, handle))
    }

    pub fn bind(addr: &SocketAddr, handle: &Handle) -> io::Result<UdpRendezvousServer> {
        let socket = UdpSocket::bind(addr, handle)?;
        let server = UdpRendezvousServer::from_socket(socket, handle)?;
        Ok(server)
    }

    pub fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<UdpRendezvousServer> {
        let socket = UdpSocket::bind_reusable(addr, handle)?;
        let server = UdpRendezvousServer::from_socket(socket, handle)?;
        Ok(server)
    }

    pub fn bind_public(
        addr: &SocketAddr,
        handle: &Handle,
        mc: &mut Mc,
    ) -> BoxFuture<(UdpRendezvousServer, SocketAddr), BindPublicError> {
        let handle = handle.clone();
        socket::bind_public_with_addr(addr, &handle, mc)
            .map(move |(socket, bind_addr, public_addr)| {
                (from_socket_inner(socket, &bind_addr, &handle), public_addr)
            })
            .into_boxed()
    }

    /// Returns the local address that this rendezvous server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns all local addresses of this rendezvous server, expanding the unspecified address
    /// into a vector of all local interface addresses.
    pub fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.local_addr.expand_local_unspecified()
    }
}

/// Main UDP rendezvous server logic.
///
/// Spawns async task that reacts to rendezvous requests.
fn from_socket_inner(
    socket: UdpSocket,
    bind_addr: &SocketAddr,
    handle: &Handle,
) -> UdpRendezvousServer {
    let (drop_tx, drop_rx) = drop_notify();
    let f = {
        let socket = SharedUdpSocket::share(socket);

        socket
        .map(move |with_addr| {
            with_addr
            .into_future()
            .map_err(|(e, _with_addr)| e)
            .and_then(|(msg_opt, with_addr)| on_addr_echo_request(msg_opt, with_addr))
        })
        .buffer_unordered(1024)
        .log_errors(LogLevel::Info, "processing echo request")
        .until(drop_rx)
        .for_each(|()| Ok(()))
        .infallible()
    };
    handle.spawn(f);
    UdpRendezvousServer {
        _drop_tx: drop_tx,
        local_addr: *bind_addr,
    }
}

/// Handles randezvous server request.
///
/// Reponds with client address.
fn on_addr_echo_request(
    msg_opt: Option<Bytes>,
    with_addr: WithAddress,
) -> BoxFuture<(), io::Error> {
    if let Some(msg) = msg_opt {
        if msg == ECHO_REQ[..] {
            let addr = with_addr.remote_addr();
            let encoded = unwrap!(bincode::serialize(&addr, Infinite));

            return {
                with_addr
                    .send(Bytes::from(encoded))
                    .map(|_with_addr| ())
                    .into_boxed()
            };
        }
    }
    future::ok(()).into_boxed()
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio_core::reactor::Core;

    mod on_addr_echo_request {
        use super::*;

        #[test]
        fn it_returns_finished_future_when_message_is_none() {
            let ev_loop = unwrap!(Core::new());
            let udp_sock = SharedUdpSocket::share(unwrap!(
                UdpSocket::bind(&addr!("0.0.0.0:0"), &ev_loop.handle())
            ));
            let udp_sock = udp_sock.with_address(addr!("192.168.1.2:1234"));

            let fut = on_addr_echo_request(None, udp_sock);

            unwrap!(fut.wait())
        }
    }
}
