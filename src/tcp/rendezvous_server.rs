use ECHO_REQ;
use bincode::{self, Infinite};
use future_utils::IoFuture;
use open_addr::BindPublicError;
pub use priv_prelude::*;
use tcp::listener::{self, TcpListenerExt};
use tokio_io;

/// Sends response to rendezvous address request (`ECHO_REQ`).
pub fn respond_with_addr(stream: TcpStream, addr: SocketAddr) -> IoFuture<TcpStream> {
    let encoded = unwrap!(bincode::serialize(&addr, Infinite));
    tokio_io::io::write_all(stream, encoded)
        .map(|(stream, _encoded)| stream)
        .into_boxed()
}

/// A TCP rendezvous server. Other peers can use this when performing rendezvous connects and
/// hole-punching.
pub struct TcpRendezvousServer {
    local_addr: SocketAddr,
    _drop_tx: DropNotify,
}

impl TcpRendezvousServer {
    /// Create a rendezvous server from a `TcpListener`.
    pub fn from_listener(
        listener: TcpListener,
        handle: &Handle,
    ) -> io::Result<TcpRendezvousServer> {
        let local_addr = listener.local_addr()?;
        Ok(from_listener_inner(listener, &local_addr, handle))
    }

    /// Create a new rendezvous server, bound to the given address.
    pub fn bind(addr: &SocketAddr, handle: &Handle) -> io::Result<TcpRendezvousServer> {
        let listener = TcpListener::bind(addr, handle)?;
        let server = TcpRendezvousServer::from_listener(listener, handle)?;
        Ok(server)
    }

    /// Create a new rendezvous server, reusably bound to the given address.
    pub fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<TcpRendezvousServer> {
        let listener = TcpListener::bind_reusable(addr, handle)?;
        let server = TcpRendezvousServer::from_listener(listener, handle)?;
        Ok(server)
    }

    /// Create a new rendezvous server, reusably bound to the given address. Returns a global,
    /// external socket address on which this server can be contacted if it can successfully create
    /// such an address (eg. by opening a port on the local network's router).
    pub fn bind_public(
        addr: &SocketAddr,
        handle: &Handle,
        mc: &P2p,
    ) -> BoxFuture<(TcpRendezvousServer, SocketAddr), BindPublicError> {
        let handle = handle.clone();
        listener::bind_public_with_addr(addr, &handle, mc)
            .map(move |(listener, bind_addr, public_addr)| {
                (
                    from_listener_inner(listener, &bind_addr, &handle),
                    public_addr,
                )
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
        let addrs = self.local_addr.expand_local_unspecified()?;
        Ok(addrs)
    }
}

fn from_listener_inner(
    listener: TcpListener,
    bind_addr: &SocketAddr,
    handle: &Handle,
) -> TcpRendezvousServer {
    let (drop_tx, drop_rx) = drop_notify();
    let f = {
        let handle = handle.clone();

        listener
        .incoming()
        .map(move |(stream, addr)| {
            let buf = [0u8; 8];
            tokio_io::io::read_exact(stream, buf)
            .and_then(move |(stream, buf)| {
                if buf == ECHO_REQ {
                    respond_with_addr(stream, addr)
                        .map(|_stream| ())
                        .into_boxed()
                } else {
                    future::ok(()).into_boxed()
                }
            })
            .with_timeout(Duration::from_secs(2), &handle)
            .and_then(|opt| opt.ok_or_else(|| io::ErrorKind::TimedOut.into()))
        })
        .buffer_unordered(1024)
        .log_errors(LogLevel::Info, "processing echo request")
        .until(drop_rx)
        .for_each(|()| Ok(()))
        .infallible()
    };
    handle.spawn(f);
    TcpRendezvousServer {
        _drop_tx: drop_tx,
        local_addr: *bind_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_core::reactor::Core;

    mod respond_with_addr {
        use super::*;
        use futures::IntoFuture;

        #[test]
        fn it_sends_serialized_client_address() {
            let mut event_loop = unwrap!(Core::new());
            let handle = event_loop.handle();

            let listener = unwrap!(TcpListener::bind(&addr!("127.0.0.1:0"), &handle));
            let listener_addr = unwrap!(listener.local_addr());
            let handle_conns = listener
                .incoming()
                .for_each(|(stream, addr)| {
                    respond_with_addr(stream, addr).then(|_| Ok(()))
                })
                .then(|_| Ok(()));
            handle.spawn(handle_conns);

            let conn = unwrap!(event_loop.run(TcpStream::connect(&listener_addr, &handle)));
            let actual_addr = unwrap!(conn.local_addr());

            let buf = unwrap!(
                event_loop.run(
                    tokio_io::io::read_to_end(conn, Vec::new())
                        .into_future()
                        .and_then(|(_stream, buf)| Ok(buf)),
                )
            );
            let received_addr: SocketAddr = unwrap!(bincode::deserialize(&buf));

            assert_eq!(received_addr, actual_addr);
        }
    }
}
