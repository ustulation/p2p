use ECHO_REQ;
use bytes::Bytes;
use open_addr::BindPublicError;
use priv_prelude::*;
use rust_sodium::crypto::box_::{PublicKey, SecretKey, gen_keypair};
use tokio_shared_udp_socket::{SharedUdpSocket, WithAddress};
use udp::socket;

/// Sends response to echo address request (`ECHO_REQ`).
/// NOTE: this function is almost identical to `tcp::rendezous_server::respond_with_addr()`,
///       except that the sink item type is `Bytes` rather than `BytesMut`. Wonder if this could
///       be generalized.
pub fn respond_with_addr<S>(
    sink: S,
    addr: SocketAddr,
    crypto_ctx: &CryptoContext,
) -> BoxFuture<S, RendezvousServerError>
where
    S: Sink<SinkItem = Bytes, SinkError = io::Error> + 'static,
{
    let encrypted = try_bfut!(
        crypto_ctx
            .encrypt(&addr)
            .map_err(RendezvousServerError::Encrypt)
            .map(|data| data.freeze())
    );
    sink.send(encrypted)
        .map_err(RendezvousServerError::SendError)
        .into_boxed()
}

/// Traversal server implementation for UDP.
/// Acts much like STUN server except doesn't implement the standard protocol - RFC 5389.
pub struct UdpRendezvousServer {
    local_addr: SocketAddr,
    our_pk: PublicKey,
    _drop_tx: DropNotify,
}

impl UdpRendezvousServer {
    /// Takes ownership of already set up UDP socket and starts rendezvous server.
    pub fn from_socket(socket: UdpSocket, handle: &Handle) -> io::Result<UdpRendezvousServer> {
        let local_addr = socket.local_addr()?;
        Ok(from_socket_inner(socket, &local_addr, handle))
    }

    /// Start listening for incoming connections.
    pub fn bind(addr: &SocketAddr, handle: &Handle) -> io::Result<UdpRendezvousServer> {
        let socket = UdpSocket::bind(addr, handle)?;
        let server = UdpRendezvousServer::from_socket(socket, handle)?;
        Ok(server)
    }

    /// Start listening for incoming connection and allow other sockets to bind to the same port.
    pub fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<UdpRendezvousServer> {
        let socket = UdpSocket::bind_reusable(addr, handle)?;
        let server = UdpRendezvousServer::from_socket(socket, handle)?;
        Ok(server)
    }

    /// Try to get an external address and start listening for incoming connections.
    pub fn bind_public(
        addr: &SocketAddr,
        handle: &Handle,
        mc: &P2p,
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

    /// Returns server public key.
    /// Server expects incoming messages to be encrypted with this public key.
    pub fn public_key(&self) -> PublicKey {
        self.our_pk
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
    let (our_pk, our_sk) = gen_keypair();

    let f = {
        let socket = SharedUdpSocket::share(socket);
        trace!("rendezvous server starting");

        socket
        .map_err(RendezvousServerError::AcceptError)
        .map(move |with_addr| {
            let our_sk = our_sk.clone();
            with_addr
            .into_future()
            .map_err(|(e, _with_addr)| RendezvousServerError::ReadError(e))
            .and_then(move |(msg_opt, with_addr)| {
                on_addr_echo_request(msg_opt, with_addr, our_pk, our_sk)
            })
        })
        .buffer_unordered(1024)
        .log_errors(LogLevel::Info, "processing echo request")
        .until(drop_rx)
        .for_each(|()| {
            Ok(())
        })
        .map(|x| {
            trace!("rendezvous server exiting");
            x
        })
        .infallible()
    };
    handle.spawn(f);
    UdpRendezvousServer {
        _drop_tx: drop_tx,
        our_pk,
        local_addr: *bind_addr,
    }
}

/// Handles randezvous server request.
///
/// Reponds with client address.
fn on_addr_echo_request(
    msg_opt: Option<Bytes>,
    with_addr: WithAddress,
    our_pk: PublicKey,
    our_sk: SecretKey,
) -> BoxFuture<(), RendezvousServerError> {
    if let Some(msg) = msg_opt {
        let crypto_ctx = CryptoContext::anonymous_decrypt(our_pk, our_sk.clone());
        let req: EncryptedRequest = try_bfut!(crypto_ctx.decrypt(&msg).map_err(
            RendezvousServerError::Decrypt,
        ));

        if req.body[..] == ECHO_REQ[..] {
            let addr = with_addr.remote_addr();
            let crypto_ctx = CryptoContext::authenticated(req.our_pk, our_sk);
            return respond_with_addr(with_addr, addr, &crypto_ctx)
                .map(|_with_addr| ())
                .into_boxed();
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
            let (our_pk, our_sk) = gen_keypair();


            let fut = on_addr_echo_request(None, udp_sock, our_pk, our_sk);

            unwrap!(fut.wait())
        }
    }
}
