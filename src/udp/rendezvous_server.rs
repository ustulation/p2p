use bytes::Bytes;
use open_addr::BindPublicError;
use priv_prelude::*;
use tokio_shared_udp_socket::{SharedUdpSocket, WithAddress};
use udp::socket;

/// Sends response to echo address request (`ECHO_REQ`).
/// NOTE: this function is almost identical to `tcp::rendezous_server::respond_with_addr()`,
///       except that the sink item type is `Bytes` rather than `BytesMut`. Wonder if this could
///       be generalized.
pub fn respond_with_addr<S>(
    sink: S,
    addr: SocketAddr,
    shared_secret: &SharedSecretKey,
) -> BoxFuture<S, RendezvousServerError>
where
    S: Sink<SinkItem = Bytes, SinkError = io::Error> + 'static,
{
    let encrypted = try_bfut!(
        shared_secret
            .encrypt(&addr)
            .map_err(RendezvousServerError::Encrypt)
            .map(Bytes::from)
    );
    sink.send(encrypted)
        .map_err(RendezvousServerError::SendError)
        .into_boxed()
}

/// Traversal server implementation for UDP.
/// Acts much like STUN server except doesn't implement the standard protocol - RFC 5389.
pub struct UdpRendezvousServer {
    local_addr: SocketAddr,
    our_pk: PublicKeys,
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
            }).into_boxed()
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
    pub fn public_key(&self) -> &PublicKeys {
        &self.our_pk
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
    let our_sk = SecretKeys::new();
    let our_pk = our_sk.public_keys().clone();

    let f = {
        let socket = SharedUdpSocket::share(socket);
        trace!("rendezvous server starting");

        socket
            .map_err(RendezvousServerError::AcceptError)
            .map(move |with_addr| {
                trace!(
                    "rendezvous server started conversation with {}",
                    with_addr.remote_addr()
                );

                let our_sk = our_sk.clone();
                with_addr
                    .into_future()
                    .map_err(|(e, _with_addr)| RendezvousServerError::ReadError(e))
                    .and_then(move |(msg_opt, with_addr)| match msg_opt {
                        Some(msg) => on_addr_echo_request(&msg, with_addr, &our_sk),
                        None => future::ok(()).into_boxed(),
                    })
            }).buffer_unordered(1024)
            .log_errors(LogLevel::Info, "processing echo request")
            .until(drop_rx)
            .for_each(|()| Ok(()))
            .map(|x| {
                trace!("rendezvous server exiting");
                x
            }).infallible()
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
    msg: &[u8],
    with_addr: WithAddress,
    our_sk: &SecretKeys,
) -> BoxFuture<(), RendezvousServerError> {
    let addr = with_addr.remote_addr();
    trace!("udp rendezvous server received message from {}", addr);
    let request: EchoRequest = try_bfut!(
        our_sk
            .decrypt_anonymous(msg)
            .map_err(RendezvousServerError::Decrypt)
    );

    trace!("udp rendezvous server received echo request from {}", addr);
    let shared_secret = our_sk.shared_secret(&request.client_pk);
    respond_with_addr(with_addr, addr, &shared_secret)
        .map(|_with_addr| ())
        .into_boxed()
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio_core::reactor::Core;

    mod rendezvous_server {
        use super::*;
        use maidsafe_utilities::serialisation;
        use util;

        #[test]
        fn when_unencrypted_request_is_sent_no_response_is_sent_back_to_client() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let server = unwrap!(UdpRendezvousServer::bind(&addr!("0.0.0.0:0"), &handle));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let client_sk = SecretKeys::new();
            let request = EchoRequest {
                client_pk: client_sk.public_keys().clone(),
            };
            let unencrypted_request = BytesMut::from(unwrap!(serialisation::serialise(&request)));

            let socket = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));

            let f = {
                socket
                    .send_dgram(unencrypted_request, server_addr)
                    .map_err(|e| panic!("error sending: {}", e))
                    .and_then(|(socket, _msg)| {
                        socket
                            .recv_dgram(util::zeroed_vec(256))
                            .map_err(|e| panic!("error receiving: {}", e))
                            .with_timeout(Duration::from_secs(1), &handle)
                            .map(|opt| {
                                assert!(opt.is_none());
                            })
                    })
            };

            evloop.run(f).void_unwrap()
        }

        #[test]
        fn it_sends_encrypted_responses() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let server = unwrap!(UdpRendezvousServer::bind(&addr!("0.0.0.0:0"), &handle));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_pk = server.public_key();
            let client_sk = SecretKeys::new();
            let request = EchoRequest {
                client_pk: client_sk.public_keys().clone(),
            };
            let encrypted_request = BytesMut::from(unwrap!(server_pk.encrypt_anonymous(&request)));
            let invalid_shared_secret = SecretKeys::new().shared_secret(&server_pk);

            let socket = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));

            let f = {
                socket
                    .send_dgram(encrypted_request, server_addr)
                    .map_err(|e| panic!("error sending: {}", e))
                    .and_then(|(socket, _msg)| {
                        socket
                            .recv_dgram(util::zeroed_vec(256))
                            .map_err(|e| panic!("error receiving: {}", e))
                            .with_timeout(Duration::from_secs(1), &handle)
                            .map(|msg_opt| {
                                let (_socket, msg, n, addr) = unwrap!(msg_opt);
                                assert_eq!(addr, server_addr);
                                match invalid_shared_secret.decrypt::<EchoRequest>(&msg[..n]) {
                                    Err(_) => (),
                                    Ok(x) => panic!("unexpected success: {:?}", x),
                                }
                            })
                    })
            };

            evloop.run(f).void_unwrap()
        }
    }
}
