use bytes::Bytes;
use open_addr::BindPublicError;
use priv_prelude::*;
use tokio_shared_udp_socket::{SharedUdpSocket, WithAddress};
use udp::socket;
use ECHO_REQ;

/// Sends response to echo address request (`ECHO_REQ`).
/// NOTE: this function is almost identical to `tcp::rendezous_server::respond_with_addr()`,
///       except that the sink item type is `Bytes` rather than `BytesMut`. Wonder if this could
///       be generalized.
pub fn respond_with_addr<T, K: SharedSecretKey>(
    sink: T,
    addr: SocketAddr,
    shared_key: K,
) -> BoxFuture<T, RendezvousServerError>
where
    T: Sink<SinkItem = Bytes, SinkError = io::Error> + 'static,
{
    let encrypted = Bytes::from(shared_key.encrypt(&addr));
    sink.send(encrypted)
        .map_err(RendezvousServerError::SendError)
        .into_boxed()
}

/// Traversal server implementation for UDP.
/// Acts much like STUN server except doesn't implement the standard protocol - RFC 5389.
pub struct UdpRendezvousServer<S: SecretId> {
    local_addr: SocketAddr,
    our_pk: S::Public,
    _drop_tx: DropNotify,
}

impl<S: SecretId> UdpRendezvousServer<S> {
    /// Takes ownership of already set up UDP socket and starts rendezvous server.
    pub fn from_socket(socket: UdpSocket, handle: &Handle) -> io::Result<UdpRendezvousServer<S>> {
        let local_addr = socket.local_addr()?;
        Ok(from_socket_inner(socket, &local_addr, handle))
    }

    /// Start listening for incoming connections.
    pub fn bind(addr: &SocketAddr, handle: &Handle) -> io::Result<UdpRendezvousServer<S>> {
        let socket = UdpSocket::bind(addr, handle)?;
        let server = UdpRendezvousServer::from_socket(socket, handle)?;
        Ok(server)
    }

    /// Start listening for incoming connection and allow other sockets to bind to the same port.
    pub fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<UdpRendezvousServer<S>> {
        let socket = UdpSocket::bind_reusable(addr, handle)?;
        let server = UdpRendezvousServer::from_socket(socket, handle)?;
        Ok(server)
    }

    /// Try to get an external address and start listening for incoming connections.
    pub fn bind_public(
        addr: &SocketAddr,
        handle: &Handle,
        mc: &P2p<S>,
    ) -> BoxFuture<(UdpRendezvousServer<S>, SocketAddr), BindPublicError> {
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
    pub fn public_key(&self) -> S::Public {
        self.our_pk.clone()
    }
}

/// Main UDP rendezvous server logic.
///
/// Spawns async task that reacts to rendezvous requests.
fn from_socket_inner<S: SecretId>(
    socket: UdpSocket,
    bind_addr: &SocketAddr,
    handle: &Handle,
) -> UdpRendezvousServer<S> {
    let (drop_tx, drop_rx) = drop_notify();
    let our_sk = S::new();
    let our_sk_cloned = our_sk.clone();

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

                let our_sk = our_sk_cloned.clone();
                with_addr
                    .into_future()
                    .map_err(|(e, _with_addr)| RendezvousServerError::ReadError(e))
                    .and_then(move |(msg_opt, with_addr)| {
                        on_addr_echo_request(msg_opt, with_addr, our_sk)
                    })
            })
            .buffer_unordered(1024)
            .log_errors(LogLevel::Info, "processing echo request")
            .until(drop_rx)
            .for_each(|()| Ok(()))
            .map(|x| {
                trace!("rendezvous server exiting");
                x
            })
            .infallible()
    };
    handle.spawn(f);
    UdpRendezvousServer {
        _drop_tx: drop_tx,
        our_pk: our_sk.public_id().clone(),
        local_addr: *bind_addr,
    }
}

/// Handles randezvous server request.
///
/// Reponds with client address.
fn on_addr_echo_request<S: SecretId>(
    msg_opt: Option<Bytes>,
    with_addr: WithAddress,
    our_sk: S,
) -> BoxFuture<(), RendezvousServerError> {
    let addr = with_addr.remote_addr();
    if let Some(msg) = msg_opt {
        trace!("udp rendezvous server received message from {}", addr);
        let req: EncryptedRequest<S::Public> = try_bfut!(
            our_sk
                .decrypt_anonymous(&msg)
                .map_err(RendezvousServerError::Decrypt)
        );
        trace!("udp rendezvous server decrypted message from {}", addr);

        if req.body[..] == ECHO_REQ[..] {
            trace!("udp rendezvous server received echo request from {}", addr);
            let shared_key = our_sk.precompute(&req.our_pk);
            return respond_with_addr(with_addr, addr, shared_key)
                .map(|_with_addr| ())
                .into_boxed();
        }
    }

    future::ok(()).into_boxed()
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::{P2pPublicId, P2pSecretId};
    use tokio_core::reactor::Core;

    mod on_addr_echo_request {
        use super::*;

        #[test]
        fn it_returns_finished_future_when_message_is_none() {
            let ev_loop = unwrap!(Core::new());
            let udp_sock = SharedUdpSocket::share(unwrap!(UdpSocket::bind(
                &addr!("0.0.0.0:0"),
                &ev_loop.handle()
            )));
            let udp_sock = udp_sock.with_address(addr!("192.168.1.2:1234"));
            let our_sk = P2pSecretId::new();

            let fut = on_addr_echo_request(None, udp_sock, our_sk);

            unwrap!(fut.wait())
        }
    }

    mod rendezvous_server {
        use super::*;
        use maidsafe_utilities::serialisation::serialise;
        use mc::udp_query_public_addr;

        #[test]
        fn when_unencrypted_request_is_sent_no_response_is_sent_back_to_client() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let server = unwrap!(UdpRendezvousServer::<P2pSecretId>::bind(
                &addr!("0.0.0.0:0"),
                &handle
            ));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_info = PeerInfo::<P2pPublicId>::with_rand_key::<P2pSecretId>(server_addr);
            let request =
                EncryptedRequest::<P2pPublicId>::with_rand_key::<P2pSecretId>(ECHO_REQ.to_vec());
            let unencrypted_request = BytesMut::from(unwrap!(serialise(&request)));

            let server_sk = P2pSecretId::new();
            let client_sk = P2pSecretId::new();
            let shared_key = client_sk.precompute(server_sk.public_id());

            let query = udp_query_public_addr::<P2pSecretId>(
                &addr!("0.0.0.0:0"),
                &server_info,
                &handle,
                shared_key,
                unencrypted_request,
            );

            let res = evloop.run(query);
            let timeout = match res {
                Err(e) => match e {
                    QueryPublicAddrError::ResponseTimeout => true,
                    _ => false,
                },
                _ => false,
            };
            assert!(timeout);
        }

        #[test]
        fn it_sends_encrypted_responses() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let server = unwrap!(UdpRendezvousServer::<P2pSecretId>::bind(
                &addr!("0.0.0.0:0"),
                &handle
            ));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_info = PeerInfo::new(server_addr, server.public_key());

            let server_pk = server.public_key();
            let client_sk = P2pSecretId::new();
            let shared_key = client_sk.precompute(&server_pk);

            let request =
                EncryptedRequest::<P2pPublicId>::with_rand_key::<P2pSecretId>(ECHO_REQ.to_vec());
            let encrypted_request = BytesMut::from(server_pk.encrypt_anonymous(&request));

            let query = udp_query_public_addr::<P2pSecretId>(
                &addr!("0.0.0.0:0"),
                &server_info,
                &handle,
                shared_key,
                encrypted_request,
            );

            let res = evloop.run(query);
            let decrypt_error = match res {
                Err(e) => match e {
                    QueryPublicAddrError::Decrypt(_e) => true,
                    _ => false,
                },
                _ => false,
            };
            assert!(decrypt_error);
        }
    }
}
