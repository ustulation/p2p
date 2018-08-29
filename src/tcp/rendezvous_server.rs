use open_addr::BindPublicError;
use priv_prelude::*;
use tcp::listener::{self, TcpListenerExt};
use tokio_io::codec::length_delimited::{self, Framed};

/// Sends response to echo address request (`ECHO_REQ`).
pub fn respond_with_addr<S>(
    sink: S,
    addr: SocketAddr,
    shared_secret: &SharedSecretKey,
) -> BoxFuture<S, RendezvousServerError>
where
    S: Sink<SinkItem = BytesMut, SinkError = io::Error> + 'static,
{
    let encrypted = try_bfut!(
        shared_secret
            .encrypt(&addr)
            .map_err(RendezvousServerError::Encrypt)
    );
    let encrypted = BytesMut::from(encrypted);
    trace!("echo server responding to address {}", addr);
    sink.send(encrypted)
        .map_err(RendezvousServerError::SendError)
        .into_boxed()
}

/// A TCP rendezvous server. Other peers can use this when performing rendezvous connects and
/// hole-punching.
pub struct TcpRendezvousServer {
    local_addr: SocketAddr,
    our_pk: PublicKeys,
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
            }).into_boxed()
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

    /// Returns server public key.
    /// Server expects incoming messages to be encrypted with this public key.
    pub fn public_key(&self) -> &PublicKeys {
        &self.our_pk
    }
}

fn from_listener_inner(
    listener: TcpListener,
    bind_addr: &SocketAddr,
    handle: &Handle,
) -> TcpRendezvousServer {
    let (drop_tx, drop_rx) = drop_notify();
    let our_sk = SecretKeys::new();
    let our_pk = our_sk.public_keys().clone();
    let handle_connections = {
        let handle = handle.clone();
        listener
            .incoming()
            .map_err(RendezvousServerError::AcceptError)
            .map(move |(stream, addr)| handle_connection(stream, addr, &handle, our_sk.clone()))
            .buffer_unordered(1024)
            .log_errors(LogLevel::Info, "processing echo request")
            .until(drop_rx)
            .for_each(|()| Ok(()))
            .infallible()
    };
    handle.spawn(handle_connections);
    TcpRendezvousServer {
        _drop_tx: drop_tx,
        local_addr: *bind_addr,
        our_pk,
    }
}

quick_error! {
    /// Errors related to rendezvous server client connection handling.
    #[derive(Debug)]
    pub enum RendezvousServerError {
        /// Failure to accept incomin client connection.
        AcceptError(e: io::Error) {
            description("Error accepting client connection")
            display("Error accepting client connection: {}", e)
            cause(e)
        }
        /// Failure to read data from client socket.
        ReadError(e: io::Error) {
            description("Error reading client message")
            display("Error reading client message: {}", e)
            cause(e)
        }
        /// Failure to write data to client socket.
        SendError(e: io::Error) {
            description("Error sending message to client")
            display("Error sennding message to client: {}", e)
            cause(e)
        }
        /// Client connection related operation timedout.
        Timeout {
            description("Connection timedout")
        }
        /// Client connection was closed.
        ConnectionClosed {
            description("Connection was closed prematurely")
        }
        /// Failure to encrypt data.
        Encrypt(e: EncryptionError) {
            description("Error encrypting message")
            display("Error encrypting message: {}", e)
            cause(e)
        }
        /// Failure to decrypt data.
        Decrypt(e: EncryptionError) {
            description("Error decrypting message")
            display("Error decrypting message: {}", e)
            cause(e)
        }
    }
}

fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    handle: &Handle,
    our_sk: SecretKeys,
) -> BoxFuture<(), RendezvousServerError> {
    let stream: Framed<_, BytesMut> = length_delimited::Builder::new().new_framed(stream);
    stream
        .into_future()
        .map_err(|(err, _stream)| RendezvousServerError::ReadError(err))
        .and_then(|(req_opt, stream)| {
            req_opt
                .map(|req| (req, stream))
                .ok_or(RendezvousServerError::ConnectionClosed)
        }).and_then(move |(req, stream)| {
            let req: EchoRequest = try_bfut!(
                our_sk
                    .decrypt_anonymous(&req,)
                    .map_err(RendezvousServerError::Decrypt,)
            );
            let shared_secret = our_sk.shared_secret(&req.client_pk);
            respond_with_addr(stream, addr, &shared_secret)
                .map(|_stream| ())
                .into_boxed()
        }).with_timeout(Duration::from_secs(2), handle)
        .and_then(|opt| opt.ok_or(RendezvousServerError::Timeout))
        .into_boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_core::reactor::Core;

    mod respond_with_addr {
        use super::*;
        use env_logger;

        #[test]
        fn it_sends_serialized_client_address() {
            let _ = env_logger::init();

            let mut event_loop = unwrap!(Core::new());
            let handle = event_loop.handle();

            let server_sk = SecretKeys::new();
            let server_pk = server_sk.public_keys().clone();
            let client_sk = SecretKeys::new();
            let client_pk = client_sk.public_keys().clone();

            let listener = unwrap!(TcpListener::bind(&addr!("127.0.0.1:0"), &handle));
            let listener_addr = unwrap!(listener.local_addr());
            let handle_conns = listener
                .incoming()
                .into_future()
                .map_err(|(e, _incoming)| panic!("error accepting tcp connection: {}", e))
                .and_then(move |(stream_addr_opt, _incoming)| {
                    let (stream, addr) = unwrap!(stream_addr_opt);
                    let stream = length_delimited::Builder::new().new_framed(stream);
                    let shared_secret = server_sk.shared_secret(&client_pk);
                    respond_with_addr(stream, addr, &shared_secret)
                        .map_err(|e| panic!("error calling respond_with_addr: {}", e))
                        .map(|_stream| ())
                });

            event_loop
                .run({
                    TcpStream::connect(&listener_addr, &handle)
                        .map_err(|e| panic!("error connecting: {}", e))
                        .and_then(|conn| {
                            let actual_addr = unwrap!(conn.local_addr());
                            let conn: Framed<_, BytesMut> =
                                length_delimited::Builder::new().new_framed(conn);
                            conn.into_future()
                                .map_err(|(e, _conn)| panic!("error receiving: {}", e))
                                .map(move |(resp_opt, _conn)| {
                                    let shared_secret = client_sk.shared_secret(&server_pk);
                                    let resp = unwrap!(resp_opt);
                                    let received_addr: SocketAddr = unwrap!(
                                    shared_secret
                                        .decrypt(&resp)
                                );
                                    assert_eq!(received_addr, actual_addr);
                                })
                        }).join(handle_conns)
                        .map(|((), ())| ())
                }).void_unwrap()
        }
    }

    mod rendezvous_server {
        use super::*;
        use maidsafe_utilities::serialisation;

        #[test]
        fn when_unencrypted_request_is_sent_client_connection_is_closed() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let server = unwrap!(TcpRendezvousServer::bind(&addr!("0.0.0.0:0"), &handle));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let client_sk = SecretKeys::new();
            let request = EchoRequest {
                client_pk: client_sk.public_keys().clone(),
            };
            let unencrypted_request = BytesMut::from(unwrap!(serialisation::serialise(&request)));

            let f = {
                TcpStream::connect(&server_addr, &handle)
                    .map_err(|e| panic!("error connecting: {}", e))
                    .and_then(move |stream| {
                        Framed::new(stream)
                            .send(unencrypted_request)
                            .map_err(|e| panic!("error sending: {}", e))
                            .and_then(|stream| {
                                stream
                                    .into_future()
                                    .map_err(|(e, _stream)| panic!("error reading: {}", e))
                                    .map(|(opt, _stream)| {
                                        assert!(opt.is_none());
                                    })
                            })
                    })
            };

            evloop.run(f).void_unwrap()
        }

        #[test]
        fn it_sends_encrypted_responses() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let server = unwrap!(TcpRendezvousServer::bind(&addr!("0.0.0.0:0"), &handle));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_pk = server.public_key();
            let client_sk = SecretKeys::new();

            let request = EchoRequest {
                client_pk: client_sk.public_keys().clone(),
            };
            let encrypted_request = BytesMut::from(unwrap!(server_pk.encrypt_anonymous(&request)));
            let invalid_shared_secret = SecretKeys::new().shared_secret(&server_pk);

            let f = {
                TcpStream::connect(&server_addr, &handle)
                    .map_err(|e| panic!("error connecting: {}", e))
                    .and_then(move |stream| {
                        Framed::new(stream)
                            .send(encrypted_request)
                            .map_err(|e| panic!("error sending: {}", e))
                            .and_then(move |framed| {
                                framed
                                    .into_future()
                                    .map_err(|(e, _stream)| panic!("error reading: {}", e))
                                    .map(move |(msg_opt, _stream)| {
                                        let msg = unwrap!(msg_opt);
                                        match invalid_shared_secret.decrypt::<EchoRequest>(&msg) {
                                            Err(_) => (),
                                            Ok(x) => panic!("unexpected success: {:?}", x),
                                        }
                                    })
                            })
                    })
            };

            evloop.run(f).void_unwrap()
        }
    }
}
