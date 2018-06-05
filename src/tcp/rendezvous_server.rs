use open_addr::BindPublicError;
use priv_prelude::*;
use tcp::listener::{self, TcpListenerExt};
use tokio_io::codec::length_delimited::{self, Framed};
use ECHO_REQ;

/// Sends response to echo address request (`ECHO_REQ`).
pub fn respond_with_addr<T, K: SharedSecretKey>(
    sink: T,
    addr: SocketAddr,
    shared_key: &K,
) -> BoxFuture<T, RendezvousServerError>
where
    T: Sink<SinkItem = BytesMut, SinkError = io::Error> + 'static,
{
    println!("responding to their request");
    let encrypted = BytesMut::from(shared_key.encrypt(&addr));
    sink.send(encrypted)
        .map_err(RendezvousServerError::SendError)
        .into_boxed()
}

/// A TCP rendezvous server. Other peers can use this when performing rendezvous connects and
/// hole-punching.
pub struct TcpRendezvousServer<S: SecretId> {
    local_addr: SocketAddr,
    our_pk: <S as SecretId>::Public,
    _drop_tx: DropNotify,
}

impl<S: SecretId> TcpRendezvousServer<S> {
    /// Create a rendezvous server from a `TcpListener`.
    pub fn from_listener(
        listener: TcpListener,
        handle: &Handle,
    ) -> io::Result<TcpRendezvousServer<S>> {
        let local_addr = listener.local_addr()?;
        Ok(from_listener_inner(listener, &local_addr, handle))
    }

    /// Create a new rendezvous server, bound to the given address.
    pub fn bind(addr: &SocketAddr, handle: &Handle) -> io::Result<TcpRendezvousServer<S>> {
        let listener = TcpListener::bind(addr, handle)?;
        let server = TcpRendezvousServer::from_listener(listener, handle)?;
        Ok(server)
    }

    /// Create a new rendezvous server, reusably bound to the given address.
    pub fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<TcpRendezvousServer<S>> {
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
        mc: &P2p<S>,
    ) -> BoxFuture<(TcpRendezvousServer<S>, SocketAddr), BindPublicError> {
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

    /// Returns server public key.
    /// Server expects incoming messages to be encrypted with this public key.
    pub fn public_key(&self) -> S::Public {
        self.our_pk.clone()
    }
}

fn from_listener_inner<S: SecretId>(
    listener: TcpListener,
    bind_addr: &SocketAddr,
    handle: &Handle,
) -> TcpRendezvousServer<S> {
    let (drop_tx, drop_rx) = drop_notify();
    let our_sk = S::new();
    let our_sk_cloned = our_sk.clone();
    let handle_connections = {
        let handle = handle.clone();
        listener
            .incoming()
            .map_err(RendezvousServerError::AcceptError)
            .map(move |(stream, addr)| {
                handle_connection(stream, addr, &handle, our_sk_cloned.clone())
            })
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
        our_pk: our_sk.public_id().clone(),
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
        /// Failure to decrypt data.
        Decrypt(e: DecryptError) {
            description("Error decrypting message")
            display("Error decrypting message: {}", e)
            cause(e)
        }
    }
}

fn handle_connection<S: SecretId>(
    stream: TcpStream,
    addr: SocketAddr,
    handle: &Handle,
    our_sk: S,
) -> BoxFuture<(), RendezvousServerError> {
    println!("got a new connection");
    let stream: Framed<_, BytesMut> = length_delimited::Builder::new().new_framed(stream);
    stream
        .into_future()
        .map_err(|(err, _stream)| RendezvousServerError::ReadError(err))
        .and_then(|(req_opt, stream)| {
            println!("read their request");
            req_opt
                .map(|req| (req, stream))
                .ok_or(RendezvousServerError::ConnectionClosed)
        })
        .and_then(move |(req, stream)| {
            let req: EncryptedRequest<S::Public> = try_bfut!(
                our_sk
                    .decrypt_anonymous(&req)
                    .map_err(RendezvousServerError::Decrypt)
            );
            println!("decrypted their request");
            if req.body[..] == ECHO_REQ {
                let shared_key = our_sk.precompute(&req.our_pk);
                respond_with_addr(stream, addr, &shared_key)
                    .map(|_stream| ())
                    .into_boxed()
            } else {
                println!("ignoring their request");
                future::ok(()).into_boxed()
            }
        })
        .with_timeout(Duration::from_secs(2), handle)
        .and_then(|opt| {
            opt.ok_or_else(|| {
                println!("timed out responding to their request");
                RendezvousServerError::Timeout
            })
        })
        .into_boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{P2pPublicId, P2pSecretId};
    use tokio_core::reactor::Core;

    mod respond_with_addr {
        use super::*;

        #[test]
        fn it_sends_serialized_client_address() {
            let mut event_loop = unwrap!(Core::new());
            let handle = event_loop.handle();

            let server_sk = P2pSecretId::new();
            let client_sk = P2pSecretId::new();
            let server_shared_key = server_sk.precompute(&client_sk.public_id());
            let client_shared_key = client_sk.precompute(&server_sk.public_id());

            let listener = unwrap!(TcpListener::bind(&addr!("127.0.0.1:0"), &handle));
            let listener_addr = unwrap!(listener.local_addr());
            let handle_conns = listener
                .incoming()
                .for_each(move |(stream, addr)| {
                    let stream = length_delimited::Builder::new().new_framed(stream);
                    respond_with_addr(stream, addr, &server_shared_key).then(|_| Ok(()))
                })
                .then(|_| Ok(()));
            handle.spawn(handle_conns);

            let conn = unwrap!(event_loop.run(TcpStream::connect(&listener_addr, &handle)));
            let actual_addr = unwrap!(conn.local_addr());
            let conn: Framed<_, BytesMut> = length_delimited::Builder::new().new_framed(conn);

            let buf = unwrap!(
                event_loop.run(
                    conn.into_future()
                        .map(|(resp_opt, _conn)| unwrap!(resp_opt)),
                )
            );
            let received_addr: SocketAddr = unwrap!(client_shared_key.decrypt(&buf));

            assert_eq!(received_addr, actual_addr);
        }
    }

    mod rendezvous_server {
        use super::*;
        use maidsafe_utilities::serialisation::serialise;
        use mc::tcp_query_public_addr;

        #[test]
        fn when_unencrypted_request_is_sent_client_connection_is_closed() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let server = unwrap!(TcpRendezvousServer::<P2pSecretId>::bind(
                &addr!("0.0.0.0:0"),
                &handle
            ));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_info = PeerInfo::<P2pPublicId>::with_rand_key::<P2pSecretId>(server_addr);
            let request =
                EncryptedRequest::<P2pPublicId>::with_rand_key::<P2pSecretId>(ECHO_REQ.to_vec());
            let unencrypted_request = BytesMut::from(unwrap!(serialise(&request)));

            let server_pk = server.public_key();
            let client_pk = P2pSecretId::new();
            let shared_key = client_pk.precompute(&server_pk);

            let query = tcp_query_public_addr::<P2pSecretId>(
                &addr!("0.0.0.0:0"),
                &server_info,
                &handle,
                shared_key,
                unencrypted_request,
            );

            let res = evloop.run(query);
            let connection_closed = match res {
                Err(e) => {
                    println!("{:?}", e);
                    match e {
                        QueryPublicAddrError::ReadResponse(_) => true,
                        _ => false,
                    }
                }
                _ => false,
            };
            assert!(connection_closed);
        }

        #[test]
        fn it_sends_encrypted_responses() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let server = unwrap!(TcpRendezvousServer::<P2pSecretId>::bind(
                &addr!("0.0.0.0:0"),
                &handle
            ));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_info = PeerInfo::new(server_addr, server.public_key());

            let request =
                EncryptedRequest::<P2pPublicId>::with_rand_key::<P2pSecretId>(ECHO_REQ.to_vec());

            let server_pk = server.public_key();
            let client_sk = P2pSecretId::new();
            let shared_key = client_sk.precompute(&server_pk);
            let encrypted_request = BytesMut::from(server_pk.encrypt_anonymous(&request));

            let query = tcp_query_public_addr::<P2pSecretId>(
                &addr!("0.0.0.0:0"),
                &server_info,
                &handle,
                shared_key,
                encrypted_request,
            );

            let res = evloop.run(query);
            match res {
                Err(e) => match e {
                    QueryPublicAddrError::Decrypt(_) => (),
                    _ => panic!("unexpected error: {}", e),
                },
                _ => panic!("unexpected success"),
            };
        }
    }
}
