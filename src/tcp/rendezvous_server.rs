use ECHO_REQ;
use open_addr::BindPublicError;
use priv_prelude::*;
use rust_sodium::crypto::box_::{PublicKey, SecretKey, gen_keypair};
use tcp::listener::{self, TcpListenerExt};
use tokio_io::codec::length_delimited::{self, Framed};

/// Sends response to echo address request (`ECHO_REQ`).
pub fn respond_with_addr<S>(
    sink: S,
    addr: SocketAddr,
    crypto_ctx: &CryptoContext,
) -> BoxFuture<S, RendezvousServerError>
where
    S: Sink<SinkItem = BytesMut, SinkError = io::Error> + 'static,
{
    let encrypted = try_bfut!(crypto_ctx.encrypt(&addr).map_err(
        RendezvousServerError::Encrypt,
    ));
    sink.send(encrypted)
        .map_err(RendezvousServerError::SendError)
        .into_boxed()
}

/// A TCP rendezvous server. Other peers can use this when performing rendezvous connects and
/// hole-punching.
pub struct TcpRendezvousServer {
    local_addr: SocketAddr,
    our_pk: PublicKey,
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

    /// Returns server public key.
    /// Server expects incoming messages to be encrypted with this public key.
    pub fn public_key(&self) -> PublicKey {
        self.our_pk
    }
}

fn from_listener_inner(
    listener: TcpListener,
    bind_addr: &SocketAddr,
    handle: &Handle,
) -> TcpRendezvousServer {
    let (drop_tx, drop_rx) = drop_notify();
    let (our_pk, our_sk) = gen_keypair();
    let handle_connections = {
        let handle = handle.clone();
        listener
        .incoming()
        .map_err(RendezvousServerError::AcceptError)
        .map(move |(stream, addr)| handle_connection(stream, addr, &handle, our_pk, our_sk.clone()))
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
        Encrypt(e: CryptoError) {
            description("Error encrypting message")
            display("Error encrypting message: {}", e)
            cause(e)
        }
        /// Failure to decrypt data.
        Decrypt(e: CryptoError) {
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
    our_pk: PublicKey,
    our_sk: SecretKey,
) -> BoxFuture<(), RendezvousServerError> {
    let stream: Framed<_, BytesMut> = length_delimited::Builder::new().new_framed(stream);
    let crypto_ctx = CryptoContext::anonymous_decrypt(our_pk, our_sk.clone());
    stream
        .into_future()
        .map_err(|(err, _stream)| RendezvousServerError::ReadError(err))
        .and_then(|(req_opt, stream)| {
            req_opt.map(|req| (req, stream)).ok_or(
                RendezvousServerError::ConnectionClosed,
            )
        })
        .and_then(move |(req, stream)| {
            let req: EncryptedRequest = try_bfut!(crypto_ctx.decrypt(&req).map_err(
                RendezvousServerError::Decrypt,
            ));
            if req.body[..] == ECHO_REQ {
                let crypto_ctx = CryptoContext::authenticated(req.our_pk, our_sk);
                respond_with_addr(stream, addr, &crypto_ctx)
                    .map(|_stream| ())
                    .into_boxed()
            } else {
                future::ok(()).into_boxed()
            }
        })
        .with_timeout(Duration::from_secs(2), handle)
        .and_then(|opt| opt.ok_or(RendezvousServerError::Timeout))
        .into_boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;
    use tokio_core::reactor::Core;

    mod respond_with_addr {
        use super::*;

        #[test]
        fn it_sends_serialized_client_address() {
            let mut event_loop = unwrap!(Core::new());
            let handle = event_loop.handle();

            let listener = unwrap!(TcpListener::bind(&addr!("127.0.0.1:0"), &handle));
            let listener_addr = unwrap!(listener.local_addr());
            let handle_conns = listener
                .incoming()
                .for_each(|(stream, addr)| {
                    let stream = length_delimited::Builder::new().new_framed(stream);
                    let crypto_ctx = CryptoContext::null();
                    respond_with_addr(stream, addr, &crypto_ctx).then(|_| Ok(()))
                })
                .then(|_| Ok(()));
            handle.spawn(handle_conns);

            let conn = unwrap!(event_loop.run(TcpStream::connect(&listener_addr, &handle)));
            let actual_addr = unwrap!(conn.local_addr());
            let conn: Framed<_, BytesMut> = length_delimited::Builder::new().new_framed(conn);

            let buf = unwrap!(event_loop.run(conn.into_future().map(|(resp_opt, _conn)| {
                unwrap!(resp_opt)
            })));
            let received_addr: SocketAddr = unwrap!(bincode::deserialize(&buf));

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
            let server = unwrap!(TcpRendezvousServer::bind(&addr!("0.0.0.0:0"), &handle));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_info = PeerInfo::with_rand_key(server_addr);
            let request = EncryptedRequest::with_rand_key(ECHO_REQ.to_vec());
            let unencrypted_request = BytesMut::from(unwrap!(serialise(&request)));

            let query = tcp_query_public_addr(
                &addr!("0.0.0.0:0"),
                &server_info,
                &handle,
                CryptoContext::null(),
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
            let server = unwrap!(TcpRendezvousServer::bind(&addr!("0.0.0.0:0"), &handle));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_info = PeerInfo::new(server_addr, server.public_key());

            let request = EncryptedRequest::with_rand_key(ECHO_REQ.to_vec());
            let crypto_ctx = CryptoContext::anonymous_encrypt(server.public_key());
            let encrypted_request = unwrap!(crypto_ctx.encrypt(&request));

            let query = tcp_query_public_addr(
                &addr!("0.0.0.0:0"),
                &server_info,
                &handle,
                CryptoContext::null(),
                encrypted_request,
            );

            let res = evloop.run(query);
            let decrypt_error = match res {
                Err(e) => {
                    match e {
                        QueryPublicAddrError::Decrypt(_) => true,
                        _ => false,
                    }
                }
                _ => false,
            };
            assert!(decrypt_error);
        }
    }
}
