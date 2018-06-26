//! Port mapping context utilities.

use priv_prelude::*;
use protocol::Protocol;
use serde;
use server_set::{ServerSet, Servers};
use tokio_io::codec::length_delimited::{self, Framed};
use ECHO_REQ;

/// `P2p` allows you to manage how NAT traversal works.
///
/// You can edit rendezvous (traversal) servers, enable/Disable IGD use, etc.
pub struct P2p<S: SecretId> {
    inner: Arc<Mutex<P2pInner<S::Public>>>,
}

impl<S: SecretId> Default for P2p<S> {
    fn default() -> P2p<S> {
        P2p {
            inner: Arc::new(Mutex::new(P2pInner::default())),
        }
    }
}

impl<S: SecretId> Clone for P2p<S> {
    fn clone(&self) -> P2p<S> {
        P2p {
            inner: self.inner.clone(),
        }
    }
}

#[derive(Clone)]
struct P2pInner<P: PublicId> {
    tcp_server_set: ServerSet<P>,
    udp_server_set: ServerSet<P>,
    igd_disabled: bool,
    igd_disabled_for_rendezvous: bool,
    force_use_local_port: bool,
}

impl<P: PublicId> Default for P2pInner<P> {
    fn default() -> P2pInner<P> {
        P2pInner {
            tcp_server_set: ServerSet::default(),
            udp_server_set: ServerSet::default(),
            igd_disabled: false,
            igd_disabled_for_rendezvous: false,
            force_use_local_port: false,
        }
    }
}

// Some macros to reduce boilerplate

macro_rules! inner_get {
    ($self:ident, $field:ident) => {{
        let inner = unwrap!($self.inner.lock());
        inner.$field
    }};
}

macro_rules! inner_set {
    ($self:ident, $field:ident, $value:ident) => {{
        let mut inner = unwrap!($self.inner.lock());
        inner.$field = $value;
    }};
}

impl<S: SecretId> P2p<S> {
    /// Check if IGD for rendezvous connections option is on or off.
    pub fn is_igd_enabled_for_rendezvous(&self) -> bool {
        !inner_get!(self, igd_disabled_for_rendezvous)
    }

    /// Try to use IGD port mapping when doing rendezvous connections.
    pub fn enable_igd_for_rendezvous(&self) {
        inner_set!(self, igd_disabled_for_rendezvous, false);
    }

    /// Don't use IGD port mapping when doing rendezvous connections.
    pub fn disable_igd_for_rendezvous(&self) {
        inner_set!(self, igd_disabled_for_rendezvous, true);
    }

    /// Tests if IGD use is enabled or not.
    /// It's enabled by default.
    pub fn is_igd_enabled(&self) -> bool {
        !inner_get!(self, igd_disabled)
    }

    /// Returns the value of `force_use_local_port` option.
    pub fn force_use_local_port(&self) -> bool {
        inner_get!(self, force_use_local_port)
    }

    /// If this option is on, when public address is determined, use our local listening port
    /// as external as well.
    pub fn set_force_use_local_port(&self, force: bool) {
        inner_set!(self, force_use_local_port, force);
    }

    /// By default `p2p` attempts to use IGD to open external ports for it's own use.
    /// Use this function to disable such behaviour.
    pub fn disable_igd(&self) {
        inner_set!(self, igd_disabled, true);
    }

    /// Re-enables IGD use.
    pub fn enable_igd(&self) {
        inner_set!(self, igd_disabled, false);
    }

    /// Tell about a `TcpTraversalServer` than can be used to help use perform rendezvous
    /// connects and hole punching.
    pub fn add_tcp_traversal_server(&self, addr: &PeerInfo<S::Public>) {
        self.add_server(Protocol::Tcp, addr);
    }

    /// Tells the library to forget a `TcpTraversalServer` previously added with
    /// `add_tcp_traversal_server`.
    pub fn remove_tcp_traversal_server(&self, addr: SocketAddr) {
        self.remove_server(Protocol::Tcp, addr);
    }

    /// Returns a iterator over all tcp traversal server addresses.
    pub fn tcp_traversal_servers(&self) -> Servers<S::Public> {
        self.iter_servers(Protocol::Tcp)
    }

    /// Tell about a `UdpTraversalServer` than can be used to help use perform rendezvous
    /// connects and hole punching.
    pub fn add_udp_traversal_server(&self, addr: &PeerInfo<S::Public>) {
        self.add_server(Protocol::Udp, addr);
    }

    /// Tells the library to forget a `UdpTraversalServer` previously added with
    /// `add_udp_traversal_server`.
    pub fn remove_udp_traversal_server(&self, addr: SocketAddr) {
        self.remove_server(Protocol::Udp, addr);
    }

    /// Returns an iterator over all udp traversal server addresses added with
    /// `add_tcp_traversal_server`.
    pub fn udp_traversal_servers(&self) -> Servers<S::Public> {
        self.iter_servers(Protocol::Udp)
    }

    /// Returns a `Stream` of traversal servers.
    pub fn iter_servers(&self, protocol: Protocol) -> Servers<S::Public> {
        let mut inner = unwrap!(self.inner.lock());
        inner.server_set(protocol).iter_servers()
    }

    fn add_server(&self, protocol: Protocol, addr: &PeerInfo<S::Public>) {
        let mut inner = unwrap!(self.inner.lock());
        inner.server_set(protocol).add_server(addr);
    }

    fn remove_server(&self, protocol: Protocol, addr: SocketAddr) {
        let mut inner = unwrap!(self.inner.lock());
        inner.server_set(protocol).remove_server(addr);
    }
}

impl<P: PublicId> P2pInner<P> {
    fn server_set(&mut self, protocol: Protocol) -> &mut ServerSet<P> {
        match protocol {
            Protocol::Udp => &mut self.udp_server_set,
            Protocol::Tcp => &mut self.tcp_server_set,
        }
    }
}

/// Request that has sender's public key and arbitrary body.
/// This request is SHOULD be anonymously encrypted and it allows receiver to switch to
/// authenticated encryption.
#[derive(Debug)]
pub struct EncryptedRequest<P: PublicId> {
    /// Sender's public key. Response should be encrypted with it.
    pub our_pk: P,
    /// Arbitrary request body.
    pub body: Vec<u8>,
}

impl<P: PublicId> Serialize for EncryptedRequest<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (&self.our_pk, &self.body).serialize(serializer)
    }
}

impl<'de, P: PublicId> Deserialize<'de> for EncryptedRequest<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (our_pk, body) = <(_, _)>::deserialize(deserializer)?;
        Ok(EncryptedRequest { our_pk, body })
    }
}

impl<P: PublicId> EncryptedRequest<P> {
    /// Create new request.
    pub fn new(our_pk: P, body: Vec<u8>) -> Self {
        Self { our_pk, body }
    }

    /// Constructs request with random public key.
    /// Useful for testing.
    #[cfg(test)]
    pub fn with_rand_key<S: SecretId<Public = P>>(body: Vec<u8>) -> Self {
        let sk = S::new();
        Self::new(sk.public_id().clone(), body)
    }
}

/// Sends request to echo address server and returns our public address on success.
pub fn query_public_addr<S: SecretId>(
    protocol: Protocol,
    bind_addr: &SocketAddr,
    server_info: &PeerInfo<S::Public>,
    handle: &Handle,
) -> BoxFuture<SocketAddr, QueryPublicAddrError> {
    let our_sk = S::new(); // TODO(povilas): pass this from upper layers. MAID-2532
    let request = EncryptedRequest::new(our_sk.public_id().clone(), ECHO_REQ.to_vec());
    // First message is encrypted anonymously.
    let encrypted_req = BytesMut::from(server_info.pub_key.encrypt_anonymous(&request));
    let shared_key = our_sk.shared_key(&server_info.pub_key);

    match protocol {
        Protocol::Tcp => {
            tcp_query_public_addr::<S>(bind_addr, server_info, handle, shared_key, encrypted_req)
        }
        Protocol::Udp => {
            udp_query_public_addr::<S>(bind_addr, server_info, handle, shared_key, encrypted_req)
        }
    }
}

quick_error! {
    /// Error indicating failure to retrieve our public address.
    #[derive(Debug)]
    pub enum QueryPublicAddrError {
        /// Failed to bind to socket before even starting a query.
        Bind(e: io::Error) {
            description("error binding to socket address")
            display("error binding to socket address: {}", e)
            cause(e)
        }
        /// Connection failure.
        Connect(e: io::Error) {
            description("error connecting to echo server")
            display("error connecting to echo server: {}", e)
            cause(e)
        }
        /// Query timed out.
        ConnectTimeout {
            description("timed out contacting server")
        }
        /// Error sending query.
        SendRequest(e: io::Error) {
            description("error sending request to echo server")
            display("error sending request to echo server: {}", e)
            cause(e)
        }
        /// Error receiving query.
        ReadResponse(e: io::Error) {
            description("error reading response from echo server")
            display("error reading response from echo server: {}", e)
            cause(e)
        }
        /// Respone timed out.
        ResponseTimeout {
            description("timed out waiting for response from echo server")
        }
        /// Failure to decrypt request.
        Decrypt(e: DecryptError) {
            description("Error decrypting message")
            display("Error decrypting message: {}", e)
            cause(e)
        }
    }
}

/// Queries our public IP.
pub fn tcp_query_public_addr<S: SecretId>(
    bind_addr: &SocketAddr,
    server_info: &PeerInfo<S::Public>,
    handle: &Handle,
    shared_key: S::SharedSecret,
    encrypted_req: BytesMut,
) -> BoxFuture<SocketAddr, QueryPublicAddrError> {
    let bind_addr = *bind_addr;
    let server_addr = server_info.addr;
    let handle = handle.clone();

    TcpStream::connect_reusable(&bind_addr, &server_addr, &handle)
        // TODO(povilas): use QueryPublicAddrError::from(ConnectReusableError)
        .map_err(|err| match err {
            ConnectReusableError::Connect(e) => QueryPublicAddrError::Connect(e),
            ConnectReusableError::Bind(e) => QueryPublicAddrError::Bind(e),
        })
        .with_timeout(Duration::from_secs(3), &handle)
        .and_then(|opt| opt.ok_or(QueryPublicAddrError::ConnectTimeout))
        .map(|stream| length_delimited::Builder::new().new_framed(stream))
        .and_then(move |stream| {
            stream.send(encrypted_req).map_err(
                QueryPublicAddrError::SendRequest,
            )
        })
        .and_then(move |stream| tcp_recv_echo_addr(&handle, stream, shared_key))
        .into_boxed()
}

fn tcp_recv_echo_addr<K: SharedSecretKey>(
    handle: &Handle,
    stream: Framed<TcpStream>,
    shared_key: K,
) -> BoxFuture<SocketAddr, QueryPublicAddrError> {
    stream
        .into_future()
        .map_err(|(err, _stream)| QueryPublicAddrError::ReadResponse(err))
        .and_then(|(resp_opt, _stream)| {
            resp_opt.ok_or_else(|| {
                QueryPublicAddrError::ReadResponse(io::ErrorKind::ConnectionReset.into())
            })
        })
        .and_then(move |resp| {
            shared_key
                .decrypt(&resp)
                .map_err(QueryPublicAddrError::Decrypt)
        })
        .with_timeout(Duration::from_secs(2), handle)
        .and_then(|opt| opt.ok_or(QueryPublicAddrError::ResponseTimeout))
        .into_boxed()
}

pub fn udp_query_public_addr<S: SecretId>(
    bind_addr: &SocketAddr,
    server_info: &PeerInfo<S::Public>,
    handle: &Handle,
    shared_key: S::SharedSecret,
    encrypted_req: BytesMut,
) -> BoxFuture<SocketAddr, QueryPublicAddrError> {
    let server_addr = server_info.addr;
    let socket = try_bfut!(
        UdpSocket::bind_connect_reusable(bind_addr, &server_addr, handle)
            .map_err(QueryPublicAddrError::Bind)
    );

    let mut timeout = Timeout::new(Duration::new(0, 0), handle);
    future::poll_fn(move || {
        while let Async::Ready(()) = timeout.poll().void_unwrap() {
            match socket.send(&encrypted_req[..]) {
                Ok(n) => {
                    let len = encrypted_req.len();
                    if len != n {
                        let e = io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "failed to send complete request. \
                                 Sent {} bytes of {}",
                                len, n
                            ),
                        );
                        return Err(QueryPublicAddrError::SendRequest(e));
                    }
                    timeout.reset(Instant::now() + Duration::from_millis(500));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => return Err(QueryPublicAddrError::SendRequest(e)),
            }
        }

        loop {
            let mut buffer = [0u8; 256];
            match socket.recv_from(&mut buffer) {
                Ok((len, recv_addr)) => {
                    if recv_addr != server_addr {
                        continue;
                    }
                    trace!("server responded with: {:?}", &buffer[..len]);
                    let external_addr = shared_key
                        .decrypt(&buffer[..len])
                        .map_err(QueryPublicAddrError::Decrypt)?;
                    return Ok(Async::Ready(external_addr));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break Ok(Async::NotReady);
                }
                Err(e) => return Err(QueryPublicAddrError::ReadResponse(e)),
            }
        }
    }).with_timeout(Duration::from_secs(3), handle)
        .and_then(|opt| opt.ok_or(QueryPublicAddrError::ResponseTimeout))
        .into_boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::P2pSecretId;
    use maidsafe_utilities::serialisation::deserialise;
    use tokio_core::reactor::Core;

    mod p2p {
        use super::*;

        mod default {
            use super::*;

            #[test]
            fn it_creates_mapping_context_with_igd_enabled() {
                let p2p = P2p::<P2pSecretId>::default();

                assert!(p2p.is_igd_enabled())
            }

            #[test]
            fn it_creates_mapping_context_with_igd_enabled_for_rendezvous() {
                let p2p = P2p::<P2pSecretId>::default();

                assert!(p2p.is_igd_enabled_for_rendezvous())
            }

            #[test]
            fn it_creates_mapping_context_with_force_use_local_port_disabled() {
                let p2p = P2p::<P2pSecretId>::default();

                assert!(!p2p.force_use_local_port())
            }
        }

        mod tcp_traversal_servers {
            use super::*;

            #[test]
            fn it_returns_current_tcp_traversal_servers() {
                let p2p = P2p::<P2pSecretId>::default();

                p2p.add_tcp_traversal_server(&peer_addr!("1.2.3.4:4000"));
                p2p.add_tcp_traversal_server(&peer_addr!("1.2.3.5:5000"));

                let addrs = p2p.tcp_traversal_servers().addrs_snapshot();
                assert!(addrs.contains(&addr!("1.2.3.4:4000")));
                assert!(addrs.contains(&addr!("1.2.3.5:5000")));
            }
        }

        mod remove_tcp_traversal_server {
            use super::*;

            #[test]
            fn it_removes_given_server_from_the_list_if_it_exists() {
                let p2p = P2p::<P2pSecretId>::default();
                p2p.add_tcp_traversal_server(&peer_addr!("1.2.3.4:4000"));
                p2p.add_tcp_traversal_server(&peer_addr!("1.2.3.5:5000"));

                p2p.remove_tcp_traversal_server(addr!("1.2.3.4:4000"));

                let addrs = p2p.tcp_traversal_servers().addrs_snapshot();
                assert!(addrs.contains(&addr!("1.2.3.5:5000")));
                assert!(!addrs.contains(&addr!("1.2.3.4:4000")));
            }

            #[test]
            fn it_does_nothing_if_give_address_is_not_in_the_list() {
                let p2p = P2p::<P2pSecretId>::default();
                p2p.add_tcp_traversal_server(&peer_addr!("1.2.3.5:5000"));

                p2p.remove_tcp_traversal_server(addr!("1.2.3.4:4000"));

                let addrs = p2p.tcp_traversal_servers().addrs_snapshot();
                assert!(addrs.contains(&addr!("1.2.3.5:5000")));
            }
        }
    }

    mod query_public_addr {
        use super::*;
        use bytes::buf::FromBuf;
        use crypto::{P2pPublicId, P2pSecretId};

        #[test]
        fn when_protocol_is_tcp_it_sends_encrypted_echo_address_request() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();
            let listener = unwrap!(TcpListener::bind(&addr!("0.0.0.0:0"), &handle));
            let server_addr = unwrap!(listener.local_addr()).unspecified_to_localhost();
            let incoming = listener.incoming();

            let server_info = PeerInfo::<P2pPublicId>::with_rand_key::<P2pSecretId>(server_addr);
            let query = query_public_addr::<P2pSecretId>(
                Protocol::Tcp,
                &addr!("0.0.0.0:0"),
                &server_info,
                &handle,
            ).then(|_| Ok(()));

            let make_query = incoming.into_future()
                .map_err(|e| panic!(e))
                .map(|(client_opt, _incoming)| {
                    unwrap!(client_opt, "Failed to receive client connection")
                })
                .map(|(client_stream, _addr)| {
                    length_delimited::Builder::new().new_framed(client_stream)
                })
                .and_then(|client_stream: Framed<TcpStream>| {
                    client_stream.into_future()
                        .map(|(request_opt, _stream)| {
                            unwrap!(request_opt, "Failed to receive data from client connection")
                        })
                        .and_then(|request| {
                            Ok(request)
                        })
                })
                // When server is running, let's make a query.
                .join(query)
                .map(|(request, _response)| request);

            let request = unwrap!(evloop.run(make_query));
            let request: Result<EncryptedRequest<P2pPublicId>, _> = deserialise(&request);
            assert!(request.is_err());
        }

        #[test]
        fn when_protocol_is_udp_it_sends_encrypted_echo_address_request() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();

            let listener = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));
            let server_addr = unwrap!(listener.local_addr()).unspecified_to_localhost();

            let server_info = PeerInfo::<P2pPublicId>::with_rand_key::<P2pSecretId>(server_addr);
            let query = query_public_addr::<P2pSecretId>(
                Protocol::Udp,
                &addr!("0.0.0.0:0"),
                &server_info,
                &handle,
            ).then(|_| Ok(()));

            let make_query = listener.recv_dgram(vec![0u8; 256])
                .map_err(|e| panic!(e))
                .map(move |(_socket, data, len, _addr)| BytesMut::from_buf(&data[..len]))
                // When server is running, let's make a query.
                .join(query)
                .map(|(request, _response)| request);

            let request = unwrap!(evloop.run(make_query));
            let request: Result<EncryptedRequest<P2pPublicId>, _> = deserialise(&request);
            assert!(request.is_err());
        }
    }
}
