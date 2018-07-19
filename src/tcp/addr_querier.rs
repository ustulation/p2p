use priv_prelude::*;
use tokio_io::codec::length_delimited::Framed;

#[derive(Debug, Clone, Hash)]
/// A remote `TcpRendezvousServer` that we can query for our external address.
pub struct RemoteTcpRendezvousServer {
    addr: SocketAddr,
    pub_key: PublicKeys,
}

impl RemoteTcpRendezvousServer {
    /// Define a new remote server.
    pub fn new(addr: SocketAddr, pub_key: PublicKeys) -> RemoteTcpRendezvousServer {
        RemoteTcpRendezvousServer { addr, pub_key }
    }
}

impl TcpAddrQuerier for RemoteTcpRendezvousServer {
    #[allow(trivial_casts)] // needed for as Box<Error>
    fn query(&self, bind_addr: &SocketAddr, handle: &Handle) -> BoxFuture<SocketAddr, Box<Error>> {
        let server_pk = self.pub_key.clone();
        let handle = handle.clone();

        TcpStream::connect_reusable(bind_addr, &self.addr, &handle)
            .with_timeout(Duration::from_secs(3), &handle)
            .map_err(|e| match e {
                ConnectReusableError::Bind(e) => QueryPublicAddrError::Bind(e),
                ConnectReusableError::Connect(e) => QueryPublicAddrError::Connect(e),
            })
            .and_then(move |stream_opt| {
                let stream = try_bfut!(stream_opt.ok_or(QueryPublicAddrError::ConnectTimeout));
                let client_sk = SecretKeys::new();
                let client_pk = client_sk.public_keys().clone();
                let msg = EchoRequest { client_pk };
                let msg = try_bfut!(
                    server_pk
                        .encrypt_anonymous(&msg)
                        .map_err(QueryPublicAddrError::Encrypt)
                );
                let framed = Framed::new(stream);

                framed
                    .send(msg)
                    .map_err(QueryPublicAddrError::SendRequest)
                    .and_then(move |framed| {
                        framed
                            .with_timeout(Duration::from_secs(2), &handle)
                            .into_future()
                            .map_err(|(e, _framed)| QueryPublicAddrError::ReadResponse(e))
                            .and_then(move |(msg_opt, _framed)| {
                                let msg = msg_opt.ok_or(QueryPublicAddrError::ResponseTimeout)?;
                                let shared_secret = client_sk.shared_secret(&server_pk);

                                shared_secret
                                    .decrypt(&msg)
                                    .map_err(QueryPublicAddrError::Decrypt)
                            })
                    })
                    .into_boxed()
            })
            .map_err(|e| Box::new(e) as Box<Error>)
            .into_boxed()
    }
}
