use filter_addrs::filter_addrs;
use maidsafe_utilities::serialisation;
use priv_prelude::*;
use rendezvous_addr::{rendezvous_addr, RendezvousAddrError};
use std::error::Error;
use tcp::builder::TcpBuilderExt;
use tcp::msg::TcpRendezvousMsg;

const RENDEZVOUS_TIMEOUT_SEC: u64 = 10;
const RENDEZVOUS_INFO_EXCHANGE_TIMEOUT_SEC: u64 = 120;

quick_error! {
    /// Errors returned by `TcpStreamExt::connect_reusable`.
    #[derive(Debug)]
    pub enum ConnectReusableError {
        /// Failure to bind socket to address.
        Bind(e: io::Error) {
            description("error binding to port")
            display("error binding to port: {}", e)
            cause(e)
        }
        /// Connection failure.
        Connect(e: io::Error) {
            description("error connecting")
            display("error connecting: {}", e)
            cause(e)
        }
    }
}

/// Errors returned by `TcpStreamExt::rendezvous_connect`.
#[derive(Debug)]
pub enum TcpRendezvousConnectError<Ei, Eo> {
    /// Failure to bind socket to some address.
    Bind(io::Error),
    /// Failure to get socket bind addresses.
    IfAddrs(io::Error),
    /// Rendezvous connection info exchange channel was closed.
    ChannelClosed,
    /// Rendezvous connection info exchange timed out.
    ChannelTimedOut,
    /// Failure to read from rendezvous connection info exchange channel.
    ChannelRead(Ei),
    /// Failure to write to rendezvous connection info exchange channel.
    ChannelWrite(Eo),
    /// Failure to serialize message sent via rendezvous channel
    SerializeMsg(SerialisationError),
    /// Failure to deserialize  message received via rendezvous channel
    DeserializeMsg(SerialisationError),
    /// Failure to encrypt message
    Encrypt(EncryptionError),
    /// Failure to decrypt message from remote peer
    Decrypt(EncryptionError),
    /// Used when all rendezvous connection attempts failed.
    AllAttemptsFailed(
        Vec<SingleRendezvousAttemptError>,
        Option<RendezvousAddrError>,
    ),
}

impl<Ei, Eo> fmt::Display for TcpRendezvousConnectError<Ei, Eo>
where
    Ei: Error,
    Eo: Error,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TcpRendezvousConnectError::*;
        write!(f, "{}. ", self.description())?;
        match *self {
            Bind(ref e) | IfAddrs(ref e) => {
                write!(f, "IO error: {}", e)?;
            }
            ChannelClosed | ChannelTimedOut => (),
            ChannelRead(ref e) => {
                write!(f, "channel error: {}", e)?;
            }
            ChannelWrite(ref e) => {
                write!(f, "channel error: {}", e)?;
            }
            SerializeMsg(ref e) => {
                write!(f, "error serializing message: {}", e)?;
            }
            DeserializeMsg(ref e) => {
                write!(f, "error deserializing message: {}", e)?;
            }
            Encrypt(ref e) => {
                write!(f, "error encrypting message: {}", e)?;
            }
            Decrypt(ref e) => {
                write!(f, "error decrypting message: {}", e)?;
            }
            AllAttemptsFailed(ref attempt_errors, ref map_error) => {
                if let Some(ref map_error) = *map_error {
                    write!(
                        f,
                        "Rendezvous address creation failed with error: {}. ",
                        map_error
                    )?;
                }
                write!(
                    f,
                    "All {} connection attempts failed with errors: {:#?}",
                    attempt_errors.len(),
                    attempt_errors
                )?;
            }
        }
        Ok(())
    }
}

impl<Ei, Eo> Error for TcpRendezvousConnectError<Ei, Eo>
where
    Ei: Error,
    Eo: Error,
{
    fn description(&self) -> &'static str {
        use TcpRendezvousConnectError::*;
        match *self {
            Bind(..) => "error binding to local address",
            IfAddrs(..) => "error getting network interface addresses",
            ChannelClosed => "rendezvous channel closed unexpectedly",
            ChannelTimedOut => "timed out waiting for message via rendezvous channel",
            ChannelRead(..) => "error reading from rendezvous channel",
            ChannelWrite(..) => "error writing to rendezvous channel",
            SerializeMsg(..) => "error serializing rendezvous message",
            DeserializeMsg(..) => "error deserializing rendezvous message",
            Encrypt(..) => "error encrypting message to send to remote peer",
            Decrypt(..) => "error decrypting message received from remote peer",
            AllAttemptsFailed(..) => "all attempts to connect to the remote host failed",
        }
    }

    fn cause(&self) -> Option<&Error> {
        use TcpRendezvousConnectError::*;
        match *self {
            Bind(ref e) | IfAddrs(ref e) => Some(e),
            ChannelRead(ref e) => Some(e),
            ChannelWrite(ref e) => Some(e),
            SerializeMsg(ref e) => Some(e),
            DeserializeMsg(ref e) => Some(e),
            Encrypt(ref e) => Some(e),
            Decrypt(ref e) => Some(e),
            ChannelClosed | ChannelTimedOut | AllAttemptsFailed(..) => None,
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum SingleRendezvousAttemptError {
        Connect(e: ConnectReusableError) {
            description("error performing reusable connect")
            display("error performing reusable connect: {}", e)
            cause(e)
        }
        Accept(e: io::Error) {
            description("error accepting incoming stream")
            display("error accepting incoming stream: {}", e)
            cause(e)
        }
        Write(e: io::Error) {
            description("error writing handshake to connection candidate socket")
            display("error writing handshake to connection candidate socket: {}", e)
            cause(e)
        }
        Read(e: io::Error) {
            description("error reading handshake on connection candidate socket")
            display("error reading handshake on connection candidate socket: {}", e)
            cause(e)
        }
        Decrypt(e: EncryptionError) {
            description("error decrypting data")
            display("error decrypting data: {:?}", e)
            cause(e)
        }
        Encrypt(e: SerialisationError) {
            description("error decrypting data")
            display("error decrypting data: {:?}", e)
            cause(e)
        }
    }
}

/// Extension methods for `TcpStream`.
pub trait TcpStreamExt {
    /// Connect to `addr` using a reusably-bound socket, bound to `bind_addr`. This can be used to
    /// create multiple TCP connections with the same local address, or with the same local address
    /// as a reusably-bound `TcpListener`.
    fn connect_reusable(
        bind_addr: &SocketAddr,
        addr: &SocketAddr,
        handle: &Handle,
    ) -> BoxFuture<TcpStream, ConnectReusableError>;

    /// Perform a TCP rendezvous connect. Both peers must call this method simultaneously in order
    /// to form one TCP connection, connected from both ends. `channel` must provide a channel
    /// through which the two connecting peers can communicate with each other out-of-band while
    /// negotiating the connection.
    fn rendezvous_connect<C>(channel: C, handle: &Handle, mc: &P2p) -> TcpRendezvousConnect<C>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static;
}

impl TcpStreamExt for TcpStream {
    fn connect_reusable(
        bind_addr: &SocketAddr,
        addr: &SocketAddr,
        handle: &Handle,
    ) -> BoxFuture<TcpStream, ConnectReusableError> {
        let try = || {
            let builder =
                { TcpBuilder::bind_reusable(bind_addr).map_err(ConnectReusableError::Bind)? };
            let stream = unwrap!(builder.to_tcp_stream());
            Ok({
                TcpStream::connect_stream(stream, addr, handle)
                    .map_err(ConnectReusableError::Connect)
            })
        };

        future::result(try()).flatten().into_boxed()
    }

    fn rendezvous_connect<C>(channel: C, handle: &Handle, mc: &P2p) -> TcpRendezvousConnect<C>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static,
    {
        // TODO(canndrew): In the current implementation, we send all data in the first message
        // along the channel. This is because we can't (currently) rely on routing to forward
        // anything other than the first message to the other peer.

        let handle0 = handle.clone();
        let (our_pk, our_sk) = gen_encrypt_keypair();

        let try = || {
            trace!("starting tcp rendezvous connect");
            let listener = {
                TcpListener::bind_reusable(&addr!("0.0.0.0:0"), &handle0)
                    .map_err(TcpRendezvousConnectError::Bind)
            }?;
            let bind_addr = {
                listener
                    .local_addr()
                    .map_err(TcpRendezvousConnectError::Bind)?
            };

            let addrs = {
                listener
                    .expanded_local_addrs()
                    .map_err(TcpRendezvousConnectError::IfAddrs)?
            };
            let our_addrs = addrs.iter().cloned().collect();

            Ok({
                trace!("getting rendezvous address");
                rendezvous_addr(Protocol::Tcp, &bind_addr, &handle0, mc)
                    .then(|res| match res {
                        Ok((addr, _nat_type)) => Ok((Some(addr), None)),
                        Err(e) => Ok((None, Some(e))),
                    }).and_then(move |(rendezvous_addr_opt, map_error)| {
                        trace!("got rendezvous address: {:?}", rendezvous_addr_opt);
                        let msg = TcpRendezvousMsg::Init {
                            enc_pk: our_pk,
                            open_addrs: addrs,
                            rendezvous_addr: rendezvous_addr_opt,
                        };

                        trace!("exchanging rendezvous info with peer");

                        exchange_conn_info(channel, &handle0, &msg).and_then(move |msg| {
                            let TcpRendezvousMsg::Init {
                                enc_pk: their_pk,
                                open_addrs,
                                rendezvous_addr,
                            } = msg;

                            // filter our subnet and loopback addresess if they can't possibly be
                            // useful.
                            let their_addrs = open_addrs.into_iter().collect();
                            let mut their_addrs = filter_addrs(&our_addrs, &their_addrs);
                            if let Some(rendezvous_addr) = rendezvous_addr {
                                let _ = their_addrs.insert(rendezvous_addr);
                            }

                            trace!("their_addrs == {:?}", their_addrs);

                            let connectors = {
                                their_addrs
                                    .into_iter()
                                    .map(|addr| {
                                        TcpStream::connect_reusable(&bind_addr, &addr, &handle0)
                                            .map_err(SingleRendezvousAttemptError::Connect)
                                    }).collect::<Vec<_>>()
                            };
                            let incoming = {
                                listener
                                    .incoming()
                                    .map(|(stream, _addr)| stream)
                                    .map_err(SingleRendezvousAttemptError::Accept)
                                    .until({
                                        Timeout::new(
                                            Duration::from_secs(RENDEZVOUS_TIMEOUT_SEC),
                                            &handle0,
                                        ).infallible()
                                    })
                            };
                            let all_incoming = stream::futures_unordered(connectors)
                                .select(incoming)
                                .into_boxed();
                            choose_connections(all_incoming, &their_pk, &our_sk, &our_pk, map_error)
                                .map(move |tcp_stream| (tcp_stream, rendezvous_addr_opt))
                        })
                    })
            })
        };

        TcpRendezvousConnect {
            inner: future::result(try()).flatten().into_boxed(),
        }
    }
}

fn exchange_conn_info<C>(
    channel: C,
    handle: &Handle,
    msg: &TcpRendezvousMsg,
) -> BoxFuture<TcpRendezvousMsg, TcpRendezvousConnectError<C::Error, C::SinkError>>
where
    C: Stream<Item = Bytes>,
    C: Sink<SinkItem = Bytes>,
    <C as Stream>::Error: fmt::Debug,
    <C as Sink>::SinkError: fmt::Debug,
    C: 'static,
{
    let handle = handle.clone();
    let msg =
        try_bfut!(serialisation::serialise(&msg).map_err(TcpRendezvousConnectError::SerializeMsg));
    let msg = Bytes::from(msg);
    channel
        .send(msg)
        .map_err(TcpRendezvousConnectError::ChannelWrite)
        .and_then(move |channel| {
            channel
                .map_err(TcpRendezvousConnectError::ChannelRead)
                .next_or_else(|| TcpRendezvousConnectError::ChannelClosed)
                .with_timeout(
                    Duration::from_secs(RENDEZVOUS_INFO_EXCHANGE_TIMEOUT_SEC),
                    &handle,
                ).and_then(|opt| opt.ok_or(TcpRendezvousConnectError::ChannelTimedOut))
                .and_then(|(msg, _channel)| {
                    serialisation::deserialise(&msg)
                        .map_err(TcpRendezvousConnectError::DeserializeMsg)
                })
        }).into_boxed()
}

#[derive(Debug, Serialize, Deserialize)]
struct ChooseMessage;

/// Finalizes rendezvous connection with sending special message 'choose'.
/// Only one peer sends this message while the other receives and validates it. Who is who is
/// determined by public keys.
fn choose_connections<Ei: 'static, Eo: 'static>(
    all_incoming: BoxStream<TcpStream, SingleRendezvousAttemptError>,
    their_pk: &PublicEncryptKey,
    our_sk: &SecretEncryptKey,
    our_pk: &PublicEncryptKey,
    map_error: Option<RendezvousAddrError>,
) -> BoxFuture<TcpStream, TcpRendezvousConnectError<Ei, Eo>> {
    let shared_secret = our_sk.shared_secret(&their_pk);
    let encrypted_msg = try_bfut!(
        shared_secret
            .encrypt(&ChooseMessage)
            .map_err(TcpRendezvousConnectError::Encrypt)
    );

    if our_pk > their_pk {
        all_incoming
            .and_then(move |stream| {
                trace!(
                    "sending choose from {:?} to {:?}",
                    stream.local_addr(),
                    stream.peer_addr()
                );
                let framed = FramedUnbuffered::new(stream);
                let encrypted_msg = Bytes::from(&encrypted_msg[..]);
                framed
                    .send(encrypted_msg.clone())
                    .map_err(SingleRendezvousAttemptError::Write)
                    .map(|framed| unwrap!(framed.into_inner()))
            }).into_boxed()
    } else {
        all_incoming
            .and_then(move |stream| {
                trace!(
                    "trying to receive choose on {:?} from {:?}",
                    stream.local_addr(),
                    stream.peer_addr()
                );
                let framed = FramedUnbuffered::new(stream);
                recv_choose_conn_msg(framed, shared_secret.clone())
            }).filter_map(|stream_opt| stream_opt)
            .into_boxed()
    }.first_ok()
    .map_err(|v| TcpRendezvousConnectError::AllAttemptsFailed(v, map_error))
    .into_boxed()
}

/// Receives incoming data stream and check's if it's connection choose message.
/// If it is, returns the stream. Otherwise None is returned.
fn recv_choose_conn_msg(
    framed: FramedUnbuffered<TcpStream>,
    shared_secret: SharedSecretKey,
) -> BoxFuture<Option<TcpStream>, SingleRendezvousAttemptError> {
    framed
        .into_future()
        .map_err(|(e, _framed)| SingleRendezvousAttemptError::Read(e))
        .and_then(move |(msg_opt, framed)| {
            let msg = match msg_opt {
                Some(msg) => msg,
                None => return future::ok(None).into_boxed(),
            };
            let _decrypted_msg: ChooseMessage = try_bfut!(
                shared_secret
                    .decrypt(&msg)
                    .map_err(SingleRendezvousAttemptError::Decrypt)
            );
            future::ok(Some(unwrap!(framed.into_inner()))).into_boxed()
        }).into_boxed()
}

type RendezvousConnectResult = (TcpStream, Option<SocketAddr>);

/// Future that yields `TcpStream` and our public address, if one was detected.
pub struct TcpRendezvousConnect<C>
where
    C: Stream<Item = Bytes>,
    C: Sink<SinkItem = Bytes>,
    C: 'static,
{
    inner: BoxFuture<RendezvousConnectResult, TcpRendezvousConnectError<C::Error, C::SinkError>>,
}

impl<C> Future for TcpRendezvousConnect<C>
where
    C: Stream<Item = Bytes>,
    C: Sink<SinkItem = Bytes>,
    C: 'static,
{
    type Item = (TcpStream, Option<SocketAddr>);
    type Error = TcpRendezvousConnectError<C::Error, C::SinkError>;

    fn poll(
        &mut self,
    ) -> Result<Async<RendezvousConnectResult>, TcpRendezvousConnectError<C::Error, C::SinkError>>
    {
        self.inner.poll()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use env_logger;
    use tokio_core::reactor::Core;
    use tokio_io;
    use util;

    #[test]
    fn rendezvous_over_loopback() {
        let _ = env_logger::init();

        let (ch0, ch1) = util::two_way_channel();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();
        let mc0 = P2p::default();
        let mc1 = mc0.clone();

        let result = core.run({
            let f0 = {
                TcpStream::rendezvous_connect(ch0, &handle, &mc0)
                    .map_err(|e| panic!("connect failed: {:?}", e))
                    .and_then(|(stream, _our_pub_addr)| tokio_io::io::write_all(stream, b"hello"))
                    .map_err(|e| panic!("writing failed: {:?}", e))
                    .map(|_| ())
            };

            let f1 = {
                TcpStream::rendezvous_connect(ch1, &handle, &mc1)
                    .map_err(|e| panic!("connect failed: {:?}", e))
                    .and_then(|(stream, _our_pub_addr)| {
                        tokio_io::io::read_to_end(stream, Vec::new())
                    }).map_err(|e| panic!("reading failed: {:?}", e))
                    .map(|(_, data)| assert_eq!(data, b"hello"))
            };

            f0.join(f1).map(|((), ())| ())
        });
        unwrap!(result)
    }
}
