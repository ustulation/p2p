use bincode::{self, Infinite};
use bytes::BufMut;
use filter_addrs::filter_addrs;
use priv_prelude::*;
use rendezvous_addr::{rendezvous_addr, RendezvousAddrError};
use rust_sodium::crypto::box_::{PublicKey, SecretKey};
use secure_serialisation::{deserialise as secure_deserialise, serialise as secure_serialise,
                           Error as SecureSerialiseError};
use std::error::Error;
use tcp::builder::TcpBuilderExt;
use tcp::msg::TcpRendezvousMsg;
use tokio_io;

const RENDEZVOUS_TIMEOUT_SEC: u64 = 10;
const RENDEZVOUS_INFO_EXCHANGE_TIMEOUT_SEC: u64 = 120;

/// Final connection handshake message.
/// One peer reads incoming stream and waits for this message, while the other sends this
/// message indicating wish to connect.
const CHOOSE: &[u8] = b"choose";

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
    /// Failure to deserialize message received from rendezvous connection info exchange channel.
    DeserializeMsg(bincode::Error),
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
            DeserializeMsg(ref e) => {
                write!(f, "error: {}", e)?;
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
            DeserializeMsg(..) => "error deserializing rendezvous message",
            AllAttemptsFailed(..) => "all attempts to connect to the remote host failed",
        }
    }

    fn cause(&self) -> Option<&Error> {
        use TcpRendezvousConnectError::*;
        match *self {
            Bind(ref e) | IfAddrs(ref e) => Some(e),
            ChannelRead(ref e) => Some(e),
            ChannelWrite(ref e) => Some(e),
            DeserializeMsg(ref e) => Some(e),
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
        Decrypt(e: SecureSerialiseError) {
            description("error decrypting data")
            display("error decrypting data: {:?}", e)
            // TODO(povilas): implement cause() when secure_serialisation::Error implements Error
            // trait.
        }
        Encrypt(e: SecureSerialiseError) {
            description("error decrypting data")
            display("error decrypting data: {:?}", e)
            // TODO(povilas): implement cause() when secure_serialisation::Error implements Error
            // trait.
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
        let (our_pk, our_sk) = crypto::box_::gen_keypair();

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
                        Ok(addr) => Ok((Some(addr), None)),
                        Err(e) => Ok((None, Some(e))),
                    })
                    .and_then(move |(rendezvous_addr_opt, map_error)| {
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

                            let connectors = {
                                their_addrs
                                    .into_iter()
                                    .map(|addr| {
                                        TcpStream::connect_reusable(&bind_addr, &addr, &handle0)
                                            .map_err(SingleRendezvousAttemptError::Connect)
                                    })
                                    .collect::<Vec<_>>()
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
                            choose_connections(all_incoming, our_pk, their_pk, our_sk)
                                .first_ok()
                                .map_err(|v| {
                                    TcpRendezvousConnectError::AllAttemptsFailed(v, map_error)
                                })
                                .into_boxed()
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
    let msg = unwrap!(bincode::serialize(&msg, Infinite));
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
                )
                .and_then(|opt| opt.ok_or(TcpRendezvousConnectError::ChannelTimedOut))
                .and_then(|(msg, _channel)| {
                    bincode::deserialize(&msg).map_err(TcpRendezvousConnectError::DeserializeMsg)
                })
        })
        .into_boxed()
}

/// Finalizes rendezvous connection with sending special message 'choose'.
/// Only one peer sends this message while the other receives and validates it. Who is who is
/// determined by public keys.
fn choose_connections(
    all_incoming: BoxStream<TcpStream, SingleRendezvousAttemptError>,
    our_pk: PublicKey,
    their_pk: PublicKey,
    our_sk: SecretKey,
) -> BoxStream<TcpStream, SingleRendezvousAttemptError> {
    let encrypted_msg = match secure_serialise(&CHOOSE, &their_pk, &our_sk) {
        Ok(msg) => msg,
        Err(e) => {
            return stream::iter_result(vec![Err(SingleRendezvousAttemptError::Encrypt(e))])
                .into_boxed()
        }
    };

    if our_pk > their_pk {
        all_incoming
            .and_then(move |stream| {
                tokio_io::io::write_all(stream, encrypted_msg.clone())
                    .map_err(SingleRendezvousAttemptError::Write)
                    .map(|(stream, _buf)| stream)
            })
            .into_boxed()
    } else {
        all_incoming
            .and_then(move |stream| {
                recv_choose_conn_msg(stream, encrypted_msg.len(), their_pk, our_sk.clone())
            })
            .filter_map(|stream_opt| stream_opt)
            .into_boxed()
    }
}

/// Receives incoming data stream and check's if it's connection choose message.
/// If it is, returns the stream. Otherwise None is returned.
fn recv_choose_conn_msg(
    stream: TcpStream,
    expected_msg_len: usize,
    their_pk: PublicKey,
    our_sk: SecretKey,
) -> BoxFuture<Option<TcpStream>, SingleRendezvousAttemptError> {
    tokio_io::io::read_exact(stream, buffer_with_len(expected_msg_len))
        .map_err(SingleRendezvousAttemptError::Read)
        .and_then(move |(stream, buf)| {
            secure_deserialise::<Vec<u8>>(&buf[..], &their_pk, &our_sk)
                .map_err(SingleRendezvousAttemptError::Decrypt)
                .map(|buf| (stream, buf))
        })
        .map(|(stream, buf)| only_chosen_connection(stream, &buf[..]))
        .into_boxed()
}

/// Returns given stream, if received "choose connection" message. Otherwise `None` is returned.
fn only_chosen_connection<T>(stream: T, buf: &[u8]) -> Option<T> {
    if buf == CHOOSE {
        Some(stream)
    } else {
        None
    }
}

/// Contructs empty mutable buffer with given size that is ready to receive data.
fn buffer_with_len(len: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(len);
    buf.put(vec![0; len]);
    buf
}

pub struct TcpRendezvousConnect<C>
where
    C: Stream<Item = Bytes>,
    C: Sink<SinkItem = Bytes>,
    C: 'static,
{
    inner: BoxFuture<TcpStream, TcpRendezvousConnectError<C::Error, C::SinkError>>,
}

impl<C> Future for TcpRendezvousConnect<C>
where
    C: Stream<Item = Bytes>,
    C: Sink<SinkItem = Bytes>,
    C: 'static,
{
    type Item = TcpStream;
    type Error = TcpRendezvousConnectError<C::Error, C::SinkError>;

    fn poll(
        &mut self,
    ) -> Result<Async<TcpStream>, TcpRendezvousConnectError<C::Error, C::SinkError>> {
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

    mod buffer_with_len {
        use super::*;

        #[test]
        fn it_returns_buffer_with_given_length() {
            let buf = buffer_with_len(8);

            assert_eq!(buf.len(), 8);
        }
    }

    mod only_chosen_connection {
        use super::*;

        #[test]
        fn when_received_message_is_not_choose_connection_it_returns_none() {
            let conn = only_chosen_connection("conn1", b"some random data");

            assert_eq!(conn, None);
        }

        #[test]
        fn when_received_message_is_choose_connection_it_returns_given_connection() {
            let conn = only_chosen_connection("conn1", CHOOSE);

            assert_eq!(conn, Some("conn1"));
        }
    }

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
                    .and_then(|stream| tokio_io::io::write_all(stream, b"hello"))
                    .map_err(|e| panic!("writing failed: {:?}", e))
                    .map(|_| ())
            };

            let f1 = {
                TcpStream::rendezvous_connect(ch1, &handle, &mc1)
                    .map_err(|e| panic!("connect failed: {:?}", e))
                    .and_then(|stream| tokio_io::io::read_to_end(stream, Vec::new()))
                    .map_err(|e| panic!("reading failed: {:?}", e))
                    .map(|(_, data)| assert_eq!(data, b"hello"))
            };

            f0.join(f1).map(|((), ())| ())
        });
        unwrap!(result)
    }
}
