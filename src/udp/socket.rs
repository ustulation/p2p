use futures::future::Loop;
use futures::stream::FuturesUnordered;
use maidsafe_utilities::serialisation;
use open_addr::{open_addr, BindPublicError};
use priv_prelude::*;
use rendezvous_addr::{rendezvous_addr, RendezvousAddrError};
use std::error::Error;
use tokio_shared_udp_socket::{SharedUdpSocket, WithAddress};
use udp::msg::UdpRendezvousMsg;

const RENDEZVOUS_INFO_EXCHANGE_TIMEOUT_SEC: u64 = 120;
const HOLE_PUNCH_DELAY_TOLERANCE_SEC: u64 = 120;
const HOLE_PUNCH_INITIAL_TTL: u32 = 2;

/// Errors returned by `UdpSocketExt::rendezvous_connect`.
#[derive(Debug)]
pub enum UdpRendezvousConnectError<Ei, Eo> {
    /// Failure to bind socket to some address.
    Bind(io::Error),
    /// Failure to bind when generating multiple sockets for hole punching with different TTLs.
    Rebind(io::Error),
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
    /// Failure to send packets to the socket.
    SocketWrite(io::Error),
    /// Failure to set socket TTL.
    SetTtl(io::Error),
    /// Failure to serialize message to send via rendezvous channel
    SerializeMsg(SerialisationError),
    /// Failure to deserialize message received via rendezvous channel
    DeserializeMsg(SerialisationError),
    /// Failture to encrypt message to send to remote peer
    Encrypt(EncryptionError),
    /// Failture to decrypt message received from remote peer
    Decrypt(EncryptionError),
    /// Used when all rendezvous connection attempts failed.
    AllAttemptsFailed(Vec<HolePunchError>, Option<Box<RendezvousAddrError>>),
}

impl<Ei, Eo> fmt::Display for UdpRendezvousConnectError<Ei, Eo>
where
    Ei: Error,
    Eo: Error,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())?;
        if let UdpRendezvousConnectError::AllAttemptsFailed(ref v, ref rendezvous) = *self {
            if let Some(ref rendezvous) = *rendezvous {
                write!(
                    f,
                    "attempt to create rendezvous socket gave: {}. ",
                    rendezvous
                )?;
            }

            let num_errors = v.len();
            write!(f, "there were {} failed hole-punch attempts:", num_errors)?;
            for (i, error) in v.iter().enumerate() {
                write!(f, ". [{} of {}] {}", i, num_errors, error)?;
            }
        } else if let Some(error) = self.cause() {
            write!(f, ". {}", error)?;
        }
        Ok(())
    }
}

impl<Ei, Eo> Error for UdpRendezvousConnectError<Ei, Eo>
where
    Ei: Error,
    Eo: Error,
{
    fn cause(&self) -> Option<&Error> {
        use self::UdpRendezvousConnectError::*;

        match *self {
            Bind(ref e) | Rebind(ref e) | IfAddrs(ref e) | SocketWrite(ref e) | SetTtl(ref e) => {
                Some(e)
            }
            ChannelRead(ref e) => Some(e),
            ChannelWrite(ref e) => Some(e),
            SerializeMsg(ref e) => Some(e),
            DeserializeMsg(ref e) => Some(e),
            Encrypt(ref e) => Some(e),
            Decrypt(ref e) => Some(e),
            ChannelClosed | ChannelTimedOut | AllAttemptsFailed(..) => None,
        }
    }

    fn description(&self) -> &str {
        use self::UdpRendezvousConnectError::*;

        match *self {
            Bind(..) => "error binding to local port",
            Rebind(..) => "error rebinding to same reusably-bound port",
            IfAddrs(..) => "error getting network interface addresses",
            ChannelClosed => "rendezvous channel closed unexpectedly",
            ChannelRead(..) => "error reading from rendezvous channel",
            ChannelWrite(..) => "error writing to rendezvous channel",
            ChannelTimedOut => "timedout waiting for message via rendezvous channel",
            SocketWrite(..) => "error writing to socket",
            SetTtl(..) => "error setting ttl value on socket",
            SerializeMsg(..) => "error serializing message to send via rendezvous channel",
            DeserializeMsg(..) => "error deserializing message received via rendezvous channel",
            Encrypt(..) => "error encrypting message to send to remote peer",
            Decrypt(..) => "error decrypting message received from remote peer",
            AllAttemptsFailed(..) => "all attempts to contact the remote peer failed",
        }
    }
}

type RendezvousConnectResult = (UdpSocket, SocketAddr, Option<SocketAddr>);

/// Extension methods for `UdpSocket`.
pub trait UdpSocketExt {
    /// Bind reusably to the given address. This method can be used to create multiple UDP sockets
    /// bound to the same local address.
    fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<UdpSocket>;

    /// Bind reusably to the given address and connect to the remote address.
    fn bind_connect_reusable(
        addr: &SocketAddr,
        remote_addr: &SocketAddr,
        handle: &Handle,
    ) -> io::Result<UdpSocket>;

    /// Returns a list of local addresses this socket is bind to.
    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>>;

    /// Returns a `UdpSocket` bound to the given address along with a public `SocketAddr`
    /// that can be used to message the socket from across the internet.
    fn bind_public(
        addr: &SocketAddr,
        handle: &Handle,
        mc: &P2p,
    ) -> BoxFuture<(UdpSocket, SocketAddr), BindPublicError>;

    /// Perform a UDP rendezvous connection to another peer. Both peers must call this
    /// simultaneously and `channel` must provide a channel through which the peers can communicate
    /// out-of-band.
    ///
    /// # Returns
    ///
    /// A future that yields a tuple of
    /// 1. hole punched socket
    /// 2. remote peer address
    /// 3. our public address used to punch a hole, if one was detected
    fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        mc: &P2p,
    ) -> BoxFuture<RendezvousConnectResult, UdpRendezvousConnectError<C::Error, C::SinkError>>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static;

    /// Send a datagram to the address previously bound via connect().
    fn send_dgram_connected<T>(self, buf: T) -> BoxFuture<(UdpSocket, T), io::Error>
    where
        T: AsRef<[u8]> + 'static;
}

fn bind_reusable(addr: &SocketAddr) -> io::Result<::std::net::UdpSocket> {
    let socket = match addr.ip() {
        IpAddr::V4(..) => UdpBuilder::new_v4()?,
        IpAddr::V6(..) => UdpBuilder::new_v6()?,
    };
    let _ = socket.reuse_address(true)?;

    #[cfg(target_family = "unix")]
    {
        use net2::unix::UnixUdpBuilderExt;
        let _ = socket.reuse_port(true)?;
    }

    let socket = socket.bind(addr)?;
    Ok(socket)
}

impl UdpSocketExt for UdpSocket {
    fn bind_reusable(addr: &SocketAddr, handle: &Handle) -> io::Result<UdpSocket> {
        let socket = bind_reusable(addr)?;

        UdpSocket::from_socket(socket, handle)
    }

    fn bind_connect_reusable(
        addr: &SocketAddr,
        remote_addr: &SocketAddr,
        handle: &Handle,
    ) -> io::Result<UdpSocket> {
        let socket = bind_reusable(addr)?;
        socket.connect(remote_addr)?;

        UdpSocket::from_socket(socket, handle)
    }

    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let addr = self.local_addr()?;
        let addrs = addr.expand_local_unspecified()?;
        Ok(addrs)
    }

    fn bind_public(
        addr: &SocketAddr,
        handle: &Handle,
        mc: &P2p,
    ) -> BoxFuture<(UdpSocket, SocketAddr), BindPublicError> {
        bind_public_with_addr(addr, handle, mc)
            .map(|(socket, _bind_addr, public_addr)| (socket, public_addr))
            .into_boxed()
    }

    fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        mc: &P2p,
    ) -> BoxFuture<RendezvousConnectResult, UdpRendezvousConnectError<C::Error, C::SinkError>>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static,
    {
        let handle0 = handle.clone();
        let handle1 = handle.clone();
        let mc0 = mc.clone();
        let (our_pk, our_sk) = gen_encrypt_keypair();
        let our_sk0 = our_sk.clone();

        trace!("starting rendezvous connect");
        try_hole_punching(&handle0, &mc0, &our_sk0, &our_pk, channel)
            .and_then(
                move |(their_pk, incoming, our_public_addr_opt, rendezvous_error_opt)| {
                    let shared_secret = our_sk.shared_secret(&their_pk);
                    if our_pk > their_pk {
                        trace!("we are choosing the connection");
                        incoming
                            .and_then(|(socket, chosen)| {
                                if chosen {
                                    return Err(HolePunchError::UnexpectedMessage);
                                }
                                trace!("successful connection found!");
                                Ok(socket)
                            }).first_ok()
                            .map_err(|v| {
                                trace!("all attempts failed (us)");
                                UdpRendezvousConnectError::AllAttemptsFailed(
                                    v,
                                    rendezvous_error_opt.map(Box::new),
                                )
                            }).and_then(move |socket| {
                                choose(&handle1, shared_secret, socket, 0).map(
                                    move |(socket, their_addr)| {
                                        (socket, their_addr, our_public_addr_opt)
                                    },
                                )
                            }).into_boxed()
                    } else {
                        trace!("they are choosing the connection");
                        incoming
                            .map(move |(socket, chosen)| {
                                if chosen {
                                    return future::ok(got_chosen(socket)).into_boxed();
                                }
                                take_chosen(&handle1, shared_secret.clone(), socket)
                            }).buffer_unordered(256)
                            .filter_map(move |opt| {
                                opt.map(move |(socket, their_addr)| {
                                    (socket, their_addr, our_public_addr_opt)
                                })
                            }).first_ok()
                            .map_err(|v| {
                                trace!("all attempts failed (them)");
                                UdpRendezvousConnectError::AllAttemptsFailed(
                                    v,
                                    rendezvous_error_opt.map(Box::new),
                                )
                            }).into_boxed()
                    }
                },
            ).into_boxed()
    }

    /// Send a datagram to the address previously bound via connect().
    fn send_dgram_connected<T>(self, buf: T) -> BoxFuture<(UdpSocket, T), io::Error>
    where
        T: AsRef<[u8]> + 'static,
    {
        let mut stuff_opt = Some((self, buf));
        future::poll_fn(move || {
            let (this, buf) = unwrap!(stuff_opt.take());
            match this.send(buf.as_ref()) {
                Ok(n) => {
                    if n < buf.as_ref().len() {
                        Err(io::Error::new(
                            io::ErrorKind::Other,
                            "failed to write entire message to dgram",
                        ))
                    } else {
                        Ok(Async::Ready((this, buf)))
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    stuff_opt = Some((this, buf));
                    Ok(Async::NotReady)
                }
                Err(e) => Err(e),
            }
        }).into_boxed()
    }
}

type HolePunchingResult = (
    PublicEncryptKey,
    BoxStream<(WithAddress, bool), HolePunchError>,
    Option<SocketAddr>, // our public address, if one was found
    Option<RendezvousAddrError>,
);

/// Hole punching is attempted when we fail to receive a public address: either via IGD
/// or if we are behind a full cone NAT.
fn try_hole_punching<C>(
    handle: &Handle,
    p2p: &P2p,
    our_sk: &SecretEncryptKey,
    our_pk: &PublicEncryptKey,
    conn_info_channel: C,
) -> BoxFuture<HolePunchingResult, UdpRendezvousConnectError<C::Error, C::SinkError>>
where
    C: Stream<Item = Bytes>,
    C: Sink<SinkItem = Bytes>,
    <C as Stream>::Error: fmt::Debug,
    <C as Sink>::SinkError: fmt::Debug,
    C: 'static,
{
    let handle = handle.clone();
    let p2p = p2p.clone();
    let our_sk = our_sk.clone();
    let our_pk = *our_pk;

    hole_punching_sockets(&handle, &p2p)
        .and_then(move |(sockets, rendezvous_error_opt)| {
            let (sockets, rendezvous_addrs): (_, Vec<SocketAddr>) =
                sockets.into_iter().unzip::<_, _, Vec<_>, _>();
            trace!("our rendezvous addresses are: {:#?}", rendezvous_addrs);
            // All hole punching sockets should have the same rendezvous IP address, so we'll just
            // take the first one.
            let our_public_addr_opt = rendezvous_addrs.iter().cloned().nth(0);
            let msg = UdpRendezvousMsg::Init {
                enc_pk: our_pk,
                rendezvous_addrs,
            };

            trace!("exchanging rendezvous info with peer");
            exchange_msgs(&handle, conn_info_channel, &msg)
                .and_then(move |their_msg| {
                    let UdpRendezvousMsg::Init {
                        enc_pk: their_pk,
                        rendezvous_addrs: their_rendezvous_addrs,
                    } = their_msg;
                    trace!(
                        "their rendezvous addresses are: {:#?}",
                        their_rendezvous_addrs
                    );

                    let shared_secret = our_sk.shared_secret(&their_pk);
                    let mut punchers = FuturesUnordered::new();
                    let iter = { sockets.into_iter().zip(their_rendezvous_addrs).enumerate() };
                    for (i, (socket, their_addr)) in iter {
                        socket
                            .set_ttl(HOLE_PUNCH_INITIAL_TTL)
                            .map_err(UdpRendezvousConnectError::SetTtl)?;
                        let shared = SharedUdpSocket::share(socket);
                        let with_addr = shared.with_address(their_addr);
                        let delay_tolerance = Duration::from_secs(HOLE_PUNCH_DELAY_TOLERANCE_SEC);
                        let duration = delay_tolerance / (1 << i);
                        punchers.push(HolePunching::new_ttl_incrementer(
                            &handle,
                            with_addr,
                            shared_secret.clone(),
                            duration,
                        ));
                    }

                    let incoming = punchers.into_boxed();
                    Ok((
                        their_pk,
                        incoming,
                        our_public_addr_opt,
                        rendezvous_error_opt,
                    ))
                }).into_boxed()
        }).into_boxed()
}

// Note that ths type is here just to make clippy and rust fmt happy. Although, it also might
// indicate too complex types.
type SocketsWithAddr = Vec<(UdpSocket, SocketAddr)>;

/// Creates N sockets for hole punching.
fn hole_punching_sockets<Ei, Eo>(
    handle: &Handle,
    p2p: &P2p,
) -> BoxFuture<(SocketsWithAddr, Option<RendezvousAddrError>), UdpRendezvousConnectError<Ei, Eo>>
where
    Ei: 'static,
    Eo: 'static,
{
    let p2p = p2p.clone();
    let handle = handle.clone();

    future::loop_fn(Vec::new(), move |mut sockets| {
        if sockets.len() == 6 {
            return future::ok(Loop::Break((sockets, None))).into_boxed();
        }

        let try = || {
            let socket = UdpSocket::bind_reusable(&addr!("0.0.0.0:0"), &handle)
                .map_err(UdpRendezvousConnectError::Rebind)?;
            let bind_addr = socket
                .local_addr()
                .map_err(UdpRendezvousConnectError::Rebind)?;
            socket
                .set_ttl(HOLE_PUNCH_INITIAL_TTL)
                .map_err(UdpRendezvousConnectError::SetTtl)?;

            Ok({
                rendezvous_addr(Protocol::Udp, &bind_addr, &handle, &p2p).then(move |res| match res
                {
                    Ok((addr, _nat_type)) => {
                        sockets.push((socket, addr));
                        trace!("generated {} rendezvous sockets", sockets.len());
                        Ok(Loop::Continue(sockets))
                    }
                    Err(err) => {
                        trace!("error generating rendezvous socket: {}", err);
                        trace!("stopping after generating {} sockets", sockets.len());
                        Ok(Loop::Break((sockets, Some(err))))
                    }
                })
            })
        };
        future::result(try()).flatten().into_boxed()
    }).into_boxed()
}

pub fn bind_public_with_addr(
    addr: &SocketAddr,
    handle: &Handle,
    mc: &P2p,
) -> BoxFuture<(UdpSocket, SocketAddr, SocketAddr), BindPublicError> {
    let handle = handle.clone();
    let try = || {
        let socket = { UdpSocket::bind_reusable(addr, &handle).map_err(BindPublicError::Bind) }?;
        let bind_addr = { socket.local_addr().map_err(BindPublicError::Bind) }?;
        Ok({
            open_addr(Protocol::Udp, &bind_addr, &handle, mc)
                .map_err(BindPublicError::OpenAddr)
                .map(move |public_addr| (socket, bind_addr, public_addr))
        })
    };
    future::result(try()).flatten().into_boxed()
}

quick_error! {
    /// Error resulting from a single failed hole-punching attempt.
    #[derive(Debug)]
    pub enum HolePunchError {
        SendMessage(e: io::Error) {
            description("error sending message to peer")
            display("error sending message to peer: {}", e)
            cause(e)
        }
        ReadMessage(e: io::Error) {
            description("error receiving message from peer")
            display("error receiving message from peer: {}", e)
            cause(e)
        }
        SocketStolen {
            description("another puncher took the socket")
        }
        UnexpectedMessage {
            description("received unexpected hole-punch message type")
        }
        Decrypt(e: EncryptionError) {
            description("received undecryptable message from peer")
            display("received undecryptable message from peer: {}", e)
            cause(e)
        }
        GetTtl(e: io::Error) {
            description("error getting ttl of socket")
            display("error getting ttl of socket: {}", e)
            cause(e)
        }
        SetTtl(e: io::Error) {
            description("error setting ttl on socket")
            display("error setting ttl on socket: {}", e)
            cause(e)
        }
        TimedOut {
            description("hole punching timed out without making a connection")
        }
        Encrypt(e: EncryptionError) {
            description("error encrypting message to be sent to peer")
            display("error encrypting message to be sent to peer: {}", e)
            cause(e)
        }
    }
}

/// This is the maximum possible TTL. TTL runners never exceed this TTL.
/// It could be possible to set this as high as 255, but some OSes could plausibly have restrictions
/// against setting TTLs that high. Plus, 128 is already a huge value.
const MAX_TTL: u32 = 128;

/// This is the default TTL used on Linux. Other OSes use anything from 30 to 128, but 64 is the
/// most common and the median value.
const SANE_DEFAULT_TTL: u32 = 64;

/// How many hops we expect it to take, at most, to reach the peer. The slowest TTL runner will
/// reach this value over the course of HOLE_PUNCH_DELAY_TOLERANCE.
const REALISTIC_MAX_TTL: u32 = 16;
const HOLE_PUNCH_MSG_PERIOD_MS: u64 = 200;

struct HolePunching {
    socket: Option<WithAddress>,
    sending_msg: Option<Bytes>,
    timeout: Timeout,
    shared_secret: SharedSecretKey,
    phase: HolePunchingPhase,
}

enum HolePunchingPhase {
    Syn {
        time_of_last_ttl_increment: Instant,
        ttl_increment_duration: Duration,
    },
    Ack,
    AckAck {
        ack_acks_sent: u32,
        received_ack_ack: bool,
    },
}

impl HolePunching {
    pub fn new_ttl_incrementer(
        handle: &Handle,
        socket: WithAddress,
        shared_secret: SharedSecretKey,
        duration_to_reach_max_ttl: Duration,
    ) -> HolePunching {
        HolePunching {
            socket: Some(socket),
            sending_msg: None,
            timeout: Timeout::new(Duration::new(0, 0), handle),
            shared_secret,
            phase: HolePunchingPhase::Syn {
                time_of_last_ttl_increment: Instant::now(),
                ttl_increment_duration: {
                    duration_to_reach_max_ttl / (REALISTIC_MAX_TTL - HOLE_PUNCH_INITIAL_TTL)
                },
            },
        }
    }

    fn flush(&mut self) -> Result<Async<()>, HolePunchError> {
        loop {
            match unwrap!(self.socket.as_mut()).poll_complete() {
                Err(e) => return Err(HolePunchError::SendMessage(e)),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(())) => (),
            };

            if let Some(bytes) = self.sending_msg.take() {
                match unwrap!(self.socket.as_mut()).start_send(bytes) {
                    Err(e) => return Err(HolePunchError::SendMessage(e)),
                    Ok(AsyncSink::Ready) => continue,
                    Ok(AsyncSink::NotReady(bytes)) => {
                        self.sending_msg = Some(bytes);
                        return Ok(Async::NotReady);
                    }
                }
            }

            return Ok(Async::Ready(()));
        }
    }

    fn send_msg(&mut self, msg: &HolePunchMsg) -> Result<(), HolePunchError> {
        let encrypted = self
            .shared_secret
            .encrypt(msg)
            .map_err(HolePunchError::Encrypt)?;
        let bytes = Bytes::from(encrypted);
        debug_assert!(self.sending_msg.is_none());
        self.sending_msg = Some(bytes);
        Ok(())
    }

    fn recv_msg(&mut self) -> Result<Async<HolePunchMsg>, HolePunchError> {
        let bytes = match unwrap!(self.socket.as_mut()).poll() {
            Err(e) => return Err(HolePunchError::ReadMessage(e)),
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(None)) => return Err(HolePunchError::SocketStolen),
            Ok(Async::Ready(Some(bytes))) => bytes,
        };
        match self.shared_secret.decrypt(&bytes) {
            Ok(msg) => Ok(Async::Ready(msg)),
            Err(e) => Err(HolePunchError::Decrypt(e)),
        }
    }

    fn send_next_message(&mut self) -> Result<Async<WithAddress>, HolePunchError> {
        let hole_punch_period = Duration::from_millis(HOLE_PUNCH_MSG_PERIOD_MS);
        self.timeout.reset(Instant::now() + hole_punch_period);
        let msg = match self.phase {
            HolePunchingPhase::Syn {
                ref mut time_of_last_ttl_increment,
                ttl_increment_duration,
            } => {
                let now = Instant::now();
                while now - *time_of_last_ttl_increment > ttl_increment_duration {
                    let ttl = {
                        unwrap!(self.socket.as_mut())
                            .ttl()
                            .map_err(HolePunchError::GetTtl)
                    }?;
                    if ttl < MAX_TTL {
                        unwrap!(self.socket.as_mut())
                            .set_ttl(ttl + 1)
                            .map_err(HolePunchError::SetTtl)?;
                    }
                    *time_of_last_ttl_increment += ttl_increment_duration;
                }
                HolePunchMsg::Syn
            }
            HolePunchingPhase::Ack => HolePunchMsg::Ack,
            HolePunchingPhase::AckAck {
                ref mut ack_acks_sent,
                received_ack_ack,
            } => {
                if *ack_acks_sent >= 5 && received_ack_ack {
                    return Ok(Async::Ready(unwrap!(self.socket.take())));
                }
                *ack_acks_sent += 1;
                HolePunchMsg::AckAck
            }
        };
        self.send_msg(&msg)?;
        Ok(Async::NotReady)
    }

    fn process_msg(&mut self, msg: &HolePunchMsg) -> Result<Async<WithAddress>, HolePunchError> {
        match *msg {
            HolePunchMsg::Syn => match self.phase {
                HolePunchingPhase::Syn { .. } => {
                    self.phase = HolePunchingPhase::Ack;
                    unwrap!(self.socket.as_mut())
                        .set_ttl(SANE_DEFAULT_TTL)
                        .map_err(HolePunchError::SetTtl)?;
                    self.timeout.reset(Instant::now());
                }
                HolePunchingPhase::Ack => {
                    self.timeout.reset(Instant::now());
                }
                HolePunchingPhase::AckAck { .. } => (),
            },
            HolePunchMsg::Ack => match self.phase {
                HolePunchingPhase::Syn { .. } | HolePunchingPhase::Ack => {
                    self.phase = HolePunchingPhase::AckAck {
                        ack_acks_sent: 0,
                        received_ack_ack: false,
                    };
                    self.timeout.reset(Instant::now());
                }
                HolePunchingPhase::AckAck { .. } => {
                    self.timeout.reset(Instant::now());
                }
            },
            HolePunchMsg::AckAck => match self.phase {
                HolePunchingPhase::Syn { .. } => {
                    return Err(HolePunchError::UnexpectedMessage);
                }
                HolePunchingPhase::Ack => {
                    self.phase = HolePunchingPhase::AckAck {
                        ack_acks_sent: 0,
                        received_ack_ack: true,
                    };
                    self.timeout.reset(Instant::now());
                }
                HolePunchingPhase::AckAck {
                    ref mut received_ack_ack,
                    ..
                } => {
                    *received_ack_ack = true;
                }
            },
            HolePunchMsg::Choose => match self.phase {
                HolePunchingPhase::Syn { .. } => {
                    return Err(HolePunchError::UnexpectedMessage);
                }
                HolePunchingPhase::Ack | HolePunchingPhase::AckAck { .. } => {
                    return Ok(Async::Ready(unwrap!(self.socket.take())))
                }
            },
        }
        Ok(Async::NotReady)
    }
}

impl Future for HolePunching {
    type Item = (WithAddress, bool);
    type Error = HolePunchError;

    fn poll(&mut self) -> Result<Async<(WithAddress, bool)>, HolePunchError> {
        loop {
            match self.flush()? {
                Async::NotReady => return Ok(Async::NotReady),
                Async::Ready(()) => (),
            };

            if let Async::Ready(()) = self.timeout.poll().void_unwrap() {
                match self.send_next_message()? {
                    Async::Ready(socket) => return Ok(Async::Ready((socket, false))),
                    Async::NotReady => continue,
                }
            }

            match self.recv_msg()? {
                Async::NotReady => return Ok(Async::NotReady),
                Async::Ready(msg) => {
                    if let Async::Ready(socket) = self.process_msg(&msg)? {
                        return Ok(Async::Ready((socket, true)));
                    }
                }
            }
        }
    }
}

// choose the given socket+address to be the socket+address we return successfully with.
fn choose<Ei, Eo>(
    handle: &Handle,
    shared_secret: SharedSecretKey,
    socket: WithAddress,
    chooses_sent: u32,
) -> BoxFuture<(UdpSocket, SocketAddr), UdpRendezvousConnectError<Ei, Eo>>
where
    Ei: 'static,
    Eo: 'static,
{
    if chooses_sent >= 5 {
        let addr = socket.remote_addr();
        let socket = unwrap!(socket.steal());
        return future::ok((socket, addr)).into_boxed();
    }

    trace!(
        "choosing {}, sending message #{}",
        socket.remote_addr(),
        chooses_sent
    );

    let handle = handle.clone();
    let encrypted = try_bfut!(
        shared_secret
            .encrypt(&HolePunchMsg::Choose)
            .map_err(UdpRendezvousConnectError::Encrypt)
    );

    let msg = Bytes::from(encrypted);
    socket
        .send(msg)
        .map_err(UdpRendezvousConnectError::SocketWrite)
        .and_then(move |socket| {
            Timeout::new(Duration::from_millis(200), &handle)
                .infallible()
                .and_then(move |()| choose(&handle, shared_secret, socket, chooses_sent + 1))
        }).into_boxed()
}

// listen on the socket to if the peer sends us a HolePunchMsg::Choose to indicate that they're
// choosing this socket+address to communicate with us.
fn take_chosen(
    handle: &Handle,
    shared_secret: SharedSecretKey,
    socket: WithAddress,
) -> BoxFuture<Option<(UdpSocket, SocketAddr)>, HolePunchError> {
    let handle = handle.clone();
    socket
        .into_future()
        .map_err(|(e, _)| HolePunchError::ReadMessage(e))
        .and_then(move |(msg_opt, socket)| match msg_opt {
            None => future::ok(None).into_boxed(),
            Some(msg) => match shared_secret.decrypt(&msg) {
                Err(e) => {
                    warn!("error deserializing packet from peer: {:?}", e);
                    take_chosen(&handle, shared_secret, socket)
                }
                Ok(HolePunchMsg::Choose) => future::ok(got_chosen(socket)).into_boxed(),
                Ok(..) => take_chosen(&handle, shared_secret, socket),
            },
        }).into_boxed()
}

// this socket got chosen by the remote peer. Return success with it.
fn got_chosen(socket: WithAddress) -> Option<(UdpSocket, SocketAddr)> {
    trace!("remote peer from {} chose us", socket.remote_addr());

    let addr = socket.remote_addr();
    let socket_opt = socket.steal();
    socket_opt.map(|socket| (socket, addr))
}

// exchange rendezvous messages along the channel
fn exchange_msgs<C>(
    handle: &Handle,
    channel: C,
    msg: &UdpRendezvousMsg,
) -> BoxFuture<UdpRendezvousMsg, UdpRendezvousConnectError<C::Error, C::SinkError>>
where
    C: Stream<Item = Bytes>,
    C: Sink<SinkItem = Bytes>,
    C: 'static,
{
    let handle = handle.clone();
    let msg =
        try_bfut!(serialisation::serialise(&msg).map_err(UdpRendezvousConnectError::SerializeMsg));

    channel
        .send(Bytes::from(msg))
        .map_err(UdpRendezvousConnectError::ChannelWrite)
        .and_then(move |channel| {
            channel
                .map_err(UdpRendezvousConnectError::ChannelRead)
                .next_or_else(|| UdpRendezvousConnectError::ChannelClosed)
                .with_timeout(
                    Duration::from_secs(RENDEZVOUS_INFO_EXCHANGE_TIMEOUT_SEC),
                    &handle,
                ).and_then(|opt| opt.ok_or(UdpRendezvousConnectError::ChannelTimedOut))
                .and_then(|(msg, _channel)| {
                    serialisation::deserialise(&msg)
                        .map_err(UdpRendezvousConnectError::DeserializeMsg)
                })
        }).into_boxed()
}

#[derive(Debug, Serialize, Deserialize)]
enum HolePunchMsg {
    Syn,
    Ack,
    AckAck,
    Choose,
}

#[cfg(test)]
mod test {
    use super::*;
    use env_logger;
    use tokio_core::reactor::Core;
    use util;

    #[test]
    fn send_dgram_connected_works() {
        const DGRAM_LEN: usize = 1024;
        let _ = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();

        let recv_sock = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));
        let recv_sock_addr = unwrap!(recv_sock.local_addr()).unspecified_to_localhost();

        let sock = unwrap!(UdpSocket::bind_connect_reusable(
            &addr!("0.0.0.0:0"),
            &recv_sock_addr,
            &handle,
        ));
        let sock_addr = unwrap!(sock.local_addr()).unspecified_to_localhost();

        let send_future = {
            let v = util::random_vec(DGRAM_LEN);
            sock.send_dgram_connected(v)
                .map(|(_sock, v)| v)
                .map_err(|e| panic!("error sending: {}", e))
        };

        let recv_future = {
            let v = util::zeroed_vec(DGRAM_LEN);
            recv_sock
                .recv_dgram(v)
                .map(|(_recv_sock, v, len, addr)| {
                    assert_eq!(len, DGRAM_LEN);
                    assert_eq!(addr, sock_addr);
                    v
                }).map_err(|e| panic!("error receiving: {}", e))
        };

        let res = core.run({
            send_future.join(recv_future).map(|(v_send, v_recv)| {
                assert_eq!(v_send, v_recv);
            })
        });
        res.void_unwrap()
    }

    #[test]
    fn hole_puncher_sends_5_ack_ack_messages() {
        let _ = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();

        let recv_sock = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));
        let sock = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));

        let recv_sock_addr = unwrap!(recv_sock.local_addr()).unspecified_to_localhost();
        let sock_addr = unwrap!(sock.local_addr()).unspecified_to_localhost();
        let recv_sock = SharedUdpSocket::share(recv_sock).with_address(sock_addr);
        let sock = SharedUdpSocket::share(sock).with_address(recv_sock_addr);

        let (sock_pk, sock_sk) = gen_encrypt_keypair();
        let (recv_sock_pk, recv_sock_sk) = gen_encrypt_keypair();
        let sock_shared_secret = sock_sk.shared_secret(&recv_sock_pk);
        let recv_shared_secret = recv_sock_sk.shared_secret(&sock_pk);
        let delay_tolerance = Duration::from_secs(5);
        let hole_punching =
            HolePunching::new_ttl_incrementer(&handle, sock, sock_shared_secret, delay_tolerance);

        let recv_side = {
            recv_sock
                .into_future()
                .map_err(|(e, _)| panic!("recv error: {}", e))
                .and_then({
                    let recv_shared_secret = recv_shared_secret.clone();
                    move |(msg_opt, recv_sock)| {
                        let msg = unwrap!(msg_opt);
                        let msg = unwrap!(recv_shared_secret.decrypt(&msg));
                        match msg {
                            HolePunchMsg::Syn => (),
                            _ => panic!("unexpected msg {:?}", msg),
                        };

                        let msg = unwrap!(recv_shared_secret.encrypt(&HolePunchMsg::Ack));
                        let msg = Bytes::from(msg);
                        recv_sock.send(msg).map_err(|e| panic!("send error: {}", e))
                    }
                }).and_then(|recv_sock| {
                    trace!("sent ack");
                    recv_sock
                        .into_future()
                        .map_err(|(e, _)| panic!("recv error: {}", e))
                }).and_then({
                    let recv_shared_secret = recv_shared_secret.clone();
                    move |(msg_opt, recv_sock)| {
                        let msg = unwrap!(msg_opt);
                        let msg = unwrap!(recv_shared_secret.decrypt(&msg));
                        match msg {
                            HolePunchMsg::AckAck => (),
                            _ => panic!("unexpected msg {:?}", msg),
                        };

                        let msg = unwrap!(recv_shared_secret.encrypt(&HolePunchMsg::AckAck));
                        let msg = Bytes::from(msg);
                        recv_sock.send(msg).map_err(|e| panic!("send error: {}", e))
                    }
                }).and_then(|recv_sock| {
                    trace!("sent ack-ack");
                    recv_sock
                        .take(5)
                        .collect()
                        .map_err(|e| panic!("recv error: {}", e))
                }).map({
                    let recv_shared_secret = recv_shared_secret.clone();
                    move |collected| {
                        trace!("read until end of stream: {:#?}", collected);
                        assert_eq!(collected.len(), 5);
                        for msg in &collected[..4] {
                            let msg = unwrap!(recv_shared_secret.decrypt(msg));
                            match msg {
                                HolePunchMsg::AckAck => (),
                                _ => panic!("unexpected msg {:?}", msg),
                            };
                        }
                        assert_eq!(&collected[4], &b"the end"[..]);
                    }
                })
        };

        let send_side = {
            hole_punching
                .map_err(|e| panic!("hole punching error: {}", e))
                .and_then(|(sock, received_choose)| {
                    assert!(!received_choose);
                    sock.send(Bytes::from(&b"the end"[..]))
                        .map_err(|e| panic!("error sending: {}", e))
                }).map(|_sock| ())
        };

        core.run(recv_side.join(send_side).map(|((), ())| ()))
            .void_unwrap()
    }

    #[test]
    fn allow_setting_max_ttl() {
        let core = unwrap!(Core::new());
        let handle = core.handle();
        let socket = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0"), &handle));
        unwrap!(socket.set_ttl(MAX_TTL));
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
#[cfg(feature = "netsim")]
mod netsim_test {
    use super::*;
    use env_logger;
    use futures;
    use netsim::device::ipv4::Ipv4NatBuilder;
    use netsim::node::{self, Ipv4Node};
    use netsim::{self, Ipv4Range, Network};
    use tokio_core::reactor::Core;
    use util;

    fn udp_rendezvous_connect_between_natted_hosts(
        num_servers: usize,
        nat_0: Ipv4NatBuilder,
        nat_1: Ipv4NatBuilder,
        start_delay: Duration,
    ) {
        let _ = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();
        let network = Network::new(&handle);
        let network_handle = network.handle();

        let res = core.run(future::lazy(|| {
            let (ch0, ch1) = util::two_way_channel();

            let mut server_drop_txs_0 = Vec::new();
            let mut server_drop_txs_1 = Vec::new();
            let (server_querier_tx_0, server_querier_rx_0) = futures::sync::mpsc::unbounded();
            let (server_querier_tx_1, server_querier_rx_1) = futures::sync::mpsc::unbounded();
            let mut server_nodes = Vec::new();
            for _ in 0..num_servers {
                let (server_drop_tx_0, server_drop_rx_0) = drop_notify();
                let (server_drop_tx_1, server_drop_rx_1) = drop_notify();
                server_drop_txs_0.push(server_drop_tx_0);
                server_drop_txs_1.push(server_drop_tx_1);

                let server_querier_tx_0 = server_querier_tx_0.clone();
                let server_querier_tx_1 = server_querier_tx_1.clone();

                let server_node = node::ipv4::machine(move |ip| {
                    let mut core = unwrap!(Core::new());
                    let handle = core.handle();

                    let res = core.run(future::lazy(move || {
                        let server =
                            unwrap!(UdpRendezvousServer::bind(&addr!("0.0.0.0:0"), &handle));
                        let server_port = server.local_addr().port();
                        let server_addr = SocketAddr::new(IpAddr::V4(ip), server_port);
                        let server_querier =
                            RemoteUdpRendezvousServer::new(server_addr, *server.public_key());

                        unwrap!(server_querier_tx_0.unbounded_send(server_querier.clone()));
                        unwrap!(server_querier_tx_1.unbounded_send(server_querier));

                        server_drop_rx_0
                            .and_then(|()| server_drop_rx_1)
                            .map(|()| drop(server))
                    }));
                    unwrap!(res)
                });
                let server_node = server_node
                    .latency(Duration::from_millis(100), Duration::from_millis(10))
                    .hops(2);
                server_nodes.push(server_node);
            }

            let node_0 = node::ipv4::nat(
                nat_0,
                node::ipv4::machine(move |_ip| {
                    let mut core = unwrap!(Core::new());
                    let handle = core.handle();

                    let res = core.run(future::lazy(|| {
                        server_querier_rx_0
                            .collect()
                            .map_err(|()| panic!("error getting server addr"))
                            .map(|server_queriers| {
                                let p2p = P2p::default();
                                for server_querier in server_queriers {
                                    p2p.add_udp_addr_querier(server_querier);
                                }
                                p2p
                            }).and_then(|p2p| {
                                UdpSocket::rendezvous_connect(ch0, &handle, &p2p)
                                    .map_err(|e| panic!("rendezvous connect error: {}", e))
                            }).map(|_socket| {
                                trace!("connected peer 0");
                                drop(server_drop_txs_0);
                            })
                    }));
                    unwrap!(res)
                }),
            );
            let node_1 = node::ipv4::nat(
                nat_1,
                node::ipv4::machine(move |_ip| {
                    let mut core = unwrap!(Core::new());
                    let handle = core.handle();

                    let res = core.run(future::lazy(|| {
                        Timeout::new(start_delay, &handle)
                            .infallible()
                            .and_then(|()| server_querier_rx_1.collect())
                            .map_err(|()| panic!("error getting server addr"))
                            .map(|server_queriers| {
                                let p2p = P2p::default();
                                for server_querier in server_queriers {
                                    p2p.add_udp_addr_querier(server_querier);
                                }
                                p2p
                            }).and_then(|p2p| {
                                UdpSocket::rendezvous_connect(ch1, &handle, &p2p)
                                    .map_err(|e| panic!("rendezvous connect error: {}", e))
                            }).map(|_socket| {
                                trace!("connected peer 1");
                                drop(server_drop_txs_1);
                            })
                    }));
                    unwrap!(res)
                }),
            );

            let node_0 = node_0
                .latency(Duration::from_millis(200), Duration::from_millis(20))
                .hops(4)
                .packet_loss(0.1, Duration::from_millis(20));

            let node_1 = node_1
                .latency(Duration::from_millis(200), Duration::from_millis(20))
                .hops(4)
                .packet_loss(0.1, Duration::from_millis(20));

            let servers = node::ipv4::router(server_nodes);
            let network = node::ipv4::router((servers, node_0, node_1));

            let (spawn_complete, _plug) =
                netsim::spawn::ipv4_tree(&network_handle, Ipv4Range::global(), network);

            spawn_complete
                .resume_unwind()
                .map(|(_v, (), ())| ())
                .with_timeout(start_delay + Duration::from_secs(20), &handle)
                .map(|opt| unwrap!(opt, "test timed out!"))
        }));
        res.void_unwrap()
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_no_delay_one_server() {
        udp_rendezvous_connect_between_natted_hosts(
            1,
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Duration::from_secs(0),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_no_delay_many_servers() {
        udp_rendezvous_connect_between_natted_hosts(
            20,
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Duration::from_secs(0),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_one_symmetric_with_no_delay_one_server() {
        udp_rendezvous_connect_between_natted_hosts(
            1,
            Ipv4NatBuilder::default().blacklist_unrecognized_addrs(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .randomize_port_allocation()
                .symmetric(),
            Duration::from_secs(0),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_one_symmetric_with_no_delay_many_servers() {
        udp_rendezvous_connect_between_natted_hosts(
            20,
            Ipv4NatBuilder::default().blacklist_unrecognized_addrs(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .randomize_port_allocation()
                .symmetric(),
            Duration::from_secs(0),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_both_symmetric_with_no_delay() {
        udp_rendezvous_connect_between_natted_hosts(
            3,
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .symmetric(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .symmetric(),
            Duration::from_secs(0),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_short_delay_one_server() {
        udp_rendezvous_connect_between_natted_hosts(
            1,
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Duration::from_secs(5),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_short_delay_many_servers() {
        udp_rendezvous_connect_between_natted_hosts(
            1,
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Duration::from_secs(5),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_one_symmetric_with_short_delay_one_server() {
        udp_rendezvous_connect_between_natted_hosts(
            1,
            Ipv4NatBuilder::default().blacklist_unrecognized_addrs(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .randomize_port_allocation()
                .symmetric(),
            Duration::from_secs(5),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_one_symmetric_with_short_delay_many_servers() {
        udp_rendezvous_connect_between_natted_hosts(
            20,
            Ipv4NatBuilder::default().blacklist_unrecognized_addrs(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .randomize_port_allocation()
                .symmetric(),
            Duration::from_secs(5),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_long_delay_one_server() {
        udp_rendezvous_connect_between_natted_hosts(
            1,
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Duration::from_secs(60),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_long_delay_many_servers() {
        udp_rendezvous_connect_between_natted_hosts(
            20,
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .restrict_endpoints(),
            Duration::from_secs(60),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_one_symmetric_with_long_delay_one_server() {
        udp_rendezvous_connect_between_natted_hosts(
            1,
            Ipv4NatBuilder::default().blacklist_unrecognized_addrs(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .randomize_port_allocation()
                .symmetric(),
            Duration::from_secs(60),
        );
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_one_symmetric_with_long_delay_many_servers() {
        udp_rendezvous_connect_between_natted_hosts(
            20,
            Ipv4NatBuilder::default().blacklist_unrecognized_addrs(),
            Ipv4NatBuilder::default()
                .blacklist_unrecognized_addrs()
                .randomize_port_allocation()
                .symmetric(),
            Duration::from_secs(60),
        );
    }
}
