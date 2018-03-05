use bincode;
use filter_addrs::filter_addrs;
use futures::future::Loop;
use futures::stream::FuturesUnordered;
use open_addr::{BindPublicError, open_addr};
use priv_prelude::*;
use rendezvous_addr::{RendezvousAddrError, rendezvous_addr};
use rust_sodium::crypto::box_::{PublicKey, SecretKey, gen_keypair};
use secure_serialisation::{self, deserialise as secure_deserialise, serialise as secure_serialise};
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
    /// Failure to serialise a message
    SerialiseMsg(secure_serialisation::Error),
    /// Failure to deserialize message received from rendezvous connection info exchange channel.
    DeserializeMsg(bincode::Error),
    /// Failure to send packets to the socket.
    SocketWrite(io::Error),
    /// Failure to set socket TTL.
    SetTtl(io::Error),
    /// Used when all rendezvous connection attempts failed.
    AllAttemptsFailed(
        Vec<HolePunchError>,
        Option<Box<BindPublicError>>,
        Option<Box<RendezvousAddrError>>
    ),
}

impl<Ei, Eo> fmt::Display for UdpRendezvousConnectError<Ei, Eo>
where
    Ei: Error,
    Eo: Error,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())?;
        if let UdpRendezvousConnectError::AllAttemptsFailed(ref v,
                                                            ref bind_public,
                                                            ref rendezvous) = *self
        {
            if let Some(ref bind_public) = *bind_public {
                write!(
                    f,
                    "attempt to create publicly-connectable socket gave error: {}. ",
                    bind_public
                )?;
            }
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
            Bind(ref e) |
            Rebind(ref e) |
            IfAddrs(ref e) |
            SocketWrite(ref e) |
            SetTtl(ref e) => Some(e),
            ChannelRead(ref e) => Some(e),
            ChannelWrite(ref e) => Some(e),
            SerialiseMsg(ref e) => Some(e),
            DeserializeMsg(ref e) => Some(e),
            ChannelClosed |
            ChannelTimedOut |
            AllAttemptsFailed(..) => None,
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
            SerialiseMsg(..) => "error serialising a message",
            DeserializeMsg(..) => "error deserializing message from rendezvous channel",
            SocketWrite(..) => "error writing to socket",
            SetTtl(..) => "error setting ttl value on socket",
            AllAttemptsFailed(..) => "all attempts to contact the remote peer failed",
        }
    }
}

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
    fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        mc: &P2p,
    ) -> BoxFuture<(UdpSocket, SocketAddr), UdpRendezvousConnectError<C::Error, C::SinkError>>
    where
        C: Stream<Item = Bytes>,
        C: Sink<SinkItem = Bytes>,
        <C as Stream>::Error: fmt::Debug,
        <C as Sink>::SinkError: fmt::Debug,
        C: 'static;
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

    // TODO(povilas): decompose this method - it would be more readable, maintainable and testable
    fn rendezvous_connect<C>(
        channel: C,
        handle: &Handle,
        mc: &P2p,
    ) -> BoxFuture<(UdpSocket, SocketAddr), UdpRendezvousConnectError<C::Error, C::SinkError>>
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
        let (our_pk, our_sk) = gen_keypair();
        let our_sk0 = our_sk.clone();
        let our_sk1 = our_sk.clone();

        trace!("starting rendezvous connect");
        UdpSocket::bind_public(&addr!("0.0.0.0:0"), handle, mc)
            .then(move |res| match res {
                Ok((socket, public_addr)) => {
                    let try = || {
                        let mut our_addrs = {
                            socket.expanded_local_addrs().map_err(
                                UdpRendezvousConnectError::IfAddrs,
                            )?
                        };
                        our_addrs.push(public_addr);
                        trace!(
                            "public bind successful, our open addresses are: {:#?}",
                            our_addrs
                        );
                        let our_addrs = our_addrs.into_iter().collect::<HashSet<_>>();
                        let msg = UdpRendezvousMsg::Init {
                            enc_pk: our_pk,
                            open_addrs: our_addrs.clone(),
                            rendezvous_addrs: Vec::new(),
                        };

                        trace!("exchanging rendezvous info with peer");
                        Ok({
                            exchange_msgs(&handle0, channel, &msg).map(move |their_msg| {
                                trace!("received rendezvous info");
                                let UdpRendezvousMsg::Init {
                                    enc_pk: their_pk,
                                    open_addrs: their_open_addrs,
                                    rendezvous_addrs: _their_rendezvous_addrs,
                                } = their_msg;

                                let their_open_addrs = filter_addrs(&our_addrs, &their_open_addrs);
                                let incoming = {
                                    open_connect(
                                        &handle0,
                                        their_pk,
                                        our_sk0,
                                        socket,
                                        their_open_addrs,
                                        true,
                                    ).into_boxed()
                                };
                                (their_pk, incoming, None, None)
                            })
                        })
                    };
                    future::result(try()).flatten().into_boxed()
                }
                Err(bind_public_error) => {
                    trace!("public bind failed: {}", bind_public_error);
                    trace!("generating rendezvous sockets");
                    let try = || {
                        let listen_socket = {
                            UdpSocket::bind_reusable(&addr!("0.0.0.0:0"), &handle0)
                                .map_err(UdpRendezvousConnectError::Bind)?
                        };
                        let our_addrs = {
                            listen_socket.expanded_local_addrs().map_err(
                                UdpRendezvousConnectError::IfAddrs,
                            )?
                        };
                        let our_addrs = our_addrs.into_iter().collect::<HashSet<_>>();

                        Ok({
                            let handle2 = handle0.clone();
                            let mc = mc0.clone();
                            future::loop_fn(Vec::new(), move |mut sockets| {
                                if sockets.len() == 6 {
                                    return future::ok(Loop::Break((sockets, None))).into_boxed();
                                }
                                let try = || {
                                    let socket = {
                                        UdpSocket::bind_reusable(&addr!("0.0.0.0:0"), &handle0)
                                            .map_err(UdpRendezvousConnectError::Rebind)
                                    }?;
                                    let bind_addr = {
                                        socket.local_addr().map_err(
                                            UdpRendezvousConnectError::Rebind,
                                        )?
                                    };
                                    socket.set_ttl(HOLE_PUNCH_INITIAL_TTL).map_err(
                                        UdpRendezvousConnectError::SetTtl,
                                    )?;
                                    Ok({
                                        rendezvous_addr(Protocol::Udp, &bind_addr, &handle0, &mc)
                                            .then(move |res| match res {
                                                Ok(addr) => {
                                                    sockets.push((socket, addr));
                                                    trace!(
                                                        "generated {} rendezvous sockets",
                                                        sockets.len()
                                                    );
                                                    Ok(Loop::Continue(sockets))
                                                }
                                                Err(err) => {
                                                    trace!(
                                                        "error generating rendezvous socket: {}",
                                                        err
                                                    );
                                                    trace!(
                                                        "stopping after generating {} sockets",
                                                        sockets.len()
                                                    );
                                                    Ok(Loop::Break((sockets, Some(err))))
                                                }
                                            })
                                    })
                                };
                                future::result(try()).flatten().into_boxed()
                            }).and_then(move |(sockets, rendezvous_error_opt)| {
                                let (sockets, rendezvous_addrs) = {
                                    sockets.into_iter().unzip::<_, _, Vec<_>, _>()
                                };
                                trace!("our rendezvous addresses are: {:#?}", rendezvous_addrs);
                                trace!("our open addresses are: {:#?}", our_addrs);
                                let msg = UdpRendezvousMsg::Init {
                                    enc_pk: our_pk,
                                    open_addrs: our_addrs.clone(),
                                    rendezvous_addrs: rendezvous_addrs,
                                };
                                trace!("exchanging rendezvous info with peer");
                                exchange_msgs(&handle2, channel, &msg).and_then(move |their_msg| {
                                    let UdpRendezvousMsg::Init {
                                        enc_pk: their_pk,
                                        open_addrs: their_open_addrs,
                                        rendezvous_addrs: their_rendezvous_addrs,
                                    } = their_msg;

                                    trace!(
                                        "their rendezvous addresses are: {:#?}",
                                        their_rendezvous_addrs
                                    );
                                    trace!("their open addresses are: {:#?}", their_open_addrs);
                                    let mut punchers = FuturesUnordered::new();
                                    let iter = {
                                        sockets.into_iter().zip(their_rendezvous_addrs).enumerate()
                                    };
                                    for (i, (socket, their_addr)) in iter {
                                        socket.set_ttl(HOLE_PUNCH_INITIAL_TTL).map_err(
                                            UdpRendezvousConnectError::SetTtl,
                                        )?;
                                        let shared = SharedUdpSocket::share(socket);
                                        let with_addr = shared.with_address(their_addr);
                                        let delay_tolerance =
                                            Duration::from_secs(HOLE_PUNCH_DELAY_TOLERANCE_SEC);
                                        let duration = delay_tolerance / (1 << i);
                                        punchers.push(HolePunching::new_ttl_incrementer(
                                            &handle2,
                                            with_addr,
                                            their_pk,
                                            our_sk1.clone(),
                                            duration,
                                        ));
                                    }

                                    let their_open_addrs =
                                        filter_addrs(&our_addrs, &their_open_addrs);

                                    trace!(
                                        "their (filtered) open addresses are: {:#?}",
                                        their_open_addrs
                                    );
                                    let incoming = {
                                        open_connect(
                                            &handle2,
                                            their_pk,
                                            our_sk1,
                                            listen_socket,
                                            their_open_addrs,
                                            false,
                                        ).select(punchers)
                                            .into_boxed()
                                    };
                                    Ok((
                                        their_pk,
                                        incoming,
                                        Some(bind_public_error),
                                        rendezvous_error_opt,
                                    ))
                                })
                            })
                        })
                    };
                    future::result(try()).flatten().into_boxed()
                }
            })
            .and_then(move |(their_pk,
                   incoming,
                   bind_public_error_opt,
                   rendezvous_error_opt)| {
                if our_pk > their_pk {
                    trace!("we are choosing the connection");
                    incoming
                        .and_then(|(socket, chosen)| {
                            if chosen {
                                return Err(HolePunchError::UnexpectedMessage);
                            }
                            trace!("successful connection found!");
                            Ok(socket)
                        })
                        .first_ok()
                        .map_err(|v| {
                            trace!("all attempts failed (us)");
                            UdpRendezvousConnectError::AllAttemptsFailed(
                                v,
                                bind_public_error_opt.map(Box::new),
                                rendezvous_error_opt.map(Box::new),
                            )
                        })
                        .and_then(move |socket| choose(&handle1, their_pk, our_sk, socket, 0))
                        .into_boxed()
                } else {
                    trace!("they are choosing the connection");
                    incoming
                        .map(move |(socket, chosen)| {
                            if chosen {
                                return future::ok(got_chosen(socket)).into_boxed();
                            }
                            take_chosen(&handle1, their_pk, our_sk.clone(), socket)
                        })
                        .buffer_unordered(256)
                        .filter_map(|opt| opt)
                        .first_ok()
                        .map_err(|v| {
                            trace!("all attempts failed (them)");
                            UdpRendezvousConnectError::AllAttemptsFailed(
                                v,
                                bind_public_error_opt.map(Box::new),
                                rendezvous_error_opt.map(Box::new),
                            )
                        })
                        .into_boxed()
                }
            })
            .into_boxed()
    }
}

pub fn bind_public_with_addr(
    addr: &SocketAddr,
    handle: &Handle,
    mc: &P2p,
) -> BoxFuture<(UdpSocket, SocketAddr, SocketAddr), BindPublicError> {
    let handle = handle.clone();
    let try = || {
        let socket = {
            UdpSocket::bind_reusable(addr, &handle).map_err(BindPublicError::Bind)
        }?;
        let bind_addr = {
            socket.local_addr().map_err(BindPublicError::Bind)
        }?;
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
        SerialiseMsg(e: secure_serialisation::Error) {
            description("error serialising message")
            display("error serialising message: {}", e)
            cause(e)
        }
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
    }
}

const MAX_TTL: u32 = 16;
const HOLE_PUNCH_MSG_PERIOD_MS: u64 = 200;

struct HolePunching {
    socket: Option<WithAddress>,
    sending_msg: Option<Bytes>,
    timeout: Timeout,
    their_pk: PublicKey,
    our_sk: SecretKey,
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
    pub fn new_for_open_peer(
        handle: &Handle,
        socket: WithAddress,
        their_pk: PublicKey,
        our_sk: SecretKey,
    ) -> HolePunching {
        HolePunching {
            socket: Some(socket),
            sending_msg: None,
            timeout: Timeout::new(Duration::new(0, 0), handle),
            their_pk: their_pk,
            our_sk: our_sk,
            phase: HolePunchingPhase::Syn {
                time_of_last_ttl_increment: Instant::now(),
                ttl_increment_duration: Duration::new(u64::max_value(), 0),
            },
        }
    }

    pub fn new_ttl_incrementer(
        handle: &Handle,
        socket: WithAddress,
        their_pk: PublicKey,
        our_sk: SecretKey,
        duration_to_reach_max_ttl: Duration,
    ) -> HolePunching {
        HolePunching {
            socket: Some(socket),
            sending_msg: None,
            timeout: Timeout::new(Duration::new(0, 0), handle),
            their_pk: their_pk,
            our_sk: our_sk,
            phase: HolePunchingPhase::Syn {
                time_of_last_ttl_increment: Instant::now(),
                ttl_increment_duration: {
                    duration_to_reach_max_ttl / (MAX_TTL - HOLE_PUNCH_INITIAL_TTL)
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
        let encrypted = secure_serialise(msg, &self.their_pk, &self.our_sk)
            .map_err(HolePunchError::SerialiseMsg)?;
        let bytes = Bytes::from(encrypted);
        debug_assert!(self.sending_msg.is_none());
        self.sending_msg = Some(bytes);
        Ok(())
    }

    fn recv_msg(&mut self) -> Result<Async<HolePunchMsg>, HolePunchError> {
        loop {
            let bytes = match unwrap!(self.socket.as_mut()).poll() {
                Err(e) => return Err(HolePunchError::ReadMessage(e)),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(None)) => return Err(HolePunchError::SocketStolen),
                Ok(Async::Ready(Some(bytes))) => bytes,
            };
            match secure_deserialise(&bytes, &self.their_pk, &self.our_sk) {
                Ok(msg) => return Ok(Async::Ready(msg)),
                Err(e) => {
                    warn!(
                        "unreceived unrecognisable data on hole punching socket: {}",
                        e
                    );
                }
            }
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
                        unwrap!(self.socket.as_mut()).ttl().map_err(
                            HolePunchError::GetTtl,
                        )
                    }?;
                    if ttl < MAX_TTL {
                        unwrap!(self.socket.as_mut()).set_ttl(ttl + 1).map_err(
                            HolePunchError::SetTtl,
                        )?;
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
            HolePunchMsg::Syn => {
                match self.phase {
                    HolePunchingPhase::Syn { .. } => {
                        self.phase = HolePunchingPhase::Ack;
                        unwrap!(self.socket.as_mut()).set_ttl(MAX_TTL).map_err(
                            HolePunchError::SetTtl,
                        )?;
                        self.timeout.reset(Instant::now());
                    }
                    HolePunchingPhase::Ack => {
                        self.timeout.reset(Instant::now());
                    }
                    HolePunchingPhase::AckAck { .. } => (),
                }
            }
            HolePunchMsg::Ack => {
                match self.phase {
                    HolePunchingPhase::Syn { .. } |
                    HolePunchingPhase::Ack => {
                        self.phase = HolePunchingPhase::AckAck {
                            ack_acks_sent: 0,
                            received_ack_ack: false,
                        };
                        self.timeout.reset(Instant::now());
                    }
                    HolePunchingPhase::AckAck { .. } => {
                        self.timeout.reset(Instant::now());
                    }
                }
            }
            HolePunchMsg::AckAck => {
                match self.phase {
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
                    HolePunchingPhase::AckAck { ref mut received_ack_ack, .. } => {
                        *received_ack_ack = true;
                    }
                }
            }
            HolePunchMsg::Choose => {
                match self.phase {
                    HolePunchingPhase::Syn { .. } => {
                        return Err(HolePunchError::UnexpectedMessage);
                    }
                    HolePunchingPhase::Ack |
                    HolePunchingPhase::AckAck { .. } => {
                        return Ok(Async::Ready(unwrap!(self.socket.take())))
                    }
                }
            }
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

// Perform a connect where one of the peers has an open port.
fn open_connect(
    handle: &Handle,
    their_pk: PublicKey,
    our_sk: SecretKey,
    socket: UdpSocket,
    their_addrs: HashSet<SocketAddr>,
    we_are_open: bool,
) -> BoxStream<(WithAddress, bool), HolePunchError> {
    let mut shared = SharedUdpSocket::share(socket);
    let mut punchers = FuturesUnordered::new();
    for addr in their_addrs {
        let with_addr = shared.with_address(addr);
        punchers.push(HolePunching::new_for_open_peer(
            handle,
            with_addr,
            their_pk,
            our_sk.clone(),
        ));
    }

    let handle = handle.clone();
    stream::poll_fn(move || {
        trace!(
            "open_connect polling shared socket on {:?}",
            shared.local_addr()
        );

        loop {
            match shared.poll() {
                Ok(Async::Ready(Some(with_addr))) => {
                    trace!(
                        "received packet from new address {}. starting punching",
                        with_addr.remote_addr()
                    );
                    punchers.push(HolePunching::new_for_open_peer(
                        &handle,
                        with_addr,
                        their_pk,
                        our_sk.clone(),
                    ));
                }
                Ok(Async::Ready(None)) => {
                    trace!("shared socket has been stolen");
                    break;
                }
                Ok(Async::NotReady) => {
                    trace!("nothing has arrived on the socket (yet)");
                    break;
                }
                Err(e) => {
                    error!("error reading from shared socket: {}", e);
                    break;
                }
            }
        }

        match punchers.poll()? {
            Async::Ready(Some(x)) => {
                trace!("puncher returned success!");
                Ok(Async::Ready(Some(x)))
            }
            Async::Ready(None) => {
                if we_are_open {
                    trace!("open_connect waiting for more connections");
                    Ok(Async::NotReady)
                } else {
                    trace!("open_connect giving up");
                    Ok(Async::Ready(None))
                }
            }
            Async::NotReady => {
                trace!("no punchers are ready yet");
                Ok(Async::NotReady)
            }
        }
    }).into_boxed()
}

// choose the given socket+address to be the socket+address we return successfully with.
fn choose<Ei, Eo>(
    handle: &Handle,
    their_pk: PublicKey,
    our_sk: SecretKey,
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
    let encrypted = match secure_serialise(&HolePunchMsg::Choose, &their_pk, &our_sk) {
        Ok(encrypted) => encrypted,
        Err(e) => return future::err(UdpRendezvousConnectError::SerialiseMsg(e)).into_boxed(),
    };

    let msg = Bytes::from(encrypted);
    socket
        .send(msg)
        .map_err(UdpRendezvousConnectError::SocketWrite)
        .and_then(move |socket| {
            Timeout::new(Duration::from_millis(200), &handle)
                .infallible()
                .and_then(move |()| {
                    choose(&handle, their_pk, our_sk, socket, chooses_sent + 1)
                })
        })
        .into_boxed()
}

// listen on the socket to if the peer sends us a HolePunchMsg::Choose to indicate that they're
// choosing this socket+address to communicate with us.
fn take_chosen(
    handle: &Handle,
    their_pk: PublicKey,
    our_sk: SecretKey,
    socket: WithAddress,
) -> BoxFuture<Option<(UdpSocket, SocketAddr)>, HolePunchError> {
    let handle = handle.clone();
    socket
        .into_future()
        .map_err(|(e, _)| HolePunchError::ReadMessage(e))
        .and_then(move |(msg_opt, socket)| match msg_opt {
            None => future::ok(None).into_boxed(),
            Some(msg) => {
                match secure_deserialise(&msg, &their_pk, &our_sk) {
                    Err(e) => {
                        warn!("error deserializing packet from peer: {:?}", e);
                        take_chosen(&handle, their_pk, our_sk, socket)
                    }
                    Ok(HolePunchMsg::Choose) => future::ok(got_chosen(socket)).into_boxed(),
                    Ok(..) => take_chosen(&handle, their_pk, our_sk, socket),
                }
            }
        })
        .into_boxed()
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
    let msg = unwrap!(bincode::serialize(&msg, bincode::Infinite));
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
                )
                .and_then(|opt| opt.ok_or(UdpRendezvousConnectError::ChannelTimedOut))
                .and_then(|(msg, _channel)| {
                    bincode::deserialize(&msg).map_err(UdpRendezvousConnectError::DeserializeMsg)
                })
        })
        .into_boxed()
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

        let (sock_pk, sock_sk) = gen_keypair();
        let (recv_sock_pk, recv_sock_sk) = gen_keypair();
        let hole_punching = HolePunching::new_for_open_peer(&handle, sock, recv_sock_pk, sock_sk);

        let recv_side = {
            recv_sock
                .into_future()
                .map_err(|(e, _)| panic!("recv error: {}", e))
                .and_then({
                    let recv_sock_sk = recv_sock_sk.clone();
                    move |(msg_opt, recv_sock)| {
                        let msg = unwrap!(msg_opt);
                        let msg = unwrap!(secure_deserialise(&msg, &sock_pk, &recv_sock_sk));
                        match msg {
                            HolePunchMsg::Syn => (),
                            _ => panic!("unexpected msg {:?}", msg),
                        };

                        let msg = unwrap!(secure_serialise(
                            &HolePunchMsg::Ack,
                            &sock_pk,
                            &recv_sock_sk,
                        ));
                        let msg = Bytes::from(msg);
                        recv_sock.send(msg).map_err(|e| panic!("send error: {}", e))
                    }
                })
                .and_then(|recv_sock| {
                    trace!("sent ack");
                    recv_sock.into_future().map_err(
                        |(e, _)| panic!("recv error: {}", e),
                    )
                })
                .and_then({
                    let recv_sock_sk = recv_sock_sk.clone();
                    move |(msg_opt, recv_sock)| {
                        let msg = unwrap!(msg_opt);
                        let msg = unwrap!(secure_deserialise(&msg, &sock_pk, &recv_sock_sk));
                        match msg {
                            HolePunchMsg::AckAck => (),
                            _ => panic!("unexpected msg {:?}", msg),
                        };

                        let msg = unwrap!(secure_serialise(
                            &HolePunchMsg::AckAck,
                            &sock_pk,
                            &recv_sock_sk,
                        ));
                        let msg = Bytes::from(msg);
                        recv_sock.send(msg).map_err(|e| panic!("send error: {}", e))
                    }
                })
                .and_then(|recv_sock| {
                    trace!("sent ack-ack");
                    recv_sock.take(5).collect().map_err(
                        |e| panic!("recv error: {}", e),
                    )
                })
                .map({
                    let recv_sock_sk = recv_sock_sk.clone();
                    move |collected| {
                        trace!("read until end of stream: {:#?}", collected);
                        assert_eq!(collected.len(), 5);
                        for msg in &collected[..4] {
                            let msg = unwrap!(secure_deserialise(msg, &sock_pk, &recv_sock_sk));
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
                })
                .map(|_sock| ())
        };

        let res = core.run({
            recv_side
            .join(send_side)
            .map(|((), ())| ())
        });

        unwrap!(res)
    }

    #[test]
    fn udp_rendezvous_connect_over_loopback() {
        let _ = env_logger::init();

        let (ch0, ch1) = util::two_way_channel();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();
        let mc0 = P2p::default();
        let mc1 = mc0.clone();

        let result = core.run({
            let f0 = {
                UdpSocket::rendezvous_connect(ch0, &handle, &mc0)
                    .map_err(|e| panic!("connect failed: {:?}", e))
                    .and_then(|(socket, addr)| {
                        trace!("rendezvous connect successful! connected to {}", addr);
                        let socket = SharedUdpSocket::share(socket).with_address(addr);
                        socket.send(Bytes::from(&b"hello"[..]))
                    })
                    .map_err(|e| panic!("writing failed: {:?}", e))
                    .map(|_| ())
            };
            let f1 = {
                UdpSocket::rendezvous_connect(ch1, &handle, &mc1)
                .map_err(|e| panic!("connect failed: {:?}", e))
                .and_then(|(socket, addr)| {
                    trace!("rendezvous connect successful! connected to {}", addr);
                    let socket = SharedUdpSocket::share(socket).with_address(addr);
                    socket
                    .filter_map(|data| {
                        if data == b"hello"[..] { Some(()) } else { None }
                    })
                    .next_or_else(|| panic!("Didn't receive a message"))
                })
                .map_err(|e| panic!("reading failed: {:?}", e))
                .map(|((), _socket)| ())
            };

            f0.join(f1).map(|((), ())| ())
        });
        unwrap!(result)
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
#[cfg(feature = "netsim")]
mod netsim_test {
    use super::*;

    use env_logger;
    use future_utils;
    use futures;
    use netsim::{self, SubnetV4};
    use netsim::device::NatV4Builder;
    use netsim::node::{self, Ipv4Node};
    use tokio_core::reactor::Core;

    use util;

    fn udp_rendezvous_connect_between_natted_hosts(start_delay: Duration) {
        let _ = env_logger::init();

        let mut core = unwrap!(Core::new());
        let handle = core.handle();

        let res = core.run(future::lazy(|| {
            let (ch0, ch1) = util::two_way_channel();
            let (server_drop_tx_0, server_drop_rx_0) = drop_notify();
            let (server_drop_tx_1, server_drop_rx_1) = drop_notify();
            let (server_info_tx_0, server_info_rx_0) = futures::sync::oneshot::channel();
            let (server_info_tx_1, server_info_rx_1) = futures::sync::oneshot::channel();
            let server_node = node::endpoint_v4(move |ip| {
                let mut core = unwrap!(Core::new());
                let handle = core.handle();

                let res = core.run(future::lazy(move || {
                    let server = unwrap!(UdpRendezvousServer::bind(&addr!("0.0.0.0:0"), &handle));
                    let server_port = server.local_addr().port();
                    let server_addr = SocketAddr::new(IpAddr::V4(ip), server_port);
                    let server_info = PeerInfo {
                        addr: server_addr,
                        pub_key: server.public_key(),
                    };

                    unwrap!(server_info_tx_0.send(server_info.clone()));
                    unwrap!(server_info_tx_1.send(server_info));

                    server_drop_rx_0
                    .and_then(|()| server_drop_rx_1)
                    .map(|()| drop(server))
                }));
                unwrap!(res)
            });
            let node_0 = node::nat_v4(
                NatV4Builder::default(),
                node::endpoint_v4(move |_ip| {
                    let mut core = unwrap!(Core::new());
                    let handle = core.handle();

                    let res = core.run(future::lazy(|| {
                        server_info_rx_0
                            .map_err(|e| panic!("error getting server addr: {}", e))
                            .map(|server_info| {
                                let p2p = P2p::default();
                                p2p.add_udp_traversal_server(&server_info);
                                p2p
                            })
                            .and_then(|p2p| {
                                UdpSocket::rendezvous_connect(ch0, &handle, &p2p).map_err(
                                    |e| {
                                        panic!("rendezvous connect error: {}", e)
                                    },
                                )
                            })
                            .map(|_socket| {
                                trace!("connected peer 0");
                                drop(server_drop_tx_0);
                            })
                    }));
                    unwrap!(res)
                }),
            );
            let node_1 = node::nat_v4(
                NatV4Builder::default(),
                node::endpoint_v4(move |_ip| {
                    let mut core = unwrap!(Core::new());
                    let handle = core.handle();

                    let res = core.run(future::lazy(|| {
                        Timeout::new(start_delay, &handle)
                        .infallible()
                        .and_then(|()| server_info_rx_1)
                        .map_err(|e| panic!("error getting server addr: {}", e))
                        .map(|server_info| {
                            let p2p = P2p::default();
                            p2p.add_udp_traversal_server(&server_info);
                            p2p
                        })
                        .and_then(|p2p| {
                            UdpSocket::rendezvous_connect(ch1, &handle, &p2p)
                            .map_err(|e| panic!("rendezvous connect error: {}", e))
                        })
                        .map(|_socket| {
                            trace!("connected peer 1");
                            drop(server_drop_tx_1);
                        })
                    }));
                    unwrap!(res)
                }),
            );

            let server_node = server_node
                .latency(Duration::from_millis(100), Duration::from_millis(10))
                .hops(2);

            let node_0 = node_0
                .latency(Duration::from_millis(200), Duration::from_millis(20))
                .hops(4)
                .packet_loss(0.1, Duration::from_millis(20));

            let node_1 = node_1
                .latency(Duration::from_millis(200), Duration::from_millis(20))
                .hops(4)
                .packet_loss(0.1, Duration::from_millis(20));

            let network = node::router_v4((server_node, node_0, node_1));

            let (join_handle, _plug) =
                netsim::spawn::network_v4(&handle, SubnetV4::global(), network);

            future_utils::thread_future(|| unwrap!(join_handle.join()))
            .map(|((), (), ())| ())
        }));
        res.void_unwrap()
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_no_delay() {
        udp_rendezvous_connect_between_natted_hosts(Duration::from_secs(0));
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_short_delay() {
        udp_rendezvous_connect_between_natted_hosts(Duration::from_secs(5));
    }

    #[test]
    fn udp_rendezvous_connect_between_natted_hosts_with_long_delay() {
        udp_rendezvous_connect_between_natted_hosts(Duration::from_secs(60));
    }
}
