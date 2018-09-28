use futures::future::Loop;
use futures::stream::FuturesOrdered;
use igd_async::{self, GetAnyAddressError};
use priv_prelude::*;
use std::error::Error;

/// Wrapper around rendezvous connect error and IGD error.
#[derive(Debug)]
pub struct RendezvousAddrError {
    igd_error: GetAnyAddressError,
    kind: RendezvousAddrErrorKind,
}

impl RendezvousAddrError {
    /// If the error kind is `UnpredictablePorts`, returns `NatType` with port details.
    pub fn unpredictable_ports(&self) -> Option<NatType> {
        match self.kind {
            RendezvousAddrErrorKind::UnpredictablePorts(ref nat_type) => Some(nat_type.clone()),
            _ => None,
        }
    }
}

impl fmt::Display for RendezvousAddrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {}", self.igd_error, self.kind)
    }
}

impl Error for RendezvousAddrError {
    fn cause(&self) -> Option<&Error> {
        self.kind.cause()
    }

    fn description(&self) -> &str {
        self.kind.description()
    }
}

quick_error! {
    /// The actual type of `RendezvousAddrError`.
    #[derive(Debug)]
    pub enum RendezvousAddrErrorKind {
        /// Our public IP addresses received from traversal/STUN servers don't match.
        /// Such behavior is unexpected and we wouldn't know how to handle that.
        InconsistentIpAddrs(a0: IpAddr, a1: IpAddr) {
            description("traversal servers giving global IP addresses")
            display("traversal servers giving global IP addresses. Got both {} and {}", a0, a1)
        }
        /// NAT assigns us ports in an unpredictable manner. Hence we don't know what our public
        /// port would be when remote peer connected to us.
        UnpredictablePorts(nat: NatType) {
            display("NAT is not giving us consistent or predictable external ports.")
        }
        /// *p2p* only tolerates specific number of errors. If that exceeds, *p2p* stops trying.
        HitErrorLimit(v: Vec<Box<Error + Send>>) {
            description("hit error limit trying to contact traversal servers")
            display("hit error limit trying to contact traversal servers. \
                    Got {} errors: {:#?}", v.len(), v)
        }
        /// *p2p* doesn't have enough traversal servers to detect our public IP address.
        LackOfServers {
            description("more traversal servers needed to perform hole-punching")
        }
    }
}

/// When we are behind NAT, try to guess an address we could use for hole punching.
/// In addition NAT type is also returned.
pub fn rendezvous_addr(
    protocol: Protocol,
    bind_addr: &SocketAddr,
    handle: &Handle,
    p2p: &P2p,
) -> BoxFuture<(SocketAddr, NatType), RendezvousAddrError> {
    let bind_addr = *bind_addr;
    let handle = handle.clone();
    let p2p = p2p.clone();

    trace!("creating rendezvous addr");
    let timeout = Duration::from_secs(300);
    igd_async::get_any_address_rendezvous(protocol, bind_addr, timeout, &handle, &p2p)
        .map(|public_addr| (public_addr, NatType::None))
        .or_else(move |igd_error| {
            trace!("failed to open port with igd: {}", igd_error);
            public_addrs_from_stun(&handle, &p2p, protocol, bind_addr)
                .map_err(|kind| RendezvousAddrError { igd_error, kind })
                .map(move |(addr, nat_type)| {
                    if p2p.force_use_local_port() {
                        (SocketAddr::new(addr.ip(), bind_addr.port()), nat_type)
                    } else {
                        (addr, nat_type)
                    }
                })
        }).into_boxed()
}

fn public_addrs_from_stun(
    handle: &Handle,
    p2p: &P2p,
    protocol: Protocol,
    bind_addr: SocketAddr,
) -> impl Future<Item = (SocketAddr, NatType), Error = RendezvousAddrErrorKind> {
    let querier_stream = {
        let mut next_query_time = Timeout::new_at(Instant::now(), handle);
        let mut querier_stream = match protocol {
            Protocol::Tcp => {
                let handle = handle.clone();
                p2p.tcp_addr_queriers()
                    .with_readiness_timeout(Duration::from_secs(2), &handle)
                    .infallible()
                    .map(move |addr_querier| addr_querier.query(&bind_addr, &handle))
                    .into_boxed()
            }
            Protocol::Udp => {
                let handle = handle.clone();
                p2p.udp_addr_queriers()
                    .with_readiness_timeout(Duration::from_secs(2), &handle)
                    .infallible()
                    .map(move |addr_querier| addr_querier.query(&bind_addr, &handle))
                    .into_boxed()
            }
        };
        stream::poll_fn(move || {
            match next_query_time.poll().void_unwrap() {
                Async::Ready(()) => (),
                Async::NotReady => return Ok(Async::NotReady),
            }
            match querier_stream.poll().void_unwrap() {
                Async::Ready(Some(querier)) => {
                    next_query_time.reset(Instant::now() + Duration::from_millis(100));
                    Ok(Async::Ready(Some(querier)))
                }
                Async::Ready(None) => Ok(Async::Ready(None)),
                Async::NotReady => Ok(Async::NotReady),
            }
        }).into_boxed()
    };

    let errors = Vec::new();
    future::loop_fn(
        (querier_stream, errors),
        move |(querier_stream, mut errors)| {
            GuessPort::start(querier_stream).and_then(|res| match res {
                Ok(addr) => Ok(Loop::Break(addr)),
                Err((querier_stream, error)) => {
                    errors.push(error);
                    if errors.len() == 5 {
                        return Err(RendezvousAddrErrorKind::HitErrorLimit(errors));
                    }
                    Ok(Loop::Continue((querier_stream, errors)))
                }
            })
        },
    )
}

type QueryFuture = BoxFuture<SocketAddr, Box<Error + Send>>;
type GuessPortResult =
    Result<(SocketAddr, NatType), (BoxStream<QueryFuture, Void>, Box<Error + Send>)>;

struct GuessPort {
    known_ip_opt: Option<IpAddr>,
    known_ports: Vec<u16>,
    active_queriers: FuturesOrdered<QueryFuture>,
    querier_stream: Option<BoxStream<QueryFuture, Void>>,
}

impl GuessPort {
    fn start(
        querier_stream: BoxStream<BoxFuture<SocketAddr, Box<Error + Send>>, Void>,
    ) -> GuessPort {
        GuessPort {
            known_ip_opt: None,
            known_ports: Vec::new(),
            active_queriers: FuturesOrdered::new(),
            querier_stream: Some(querier_stream),
        }
    }

    /// Returns `true` when queriers stream is exhausted.
    fn poll_for_more_queriers(&mut self) -> bool {
        // keep max 3 responses
        while self.known_ports.len() + self.active_queriers.len() < 3 {
            match unwrap!(self.querier_stream.as_mut()).poll().void_unwrap() {
                Async::Ready(Some(querier)) => {
                    self.active_queriers.push(querier);
                }
                Async::Ready(None) => return true,
                Async::NotReady => break,
            }
        }
        false
    }

    fn handle_new_address(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Async<(SocketAddr, NatType)>, RendezvousAddrErrorKind> {
        let received_ip = addr.ip();
        let known_ip = match self.known_ip_opt {
            Some(known_ip) => known_ip,
            None => {
                self.known_ip_opt = Some(received_ip);
                received_ip
            }
        };
        if received_ip != known_ip {
            let err = RendezvousAddrErrorKind::InconsistentIpAddrs(received_ip, known_ip);
            return Err(err);
        }

        self.known_ports.push(addr.port());
        if self.known_ports.len() == 2 && self.known_ports[0] == self.known_ports[1] {
            // same port for multiple queries - endpoint independent mapping
            return Ok(Async::Ready((addr, NatType::EIM)));
        }

        if self.known_ports.len() == 3 {
            let diff0 = self.known_ports[1].wrapping_sub(self.known_ports[0]);
            let diff1 = self.known_ports[2].wrapping_sub(self.known_ports[1]);
            if diff0 == diff1 {
                let next_port = self.known_ports[2].wrapping_add(diff0);
                let addr = SocketAddr::new(known_ip, next_port);
                // different port for different queries - endpoint dependent mapping
                return Ok(Async::Ready((addr, NatType::EDM)));
            } else {
                let err = RendezvousAddrErrorKind::UnpredictablePorts(NatType::EDMRandomPorts(
                    self.known_ports.clone(),
                ));
                return Err(err);
            }
        }

        Ok(Async::NotReady)
    }

    fn queriers_exhausted(&mut self) -> Result<(SocketAddr, NatType), RendezvousAddrErrorKind> {
        info!("Unable to contact enough query servers to hole-punch reliably.");
        let known_ip = match self.known_ip_opt {
            Some(known_ip) => known_ip,
            None => {
                let err = RendezvousAddrErrorKind::LackOfServers;
                return Err(err);
            }
        };
        match self.known_ports.len() {
            0 => unreachable!(), // since we have known_ip we must have gotten a port
            1 => {
                info!("Guessing port based on only one response.");
                Ok((
                    SocketAddr::new(known_ip, self.known_ports[0]),
                    NatType::Unknown,
                ))
            }
            2 => {
                info!("Guessing port based on only two responses.");
                let diff = self.known_ports[1].wrapping_sub(self.known_ports[0]);
                let next_port = self.known_ports[1].wrapping_add(diff);
                Ok((SocketAddr::new(known_ip, next_port), NatType::EDM))
            }
            3 => {
                let err = RendezvousAddrErrorKind::UnpredictablePorts(NatType::EDMRandomPorts(
                    self.known_ports.clone(),
                ));
                Err(err)
            }
            _ => unreachable!(), // we never collect more than 3 ports,
        }
    }
}

impl Future for GuessPort {
    type Item = GuessPortResult;
    type Error = RendezvousAddrErrorKind;

    fn poll(&mut self) -> Result<Async<GuessPortResult>, RendezvousAddrErrorKind> {
        loop {
            let querier_stream_exhausted = self.poll_for_more_queriers();

            match self.active_queriers.poll() {
                Ok(Async::Ready(Some(addr))) => match self.handle_new_address(addr)? {
                    Async::Ready((addr, nat_type)) => return Ok(Async::Ready(Ok((addr, nat_type)))),
                    Async::NotReady => (),
                },
                Ok(Async::Ready(None)) => {
                    if querier_stream_exhausted {
                        let (addr, nat_type) = self.queriers_exhausted()?;
                        return Ok(Async::Ready(Ok((addr, nat_type))));
                    }
                    return Ok(Async::NotReady);
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => return Ok(Async::Ready(Err((unwrap!(self.querier_stream.take()), e)))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::Protocol;
    use tokio_core::reactor::Core;
    use udp::addr_querier::RemoteUdpRendezvousServer;
    use udp::rendezvous_server::UdpRendezvousServer;

    mod rendezvous_addr {
        use super::*;

        #[test]
        fn it_works_on_localhost() {
            let mut evloop = unwrap!(Core::new());
            let handle = evloop.handle();

            let server = unwrap!(UdpRendezvousServer::bind_reusable(
                &addr!("0.0.0.0:0"),
                &handle
            ));
            let server_addr = server.local_addr().unspecified_to_localhost();
            let server_pk = server.public_key();

            let p2p = P2p::default();
            p2p.disable_igd();
            p2p.disable_igd_for_rendezvous();
            p2p.add_udp_addr_querier(RemoteUdpRendezvousServer::new(server_addr, *server_pk));

            let task = rendezvous_addr(Protocol::Udp, &addr!("0.0.0.0:0"), &handle, &p2p)
                .map(|(our_addr, _nat_type)| our_addr);
            let our_addr = unwrap!(evloop.run(task));

            assert_eq!(our_addr.ip(), ipv4!("127.0.0.1"));
        }
    }
}
