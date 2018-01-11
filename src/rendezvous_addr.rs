use igd_async::{self, GetAnyAddressError};
use mc;
use priv_prelude::*;
use std::error::Error;

/// Wrapper around rendezvous connect error and IGD error.
#[derive(Debug)]
pub struct RendezvousAddrError {
    igd_error: GetAnyAddressError,
    kind: RendezvousAddrErrorKind,
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
        UnpredictablePorts(p0: u16, p1: u16, p2: u16) {
            description("NAT is not giving us consistent or predictable external ports")
            display("NAT is not giving us consistent or predictable external ports. \
                    Got {}, then {}, then {}", p0, p1, p2)
        }
        /// *p2p* only tolerates specific number of errors. If that exceeds, *p2p* stops trying.
        HitErrorLimit(v: Vec<QueryPublicAddrError>) {
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

pub fn rendezvous_addr(
    protocol: Protocol,
    bind_addr: &SocketAddr,
    handle: &Handle,
    mc: &P2p,
) -> BoxFuture<SocketAddr, RendezvousAddrError> {
    let bind_addr = *bind_addr;
    let handle = handle.clone();
    let mc0 = mc.clone();

    trace!("creating rendezvous addr");
    let timeout = Duration::from_secs(300);
    igd_async::get_any_address_rendezvous(protocol, bind_addr, timeout, &handle, mc)
        .or_else(move |igd_error| {
            trace!("failed to open port with igd: {}", igd_error);
            PublicAddrsFromStun::new(handle.clone(), mc0.clone(), protocol, bind_addr, igd_error)
                .map(move |addr| if mc0.force_use_local_port() {
                    SocketAddr::new(addr.ip(), bind_addr.port())
                } else {
                    addr
                })
        })
        .into_boxed()
}

/// Does the heavy lifting of public address determination.
struct PublicAddrsFromStun {
    handle: Handle,
    p2p: P2p,
    protocol: Protocol,
    bind_addr: SocketAddr,
    stun_queries: stream::FuturesOrdered<BoxFuture<SocketAddr, QueryPublicAddrError>>,
    ports: Vec<u16>,
    errors: Vec<QueryPublicAddrError>,
    known_ip_opt: Option<IpAddr>,
    igd_error: Option<GetAnyAddressError>,
    failed_sequences: usize,
    max_stun_errors: usize,
    keep_querying_stun: bool,
    more_servers_timeout: Option<Timeout>,
}

impl PublicAddrsFromStun {
    /// Constructs future that yields our public IP address.
    /// This code is only meant to be used, if IGD fails. Hence, IGD error must be always passed.
    fn new(
        handle: Handle,
        p2p: P2p,
        protocol: Protocol,
        bind_addr: SocketAddr,
        igd_error: GetAnyAddressError,
    ) -> PublicAddrsFromStun {
        PublicAddrsFromStun {
            handle,
            p2p,
            protocol,
            bind_addr,
            stun_queries:
                stream::FuturesOrdered::<BoxFuture<SocketAddr, QueryPublicAddrError>>::new(),
            ports: Vec::new(),
            errors: Vec::new(),
            known_ip_opt: None,
            igd_error: Some(igd_error),
            failed_sequences: 0,
            max_stun_errors: 5,
            keep_querying_stun: false,
            more_servers_timeout: None,
        }
    }

    /// Constructs `PublicAddrsFromStun` with convenient defaults for testing.
    #[cfg(test)]
    fn with_defaults(handle: Handle, igd_error: GetAnyAddressError) -> PublicAddrsFromStun {
        PublicAddrsFromStun::new(
            handle,
            P2p::default(),
            Protocol::Udp,
            addr!("0.0.0.0:0"),
            igd_error,
        )
    }

    fn add_stun_query(&mut self, query: BoxFuture<SocketAddr, QueryPublicAddrError>) {
        self.stun_queries.push(query)
    }

    /// Polls for new STUN servers. If there are some, adds new STUN queries.
    fn poll_stun_servers(&mut self) -> Poll<SocketAddr, RendezvousAddrError> {
        let mut servers = self.p2p.iter_servers(self.protocol);
        self.keep_querying_stun = false;
        match servers.poll().void_unwrap() {
            Async::Ready(Some(server_addr)) => {
                trace!("got a new server to try: {}", server_addr);
                let active_query = mc::query_public_addr(
                    self.protocol,
                    &self.bind_addr,
                    &server_addr,
                    &self.handle,
                );
                self.add_stun_query(active_query);
                self.more_servers_timeout = None;
                self.keep_querying_stun = true;
                Ok(Async::NotReady)
            }
            Async::Ready(None) => {
                trace!(
                    "run out of rendezvous servers with {} active queries, {} ports",
                    self.stun_queries.len(),
                    self.ports.len()
                );
                if self.stun_queries.is_empty() {
                    if self.ports.len() == 1 {
                        let ip = unwrap!(self.known_ip_opt);
                        return Ok(Async::Ready(SocketAddr::new(ip, self.ports[0])));
                    }
                    return Err(RendezvousAddrError {
                        igd_error: unwrap!(self.igd_error.take()),
                        kind: RendezvousAddrErrorKind::LackOfServers,
                    });
                }
                self.keep_querying_stun = true;
                Ok(Async::NotReady)
            }
            Async::NotReady => {
                trace!("no new rendezvous servers ready");
                if self.stun_queries.is_empty() {
                    trace!("waiting for more rendezvous servers...");
                    loop {
                        if let Some(ref mut timeout) = self.more_servers_timeout {
                            if let Async::Ready(()) = timeout.poll().void_unwrap() {
                                trace!("... timed out");
                                if self.ports.len() == 1 {
                                    let ip = unwrap!(self.known_ip_opt);
                                    return Ok(Async::Ready(
                                        SocketAddr::new(ip, self.ports[0])));
                                }
                                return Err(RendezvousAddrError {
                                    igd_error: unwrap!(self.igd_error.take()),
                                    kind: RendezvousAddrErrorKind::LackOfServers,
                                });
                            }
                            break;
                        } else {
                            self.more_servers_timeout =
                                Some(Timeout::new(Duration::from_secs(2), &self.handle));
                        }
                    }
                }
                Ok(Async::NotReady)
            }
        }
    }

    /// Handles STUN queries.
    ///
    /// It returns our public address if:
    /// * we received 2 responses with the same port. That means router is consistently giving us
    ///   the same port for the same bind address.
    /// * we received 3 responses with different ports but same difference between those ports.
    ///   In this case we guess the future address using consistent differece between ports.
    fn poll_stun_queries(&mut self) -> Poll<SocketAddr, RendezvousAddrError> {
        match self.stun_queries.poll() {
            Err(e) => {
                trace!("query returned error: {}", e);
                self.errors.push(e);
                if self.errors.len() >= self.max_stun_errors {
                    let errors = mem::replace(&mut self.errors, Vec::new());
                    Err(RendezvousAddrError {
                        igd_error: unwrap!(self.igd_error.take()),
                        kind: RendezvousAddrErrorKind::HitErrorLimit(errors),
                    })
                } else {
                    Ok(Async::NotReady)
                }
            }
            Ok(Async::Ready(Some(addr))) => {
                trace!("query returned address: {}", addr);
                let ip = addr.ip();
                if IpAddrExt::is_global(&ip) {
                    if let Some(known_ip) = self.known_ip_opt {
                        if known_ip != ip {
                            return Err(RendezvousAddrError {
                                igd_error: unwrap!(self.igd_error.take()),
                                kind: RendezvousAddrErrorKind::InconsistentIpAddrs(known_ip, ip),
                            });
                        }
                    }
                    self.known_ip_opt = Some(ip);
                    self.ports.push(addr.port());
                    if self.ports.len() == 2 && self.ports[0] == self.ports[1] {
                        return Ok(Async::Ready(SocketAddr::new(ip, self.ports[0])));
                    }
                    if self.ports.len() == 3 {
                        let diff0 = self.ports[1].wrapping_sub(self.ports[0]);
                        let diff1 = self.ports[2].wrapping_sub(self.ports[1]);
                        if diff0 == diff1 {
                            return Ok(Async::Ready(
                                SocketAddr::new(ip, self.ports[2].wrapping_add(diff0)),
                            ));
                        } else {
                            let _ = self.ports.remove(0);
                            self.failed_sequences += 1;
                            if self.failed_sequences >= 3 {
                                return Err(RendezvousAddrError {
                                    igd_error: unwrap!(self.igd_error.take()),
                                    kind: RendezvousAddrErrorKind::UnpredictablePorts(
                                        self.ports[0],
                                        self.ports[1],
                                        self.ports[2],
                                    ),
                                });
                            }
                        }
                    }
                }
                Ok(Async::NotReady)
            }
            _ => Ok(Async::NotReady),
        }
    }
}

impl Future for PublicAddrsFromStun {
    type Item = SocketAddr;
    type Error = RendezvousAddrError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            trace!("in PublicAddrsFromStun::poll() loop");
            match self.poll_stun_queries() {
                Ok(Async::Ready(addr)) => return Ok(Async::Ready(addr)),
                Err(e) => return Err(e),
                _ => (),
            };

            if self.stun_queries.len() == 3 {
                return Ok(Async::NotReady);
            }

            match self.poll_stun_servers() {
                Err(e) => return Err(e),
                Ok(Async::Ready(addr)) => return Ok(Async::Ready(addr)),
                Ok(Async::NotReady) => {
                    if !self.keep_querying_stun {
                        return Ok(Async::NotReady);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod public_addrs_from_stun {
        use super::*;
        use tokio_core::reactor::Core;

        mod poll_stun_servers {
            use super::*;

            #[test]
            fn it_notifies_that_stun_servers_should_be_queried_when_new_servers_are_polled() {
                let mut evloop = unwrap!(Core::new());

                let p2p = P2p::default();
                p2p.add_udp_traversal_server(&addr!("1.2.3.4:4000"));
                let mut public_addrs = PublicAddrsFromStun::new(
                    evloop.handle(),
                    p2p,
                    Protocol::Udp,
                    addr!("0.0.0.0:0"),
                    GetAnyAddressError::Disabled,
                );

                {
                    let poll_stun = future::poll_fn(|| match public_addrs.poll_stun_servers() {
                        Ok(Async::NotReady) => Ok(Async::Ready(())),
                        Err(e) => Err(e),
                        _ => panic!("Unexpected poll_stun_servers() result!"),
                    });
                    unwrap!(evloop.run(poll_stun));
                }

                assert!(public_addrs.keep_querying_stun);
            }
        }

        mod poll_stun_queries {
            use super::*;

            #[test]
            fn it_returns_address_when_same_port_is_returned_twice_by_stun_queries() {
                let mut evloop = unwrap!(Core::new());

                let mut public_addrs = PublicAddrsFromStun::with_defaults(
                    evloop.handle(),
                    GetAnyAddressError::Disabled,
                );

                let addr_fut = future::ok::<SocketAddr, QueryPublicAddrError>(
                    addr!("1.2.3.4:4000"),
                ).into_boxed();
                public_addrs.add_stun_query(addr_fut);
                let addr_fut = future::ok::<SocketAddr, QueryPublicAddrError>(
                    addr!("1.2.3.4:4000"),
                ).into_boxed();
                public_addrs.add_stun_query(addr_fut);

                let poll_addrs = future::poll_fn(|| {
                    let _ = public_addrs.poll_stun_queries(); // consume 1st address
                    public_addrs.poll_stun_queries() // consume 2nd address
                });

                let addr = unwrap!(evloop.run(poll_addrs));

                assert_eq!(addr, addr!("1.2.3.4:4000"));
            }

            #[test]
            fn it_returns_error_when_stun_query_error_limit_is_reached() {
                let mut evloop = unwrap!(Core::new());
                let mut public_addrs = PublicAddrsFromStun::with_defaults(
                    evloop.handle(),
                    GetAnyAddressError::Disabled,
                );
                public_addrs.max_stun_errors = 2;

                let addr_fut = future::err(QueryPublicAddrError::ResponseTimeout).into_boxed();
                public_addrs.add_stun_query(addr_fut);
                let addr_fut = future::err(QueryPublicAddrError::ResponseTimeout).into_boxed();
                public_addrs.add_stun_query(addr_fut);

                let poll_addrs = future::poll_fn(|| {
                    let _ = public_addrs.poll_stun_queries(); // consume 1st address
                    public_addrs.poll_stun_queries() // consume 2nd address
                });

                let res = evloop.run(poll_addrs);

                assert!(res.is_err());
                let error_limit_reached = match unwrap!(res.err()).kind {
                    RendezvousAddrErrorKind::HitErrorLimit(_) => true,
                    _ => false,
                };
                assert!(error_limit_reached);
            }
        }
    }
}
