use igd_async::{self, GetAnyAddressError};
use mc;
use priv_prelude::*;
use std::error::Error;

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
    #[derive(Debug)]
    pub enum RendezvousAddrErrorKind {
        InconsistentIpAddrs(a0: IpAddr, a1: IpAddr) {
            description("traversal servers giving global IP addresses")
            display("traversal servers giving global IP addresses. Got both {} and {}", a0, a1)
        }
        UnpredictablePorts(p0: u16, p1: u16, p2: u16) {
            description("NAT is not giving us consistent or predictable external ports")
            display("NAT is not giving us consistent or predictable external ports. \
                    Got {}, then {}, then {}", p0, p1, p2)
        }
        HitErrorLimit(v: Vec<QueryPublicAddrError>) {
            description("hit error limit trying to contact traversal servers")
            display("hit error limit trying to contact traversal servers. \
                    Got {} errors: {:#?}", v.len(), v)
        }
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
    let mut servers = mc.iter_servers(protocol);
    let mut more_servers_timeout = None::<Timeout>;
    let mc0 = mc.clone();

    trace!("creating rendezvous addr");
    let timeout = Duration::from_secs(300);
    igd_async::get_any_address_rendezvous(protocol, bind_addr, timeout, &handle, mc)
        .or_else(move |igd_error| {
            trace!("failed to open port with igd: {}", igd_error);
            let mut public_addr_fut = PublicAddrsFromStun::new(igd_error);
            future::poll_fn(move || loop {
                trace!("in rendezvous_addr loop");
                match public_addr_fut.poll() {
                    Ok(Async::Ready(addr)) => return Ok(Async::Ready(addr)),
                    Err(e) => return Err(e),
                    _ => (),
                };

                if public_addr_fut.stun_queries.len() == 3 {
                    return Ok(Async::NotReady);
                }

                match servers.poll().void_unwrap() {
                    Async::Ready(Some(server_addr)) => {
                        trace!("got a new server to try: {}", server_addr);
                        let active_query =
                            mc::query_public_addr(protocol, &bind_addr, &server_addr, &handle);
                        public_addr_fut.add_stun_query(active_query);
                        more_servers_timeout = None;
                    }
                    Async::Ready(None) => {
                        trace!(
                            "run out of rendezvous servers with {} active queries, {} ports",
                            public_addr_fut.stun_queries.len(),
                            public_addr_fut.ports.len()
                        );
                        if public_addr_fut.stun_queries.is_empty() {
                            if public_addr_fut.ports.len() == 1 {
                                let ip = unwrap!(public_addr_fut.known_ip_opt);
                                return Ok(
                                    Async::Ready(SocketAddr::new(ip, public_addr_fut.ports[0])),
                                );
                            }
                            return Err(RendezvousAddrError {
                                igd_error: unwrap!(public_addr_fut.igd_error.take()),
                                kind: RendezvousAddrErrorKind::LackOfServers,
                            });
                        }
                    }
                    Async::NotReady => {
                        trace!("no new rendezvous servers ready");
                        if public_addr_fut.stun_queries.is_empty() {
                            trace!("waiting for more rendezvous servers...");
                            loop {
                                if let Some(ref mut timeout) = more_servers_timeout {
                                    if let Async::Ready(()) = timeout.poll().void_unwrap() {
                                        trace!("... timed out");
                                        if public_addr_fut.ports.len() == 1 {
                                            let ip = unwrap!(public_addr_fut.known_ip_opt);
                                            return Ok(Async::Ready(
                                                SocketAddr::new(ip, public_addr_fut.ports[0])));
                                        }
                                        return Err(RendezvousAddrError {
                                            igd_error: unwrap!(public_addr_fut.igd_error.take()),
                                            kind: RendezvousAddrErrorKind::LackOfServers,
                                        });
                                    }
                                    break;
                                } else {
                                    more_servers_timeout =
                                        Some(Timeout::new(Duration::from_secs(2), &handle));
                                }
                            }
                        }
                        return Ok(Async::NotReady);
                    }
                }
            }).map(move |addr| if mc0.force_use_local_port() {
                SocketAddr::new(addr.ip(), bind_addr.port())
            } else {
                addr
            })
        })
        .into_boxed()
}

/// Handles STUN queries.
///
/// It returns our public address if:
/// * we received 2 responses with the same port. That means router is consistently giving us the
///   same port for the same bind address.
/// * we received 3 responses with different ports but same difference between those ports.
///   In this case we guess the future address using consistent differece between ports.
struct PublicAddrsFromStun {
    stun_queries: stream::FuturesOrdered<BoxFuture<SocketAddr, QueryPublicAddrError>>,
    ports: Vec<u16>,
    errors: Vec<QueryPublicAddrError>,
    known_ip_opt: Option<IpAddr>,
    igd_error: Option<GetAnyAddressError>,
    failed_sequences: usize,
    max_stun_errors: usize,
}

impl PublicAddrsFromStun {
    /// Constructs future that yields our public IP address.
    /// This code is only meant to be used, if IGD fails. Hence, IGD error must be always passed.
    fn new(igd_error: GetAnyAddressError) -> PublicAddrsFromStun {
        PublicAddrsFromStun {
            stun_queries:
                stream::FuturesOrdered::<BoxFuture<SocketAddr, QueryPublicAddrError>>::new(),
            ports: Vec::new(),
            errors: Vec::new(),
            known_ip_opt: None,
            igd_error: Some(igd_error),
            failed_sequences: 0,
            max_stun_errors: 5,
        }
    }

    fn add_stun_query(&mut self, query: BoxFuture<SocketAddr, QueryPublicAddrError>) {
        self.stun_queries.push(query)
    }
}

impl Future for PublicAddrsFromStun {
    type Item = SocketAddr;
    type Error = RendezvousAddrError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
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
                            self.ports.remove(0);
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

#[cfg(test)]
mod tests {
    use super::*;

    mod public_addrs_from_stun {
        use super::*;

        mod poll {
            use super::*;
            use tokio_core::reactor::Core;

            #[test]
            fn it_returns_address_when_same_port_is_returned_twice_by_stun_queries() {
                let mut evloop = unwrap!(Core::new());

                let mut public_addrs = PublicAddrsFromStun::new(GetAnyAddressError::Disabled);

                let addr_fut = future::ok::<SocketAddr, QueryPublicAddrError>(
                    addr!("1.2.3.4:4000"),
                ).into_boxed();
                public_addrs.add_stun_query(addr_fut);
                let addr_fut = future::ok::<SocketAddr, QueryPublicAddrError>(
                    addr!("1.2.3.4:4000"),
                ).into_boxed();
                public_addrs.add_stun_query(addr_fut);

                let poll_addrs = future::poll_fn(|| {
                    let _ = public_addrs.poll(); // consume 1st address
                    public_addrs.poll() // consume 2nd address
                });

                let addr = unwrap!(evloop.run(poll_addrs));

                assert_eq!(addr, addr!("1.2.3.4:4000"));
            }

            #[test]
            fn it_returns_error_when_stun_query_error_limit_is_reached() {
                let mut evloop = unwrap!(Core::new());
                let mut public_addrs = PublicAddrsFromStun::new(GetAnyAddressError::Disabled);
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
