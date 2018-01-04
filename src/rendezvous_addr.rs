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
    let mut active_queries =
        stream::FuturesOrdered::<BoxFuture<SocketAddr, QueryPublicAddrError>>::new();
    let mut errors = Vec::new();
    let mut more_servers_timeout = None::<Timeout>;
    let mut ports = Vec::new();
    let mut known_ip_opt = None;
    let mut failed_sequences = 0;
    let mc0 = mc.clone();

    trace!("creating rendezvous addr");
    let timeout = Duration::from_secs(300);
    igd_async::get_any_address_rendezvous(protocol, bind_addr, timeout, &handle, mc)
        .or_else(move |igd_error| {
            trace!("failed to open port with igd: {}", igd_error);
            let mut igd_error = Some(igd_error);
            future::poll_fn(move || loop {
                trace!("in rendezvous_addr loop");
                let res = PublicAddrsFromStun {
                    stun_queries: &mut active_queries,
                    ports: &mut ports,
                    errors: &mut errors,
                    known_ip_opt: &mut known_ip_opt,
                    igd_error: &mut igd_error,
                    failed_sequences: &mut failed_sequences,
                }.poll();
                match res {
                    Ok(Async::Ready(addr)) => return Ok(Async::Ready(addr)),
                    Err(e) => return Err(e),
                    _ => (),
                };

                if errors.len() >= 5 {
                    let errors = mem::replace(&mut errors, Vec::new());
                    return Err(RendezvousAddrError {
                        igd_error: unwrap!(igd_error.take()),
                        kind: RendezvousAddrErrorKind::HitErrorLimit(errors),
                    });
                }

                if active_queries.len() == 3 {
                    return Ok(Async::NotReady);
                }

                match servers.poll().void_unwrap() {
                    Async::Ready(Some(server_addr)) => {
                        trace!("got a new server to try: {}", server_addr);
                        let active_query =
                            mc::query_public_addr(protocol, &bind_addr, &server_addr, &handle);
                        active_queries.push(active_query);
                        more_servers_timeout = None;
                    }
                    Async::Ready(None) => {
                        trace!(
                            "run out of rendezvous servers with {} active queries, {} ports",
                            active_queries.len(),
                            ports.len()
                        );
                        if active_queries.is_empty() {
                            if ports.len() == 1 {
                                let ip = unwrap!(known_ip_opt);
                                return Ok(Async::Ready(SocketAddr::new(ip, ports[0])));
                            }
                            return Err(RendezvousAddrError {
                                igd_error: unwrap!(igd_error.take()),
                                kind: RendezvousAddrErrorKind::LackOfServers,
                            });
                        }
                    }
                    Async::NotReady => {
                        trace!("no new rendezvous servers ready");
                        if active_queries.is_empty() {
                            trace!("waiting for more rendezvous servers...");
                            loop {
                                if let Some(ref mut timeout) = more_servers_timeout {
                                    if let Async::Ready(()) = timeout.poll().void_unwrap() {
                                        trace!("... timed out");
                                        if ports.len() == 1 {
                                            let ip = unwrap!(known_ip_opt);
                                            return Ok(Async::Ready(SocketAddr::new(ip, ports[0])));
                                        }
                                        return Err(RendezvousAddrError {
                                            igd_error: unwrap!(igd_error.take()),
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
struct PublicAddrsFromStun<'a> {
    stun_queries: &'a mut stream::FuturesOrdered<BoxFuture<SocketAddr, QueryPublicAddrError>>,
    ports: &'a mut Vec<u16>,
    errors: &'a mut Vec<QueryPublicAddrError>,
    known_ip_opt: &'a mut Option<IpAddr>,
    igd_error: &'a mut Option<GetAnyAddressError>,
    failed_sequences: &'a mut usize,
}

impl<'a> Future for PublicAddrsFromStun<'a> {
    type Item = SocketAddr;
    type Error = RendezvousAddrError;

    // Note, that this is in the process of refactoring and it has way more side effects than
    // I'd like it to.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.stun_queries.poll() {
            Err(e) => {
                trace!("query returned error: {}", e);
                self.errors.push(e);
                Ok(Async::NotReady)
            }
            Ok(Async::Ready(Some(addr))) => {
                trace!("query returned address: {}", addr);
                let ip = addr.ip();
                if IpAddrExt::is_global(&ip) {
                    if let Some(known_ip) = *self.known_ip_opt {
                        if known_ip != ip {
                            return Err(RendezvousAddrError {
                                igd_error: unwrap!(self.igd_error.take()),
                                kind: RendezvousAddrErrorKind::InconsistentIpAddrs(known_ip, ip),
                            });
                        }
                    }
                    *self.known_ip_opt = Some(ip);
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
                            *self.failed_sequences += 1;
                            if *self.failed_sequences >= 3 {
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

                let mut errors = Vec::new();
                let mut ports = Vec::new();
                let mut known_ip_opt = None;
                let mut igd_error = None;
                let mut failed_sequences = 0;

                let mut stun_queries = stream::FuturesOrdered::new();
                let addr_fut = future::ok::<SocketAddr, QueryPublicAddrError>(
                    addr!("1.2.3.4:4000"),
                ).into_boxed();
                stun_queries.push(addr_fut);
                let addr_fut = future::ok::<SocketAddr, QueryPublicAddrError>(
                    addr!("1.2.3.4:4000"),
                ).into_boxed();
                stun_queries.push(addr_fut);

                let mut public_addrs = PublicAddrsFromStun {
                    stun_queries: &mut stun_queries,
                    ports: &mut ports,
                    errors: &mut errors,
                    known_ip_opt: &mut known_ip_opt,
                    igd_error: &mut igd_error,
                    failed_sequences: &mut failed_sequences,
                };
                let poll_addrs = future::poll_fn(|| {
                    let _ = public_addrs.poll(); // consume 1st address
                    public_addrs.poll() // consume 2nd address
                });

                let addr = unwrap!(evloop.run(poll_addrs));

                assert_eq!(addr, addr!("1.2.3.4:4000"));
            }
        }
    }
}
