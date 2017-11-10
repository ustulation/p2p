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
) -> BoxFuture<SocketAddr, RendezvousAddrError> {
    let bind_addr = *bind_addr;
    let handle = handle.clone();
    let mut servers = mc::traversal_servers(protocol);
    let mut active_queries =
        stream::FuturesOrdered::<BoxFuture<SocketAddr, QueryPublicAddrError>>::new();
    let mut errors = Vec::new();
    let mut more_servers_timeout = None::<Timeout>;
    let mut ports = Vec::new();
    let mut known_ip_opt = None;
    let mut failed_sequences = 0;

    igd_async::get_any_address(protocol, bind_addr)
        .or_else(move |igd_error| {
            let mut igd_error = Some(igd_error);
            future::poll_fn(move || loop {
                trace!("in rendezvous_addr loop");
                match active_queries.poll() {
                    Err(e) => {
                        trace!("query returned error: {}", e);
                        errors.push(e);
                    }
                    Ok(Async::Ready(Some(addr))) => {
                        trace!("query returned address: {}", addr);
                        let ip = addr.ip();
                        if IpAddrExt::is_global(&ip) {
                            if let Some(known_ip) = known_ip_opt {
                                if known_ip != ip {
                                    return Err(RendezvousAddrError {
                                        igd_error: unwrap!(igd_error.take()),
                                        kind: RendezvousAddrErrorKind::InconsistentIpAddrs(
                                            known_ip,
                                            ip,
                                        ),
                                    });
                                }
                            }
                            known_ip_opt = Some(ip);
                            ports.push(addr.port());
                            if ports.len() == 2 {
                                if ports[0] == ports[1] {
                                    return Ok(Async::Ready(SocketAddr::new(ip, ports[0])));
                                }
                            }
                            if ports.len() == 3 {
                                let diff0 = ports[1].wrapping_sub(ports[0]);
                                let diff1 = ports[2].wrapping_sub(ports[1]);
                                if diff0 == diff1 {
                                    return Ok(Async::Ready(
                                        SocketAddr::new(ip, ports[2].wrapping_add(diff0)),
                                    ));
                                } else {
                                    ports.remove(0);
                                    failed_sequences += 1;
                                    if failed_sequences >= 3 {
                                        return Err(RendezvousAddrError {
                                            igd_error: unwrap!(igd_error.take()),
                                            kind: RendezvousAddrErrorKind::UnpredictablePorts(
                                                ports[0],
                                                ports[1],
                                                ports[2],
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => (),
                }

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
                        if active_queries.len() == 0 {
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
                        if active_queries.len() == 0 {
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
            })
        })
        .into_boxed()
}
