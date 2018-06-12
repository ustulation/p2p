use futures::future::Loop;
use igd_async::{self, GetAnyAddressError};
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
        HitErrorLimit(v: Vec<Box<Error>>) {
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
    p2p: &P2p,
) -> BoxFuture<SocketAddr, RendezvousAddrError> {
    let bind_addr = *bind_addr;
    let handle = handle.clone();
    let p2p = p2p.clone();

    trace!("creating rendezvous addr");
    let timeout = Duration::from_secs(300);
    igd_async::get_any_address_rendezvous(protocol, bind_addr, timeout, &handle, &p2p)
        .or_else(move |igd_error| {
            trace!("failed to open port with igd: {}", igd_error);
            public_addrs_from_stun(&handle, &p2p, protocol, bind_addr)
                .map_err(|kind| RendezvousAddrError { igd_error, kind })
                .map(move |addr| {
                    if p2p.force_use_local_port() {
                        SocketAddr::new(addr.ip(), bind_addr.port())
                    } else {
                        addr
                    }
                })
        })
        .into_boxed()
}

fn public_addrs_from_stun(
    handle: &Handle,
    p2p: &P2p,
    protocol: Protocol,
    bind_addr: SocketAddr,
) -> impl Future<Item = SocketAddr, Error = RendezvousAddrErrorKind> {
    const NUM_PARALLEL_QUERIES: usize = 3;

    let incoming_addrs = match protocol {
        Protocol::Tcp => {
            let handle = handle.clone();
            p2p.tcp_addr_queriers()
                .with_readiness_timeout(Duration::from_secs(2), &handle)
                .infallible()
                .map(move |addr_querier| addr_querier.query(&bind_addr, &handle))
                .buffer_unordered(NUM_PARALLEL_QUERIES)
                .into_boxed()
        }
        Protocol::Udp => {
            let handle = handle.clone();
            p2p.udp_addr_queriers()
                .with_readiness_timeout(Duration::from_secs(2), &handle)
                .infallible()
                .map(move |addr_querier| addr_querier.query(&bind_addr, &handle))
                .buffer_unordered(NUM_PARALLEL_QUERIES)
                .into_boxed()
        }
    };

    let errors = Vec::new();
    let known_ip_opt = None;
    let known_ports = Vec::new();
    future::loop_fn(
        (errors, known_ip_opt, known_ports, incoming_addrs),
        move |(mut errors, mut known_ip_opt, mut known_ports, incoming_addrs)| {
            incoming_addrs.into_future().then(move |res| match res {
                Err((e, incoming_addrs)) => {
                    errors.push(e);
                    if errors.len() == 5 {
                        return Err(RendezvousAddrErrorKind::HitErrorLimit(errors));
                    }
                    Ok(Loop::Continue((
                        errors,
                        known_ip_opt,
                        known_ports,
                        incoming_addrs,
                    )))
                }
                Ok((incoming_addr_opt, incoming_addrs)) => {
                    let incoming_addr = match incoming_addr_opt {
                        Some(incoming_addr) => incoming_addr,
                        None => {
                            if let Some(known_ip) = known_ip_opt {
                                return Ok(Loop::Break(SocketAddr::new(known_ip, known_ports[0])));
                            }
                            return Err(RendezvousAddrErrorKind::LackOfServers);
                        }
                    };

                    known_ports.push(incoming_addr.port());
                    let known_ip = match known_ip_opt {
                        Some(known_ip) => known_ip,
                        None => {
                            known_ip_opt = Some(incoming_addr.ip());
                            return Ok(Loop::Continue((
                                errors,
                                known_ip_opt,
                                known_ports,
                                incoming_addrs,
                            )));
                        }
                    };

                    if known_ip != incoming_addr.ip() {
                        return Err(RendezvousAddrErrorKind::InconsistentIpAddrs(
                            known_ip,
                            incoming_addr.ip(),
                        ));
                    }

                    if known_ports.len() == 2 {
                        if known_ports[0] == known_ports[1] {
                            return Ok(Loop::Break(SocketAddr::new(known_ip, known_ports[0])));
                        }
                        return Ok(Loop::Continue((
                            errors,
                            known_ip_opt,
                            known_ports,
                            incoming_addrs,
                        )));
                    }

                    let num_known_ports = known_ports.len();
                    let port0 = known_ports[num_known_ports - 3];
                    let port1 = known_ports[num_known_ports - 2];
                    let port2 = known_ports[num_known_ports - 1];
                    let diff0 = port1.wrapping_sub(port0);
                    let diff1 = port2.wrapping_sub(port1);

                    if diff0 == diff1 {
                        let port = port2.wrapping_add(diff0);
                        return Ok(Loop::Break(SocketAddr::new(known_ip, port)));
                    }

                    if num_known_ports > 5 {
                        return Err(RendezvousAddrErrorKind::UnpredictablePorts(
                            port0, port1, port2,
                        ));
                    }
                    Ok(Loop::Continue((
                        errors,
                        known_ip_opt,
                        known_ports,
                        incoming_addrs,
                    )))
                }
            })
        },
    )
}
