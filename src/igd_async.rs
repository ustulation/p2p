use future_utils::thread_future;
use get_if_addrs::{self, IfAddr, Interface};
use igd::{self, AddAnyPortError, PortMappingProtocol, RemovePortError, SearchError};
use priv_prelude::*;

pub fn search_gateway_from_timeout(
    ipv4: Ipv4Addr,
    timeout: Duration,
) -> BoxFuture<Gateway, SearchError> {
    thread_future(move || {
        let res = igd::search_gateway_from_timeout(ipv4, timeout);
        let res = res.map(|gateway| Gateway { inner: gateway });
        res
    }).infallible()
        .and_then(|r| r)
        .into_boxed()
}

#[derive(Debug)]
pub struct Gateway {
    inner: igd::Gateway,
}

impl Gateway {
    /// Asynchronously maps local address to external one.
    ///
    /// # Returns
    ///
    /// Future that resolves to mapped external `IP:port`.
    pub fn get_any_address(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddrV4,
        lease_duration: u32,
        description: &str,
    ) -> BoxFuture<SocketAddrV4, GetAnyAddressError> {
        let description = String::from(description);
        let gateway = self.inner.clone();

        thread_future(move || {
            specified_local_addr_to_gateway(local_addr, *gateway.addr.ip())
                .map_err(|e| GetAnyAddressError::PathToGateway(e))
                .and_then(move |addr| {
                    gateway
                        .get_any_address(protocol, addr, lease_duration, &description)
                        .map_err(GetAnyAddressError::RequestPort)
                })
        }).infallible()
            .and_then(|r| r)
            .into_boxed()
    }

    /// Same as `get_any_address` except that we manually implement a timeout on the port. Used for
    /// routers which don't support timeouts on port allocations.
    pub fn get_any_address_manual_timeout(
        self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddrV4,
        timeout: Duration,
        description: &str,
        handle: &Handle,
    ) -> BoxFuture<SocketAddrV4, GetAnyAddressError> {
        let handle = handle.clone();
        self.get_any_address(protocol, local_addr, 0, description)
            .map(move |addr| {
                let port = addr.port();
                handle.spawn({
                    Timeout::new(timeout, &handle)
                .infallible()
                .and_then(move |()| {
                    self
                    .remove_port(protocol, port)
                })
                .log_error(LogLevel::Warn, "unregister router port")
                .infallible()
                });
                addr
            })
            .into_boxed()
    }

    pub fn remove_port(
        &self,
        protocol: PortMappingProtocol,
        port: u16,
    ) -> BoxFuture<(), RemovePortError> {
        let gateway = self.inner.clone();

        thread_future(move || gateway.remove_port(protocol, port))
            .infallible()
            .and_then(|r| r)
            .into_boxed()
    }
}

fn specified_local_addr_to_gateway(
    local_addr: SocketAddrV4,
    gateway_addr: Ipv4Addr,
) -> io::Result<SocketAddrV4> {
    if local_addr.ip().is_unspecified() {
        let addr = discover_local_addr_to_gateway(gateway_addr)?;
        Ok(SocketAddrV4::new(addr, local_addr.port()))
    } else {
        Ok(local_addr)
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum GetAnyAddressError {
        Ipv6NotSupported {
            description("IPv6 not supported for UPnP")
        }
        FindGateway(e: SearchError) {
            description("failed to find IGD gateway")
            display("failed to find IGD gateway: {}", e)
            cause(e)
        }
        PathToGateway(e: io::Error) {
            description("error finding path to gateway")
            display("error finding path to gateway: {}", e)
            cause(e)
        }
        RequestPort(e: AddAnyPortError) {
            description("error opening port on UPnP router")
            display("error opening port on UPnP router: {}", e)
            cause(e)
        }
        Disabled {
            description("IGD has been disabled in the library")
        }
    }
}

/// Used by the `rendezvous_addr` module. This function will try to temporarily open a port for you
/// during a rendezvous connect.
pub fn get_any_address_rendezvous(
    protocol: Protocol,
    local_addr: SocketAddr,
    timeout: Duration,
    handle: &Handle,
) -> BoxFuture<SocketAddr, GetAnyAddressError> {
    if !is_igd_enabled_for_rendezvous() {
        return future::err(GetAnyAddressError::Disabled).into_boxed();
    }

    get_any_address(protocol, local_addr, Some(timeout), handle)
}

/// Used by the `open_addr` module. This function will try to permanently open port for a server to
/// listen on.
pub fn get_any_address_open(
    protocol: Protocol,
    local_addr: SocketAddr,
    handle: &Handle,
) -> BoxFuture<SocketAddr, GetAnyAddressError> {
    get_any_address(protocol, local_addr, None, handle)
}

fn get_any_address(
    protocol: Protocol,
    local_addr: SocketAddr,
    timeout: Option<Duration>,
    handle: &Handle,
) -> BoxFuture<SocketAddr, GetAnyAddressError> {
    if !is_igd_enabled() {
        return future::err(GetAnyAddressError::Disabled).into_boxed();
    }

    let lease_duration = match timeout {
        None => 0,
        Some(duration) => duration.as_secs() as u32,
    };

    let handle = handle.clone();
    let try = || {
        let socket_addr_v4 = match local_addr {
            SocketAddr::V4(socket_addr_v4) => socket_addr_v4,
            SocketAddr::V6(..) => return Err(GetAnyAddressError::Ipv6NotSupported),
        };
        Ok({
            search_gateway_from_timeout(*socket_addr_v4.ip(), Duration::from_millis(200))
                .map_err(GetAnyAddressError::FindGateway)
                .and_then(move |gateway| {
                    let protocol = match protocol {
                        Protocol::Tcp => PortMappingProtocol::TCP,
                        Protocol::Udp => PortMappingProtocol::UDP,
                    };
                    // TODO(povilas): make port mapping description configurable
                    gateway
                        .get_any_address(protocol, socket_addr_v4, lease_duration, "p2p")
                        .or_else(move |e| {
                            if let GetAnyAddressError::RequestPort(
                                AddAnyPortError::OnlyPermanentLeasesSupported
                            ) = e {
                                if let Some(timeout) = timeout {
                                    return gateway.get_any_address_manual_timeout(
                                        protocol,
                                        socket_addr_v4,
                                        timeout,
                                        "p2p",
                                        &handle,
                                    );
                                }
                            }
                            return future::err(e).into_boxed();
                        })
                        .map(|addr| {
                            trace!("igd returned address {}", addr);
                            SocketAddr::V4(addr)
                        })
                })
        })
    };
    future::result(try()).flatten().into_boxed()
}

/// # Returns
///
/// Local IP address that is on the same subnet as gateway address. Returned address is always
/// IPv4 because gateway always has IPv4 address as well.
fn discover_local_addr_to_gateway(gateway_addr: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let ifs = get_if_addrs::get_if_addrs()?;
    local_addr_to_gateway(ifs, gateway_addr).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "No local addresses to gateway")
    })
}

fn local_addr_to_gateway(interfaces: Vec<Interface>, gateway_addr: Ipv4Addr) -> Option<Ipv4Addr> {
    for interface in interfaces {
        if let IfAddr::V4(addr) = interface.addr {
            if in_same_subnet(addr.ip, gateway_addr, addr.netmask) {
                return Some(addr.ip);
            }
        }
    }
    None
}

/// # Returns
///
/// `true` if given IP addresses are in the same subnet, `false` otherwise.
fn in_same_subnet(addr1: Ipv4Addr, addr2: Ipv4Addr, subnet_mask: Ipv4Addr) -> bool {
    addr1
        .octets()
        .iter()
        .zip(subnet_mask.octets().iter())
        .map(|(o1, o2)| o1 & o2)
        .eq(addr2.octets().iter().zip(subnet_mask.octets().iter()).map(
            |(o1, o2)| o1 & o2,
        ))
}

#[cfg(test)]
mod test {
    use super::*;
    use get_if_addrs::Ifv4Addr;

    fn interface(addr: Ipv4Addr, netmask: Ipv4Addr) -> Interface {
        let ipv4 = Ifv4Addr {
            ip: addr,
            netmask,
            broadcast: None,
        };
        Interface {
            name: "test-if".to_string(),
            addr: IfAddr::V4(ipv4),
        }
    }

    mod in_same_subnet {
        use super::*;

        #[test]
        fn it_returns_true_when_given_addresses_are_in_same_subnet() {
            assert!(in_same_subnet(
                ipv4!("192.168.1.1"),
                ipv4!("192.168.1.10"),
                ipv4!("255.255.255.0"),
            ));
        }

        #[test]
        fn it_returns_false_when_given_addresses_are_not_in_same_subnet() {
            assert!(!in_same_subnet(
                ipv4!("192.168.1.1"),
                ipv4!("172.10.0.5"),
                ipv4!("255.255.255.0"),
            ));
        }
    }

    mod local_addr_to_gateway {
        use super::*;

        #[test]
        fn it_returns_none_interfaces_list_is_empty() {
            let local_addr = local_addr_to_gateway(Vec::new(), ipv4!("192.168.1.1"));

            assert!(local_addr.is_none());
        }

        #[test]
        fn it_returns_none_when_no_interface_is_in_the_same_subnet_as_gateway() {
            let local_addr = local_addr_to_gateway(
                vec![interface(ipv4!("172.17.0.1"), ipv4!("255.255.0.0"))],
                ipv4!("192.168.1.1"),
            );

            assert!(local_addr.is_none());
        }

        #[test]
        fn it_returns_ip_address_of_the_interface_that_is_in_the_same_subnet_as_gateway() {
            let local_addr = local_addr_to_gateway(
                vec![
                    interface(ipv4!("172.17.0.1"), ipv4!("255.255.0.0")),
                    interface(ipv4!("192.168.1.100"), ipv4!("255.255.255.0")),
                ],
                ipv4!("192.168.1.1"),
            );

            assert_eq!(unwrap!(local_addr), ipv4!("192.168.1.100"));
        }
    }
}
