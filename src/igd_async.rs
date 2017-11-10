use futures::sync::oneshot;
use get_if_addrs::{self, IfAddr, Interface};
use igd::{self, AddAnyPortError, PortMappingProtocol, RequestError, SearchError};
use priv_prelude::*;

use std::thread;

#[derive(Debug)]
pub struct SearchGatewayFromTimeout {
    rx: oneshot::Receiver<Result<Gateway, SearchError>>,
}

impl Future for SearchGatewayFromTimeout {
    type Item = Gateway;
    type Error = SearchError;

    fn poll(&mut self) -> Result<Async<Gateway>, SearchError> {
        match unwrap!(self.rx.poll()) {
            Async::Ready(res) => Ok(Async::Ready(res?)),
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}

pub fn search_gateway_from_timeout(ipv4: Ipv4Addr, timeout: Duration) -> SearchGatewayFromTimeout {
    let (tx, rx) = oneshot::channel();
    let _ = thread::spawn(move || {
        let res = igd::search_gateway_from_timeout(ipv4, timeout);
        let res = res.map(|gateway| Gateway { inner: gateway });
        tx.send(res)
    });
    SearchGatewayFromTimeout { rx: rx }
}

#[derive(Debug)]
pub struct Gateway {
    inner: igd::Gateway,
}

#[derive(Debug)]
pub struct GetAnyAddress {
    rx: oneshot::Receiver<Result<SocketAddrV4, AddAnyPortError>>,
}

impl Future for GetAnyAddress {
    type Item = SocketAddrV4;
    type Error = AddAnyPortError;

    fn poll(&mut self) -> Result<Async<SocketAddrV4>, AddAnyPortError> {
        match unwrap!(self.rx.poll()) {
            Async::Ready(res) => Ok(Async::Ready(res?)),
            Async::NotReady => Ok(Async::NotReady),
        }
    }
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
    ) -> GetAnyAddress {
        let description = String::from(description);
        let gateway = self.inner.clone();
        let (tx, rx) = oneshot::channel();

        let _ = thread::spawn(move || {
            let res = add_port_mapping(gateway, protocol, local_addr, lease_duration, description);
            tx.send(res)
        });

        GetAnyAddress { rx: rx }
    }
}

/// Maps given local address to external `IP:port`.
/// If local address is unspecified (`0.0.0.0`), it's resolved by gateway address.
///
/// # Returns
///
/// Mapped external address on success.
fn add_port_mapping(
    gateway: igd::Gateway,
    protocol: PortMappingProtocol,
    local_addr: SocketAddrV4,
    lease_duration: u32,
    description: String,
) -> Result<SocketAddrV4, AddAnyPortError> {
    if local_addr.ip().is_unspecified() {
        match discover_local_addr_to_gateway(*gateway.addr.ip()) {
            Ok(ipv4) => {
                let local_addr = SocketAddrV4::new(ipv4, local_addr.port());
                gateway.get_any_address(protocol, local_addr, lease_duration, &description)
            }
            // TODO(povilas): test upper layers, seems like this error is not handled.
            Err(e) => Err(AddAnyPortError::RequestError(RequestError::IoError(e))),
        }
    } else {
        gateway.get_any_address(protocol, local_addr, lease_duration, &description)
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

pub fn get_any_address(
    protocol: Protocol,
    local_addr: SocketAddr,
) -> BoxFuture<SocketAddr, GetAnyAddressError> {
    if !is_igd_enabled() {
        return future::err(GetAnyAddressError::Disabled).into_boxed();
    }

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
                    gateway
                        .get_any_address(protocol, socket_addr_v4, 0, "tokio-nat-traversal")
                        .map_err(GetAnyAddressError::RequestPort)
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
    local_addr_to_gateway(ifs, gateway_addr).map_or(
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No local addresses to gateway",
        )),
        |addr| Ok(addr),
    )
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
