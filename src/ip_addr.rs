use get_if_addrs::{self, IfAddr};
use priv_prelude::*;

pub trait IpAddrExt {
    /// Check whether an IP address is global.
    fn is_global(&self) -> bool;
    /// Check whether an IP address belongs to a private subnet.
    fn is_private(&self) -> bool;
    /// If the IP address is an unspecified address (eg. `0.0.0.0`), then it is expanded into a
    /// vector with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<IpAddr>>;
}

impl IpAddrExt for IpAddr {
    fn is_global(&self) -> bool {
        match *self {
            IpAddr::V4(ref ip) => Ipv4AddrExt::is_global(ip),
            IpAddr::V6(ref ip) => Ipv6AddrExt::is_global(ip),
        }
    }

    fn is_private(&self) -> bool {
        match *self {
            //IpAddr::V4(ref ip) => Ipv4AddrExt::is_private(ip),
            IpAddr::V4(ref ip) => ip.is_private(),
            IpAddr::V6(_) => false,
        }
    }

    fn expand_local_unspecified(&self) -> io::Result<Vec<IpAddr>> {
        let ret = match *self {
            IpAddr::V4(v4_addr) => {
                v4_addr
                    .expand_local_unspecified()?
                    .into_iter()
                    .map(|v4_addr| IpAddr::V4(v4_addr))
                    .collect()
            }
            IpAddr::V6(v6_addr) => {
                v6_addr
                    .expand_local_unspecified()?
                    .into_iter()
                    .map(|v6_addr| IpAddr::V6(v6_addr))
                    .collect()
            }
        };
        Ok(ret)
    }
}

pub trait Ipv4AddrExt {
    /// Check whether an IP address is global.
    fn is_global(&self) -> bool;
    /// If the IP address is the unspecified address `0.0.0.0`, then it is expanded into a vector
    /// with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<Ipv4Addr>>;
}

pub trait Ipv6AddrExt {
    fn is_global(&self) -> bool;
    /// If the IP address is the unspecified address `::`, then it is expanded into a vector with a
    /// seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<Ipv6Addr>>;
}

impl Ipv4AddrExt for Ipv4Addr {
    fn is_global(&self) -> bool {
        !self.is_private() && !self.is_loopback() && !self.is_link_local() &&
            !self.is_broadcast() && !self.is_documentation() && !self.is_unspecified()
    }

    fn expand_local_unspecified(&self) -> io::Result<Vec<Ipv4Addr>> {
        if !self.is_unspecified() {
            return Ok(vec![*self]);
        }

        let mut ret = Vec::new();
        let ifs = get_if_addrs::get_if_addrs()?;
        for interface in ifs {
            if let IfAddr::V4(v4_addr) = interface.addr {
                ret.push(v4_addr.ip);
            }
        }
        Ok(ret)
    }
}

impl Ipv6AddrExt for Ipv6Addr {
    fn is_global(&self) -> bool {
        // TODO: this is very incomplete
        !self.is_loopback() && !self.is_unspecified()
    }

    fn expand_local_unspecified(&self) -> io::Result<Vec<Ipv6Addr>> {
        if !self.is_unspecified() {
            return Ok(vec![*self]);
        }

        let mut ret = Vec::new();
        let ifs = get_if_addrs::get_if_addrs()?;
        for interface in ifs {
            if let IfAddr::V6(v6_addr) = interface.addr {
                ret.push(v6_addr.ip);
            }
        }
        Ok(ret)
    }
}
