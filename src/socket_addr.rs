use priv_prelude::*;

/// Some helpful additional methods for `SocketAddr`.
pub trait SocketAddrExt {
    /// If the IP address is an unspecified address (eg. `0.0.0.0`), then it is expanded into a
    /// vector with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddr>>;

    /// If this is the unspecified address then map it to the localhost address.
    fn unspecified_to_localhost(&self) -> SocketAddr;
}

impl SocketAddrExt for SocketAddr {
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddr>> {
        let ret = match *self {
            SocketAddr::V4(v4_addr) => v4_addr
                .expand_local_unspecified()?
                .into_iter()
                .map(SocketAddr::V4)
                .collect(),
            SocketAddr::V6(v6_addr) => v6_addr
                .expand_local_unspecified()?
                .into_iter()
                .map(SocketAddr::V6)
                .collect(),
        };
        Ok(ret)
    }

    fn unspecified_to_localhost(&self) -> SocketAddr {
        SocketAddr::new(self.ip().unspecified_to_localhost(), self.port())
    }
}

/// Some helpful additional methods for `SocketAddrV4`.
pub trait SocketAddrV4Ext {
    /// If the IP address is the unspecified address `0.0.0.0`, then it is expanded into a vector
    /// with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV4>>;

    /// Convert the unspecified address 0.0.0.0 to 127.0.0.1
    fn unspecified_to_localhost(&self) -> SocketAddrV4;
}

/// Some helpful additional methods for `SocketAddrV6`.
pub trait SocketAddrV6Ext {
    /// If the IP address is the unspecified address `::`, then it is expanded into a vector with a
    /// seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV6>>;

    /// Convert the unspecified address :: to ::1
    fn unspecified_to_localhost(&self) -> SocketAddrV6;
}

impl SocketAddrV4Ext for SocketAddrV4 {
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV4>> {
        Ok({
            self.ip()
                .expand_local_unspecified()?
                .into_iter()
                .map(|ip| SocketAddrV4::new(ip, self.port()))
                .collect()
        })
    }

    fn unspecified_to_localhost(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip().unspecified_to_localhost(), self.port())
    }
}

impl SocketAddrV6Ext for SocketAddrV6 {
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV6>> {
        Ok({
            self.ip()
                .expand_local_unspecified()?
                .into_iter()
                .map(|ip| SocketAddrV6::new(ip, self.port(), self.flowinfo(), self.scope_id()))
                .collect()
        })
    }

    fn unspecified_to_localhost(&self) -> SocketAddrV6 {
        SocketAddrV6::new(
            self.ip().unspecified_to_localhost(),
            self.port(),
            self.flowinfo(),
            self.scope_id(),
        )
    }
}
