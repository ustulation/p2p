use priv_prelude::*;

pub trait SocketAddrExt {
    /// If the IP address is an unspecified address (eg. `0.0.0.0`), then it is expanded into a
    /// vector with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddr>>;
}

impl SocketAddrExt for SocketAddr {
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddr>> {
        let ret = match *self {
            SocketAddr::V4(v4_addr) => {
                v4_addr
                    .expand_local_unspecified()?
                    .into_iter()
                    .map(SocketAddr::V4)
                    .collect()
            }
            SocketAddr::V6(v6_addr) => {
                v6_addr
                    .expand_local_unspecified()?
                    .into_iter()
                    .map(SocketAddr::V6)
                    .collect()
            }
        };
        Ok(ret)
    }
}

pub trait SocketAddrV4Ext {
    /// If the IP address is the unspecified address `0.0.0.0`, then it is expanded into a vector
    /// with a seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV4>>;
}

pub trait SocketAddrV6Ext {
    /// If the IP address is the unspecified address `::`, then it is expanded into a vector with a
    /// seperate IP address for each network interface.
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV6>>;
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
}

impl SocketAddrV6Ext for SocketAddrV6 {
    fn expand_local_unspecified(&self) -> io::Result<Vec<SocketAddrV6>> {
        Ok({
            self.ip()
                .expand_local_unspecified()?
                .into_iter()
                .map(|ip| {
                    SocketAddrV6::new(ip, self.port(), self.flowinfo(), self.scope_id())
                })
                .collect()
        })
    }
}
