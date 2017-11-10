use priv_prelude::*;

use socket_addr::SocketAddrExt;

/// Extensions methods for `TcpBuilder`.
pub trait TcpBuilderExt {
    /// Bind reusably to the given address. Multiple sockets can be bound to the same local address
    /// using this method.
    fn bind_reusable(addr: &SocketAddr) -> io::Result<TcpBuilder>;
    /// Returns all local addresses of this socket, expanding an unspecified address (eg `0.0.0.0`)
    /// into a vector of addresses, one for each network interface.
    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>>;
}

impl TcpBuilderExt for TcpBuilder {
    fn bind_reusable(addr: &SocketAddr) -> io::Result<TcpBuilder> {
        let socket = match addr.ip() {
            IpAddr::V4(..) => TcpBuilder::new_v4()?,
            IpAddr::V6(..) => TcpBuilder::new_v6()?,
        };
        socket.reuse_address(true)?;

        #[cfg(target_family = "unix")]
        {
            use net2::unix::UnixTcpBuilderExt;
            socket.reuse_port(true)?;
        }

        socket.bind(addr)?;

        Ok(socket)
    }

    fn expanded_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let addr = self.local_addr()?;
        let addrs = addr.expand_local_unspecified()?;
        Ok(addrs)
    }
}

