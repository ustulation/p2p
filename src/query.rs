use priv_prelude::*;

/// A trait for objects that can be used to discover the external address of a local TCP port
pub trait TcpAddrQuerier: fmt::Debug + 'static {
    /// Find the external address of `bind_addr`
    fn query(
        &self,
        bind_addr: &SocketAddr,
        handle: &Handle,
    ) -> BoxFuture<SocketAddr, Box<Error + Send>>;
}

/// A trait for objects that can be used to discover the external address of a local UDP port
pub trait UdpAddrQuerier: fmt::Debug + 'static {
    /// Find the external address of `bind_addr`
    fn query(
        &self,
        bind_addr: &SocketAddr,
        handle: &Handle,
    ) -> BoxFuture<SocketAddr, Box<Error + Send>>;
}
