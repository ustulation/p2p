//! Port mapping context utilities.

use future_utils::mpsc::UnboundedReceiver;
use priv_prelude::*;

/// `P2p` allows you to manage how NAT traversal works.
///
/// You can edit rendezvous (traversal) servers, enable/Disable IGD use, etc.
#[derive(Default, Clone)]
pub struct P2p {
    inner: Arc<Mutex<P2pInner>>,
}

#[derive(Default)]
struct P2pInner {
    tcp_addr_querier_set: TcpAddrQuerierSet,
    udp_addr_querier_set: UdpAddrQuerierSet,
    igd_disabled: bool,
    igd_disabled_for_rendezvous: bool,
    force_use_local_port: bool,
}

// Some macros to reduce boilerplate

macro_rules! inner_get {
    ($self:ident, $field:ident) => {{
        let inner = unwrap!($self.inner.lock());
        inner.$field
    }};
}

macro_rules! inner_set {
    ($self:ident, $field:ident, $value:ident) => {{
        let mut inner = unwrap!($self.inner.lock());
        inner.$field = $value;
    }};
}

impl P2p {
    /// Check if IGD for rendezvous connections option is on or off.
    pub fn is_igd_enabled_for_rendezvous(&self) -> bool {
        !inner_get!(self, igd_disabled_for_rendezvous)
    }

    /// Try to use IGD port mapping when doing rendezvous connections.
    pub fn enable_igd_for_rendezvous(&self) {
        inner_set!(self, igd_disabled_for_rendezvous, false);
    }

    /// Don't use IGD port mapping when doing rendezvous connections.
    pub fn disable_igd_for_rendezvous(&self) {
        inner_set!(self, igd_disabled_for_rendezvous, true);
    }

    /// Tests if IGD use is enabled or not.
    /// It's enabled by default.
    pub fn is_igd_enabled(&self) -> bool {
        !inner_get!(self, igd_disabled)
    }

    /// Returns the value of `force_use_local_port` option.
    pub fn force_use_local_port(&self) -> bool {
        inner_get!(self, force_use_local_port)
    }

    /// If this option is on, when public address is determined, use our local listening port
    /// as external as well.
    pub fn set_force_use_local_port(&self, force: bool) {
        inner_set!(self, force_use_local_port, force);
    }

    /// By default `p2p` attempts to use IGD to open external ports for it's own use.
    /// Use this function to disable such behaviour.
    pub fn disable_igd(&self) {
        inner_set!(self, igd_disabled, true);
    }

    /// Re-enables IGD use.
    pub fn enable_igd(&self) {
        inner_set!(self, igd_disabled, false);
    }

    /// Register a TCP addr_querier with p2p
    pub fn add_tcp_addr_querier(&self, tcp_addr_querier: impl TcpAddrQuerier + Hash) {
        let mut inner = unwrap!(self.inner.lock());
        inner
            .tcp_addr_querier_set
            .add_addr_querier(tcp_addr_querier);
    }

    /// Register a UDP addr_querier with p2p
    pub fn add_udp_addr_querier(&self, udp_addr_querier: impl UdpAddrQuerier + Hash) {
        let mut inner = unwrap!(self.inner.lock());
        inner
            .udp_addr_querier_set
            .add_addr_querier(udp_addr_querier);
    }

    /// Remove a TCP addr_querier from p2p
    pub fn remove_tcp_addr_querier<T: Hash>(&self, tcp_addr_querier: &T) {
        let mut inner = unwrap!(self.inner.lock());
        inner
            .tcp_addr_querier_set
            .remove_addr_querier(tcp_addr_querier);
    }

    /// Remove a UDP addr_querier from p2p
    pub fn remove_udp_addr_querier<T: Hash>(&self, udp_addr_querier: &T) {
        let mut inner = unwrap!(self.inner.lock());
        inner
            .udp_addr_querier_set
            .remove_addr_querier(udp_addr_querier);
    }

    /// Iterate over the registered TCP addr_queriers
    pub fn tcp_addr_queriers(&self) -> UnboundedReceiver<Arc<TcpAddrQuerier>> {
        let mut inner = unwrap!(self.inner.lock());
        inner.tcp_addr_querier_set.addr_queriers()
    }

    /// Iterate over the registered UDP addr_queriers
    pub fn udp_addr_queriers(&self) -> UnboundedReceiver<Arc<UdpAddrQuerier>> {
        let mut inner = unwrap!(self.inner.lock());
        inner.udp_addr_querier_set.addr_queriers()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoRequest {
    pub client_pk: PublicId,
}

quick_error! {
    /// Error indicating failure to retrieve our public address.
    #[derive(Debug)]
    pub enum QueryPublicAddrError {
        /// Failed to bind to socket before even starting a query.
        Bind(e: io::Error) {
            description("error binding to socket address")
            display("error binding to socket address: {}", e)
            cause(e)
        }
        /// Connection failure.
        Connect(e: io::Error) {
            description("error connecting to echo server")
            display("error connecting to echo server: {}", e)
            cause(e)
        }
        /// Query timed out.
        ConnectTimeout {
            description("timed out contacting server")
        }
        /// Error sending query.
        SendRequest(e: io::Error) {
            description("error sending request to echo server")
            display("error sending request to echo server: {}", e)
            cause(e)
        }
        /// Error receiving query.
        ReadResponse(e: io::Error) {
            description("error reading response from echo server")
            display("error reading response from echo server: {}", e)
            cause(e)
        }
        /// Respone timed out.
        ResponseTimeout {
            description("timed out waiting for response from echo server")
        }
        /// Failure to encrypt request.
        Encrypt(e: EncryptionError) {
            description("Error encrypting message")
            display("Error encrypting message: {}", e)
            cause(e)
        }
        /// Failure to decrypt request.
        Decrypt(e: EncryptionError) {
            description("Error decrypting message")
            display("Error decrypting message: {}", e)
            cause(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_core::reactor::Core;

    mod p2p {
        use super::*;

        mod default {
            use super::*;

            #[test]
            fn it_creates_mapping_context_with_igd_enabled() {
                let p2p = P2p::default();

                assert!(p2p.is_igd_enabled())
            }

            #[test]
            fn it_creates_mapping_context_with_igd_enabled_for_rendezvous() {
                let p2p = P2p::default();

                assert!(p2p.is_igd_enabled_for_rendezvous())
            }

            #[test]
            fn it_creates_mapping_context_with_force_use_local_port_disabled() {
                let p2p = P2p::default();

                assert!(!p2p.force_use_local_port())
            }
        }

        mod tcp_addr_queriers {
            use super::*;

            #[test]
            fn it_returns_tcp_addr_queriers() {
                let p2p = P2p::default();

                let server_sk0 = SecretId::new();
                let server_pk0 = server_sk0.public_id().clone();
                let server_addr0 = addr!("1.2.3.4:5000");
                let server_sk1 = SecretId::new();
                let server_pk1 = server_sk1.public_id().clone();
                let server_addr1 = addr!("5.6.7.8:9000");

                let mut core = unwrap!(Core::new());
                let handle = core.handle();
                let addr_queriers = {
                    p2p.tcp_addr_queriers()
                        .with_readiness_timeout(Duration::from_secs(1), &handle)
                        .collect()
                };
                p2p.add_tcp_addr_querier(RemoteTcpRendezvousServer::new(server_addr0, server_pk0));
                p2p.add_tcp_addr_querier(RemoteTcpRendezvousServer::new(server_addr1, server_pk1));

                let addr_queriers: Vec<_> = core.run(addr_queriers).void_unwrap();
                assert_eq!(addr_queriers.len(), 2);
            }
        }
    }
}
