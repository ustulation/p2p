//! Various defaults for behaviour configuration

use std::net::SocketAddr;

/// Default for udp rendezvous port
pub const UDP_RENDEZVOUS_PORT: u16 = 5483;
/// Default for tcp rendezvous port
pub const TCP_RENDEZVOUS_PORT: u16 = 5484;
/// Default for rendezvous timeout in seconds
pub const RENDEZVOUS_TIMEOUT_SEC: u64 = 8;
/// Default for hole-punch timeout in seconds
pub const HOLE_PUNCH_TIMEOUT_SEC: u64 = 15;
/// Default for if we want to wait for the other, given one of TCP or UDP has hole-punched
pub const HOLE_PUNCH_WAIT_FOR_OTHER: bool = true;

/// Various configurations with which to proceed with NAT traversal.
///
/// User can opt to provide this in a file, read from it and pass it when required. For optional
/// fields that are `None`, reasonable defaults will be used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Rendezvous timeout in seconds
    pub rendezvous_timeout_sec: Option<u64>,
    /// Hole punch timeout in seconds
    pub hole_punch_timeout_sec: Option<u64>,
    /// If we want to wait for the other, given one of TCP or UDP has hole-punched
    pub hole_punch_wait_for_other: Option<bool>,
    /// UDP Rendezvous port. This is the port our UDP Rendezvous server will bind to and listen on.
    pub udp_rendezvous_port: Option<u16>,
    /// TCP Rendezvous port. This is the port our TCP Rendezvous server will bind to and listen on.
    pub tcp_rendezvous_port: Option<u16>,
    /// Remote UDP Rendezvous servers. It is recommended to provide at-least 2 and ideally 3 or
    /// more for proper NAT detection or else detection (and consequently prediction) of an
    /// `Endpoint Dependent Mapping` (`EDM`) NAT will fail.
    pub remote_udp_rendezvous_servers: Vec<SocketAddr>,
    /// Remote TCP Rendezvous servers. It is recommended to provide at-least 2 and ideally 3 for
    /// proper NAT detection or else detection (and consequently prediction) of an `Endpoint
    /// Dependent Mapping` (`EDM`) NAT will fail.
    pub remote_tcp_rendezvous_servers: Vec<SocketAddr>,
    /// Details of all our UDP hole punchers
    pub udp_hole_punchers: Vec<UdpHolePuncher>,
}

/// Details of each UDP Hole puncher
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHolePuncher {
    /// Starting value of `TTL`.
    pub starting_ttl: u8,
    /// Delay before retransmitting with an incremented value of `TTL`. Once it is established the
    /// peer is reached this will be bounced back to the platform default so normal communication
    /// can ensue.
    pub ttl_increment_delay_ms: u64,
}
