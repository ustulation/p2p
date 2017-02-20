use std::net::SocketAddr;

pub const UDP_RENDEZVOUS_PORT: u16 = 5484;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub udp_rendezvous_port: Option<u16>,
    pub remote_udp_rendezvous_servers: Vec<SocketAddr>,
    pub udp_hole_punchers: Vec<UdpHolePuncher>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHolePuncher {
    pub starting_ttl: u8,
    pub ttl_increment_delay_ms: u64,
}
