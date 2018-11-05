pub use self::hole_punch::TcpHolePunchMediator;
pub use self::rendezvous_server::TcpRendezvousServer;

use net2::TcpBuilder;
use safe_crypto::PUBLIC_ENCRYPT_KEY_BYTES;
use std::net::{IpAddr, SocketAddr};

mod hole_punch;
mod rendezvous_server;

#[derive(Debug, Serialize, Deserialize)]
struct TcpEchoReq(pub [u8; PUBLIC_ENCRYPT_KEY_BYTES]);
#[derive(Debug, Serialize, Deserialize)]
struct TcpEchoResp(pub Vec<u8>);

pub fn new_reusably_bound_tcp_sockets(
    local_addr: &SocketAddr,
    n: usize,
) -> ::Res<(Vec<TcpBuilder>, SocketAddr)> {
    if n < 1 {
        return Ok((vec![], *local_addr));
    }

    let mut v = Vec::with_capacity(n);

    let sock = match local_addr.ip() {
        IpAddr::V4(..) => TcpBuilder::new_v4()?,
        IpAddr::V6(..) => TcpBuilder::new_v6()?,
    };
    let _ = sock.reuse_address(true)?;
    enable_so_reuseport(&sock)?;
    let _ = sock.bind(local_addr)?;

    let addr = sock.local_addr()?;

    v.push(sock);

    for _ in 0..(n - 1) {
        let sock = match local_addr.ip() {
            IpAddr::V4(..) => TcpBuilder::new_v4()?,
            IpAddr::V6(..) => TcpBuilder::new_v6()?,
        };
        let _ = sock.reuse_address(true)?;
        enable_so_reuseport(&sock)?;
        let _ = sock.bind(&addr)?;
        v.push(sock);
    }

    Ok((v, addr))
}

#[cfg(target_family = "unix")]
fn enable_so_reuseport(sock: &TcpBuilder) -> ::Res<()> {
    use net2::unix::UnixTcpBuilderExt;
    let _ = sock.reuse_port(true)?;
    Ok(())
}

#[cfg(target_family = "windows")]
fn enable_so_reuseport(_sock: &TcpBuilder) -> ::Res<()> {
    Ok(())
}
