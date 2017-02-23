pub use self::hole_punch::TcpHolePunchMediator;
pub use self::rendezvous_server::TcpRendezvousServer;
pub use self::socket::Socket;

use net2::TcpBuilder;
use sodium::crypto::box_::PUBLICKEYBYTES;
use std::io;
use std::net;
use std::net::{IpAddr, SocketAddr};

mod hole_punch;
mod rendezvous_server;
mod socket;

#[derive(Debug, Serialize, Deserialize)]
struct TcpEchoReq(pub [u8; PUBLICKEYBYTES]);
#[derive(Debug, Serialize, Deserialize)]
struct TcpEchoResp(pub Vec<u8>);

pub fn new_reusably_bound_tcp_sockets(local_addr: &SocketAddr,
                                      n: usize)
                                      -> ::Res<(Vec<TcpBuilder>, SocketAddr)> {
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

    let addr = tcp_builder_local_addr(&sock)?;

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

#[cfg(target_family = "unix")]
#[allow(unsafe_code)]
fn tcp_builder_local_addr(sock: &TcpBuilder) -> io::Result<SocketAddr> {
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

    let fd = sock.as_raw_fd();
    let stream = unsafe { net::TcpStream::from_raw_fd(fd) };
    let ret = stream.local_addr();
    let _ = stream.into_raw_fd();
    ret
}

#[cfg(target_family = "windows")]
#[allow(unsafe_code)]
fn tcp_builder_local_addr(sock: &TcpBuilder) -> io::Result<SocketAddr> {
    use std::mem;
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let fd = sock.as_raw_socket();
    let stream = unsafe { net::TcpStream::from_raw_socket(fd) };
    let ret = stream.local_addr();
    mem::forget(stream);
    ret
}
