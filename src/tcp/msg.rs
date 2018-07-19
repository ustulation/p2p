use priv_prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub enum TcpRendezvousMsg {
    Init {
        enc_pk: PublicKeys,
        open_addrs: Vec<SocketAddr>,
        rendezvous_addr: Option<SocketAddr>,
    },
}
