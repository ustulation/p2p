use priv_prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub enum TcpRendezvousMsg {
    Init {
        enc_pk: PublicEncryptKey,
        open_addrs: Vec<SocketAddr>,
        rendezvous_addr: SocketAddr,
    },
}
