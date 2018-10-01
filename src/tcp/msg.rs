use priv_prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub enum TcpRendezvousMsg {
    Init {
        enc_pk: PublicEncryptKey,
        rendezvous_addr: SocketAddr,
    },
}
