use priv_prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub enum UdpRendezvousMsg {
    Init {
        enc_pk: PublicEncryptKey,
        rendezvous_addrs: Vec<SocketAddr>,
    },
}
