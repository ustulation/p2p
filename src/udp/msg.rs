use priv_prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub enum UdpRendezvousMsg {
    Init {
        enc_pk: PublicId,
        open_addrs: HashSet<SocketAddr>,
        rendezvous_addrs: Vec<SocketAddr>,
    },
}
