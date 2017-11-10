use priv_prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub enum UdpRendezvousMsg {
    Init {
        enc_pk: crypto::box_::PublicKey,
        open_addrs: HashSet<SocketAddr>,
        rendezvous_addrs: Vec<SocketAddr>,
    },
}

