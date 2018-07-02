use priv_prelude::*;

/// Information necessary to connect to peer.
// NOTE: this structure is very similar to the one in Crust. Except the one in Crust stores
// PaAddr instead of SocketAddr. But it's worth considering moving PaAddr to p2p to reuse code.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer IP address.
    pub addr: SocketAddr,
    /// Peer public key.
    pub pub_key: PublicId,
}

impl PeerInfo {
    /// Constructs peer info.
    pub fn new(addr: SocketAddr, pub_key: PublicId) -> Self {
        Self { addr, pub_key }
    }

    /// Constructs peer info with random generated public key.
    #[cfg(test)]
    pub fn with_rand_key(addr: SocketAddr) -> Self {
        let sk = SecretId::new();
        let pk = sk.public_id().clone();
        Self::new(addr, pk)
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {:?})", self.addr, self.pub_key)
    }
}
