use p2p::RendezvousInfo;
use sodium::crypto::box_;
use std::fmt;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerId {
    pub name: String,
    pub pk: box_::PublicKey,
}

impl PeerId {
    pub fn new(name: String, pk: box_::PublicKey) -> Self {
        Self { name, pk }
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Peer: {} ({:02x}{:02x}{:02x}{:02x})",
            self.name, self.pk.0[0], self.pk.0[1], self.pk.0[2], self.pk.0[3]
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PlainTextMsg {
    ReqUpdateName(String),
    UpdateNameResp(bool),
    ReqOnlinePeers,
    OnlinePeersResp(Vec<PeerId>),
    ExchgRendezvousInfo {
        src_info: RendezvousInfo,
        dst_peer: PeerId,
    },
    FwdRendezvousInfo {
        src_info: RendezvousInfo,
        src_peer: PeerId,
    },
    Chat(String),
}

#[derive(Serialize, Deserialize)]
pub enum PeerMsg {
    PubKey(box_::PublicKey),
    CipherText(Vec<u8>),
}
