use p2p::RendezvousInfo;
use safe_crypto::PublicEncryptKey;
use std::fmt;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerId {
    pub name: String,
    pub pk: PublicEncryptKey,
}

impl PeerId {
    pub fn new(name: String, pk: PublicEncryptKey) -> Self {
        Self { name, pk }
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pk = self.pk.into_bytes();
        write!(
            f,
            "Peer: {} ({:02x}{:02x}{:02x}{:02x})",
            self.name, pk[0], pk[1], pk[2], pk[3]
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
    PubKey(PublicEncryptKey),
    CipherText(Vec<u8>),
}
