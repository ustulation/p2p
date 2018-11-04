use p2p::RendezvousInfo;
use sodium::crypto::box_;

#[derive(Debug, Serialize, Deserialize)]
pub enum PlainTextMsg {
    ReqUpdateName(String),
    UpdateNameResp(bool),
    ReqOnlinePeers,
    OnlinePeersResp(Vec<(String, box_::PublicKey)>),
    ReqRendezvousInfo {
        src_info: RendezvousInfo,
        dst_peer: String,
        dst_pk: box_::PublicKey,
    },
    ForwardedRendezvousReq {
        src_info: RendezvousInfo,
        src_peer: String,
    },
    RendezvousInfoResp {
        src_info: RendezvousInfo,
        dst_peer: String,
        dst_pk: box_::PublicKey,
    },
    ForwardedRendezvousResp {
        src_info: RendezvousInfo,
        src_peer: String,
    },
}

#[derive(Serialize, Deserialize)]
pub enum PeerMsg {
    PubKey(box_::PublicKey),
    CipherText(Vec<u8>),
}
