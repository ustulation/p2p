use mio::Token;

#[derive(Debug)]
pub enum Event {
    OverlayConnected(Token),
    OverlayConnectFailed,
    PeersRefreshed,
    PeerConnected(String, Token),
    PeerConnectFailed(String),
}
