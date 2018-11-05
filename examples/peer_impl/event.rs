use mio::Token;

pub enum Event {
    OverlayConnected(Token),
    OverlayConnectFailed(String),
}
