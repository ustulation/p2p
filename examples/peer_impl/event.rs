use common::types::PeerId;
use mio::Token;
use std::fmt;

#[derive(Debug)]
pub enum Event {
    OverlayConnected(Token),
    OverlayConnectFailed,
    PeersRefreshed,
    PeerConnected(PeerId, Token),
    PeerConnectFailed(PeerId),
    PeerDisconnected(PeerId),
    Quit,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Event::OverlayConnected(_) => write!(f, "###### Overlay is connected. ######"),
            Event::OverlayConnectFailed => write!(f, "###### Overlay connect failed. ######"),
            Event::PeersRefreshed => write!(f, "###### Peer List has been refreshed. ######"),
            Event::PeerConnected(ref id, ..) => write!(f, "###### {} is now connected. ######", id),
            Event::PeerConnectFailed(ref id) => {
                write!(f, "###### {} is could not be connected. ######", id)
            }
            Event::PeerDisconnected(ref id) => {
                write!(f, "###### {} has been disconnected. ######", id)
            }
            Event::Quit => write!(f, "Event::Quit"),
        }
    }
}
