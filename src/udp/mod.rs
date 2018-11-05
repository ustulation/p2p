pub use self::hole_punch::UdpHolePunchMediator;
pub use self::rendezvous_server::UdpRendezvousServer;

mod hole_punch;
mod rendezvous_server;

use safe_crypto::PUBLIC_ENCRYPT_KEY_BYTES;

#[derive(Debug, Serialize, Deserialize)]
struct UdpEchoReq(pub [u8; PUBLIC_ENCRYPT_KEY_BYTES]);
#[derive(Debug, Serialize, Deserialize)]
struct UdpEchoResp(pub Vec<u8>);
