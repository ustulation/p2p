pub use self::hole_punch::UdpHolePunchMediator;
pub use self::rendezvous_server::UdpRendezvousServer;

use sodium::crypto::box_::PUBLICKEYBYTES;

mod hole_punch;
mod rendezvous_server;

#[derive(Debug, Serialize, Deserialize)]
struct UdpEchoReq(pub [u8; PUBLICKEYBYTES]);
#[derive(Debug, Serialize, Deserialize)]
struct UdpEchoResp(pub Vec<u8>);
