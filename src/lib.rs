//! # General
//!
//! The goal of this crate is to provide a robust and crypto-secure NAT traversal for peer to peer
//! connection. It assumes a publicly reachable rendezvous servers are provided. The server code
//! itself is in the crate too, so it can either be deployed as a server or used as a peer to peer
//! client or both simultaneously - for e.g. if you run the server on a port forwarded endpoint, it
//! will be publicly available while you could choose normal NAT traversal mechanisms to
//! communicate with other peers.
//!
//! ## Endpoint Independent Mapping (EIM)
//!
//! Here whatever packets we send out from a local endpoint will go out of the same mapping in our
//! NAT.
//!
//! ###  Endpoint Independent Filtering (Full Cone)
//!
//! This is the least restrictive NAT. All we need to do is make sure the mapping exists. This can
//! be done by simply going through the rendezvous handshake coded in this crate. It should have
//! the same effect as if the port had been forwarded manually or via Internet Gateway Device
//! Protocol through code. If both sides are full cone then we can easily establis p2p
//! communication.
//!
//! ### Endpoint Address & Port Dependent Filtering (Port Restricted Cone)
//!
//! This is the most restrictive NAT under EIM. In this crate this is what we assume for EIMs
//! because if we cover this then the less restrictive Endpoint Address Dependent Filtering will be
//! automatically covered (thus covering the worst case for EIMs).
//!
//! When we talk to the rendezvous servers, such a NAT allows us to talk to only one of them at a
//! time from the same local UDP endpoint. Once we talk to them in succession we can easily find
//! out if we are behind an EIM NAT. This is because the external address seen by all the servers
//! will be exactly the same for the same socket on the local endpoint. Once we exchange this
//! information with the peer (out of band), the filtering will not allow either of us to reach the
//! other end because our routers will remember that the last remote endpoint we talked to was the
//! last rendezvous server, thus allowing incoming traffic only from that exact endpoint. However
//! if we now start sending packets to the peer instead using the obtained information that had
//! been exchanged out of band, our respective routers will update the filtering to allow incoming
//! packets from the peer (since it saw an outgoing one to them) and stop further packets from the
//! rendezvous server, which is totally fine because our job with the rendezvous server is done.
//! Thus p2p communication ensues.
//!
//! So far so good. However some routers are unfriendlier still and pose additional problem. As we
//! talked above, to make the router update its filtering, we need to start sending packets to the
//! peer, they do the same and eventually both our routers have updated their filters and allow our
//! packets through. While the filters are not updated, the router would simply see the incoming
//! packet from the peer as unsolicited communication and drop it. The unfriendlier ones however go
//! a step further and temporarily blacklist the peer endpoint, seeing it as a flooding attack
//! prevention or something similar.
//!
//! This poses a challange to us. If our packet has left our router for the peer but has not
//! reached it yet and peer packet has left its router towards us in the meantime, hole-punching
//! will succeed. However if either one of our packet reaches the other before the other's had a
//! chance to get out of its own router, the unfriendlier routers would blacklist the endpoint.
//! This means that even if now the packet for the peer leaves the unfriendly router, it will be
//! received by the other end, but the packets from other end will be filtered out due to the
//! blacklist and the more packet it sends the blacklist timers resets thus never allowing the
//! packets through. This has effectively lead to a one way communication. If both routers were
//! unfriendly then not even a one way communication could exist.
//!
//! The above mentioned scenario was seen in some of the routers tested. To circumvent such routers
//! this crate uses a technique to trick the routers. The problem is we don't want to reach the
//! other end fast (thus getting ourselves blacklisted) while updating the filter at our routers.
//! `TTL` (time-to-live) to the rescue. While punching hole, we start with the lowest reasonable
//! TTL (of say 2). Note that some routers were found to drop the packet when TTL was 1 after
//! decrementing while some still send it but drop if the the TTL reached the value of 0. With 2 it
//! will definitely go past the first router. We put a delay, increase the TTL by 1 and send again.
//! Both sides (peers) do this. In pracitice it's usually the 1st couple (or 3) routers that do NAT
//! while others are non-NAT. This gives ample amount of time for the NAT-routers to update their
//! filter to allow the peer's incoming packet in the future while not reaching the peer quickly
//! and getting blacklisted. By the time we hit TTL of around 12, we would like reach the other
//! end.
//!
//! This crate is highly configurable while providing reasonable defaults. So if the user wants he
//! can choose the starting TTL and the delay between bumping it up and re-transmitting. The
//! resonable default would be to choose 3 sockets per peer, one with TTL starting 2, one with 6
//! and one with 64 (or OS default), so that if the fastest one was going to succeed it would do so
//! immediately (for friendlier routers) otherwise the slower ones would eventually reach there.
//!
//! Once the hole is punched the TTL is put back to the OS default and normal p2p communication can
//! ensue. Also once the hole is punched by any socket, the others are immediately discarded so
//! that we don't end up with a lot of reserved descriptors for a single peer.
//!
//! Finally the attempt will either timeout (configurable or use the defaults in the crate) or if
//! the TTL has reached the OS default for the platform, the attempt is considered to have failed
//! and failure returned.
//!
//! ## Endpoint Dependent Mapping (EDM) - Symmetric NATs
//!
//! This is trickier because our external address as seen by the outsiders will change depending on
//! the remote endpoint we are talking to, irrespective of the fact we are using the same local
//! endpoint. That is why the recommended number of rendezvous servers is 3. Using them we can
//! predict how our router maps our address by inspecting at the differnt addresses returned by
//! different rendezvous servers. Most of the time a fixed delta can be predicted and that is what
//! is used by this crate to guess what our address will be when we start hole-punching to the peer
//! and we exchange that guessed information (out of band as usual), then start sending packets to
//! the peer on their guessed address. This has worked for most of the routers. For filtering, it's
//! the same as before and we proceed the same way with our guessed address.
//!
//! There are unfriendly routers in this category too in which the mapping is random and unrelated
//! to any deltas/offsets. Such cases are currently not supported by this crate (though there is
//! some work in pipeline to alleviate that too using a whole lot of sockets in a hope of getting
//! one of them right). However it will be detected and will be logged (if logging is turned on) to
//! the user and connection attempt to the peer will be discarded.
//!
//! ## Hairpinning
//!
//! Some routers disallow hairpinning. This means if people in two different LANs are under the
//! same NAT, both their external addresses would be similar. When non-hairpinning routers see
//! this, a packet with source and destination containing IP's they know are allocated by them from
//! the pool (although source and destination endpoints maybe quite different), they will discard
//! and not route it further. This is really a tough one and currently there is no solution to
//! this in this crate.
//!
//! ## Secure communication
//!
//! Finally all communication is crypto-secure. When two peers exchange information out of band it
//! involves exchanging public asymmetric keys. All messages between peers (including handshake)
//! are encrypted and signed with different nonces each time, so cannot be spoofed.
//!
//! The message to the rendezvous servers includes our public key so the message they send back is
//! encrypted. This prevents some routers/firewalls from identifying it's a rendezvous attempt by
//! looking at the message body and thus either mangling or discarding the packet. Such
//! routers/firewalls seem to scan for socket addresses and if it matches the ones in the router's
//! pool they try to figure out it's a rendezvous/STUN attempt. With encrypted contents there is no
//! chance of such detection, so we are safe there.

#![cfg_attr(feature="cargo-clippy", allow(too_many_arguments))]
#![recursion_limit="100"]

// Coding guidelines:
// 1. If called by someone don't reply to caller via stored callback, reply directly, else caller
//    is already borrowed and it will be borrowed again inside the callback (via weak-ptr upgrade)
//    leading to panic.
// 2. In invoked via callback, don't call the caller (child) again as borrow of the child is
//    active when it's calling you (i.e. don't call terminate which will borrow the child again to
//    call its terminate etc. Instead remove the child immediately from list of children if it
//    makes sense, because the child's job is over etc., and then call terminate on self etc.).

#[macro_use]
extern crate log;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate serde_derive;

extern crate bincode;
extern crate mio;
extern crate rand;
extern crate rust_sodium as sodium;
extern crate serde;

use mio::{Poll, Ready, Token};
use mio::channel::Sender;
use mio::timer::{Timeout, TimerError};
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

pub mod config;

mod error;
mod hole_punch;
mod tcp;
mod udp;

pub use config::Config;
pub use error::NatError;
pub use hole_punch::{GetInfo, Handle, HolePunchFinsih, HolePunchInfo, HolePunchMediator,
                     RendezvousInfo};
pub use udp::UdpRendezvousServer;

pub type Res<T> = Result<T, NatError>;

pub struct NatTimer {
    pub associated_nat_state: Token,
    pub timer_id: u8,
}
impl NatTimer {
    pub fn new(state: Token, timer_id: u8) -> Self {
        NatTimer {
            associated_nat_state: state,
            timer_id: timer_id,
        }
    }
}

pub struct NatMsg(Box<FnMut(&mut Interface, &Poll) + Send + 'static>);
impl NatMsg {
    pub fn new<F>(f: F) -> Self
        where F: FnOnce(&mut Interface, &Poll) + Send + 'static
    {
        let mut f = Some(f);
        NatMsg(Box::new(move |ifc: &mut Interface, poll: &Poll| if let Some(f) = f.take() {
            f(ifc, poll)
        }))
    }

    pub fn invoke(mut self, ifc: &mut Interface, poll: &Poll) {
        (self.0)(ifc, poll)
    }
}

pub trait NatState {
    fn ready(&mut self, &mut Interface, &Poll, Ready) {}
    fn terminate(&mut self, &mut Interface, &Poll) {}
    fn timeout(&mut self, &mut Interface, &Poll, u8) {}
    fn as_any(&mut self) -> &mut Any;
}

pub trait Interface {
    fn insert_state(&mut self,
                    token: Token,
                    state: Rc<RefCell<NatState>>)
                    -> Result<(), (Rc<RefCell<NatState>>, String)>;
    fn remove_state(&mut self, token: Token) -> Option<Rc<RefCell<NatState>>>;
    fn state(&mut self, token: Token) -> Option<Rc<RefCell<NatState>>>;
    fn set_timeout(&mut self,
                   duration: Duration,
                   timer_detail: NatTimer)
                   -> Result<Timeout, TimerError>;
    fn cancel_timeout(&mut self, timeout: &Timeout) -> Option<NatTimer>;
    fn new_token(&mut self) -> Token;
    fn config(&self) -> &Config;
    fn enc_pk(&self) -> &box_::PublicKey;
    fn enc_sk(&self) -> &box_::SecretKey;
    fn sender(&self) -> &Sender<NatMsg>;
}
