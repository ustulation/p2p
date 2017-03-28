//! # General
//!
//! The goal of this crate is to provide a robust and crypto-secure NAT traversal for peer to peer
//! connection. It assumes publicly reachable rendezvous servers are provided. The server code
//! itself is in the crate too, so the crate can either be used to deploy a server or used for peer
//! to peer client communication or both simultaneously - for e.g. if you run the server on a port
//! forwarded endpoint, it will be publicly available for others to rendezvous while you could
//! choose normal NAT traversal mechanisms to communicate with other peers.
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
//! the same effect as if the port had been forwarded manually or via [Internet Gateway Device
//! Protocol][0] through code. If both sides are full cone then we can easily establish p2p
//! communication.
//!
//! ### Endpoint Address & Port Dependent Filtering (Port Restricted Cone)
//!
//! This is the most restrictive NAT under `EIM`. In this crate this is what we assume for `EIMs`
//! because if we cover this then the less restrictive `Endpoint Address Dependent Filtering` will
//! be automatically covered (in other words we cover the worst case scenario for `EIMs`).
//!
//! When we talk to the rendezvous servers, such a NAT allows us to talk to only one of them at a
//! time from the same local `UDP` endpoint. Once we talk to them in succession we can easily find
//! out if we are behind an `EIM` NAT. This is because the external address seen by all the servers
//! will be exactly the same for the same socket on the local endpoint. Once we exchange this
//! information with the peer (out of band), the filtering will not allow either of us to reach the
//! other end because our routers will remember that the last remote endpoint we talked to was the
//! last rendezvous server, thus allowing incoming traffic only from that exact endpoint. However
//! if we now start sending packets to the peer instead, using the obtained information that had
//! been exchanged out of band, our respective routers will update the filtering to allow incoming
//! packets from the peer (since it saw an outgoing one to them) and stop further packets from the
//! rendezvous server, which is totally fine because our job with the rendezvous server is done.
//! Thus p2p communication ensues.
//!
//! So far so good. However some routers are unfriendlier still and pose additional problems. As we
//! talked above, to make the router update its filtering, we need to start sending packets to the
//! peer while they do the same and eventually both our routers will have updated their filters and
//! allow our packets through. When the filters are not updated, the router would simply see the
//! incoming packet from the peer as an unsolicited communication and drop it. The unfriendlier
//! ones however go a step further and temporarily blacklist the peer endpoint, seeing it as a
//! flooding attack prevention or something similar.
//!
//! This poses a challenge to us. If our packet has left our router for the peer but has not
//! reached it yet and peer packet has left its router towards us in the meantime, hole-punching
//! will succeed. However if either one of our packet reaches the other before the other's had a
//! chance to get out of its own router, the unfriendlier routers would blacklist the endpoint.
//! This means that even if now the packet for the peer leaves the unfriendly router, it will be
//! received by the other end, but the packets from other end will be filtered out due to the
//! blacklist and the more packet it sends the blacklist timers reset thus never allowing the
//! packets through. This has effectively lead to a one way communication. If both routers were
//! unfriendly then not even a one way communication would exist.
//!
//! The above mentioned scenario was seen in some of the routers tested. To circumvent such routers
//! this crate uses a technique to trick the routers. The problem is we don't want to reach the
//! other end fast (thus getting ourselves blacklisted) while updating the filter at our routers.
//! `TTL` (time-to-live) to the rescue. While punching hole, we start with the lowest reasonable
//! `TTL` (of say 2). Note that some routers were found to drop the packet when `TTL` was 1 after
//! decrementing while some still send it but drop if the TTL reached the value of 0. With 2 it
//! will definitely go past the first router. We put a delay, increase the `TTL` by 1 and send
//! again.  Both sides (peers) do this. In practice it's usually the 1st couple (or 3) routers
//! that do NAT while others are non-NAT. This gives ample amount of time for the NAT-routers to
//! update their filters to allow the peer's incoming packets in the future while not reaching the
//! peer quickly themselves and getting blacklisted. By the time we hit `TTL` of around 12, we
//! would likely have reached the other end.
//!
//! This crate is highly configurable while providing reasonable defaults. So if the user wants
//! they can choose the starting `TTL` and the delay between bumping it up and re-transmitting. The
//! reasonable default would be to choose 3 sockets per peer, one with `TTL` starting 2, one with 6
//! and one with 64 (or OS default), so that if the fastest one was going to succeed it would do so
//! immediately (for friendlier routers) otherwise the slower ones would eventually reach there.
//! The blacklisting happens for the exact (remote) endpoint, so even if the faster ones got
//! blacklisted by the unfreindly routers the slower sockets (on different endpoints) still have
//! their chances.
//!
//! Once the hole is punched the `TTL` is put back to the OS default and normal p2p communication
//! can ensue. Also once the hole is punched by any socket, the others are immediately discarded so
//! that we don't end up with a lot of reserved descriptors for a single peer.
//!
//! Finally the attempt will either timeout (configurable or use the defaults in the crate) or if
//! the `TTL` has reached the OS default for the platform, the attempt is considered to have failed
//! and failure returned.
//!
//! ## Endpoint Dependent Mapping (EDM) - Symmetric NATs
//!
//! This is trickier because our external address as seen by the outsiders will change depending on
//! the remote endpoint we are talking to, irrespective of the fact we are using the same local
//! endpoint. That is why the recommended number of rendezvous servers is 3. Using them we can
//! predict how our router maps our address by inspecting the different addresses returned by
//! different rendezvous servers. Most of the time a fixed delta can be predicted and that is what
//! is used by this crate to guess what our address will be when we start hole-punching to the peer
//! and we exchange that guessed information (out of band as usual), then start sending packets to
//! the peer on their guessed address. This has worked for most of the routers. For filtering, it's
//! the same as before and we proceed in the same way with our guessed addresses.
//!
//! There are unfriendly routers in this category too in which the mapping is random and unrelated
//! to any deltas/offsets. Such cases are currently not supported by this crate (though there is
//! some work in pipeline to alleviate that too using a whole lot of sockets in a hope of getting
//! one of them right). Some might even make slight changes in IP (and not only the ports) though
//! this has not yet been encountered during testing with various routers. However all these will
//! be detected and will be logged (if logging is turned on) to the user and connection attempt to
//! the peer will be discarded.
//!
//! Also one more thing to note is, even with the friendlier NATs which apply fixed deltas to port
//! increment, the resultant port might already be occupied by another socket. In such a case they
//! would skip that port and yield some other unused ones and our prediction would fail here too.
//!
//! ## Hair-pinning
//!
//! Some routers disallow hair-pinning. This means if people in two different LANs are under the
//! same NAT, both their external addresses would be similar. When non-hair-pinning routers see
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
//! routers/firewalls seem to scan for socket addresses in the body and if it matches the ones in
//! the router's pool they try to figure out it's a rendezvous/STUN attempt. With encrypted
//! contents there is no chance of such detection, so we are safe there.
//!
//! ## TCP
//!
//! With `TCP` some of the challenges are greater. The usual process is going through the same
//! rendezvous as with `UDP` above. While one `UDP` socket did fine for communicating with all the
//! servers and then hole punching to peer, `TCP` is connection oriented and thus we need multiple
//! sockets. We will bind a connector per server and then a connector to the peer. While beginning
//! to hole punch to the peer we will also additionally bind a listener to the same exact local
//! endpoint.
//!
//! TCP connection can be established either via normal connector-listener pair, in which one side
//! is active (sends `SYNs`) while the other is passive (reacts to `SYNs` by sending `SYN-ACKs`),
//! or via lesser know `TCP Simultaneous Connect` in which both sides actively send `SYNs` and
//! both establish the connection because when they see a `SYN` in response to a `SYN` they assume
//! the other side also wants to establish the connection and then it materialises. If there is an
//! active connector and a listener bound to the same local endpoint on either side (like stated
//! above), there is a better chance of establishing a connection. If `SYN` is sent by peer 1 to 2
//! punching a hole (updating the filter) in 1's router for 2 and similarly sent by 2 for 1 then
//! when they reach each other's routers they are let through and `TCP Simultaneous Connect` kicks
//! in. If one of the `SYNs` reached the other end before the other's `SYN` could leave its router,
//! it will be dropped as an unsolicited communication by the router. If the connect times out for
//! the first peer and then the other sends the connect `SYN`, the first peer's listener will
//! accept it, thus increasing the connection chances.
//!
//! One of the challenge here is that some peer routers don't drop the unsolicited `SYN` silently
//! (which would be good for us) but additionally sends an `RST`. This could have bad effects. One
//! is our router might close the hole (update the filter to not allow remote traffic from peer any
//! more) because it realises that the connection has been closed. This means we will have to
//! continually send `SYNs` to re-enliven the hole even though we get `RSTs` and also to keep our
//! connector exiting (because they would also error out on `RST` reception). So the connect logic
//! sort of happens in a busy loop consuming resources and becomes very timing dependent.
//!
//! The other challenge is worse - some routers simply discard the incoming `SYNs` thus making it
//! impossible to do a TCP hole punch (or at-least until someone can show a cleverer way to
//! outsmart the router).
//!
//! Combined with non-hair-pinning and blacklisting (aggressive flood attack prevention), we can
//! quickly see why `TCP` NAT traversal is more difficult than `UDP`. The same trick as with
//! incremental `TTLs` was tried with TCP connects too, so that we punch holes but not reach the
//! other end quickly to get blacklisted or get `RST` which would close the hole. However for TCP
//! many intermediate routers send ICMP _No route to host_ error when `TTL` reaches 0. This too can
//! shutdown the hole thus this method is not used in this crate.
//!
//! Instead on any error to a send of `SYN` we discard the socket, get a new one on the same local
//! endpoint and retry sending `SYN` in hope to forge a `Simultaneous Connect`. We could end up
//! with a lot of reserved descriptors due to this so we explicitly set the TCP linger to 0. We set
//! it back up to default once we are connected.
//!
//! # Crate Design
//!
//! This crate is async and currently written using pure [mio]. The user is free to choose their
//! own event loop scheme. To work with user's async code, this crate has certain _expectations_.
//! It is expected that the user code implements our [`Interface`] trait which is passed
//! ubiquitously throughout the code here. Through this trait we are able to specify our
//! requirement from the user code. For e.g. most code in this crate go through several states
//! (like in a State Pattern) before reaching the final stage where we indicate via the callbacks
//! we take, whether the operation succeeded or failed. These intermediate states must be preserved
//! and notified to appropriately function. So we ask the user to provide us a way to preserve our
//! state (via [`insert_state`]), retrieve state ([`state`]), remove it ([`remove_state`])
//! and so on. The crate completely managers its own states including resource cleanups etc. and
//! not burden the user with it. This is what we ask via [`Interface`] trait.
//!
//! Just like we expect user to give us an expected [`Interface`] we ourselves implement
//! [`NatState`] trait. This trait allows the user to call our various states on appropriate events
//! during [Poll]. Any registered state can be actively terminated by user by invoking
//! [`terminate`].
//!
//! [0]: https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol
//! [mio]: https://github.com/carllerche/mio
//! [`Interface`]: ./trait.Interface.html
//! [`NatState`]: ./trait.NatState.html
//! [`insert_state`]: ./trait.Interface.html#method.insert_state
//! [`state`]: ./trait.Interface.html#method.state
//! [`remove_state`]: ./trait.Interface.html#method.remove_state
//! [`terminate`]: ./trait.NatState.html#method.terminate
//! [Poll]: http://rust-doc.s3-website-us-east-1.amazonaws.com/mio/master/mio/struct.Poll.html

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="cargo-clippy", allow(too_many_arguments))]
#![recursion_limit="100"]
#![allow(deprecated)]

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
extern crate byteorder;
extern crate mio;
extern crate net2;
extern crate rand;
extern crate rust_sodium as sodium;
extern crate serde;

use bincode::{Infinite, deserialize, serialize};
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
pub use tcp::TcpRendezvousServer;
pub use udp::UdpRendezvousServer;

/// Result type used by this crate.
pub type Res<T> = Result<T, NatError>;

/// The timer state used by this crate.
///
/// When the timer fires in the user's event loop poll, it is expected that they retrieve the
/// [`NatState`] using the associated token held in the timer and call its [`NatState::timeout`]
/// using the timer id. This allows the invocation of the correct [`NatState`] that started this
/// timer and also pinpoint which timer within it (using timer id) if it had started several
/// timers.
///
/// [`NatState`]: ./trait.NatState.html
/// [`NatState::timeout`]: ./trait.NatState.html#method.timeout
pub struct NatTimer {
    /// Associated `NatState::timeout` to be called
    pub associated_nat_state: Token,
    /// Indicates which timer fired out of potentially many that a state could have started. Also
    /// given to the parameter of `NatState::timeout`.
    pub timer_id: u8,
}

impl NatTimer {
    /// Create a new `NatTimer`
    pub fn new(state: Token, timer_id: u8) -> Self {
        NatTimer {
            associated_nat_state: state,
            timer_id: timer_id,
        }
    }
}

/// A message that can be sent to the event loop to perform an action.
///
/// This can be used to send actions from a thread outside the event loop too if sent via
/// [`mio::channel::Sender`][0].
///
/// [0]: http://rust-doc.s3-website-us-east-1.amazonaws.com/mio/master/mio/channel
pub struct NatMsg(Box<FnMut(&mut Interface, &Poll) + Send + 'static>);
impl NatMsg {
    /// Construct a new message indicating the action via a function/functor.
    pub fn new<F>(f: F) -> Self
        where F: FnOnce(&mut Interface, &Poll) + Send + 'static
    {
        let mut f = Some(f);
        NatMsg(Box::new(move |ifc: &mut Interface, poll: &Poll| if let Some(f) = f.take() {
                            f(ifc, poll)
                        }))
    }

    /// Execute the message (and thus the action).
    pub fn invoke(mut self, ifc: &mut Interface, poll: &Poll) {
        (self.0)(ifc, poll)
    }
}

/// The main trait that we implement.
///
/// All our registered states essentially implement this trait so that the user code can call us
/// and indicate what event was fired for us in poll.
pub trait NatState {
    /// To be called when readiness event has fired
    fn ready(&mut self, &mut Interface, &Poll, Ready) {}
    /// To be called when user wants to actively terminate this state. It will do all the necessary
    /// clean ups and resource (file/socket descriptors) cleaning freeing so merely calling this is
    /// sufficient.
    fn terminate(&mut self, &mut Interface, &Poll) {}
    /// To be called when timeout has been fired and the user has retrieved the state using the
    /// token stored inside the `NatTimer::associated_nat_state`.
    fn timeout(&mut self, &mut Interface, &Poll, u8) {}
    /// This is for internal use for the crate and is rarely needed.
    fn as_any(&mut self) -> &mut Any;
}

/// The main trait that our users should implement.
///
/// We enlist our _expectations_ from the user code using this trait. This trait object is passed
/// ubiquitously in this crate and also passed back to the user via various callbacks we take to
/// communicate results back to them.
pub trait Interface {
    /// We call this when we want our state to be held before we go back to the event loop. The
    /// callee is expected to store this some place (e.g. `HashMap<Token, Rc<RefCell<NatState>>>`)
    /// to be retrieved when `mio` poll indicates some event associated with the `token` has
    /// occurred. In that case call `NatState::ready`.
    fn insert_state(&mut self,
                    token: Token,
                    state: Rc<RefCell<NatState>>)
                    -> Result<(), (Rc<RefCell<NatState>>, String)>;
    /// Remove the state that was previously stored against the `token` and return it if
    /// successfully retrieved.
    fn remove_state(&mut self, token: Token) -> Option<Rc<RefCell<NatState>>>;
    /// Return the state (without removing - just a query) associated with the `token`
    fn state(&mut self, token: Token) -> Option<Rc<RefCell<NatState>>>;
    /// Set timeout. User code is expected to have a `mio::timer::Timer<NatTimer>` on which the
    /// timeout can be set.
    fn set_timeout(&mut self,
                   duration: Duration,
                   timer_detail: NatTimer)
                   -> Result<Timeout, TimerError>;
    /// Cancel the timout
    fn cancel_timeout(&mut self, timeout: &Timeout) -> Option<NatTimer>;
    /// Give us a new unique token
    fn new_token(&mut self) -> Token;
    /// Give us the `Config` the crate uses to figure out various values and behaviors
    fn config(&self) -> &Config;
    /// Hand over a public encryption key. This must be ideally initialised once and must not
    /// change in subsequent calls as this is what will be shared with remote contacts for secure
    /// communication.
    fn enc_pk(&self) -> &box_::PublicKey;
    /// Hand over a reference to secret encryption key. This must be ideally initialised once and
    /// must not change in subsequent calls as this is what will be used for secure communication.
    fn enc_sk(&self) -> &box_::SecretKey;
    /// Obtain a sender for use to send messages into event loop.
    fn sender(&self) -> &Sender<NatMsg>;
}

/// General wire format for encrypted communication
#[derive(Serialize, Deserialize)]
pub struct CryptMsg {
    /// Nonce used for this message
    pub nonce: [u8; box_::NONCEBYTES],
    /// Encrypted message
    pub cipher_text: Vec<u8>,
}


/// Utility function to encrypt messages to peer
pub fn msg_to_send(plain_text: &[u8], key: &box_::PrecomputedKey) -> ::Res<Vec<u8>> {
    let nonce = box_::gen_nonce();
    let handshake = CryptMsg {
        nonce: nonce.0,
        cipher_text: box_::seal_precomputed(plain_text, &nonce, key),
    };

    Ok(serialize(&handshake, Infinite)?)
}

/// Utility function to decrypt messages from peer
pub fn msg_to_read(raw: &[u8], key: &box_::PrecomputedKey) -> ::Res<Vec<u8>> {
    let CryptMsg { nonce, cipher_text } = deserialize(raw)?;
    box_::open_precomputed(&cipher_text, &box_::Nonce(nonce), key).
        map_err(|()| NatError::AsymmetricDecipherFailed)
}
