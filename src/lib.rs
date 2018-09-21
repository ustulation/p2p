//! # General
//!
//! The goal of this crate is to provide a robust and crypto-secure NAT traversal for peer to peer
//! connection. It assumes publicly reachable rendezvous servers are provided. The server code
//! itself is in the crate too, so the crate can either be used to deploy a server or used for peer
//! to peer client communication or both simultaneously - for e.g. if you run the server on a port
//! forwarded endpoint, it will be publicly available for others to rendezvous while you could
//! choose normal NAT traversal mechanisms to communicate with other peers.
//!
//! There are different NAT types and filters around. The following is one of the ways to
//! categorise them and also explained within each section is what we do in our code to attempt to
//! traverse them.
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
//! This is the most restrictive NAT under *EIM*. In this crate this is what we assume for *EIMs*
//! because if we cover this then the less restrictive `Endpoint Address Dependent Filtering` will
//! be automatically covered (in other words we cover the worst case scenario for *EIMs*).
//!
//! When we talk to the rendezvous servers, such a NAT allows us to talk to only one of them at a
//! time from the same local *UDP* endpoint. Once we talk to them in succession we can easily find
//! out if we are behind an *EIM* NAT. This is because the external address seen by all the servers
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
//! *TTL* (time-to-live) to the rescue. While punching hole, we start with the lowest reasonable
//! *TTL* (of say 2). Note that some routers were found to drop the packet when *TTL* was 1 after
//! decrementing while some still send it but drop if the TTL reached the value of 0. With 2 it
//! will definitely go past the first router. We put a delay, increase the *TTL* by 1 and send
//! again.  Both sides (peers) do this. In practice it's usually the 1st couple (or 3) routers
//! that do NAT while others are non-NAT. This gives ample amount of time for the NAT-routers to
//! update their filters to allow the peer's incoming packets in the future while not reaching the
//! peer quickly themselves and getting blacklisted. By the time we hit *TTL* of around 12, we
//! would likely have reached the other end.
//!
//! This crate is highly configurable while providing reasonable defaults. So if the user wants
//! they can choose the starting *TTL* and the delay between bumping it up and re-transmitting. The
//! reasonable default would be to choose 3 sockets per peer, one with *TTL* starting 2, one with 6
//! and one with 64 (or OS default), so that if the fastest one was going to succeed it would do so
//! immediately (for friendlier routers) otherwise the slower ones would eventually reach there.
//! The blacklisting happens for the exact (remote) endpoint, so even if the faster ones got
//! blacklisted by the unfreindly routers the slower sockets (on different endpoints) still have
//! their chances.
//!
//! Once the hole is punched the *TTL* is put back to the OS default and normal p2p communication
//! can ensue. Also once the hole is punched by any socket, the others are immediately discarded so
//! that we don't end up with a lot of reserved descriptors for a single peer.
//!
//! Finally the attempt will either timeout (configurable or use the defaults in the crate) or if
//! the *TTL* has reached the OS default for the platform, the attempt is considered to have failed
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
//! With *TCP* some of the challenges are greater. The usual process is going through the same
//! rendezvous as with *UDP* above. While one *UDP* socket did fine for communicating with all the
//! servers and then hole punching to peer, *TCP* is connection oriented and thus we need multiple
//! sockets. We will bind a connector per server and then a connector to the peer. While beginning
//! to hole punch to the peer we will also additionally bind a listener to the same exact local
//! endpoint.
//!
//! TCP connection can be established either via normal connector-listener pair, in which one side
//! is active (sends *SYNs*) while the other is passive (reacts to *SYNs* by sending *SYN-ACKs*),
//! or via lesser know *TCP Simultaneous Connect* in which both sides actively send *SYNs* and
//! both establish the connection because when they see a *SYN* in response to a *SYN* they assume
//! the other side also wants to establish the connection and then it materialises. If there is an
//! active connector and a listener bound to the same local endpoint on either side (like stated
//! above), there is a better chance of establishing a connection. If *SYN* is sent by peer 1 to 2
//! punching a hole (updating the filter) in 1's router for 2 and similarly sent by 2 for 1 then
//! when they reach each other's routers they are let through and *TCP Simultaneous Connect* kicks
//! in. If one of the *SYNs* reached the other end before the other's *SYN* could leave its router,
//! it will be dropped as an unsolicited communication by the router. If the connect times out for
//! the first peer and then the other sends the connect *SYN*, the first peer's listener will
//! accept it, thus increasing the connection chances.
//!
//! One of the challenge here is that some peer routers don't drop the unsolicited *SYN* silently
//! (which would be good for us) but additionally sends an *RST*. This could have bad effects. One
//! is our router might close the hole (update the filter to not allow remote traffic from peer any
//! more) because it realises that the connection has been closed. This means we will have to
//! continually send *SYNs* to re-enliven the hole even though we get *RSTs* and also to keep our
//! connector exiting (because they would also error out on *RST* reception). So the connect logic
//! sort of happens in a busy loop consuming resources and becomes very timing dependent.
//!
//! The other challenge is worse - some routers simply discard the incoming *SYNs* (even if they
//! have seen an outgoing SYN to that remote endpoint) thus making it impossible to do a TCP hole
//! punch (or at-least until someone can show a cleverer way to outsmart the router).
//!
//! Combined with non-hair-pinning and blacklisting (aggressive flood attack prevention), we can
//! quickly see why *TCP* NAT traversal is more difficult than *UDP*. The same trick as with
//! incremental *TTLs* was tried with TCP connects too, so that we punch holes but not reach the
//! other end quickly to get blacklisted or get *RST* which would close the hole. However for TCP
//! many intermediate routers send ICMP _No route to host_ error when *TTL* reaches 0. This too can
//! shutdown the hole thus this method is not used in this crate.
//!
//! Instead on any error to a send of *SYN* we discard the socket, get a new one on the same local
//! endpoint and retry sending *SYN* in hope to forge a *Simultaneous Connect*. We could end up
//! with a lot of reserved descriptors due to this so we explicitly set the TCP linger to 0. We set
//! it back up to default once we are connected.
//!
//! [0]: https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol

#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]
#![recursion_limit = "100"]

extern crate bytes;
#[cfg(test)]
extern crate env_logger;
extern crate future_utils;
extern crate futures;
extern crate get_if_addrs;
extern crate igd;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
#[cfg(test)]
#[macro_use]
extern crate maplit;
extern crate net2;
#[macro_use]
extern crate net_literals;
#[cfg(test)]
#[cfg(target_os = "linux")]
#[cfg(feature = "netsim")]
extern crate netsim;
#[macro_use]
extern crate quick_error;
extern crate rand;
#[macro_use]
extern crate serde_derive;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_shared_udp_socket;
#[macro_use]
extern crate unwrap;
extern crate safe_crypto;
extern crate void;

mod prelude;
mod priv_prelude;

#[macro_use]
mod util;

mod filter_addrs;
mod igd_async;
mod ip_addr;
mod mc;
mod open_addr;
mod peer;
mod protocol;
mod querier_set;
mod query;
mod rendezvous_addr;
mod socket_addr;
mod tcp;
mod udp;

pub use prelude::*;

/// Network Address Translation type
#[derive(Debug, PartialEq)]
pub enum NatType {
    /// We failed to detect NAT type.
    Unknown,
    /// No NAT - direct connection is possible.
    None,
    /// Endpoint Independent Mapping
    EIM,
    /// Endpoint Dependent Mapping
    EDM,
}
