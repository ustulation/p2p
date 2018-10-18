# P2P NAT-Traversal

|Crate|Documentation|Linux/OSX/Windows|
|:---:|:-----------:|:----------------:|
| [![](http://meritbadge.herokuapp.com/p2p)](https://crates.io/crates/p2p) | [![Documentation](https://docs.rs/p2p/badge.svg)](https://docs.rs/p2p) | [![Build Status](https://travis-ci.org/ustulation/p2p.svg?branch=master)](https://travis-ci.org/ustulation/p2p)


The goal of this crate is to provide a robust and crypto-secure NAT traversal for peer to peer connection. It assumes publicly reachable rendezvous servers are provided. The server code itself is in the crate too, so the crate can either be used to deploy a server or used for peer to peer client communication or both simultaneously - for e.g. if you run the server on a port forwarded endpoint, it will be publicly available for others to rendezvous while you could choose normal NAT traversal mechanisms to communicate with other peers.

Please refer to the documentation above for detailed explanation. The examples and the integration tests show how the crate can be used.
