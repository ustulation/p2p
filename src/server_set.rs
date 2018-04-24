use future_utils::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use priv_prelude::*;
use rand;

/// Server list change event.
enum ListChange {
    Remove(SocketAddr),
    Add(PeerInfo),
}

#[derive(Default, Clone)]
pub struct ServerSet {
    servers: HashMap<SocketAddr, PeerInfo>,
    iterators: Vec<UnboundedSender<ListChange>>,
}

impl ServerSet {
    pub fn add_server(&mut self, peer: &PeerInfo) {
        self.iterators
            .retain(|sender| sender.unbounded_send(ListChange::Add(peer.clone())).is_ok());

        let _ = self.servers.insert(peer.addr, peer.clone());
    }

    pub fn remove_server(&mut self, addr: SocketAddr) {
        self.iterators
            .retain(move |sender| sender.unbounded_send(ListChange::Remove(addr)).is_ok());

        let _ = self.servers.remove(&addr);
    }

    pub fn iter_servers(&mut self) -> Servers {
        let (tx, rx) = unbounded();
        self.iterators.push(tx);
        let servers = self.servers.clone();
        trace!("iterating {} servers", servers.len());
        Servers {
            servers: servers,
            modifications: rx,
        }
    }
}

/// A list of servers that observes for modifications: updates itself when someone notifies about
/// new servers added or removed.
pub struct Servers {
    servers: HashMap<SocketAddr, PeerInfo>,
    modifications: UnboundedReceiver<ListChange>,
}

impl Servers {
    /// Returns a snapshot of current server list.
    pub fn snapshot(&self) -> HashSet<PeerInfo> {
        self.servers.values().cloned().collect()
    }

    /// Returns a snapshot of current server list addresses only.
    pub fn addrs_snapshot(&self) -> HashSet<SocketAddr> {
        self.servers.keys().cloned().collect()
    }
}

impl Stream for Servers {
    type Item = PeerInfo;
    type Error = Void;

    fn poll(&mut self) -> Result<Async<Option<PeerInfo>>, Void> {
        while let Async::Ready(Some(event)) = self.modifications.poll().void_unwrap() {
            let _ = match event {
                ListChange::Add(peer) => self.servers.insert(peer.addr, peer),
                ListChange::Remove(addr) => self.servers.remove(&addr),
            };
        }

        let server = match self.servers.remove_random(&mut rand::thread_rng()) {
            Some(server) => server,
            None => return Ok(Async::NotReady),
        };

        Ok(Async::Ready(Some(server)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod servers {
        use super::*;

        mod snapshot {
            use super::*;

            #[test]
            fn it_returns_current_server_list() {
                let mut servers = ServerSet::default();
                servers.add_server(&peer_addr!("1.2.3.4:4000"));
                servers.add_server(&peer_addr!("1.2.3.5:5000"));

                let addrs: HashSet<SocketAddr> = servers
                    .iter_servers()
                    .snapshot()
                    .iter()
                    .map(|info| info.addr)
                    .collect();

                assert!(addrs.contains(&addr!("1.2.3.4:4000")));
                assert!(addrs.contains(&addr!("1.2.3.5:5000")));
            }
        }

        mod poll {
            use super::*;
            use tokio_core::reactor::Core;

            #[test]
            fn it_returns_random_server_and_removes_it_from_the_list() {
                let mut servers = ServerSet::default();
                servers.add_server(&peer_addr!("1.2.3.4:4000"));

                let mut evloop = unwrap!(Core::new());

                let ret = evloop.run(
                    servers
                        .iter_servers()
                        .into_future()
                        .and_then(|(peer_addr, servers)| Ok((peer_addr, servers))),
                );
                let (random_addr, servers) = match ret {
                    Ok(result) => result,
                    Err(_e) => panic!("Failed to poll server address."),
                };

                assert_eq!(servers.addrs_snapshot().len(), 0);
                assert_eq!(unwrap!(random_addr).addr, addr!("1.2.3.4:4000"));
            }
        }
    }
}
