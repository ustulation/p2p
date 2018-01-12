use future_utils::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use priv_prelude::*;
use rand;

#[derive(Default, Clone)]
pub struct ServerSet {
    servers: HashSet<SocketAddr>,
    iterators: Vec<UnboundedSender<(SocketAddr, bool)>>,
}

impl ServerSet {
    pub fn add_server(&mut self, addr: &SocketAddr) {
        self.iterators.retain(|sender| {
            sender.unbounded_send((*addr, true)).is_ok()
        });

        let _ = self.servers.insert(*addr);
    }

    pub fn remove_server(&mut self, addr: &SocketAddr) {
        self.iterators.retain(|sender| {
            sender.unbounded_send((*addr, false)).is_ok()
        });

        let _ = self.servers.remove(addr);
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

pub struct Servers {
    servers: HashSet<SocketAddr>,
    modifications: UnboundedReceiver<(SocketAddr, bool)>,
}

impl Servers {
    /// Returns a snapshot of current server list.
    pub fn snapshot(&self) -> HashSet<SocketAddr> {
        self.servers.clone()
    }
}

impl Stream for Servers {
    type Item = SocketAddr;
    type Error = Void;

    fn poll(&mut self) -> Result<Async<Option<SocketAddr>>, Void> {
        while let Async::Ready(Some((server, add))) = self.modifications.poll().void_unwrap() {
            if add {
                let _ = self.servers.insert(server);
            } else {
                let _ = self.servers.remove(&server);
            }
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
                servers.add_server(&addr!("1.2.3.4:4000"));
                servers.add_server(&addr!("1.2.3.5:5000"));

                let addrs = servers.iter_servers().snapshot();

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
                servers.add_server(&addr!("1.2.3.4:4000"));

                let mut evloop = unwrap!(Core::new());

                let ret = evloop.run(servers.iter_servers().into_future().and_then(
                    |(addr, servers)| {
                        Ok((addr, servers))
                    },
                ));
                let (random_addr, servers) = match ret {
                    Ok(result) => result,
                    Err(_e) => panic!("Failed to poll server address."),
                };

                assert_eq!(servers.snapshot().len(), 0);
                assert_eq!(random_addr, Some(addr!("1.2.3.4:4000")));
            }
        }
    }
}
