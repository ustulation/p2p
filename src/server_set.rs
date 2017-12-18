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

        self.servers.insert(*addr);
    }

    pub fn remove_server(&mut self, addr: &SocketAddr) {
        self.iterators.retain(|sender| {
            sender.unbounded_send((*addr, false)).is_ok()
        });

        self.servers.remove(addr);
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

impl Stream for Servers {
    type Item = SocketAddr;
    type Error = Void;

    fn poll(&mut self) -> Result<Async<Option<SocketAddr>>, Void> {
        while let Async::Ready(Some((server, add))) = self.modifications.poll().void_unwrap() {
            if add {
                self.servers.insert(server);
            } else {
                self.servers.remove(&server);
            }
        }

        let server = match self.servers.remove_random(&mut rand::thread_rng()) {
            Some(server) => server,
            None => return Ok(Async::NotReady),
        };

        Ok(Async::Ready(Some(server)))
    }
}
