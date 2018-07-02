use future_utils::mpsc::{self, UnboundedReceiver, UnboundedSender};
use priv_prelude::*;
use std::collections::hash_map;
use std::hash::Hasher;

#[derive(Default, Debug)]
pub struct TcpAddrQuerierSet {
    addr_queriers: HashMap<u64, Arc<TcpAddrQuerier>>,
    txs: Vec<UnboundedSender<Arc<TcpAddrQuerier>>>,
}

impl TcpAddrQuerierSet {
    pub fn add_addr_querier(&mut self, addr_querier: impl TcpAddrQuerier + Hash) {
        let addr_querier = Arc::new(addr_querier);
        self.txs
            .retain(|tx| tx.unbounded_send(addr_querier.clone()).is_ok());
        let mut hasher = hash_map::DefaultHasher::new();
        addr_querier.hash(&mut hasher);
        let hash = hasher.finish();
        let _ = self.addr_queriers.insert(hash, addr_querier);
    }

    pub fn remove_addr_querier<T: Hash>(&mut self, addr_querier: &T) {
        let mut hasher = hash_map::DefaultHasher::new();
        addr_querier.hash(&mut hasher);
        let hash = hasher.finish();
        let _ = self.addr_queriers.remove(&hash);
    }

    pub fn addr_queriers(&mut self) -> UnboundedReceiver<Arc<TcpAddrQuerier>> {
        let (tx, rx) = mpsc::unbounded();
        for addr_querier in self.addr_queriers.values() {
            let _ = tx.unbounded_send(addr_querier.clone());
        }
        self.txs.push(tx);
        rx
    }
}

#[derive(Default, Debug)]
pub struct UdpAddrQuerierSet {
    addr_queriers: HashMap<u64, Arc<UdpAddrQuerier>>,
    txs: Vec<UnboundedSender<Arc<UdpAddrQuerier>>>,
}

impl UdpAddrQuerierSet {
    pub fn add_addr_querier(&mut self, addr_querier: impl UdpAddrQuerier + Hash) {
        let addr_querier = Arc::new(addr_querier);
        self.txs
            .retain(|tx| tx.unbounded_send(addr_querier.clone()).is_ok());
        let mut hasher = hash_map::DefaultHasher::new();
        addr_querier.hash(&mut hasher);
        let hash = hasher.finish();
        let _ = self.addr_queriers.insert(hash, addr_querier);
    }

    pub fn remove_addr_querier<T: Hash>(&mut self, addr_querier: &T) {
        let mut hasher = hash_map::DefaultHasher::new();
        addr_querier.hash(&mut hasher);
        let hash = hasher.finish();
        let _ = self.addr_queriers.remove(&hash);
    }

    pub fn addr_queriers(&mut self) -> UnboundedReceiver<Arc<UdpAddrQuerier>> {
        let (tx, rx) = mpsc::unbounded();
        for addr_querier in self.addr_queriers.values() {
            let _ = tx.unbounded_send(addr_querier.clone());
        }
        self.txs.push(tx);
        rx
    }
}
