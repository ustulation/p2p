use future_utils::mpsc::{SendError, UnboundedReceiver, UnboundedSender, unbounded};
use priv_prelude::*;

#[derive(Debug)]
pub struct TwoWayChannel<T> {
    tx: UnboundedSender<T>,
    rx: UnboundedReceiver<T>,
}

impl<T> Sink for TwoWayChannel<T> {
    type SinkItem = T;
    type SinkError = SendError<T>;

    fn start_send(&mut self, item: T) -> Result<AsyncSink<T>, SendError<T>> {
        self.tx.start_send(item)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, SendError<T>> {
        self.tx.poll_complete()
    }
}

impl<T> Stream for TwoWayChannel<T> {
    type Item = T;
    type Error = Void;

    fn poll(&mut self) -> Result<Async<Option<T>>, Void> {
        self.rx.poll()
    }
}

pub fn two_way_channel<T>() -> (TwoWayChannel<T>, TwoWayChannel<T>) {
    let (tx0, rx0) = unbounded();
    let (tx1, rx1) = unbounded();

    (
        TwoWayChannel { tx: tx0, rx: rx1 },
        TwoWayChannel { tx: tx1, rx: rx0 },
    )
}
