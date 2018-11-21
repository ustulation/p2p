use super::{Config, Interface, NatMsg, NatState, NatTimer};
use maidsafe_utilities::thread::{self, Joiner};
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::channel;
use mio_extras::channel::Sender;
use mio_extras::timer::{Timeout, Timer};
use serde_json;
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::rc::Rc;
use std::time::Duration;

/// Simplified state machine implementation for tests.
pub struct StateMachine {
    pub nat_states: HashMap<Token, Rc<RefCell<NatState>>>,
    pub timer: Timer<NatTimer>,
    pub token: usize,
    pub config: Config,
    pub enc_pk: box_::PublicKey,
    pub enc_sk: box_::SecretKey,
    pub tx: Sender<NatMsg>,
}

impl StateMachine {
    pub fn handle_nat_timer(&mut self, poll: &Poll) {
        while let Some(nat_timer) = self.timer.poll() {
            if let Some(nat_state) = self.state(nat_timer.associated_nat_state) {
                nat_state
                    .borrow_mut()
                    .timeout(self, poll, nat_timer.timer_id);
            }
        }
    }

    pub fn handle_readiness(&mut self, poll: &Poll, token: Token, kind: Ready) {
        if let Some(nat_state) = self.state(token) {
            return nat_state.borrow_mut().ready(self, poll, kind);
        }
    }
}

impl Interface for StateMachine {
    fn insert_state(
        &mut self,
        token: Token,
        state: Rc<RefCell<NatState>>,
    ) -> Result<(), (Rc<RefCell<NatState>>, String)> {
        if let Entry::Vacant(ve) = self.nat_states.entry(token) {
            let _ = ve.insert(state);
            Ok(())
        } else {
            Err((state, "Token is already mapped".to_string()))
        }
    }

    fn remove_state(&mut self, token: Token) -> Option<Rc<RefCell<NatState>>> {
        self.nat_states.remove(&token)
    }

    fn state(&mut self, token: Token) -> Option<Rc<RefCell<NatState>>> {
        self.nat_states.get(&token).cloned()
    }

    fn set_timeout(&mut self, duration: Duration, timer_detail: NatTimer) -> Timeout {
        self.timer.set_timeout(duration, timer_detail)
    }

    fn cancel_timeout(&mut self, timeout: &Timeout) -> Option<NatTimer> {
        self.timer.cancel_timeout(timeout)
    }

    fn new_token(&mut self) -> Token {
        self.token += 1;
        Token(self.token)
    }

    fn config(&self) -> &Config {
        &self.config
    }

    fn enc_pk(&self) -> &box_::PublicKey {
        &self.enc_pk
    }

    fn enc_sk(&self) -> &box_::SecretKey {
        &self.enc_sk
    }

    fn sender(&self) -> &Sender<NatMsg> {
        &self.tx
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

/// Spawn testing event loop in a separate thread and return a handle to control it.
pub fn spawn_event_loop(config: Config) -> EventLoop {
    let (done_tx, done_rx) = channel::channel();
    let (nat_tx, nat_rx) = channel::channel();
    let nat_tx2 = nat_tx.clone();

    let j = thread::named("Event-Loop", move || {
        const TIMER_TOKEN: usize = 0;
        const DONE_RX_TOKEN: usize = TIMER_TOKEN + 1;
        const NAT_RX_TOKEN: usize = DONE_RX_TOKEN + 1;

        let poll = unwrap!(Poll::new());

        let (enc_pk, enc_sk) = box_::gen_keypair();
        let timer = Timer::default();

        unwrap!(poll.register(
            &timer,
            Token(TIMER_TOKEN),
            Ready::readable(),
            PollOpt::edge(),
        ));
        unwrap!(poll.register(
            &done_rx,
            Token(DONE_RX_TOKEN),
            Ready::readable(),
            PollOpt::edge(),
        ));
        unwrap!(poll.register(
            &nat_rx,
            Token(NAT_RX_TOKEN),
            Ready::readable(),
            PollOpt::edge(),
        ));

        let mut sm = StateMachine {
            nat_states: HashMap::with_capacity(10),
            timer,
            token: NAT_RX_TOKEN + 1,
            config,
            enc_pk,
            enc_sk,
            tx: nat_tx,
        };

        let mut events = Events::with_capacity(1024);

        'event_loop: loop {
            unwrap!(poll.poll(&mut events, None));

            for event in events.iter() {
                match event.token() {
                    Token(TIMER_TOKEN) => {
                        assert!(event.readiness().is_readable());
                        sm.handle_nat_timer(&poll);
                    }
                    Token(DONE_RX_TOKEN) => {
                        assert!(event.readiness().is_readable());
                        unwrap!(done_rx.try_recv());
                        break 'event_loop;
                    }
                    Token(NAT_RX_TOKEN) => {
                        assert!(event.readiness().is_readable());
                        while let Ok(f) = nat_rx.try_recv() {
                            f.invoke(&mut sm, &poll);
                        }
                    }
                    t => sm.handle_readiness(&poll, t, event.readiness()),
                }
            }
        }
    });

    EventLoop {
        nat_tx: nat_tx2,
        done_tx,
        _j: j,
    }
}

/// Handle to event loop running in a separate thread.
pub struct EventLoop {
    pub nat_tx: Sender<NatMsg>,
    pub done_tx: Sender<()>,
    _j: Joiner,
}

impl Drop for EventLoop {
    fn drop(&mut self) {
        unwrap!(self.done_tx.send(()));
    }
}

/// Read p2p config from json file.
#[allow(unused)]
pub fn read_config(path: &str) -> Config {
    let mut file = unwrap!(File::open(path));
    let mut content = String::new();
    unwrap!(file.read_to_string(&mut content));
    unwrap!(serde_json::from_str(&content))
}
