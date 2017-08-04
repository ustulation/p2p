use mio::{Events, Poll, PollOpt, Ready, Token};
use mio::channel::{self, Sender};
use mio::timer::{Timeout, Timer, TimerError};
use p2p::{Config, Interface, NatMsg, NatState, NatTimer};
use serde_json;
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::Read;
use std::rc::Rc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct Core {
    nat_states: HashMap<Token, Rc<RefCell<NatState>>>,
    peer_states: HashMap<Token, Rc<RefCell<CoreState>>>,
    timer: Timer<NatTimer>,
    token: usize,
    config: Config,
    enc_pk: box_::PublicKey,
    enc_sk: box_::SecretKey,
    tx: Sender<NatMsg>,
}

impl Core {
    #[allow(unused)]
    pub fn insert_peer_state(
        &mut self,
        token: Token,
        state: Rc<RefCell<CoreState>>,
    ) -> Result<(), (Rc<RefCell<CoreState>>, String)> {
        if let Entry::Vacant(ve) = self.peer_states.entry(token) {
            ve.insert(state);
            Ok(())
        } else {
            Err((state, "Token is already mapped".to_string()))
        }
    }

    #[allow(unused)]
    pub fn peer_state(&mut self, token: Token) -> Option<Rc<RefCell<CoreState>>> {
        self.peer_states.get(&token).cloned()
    }

    fn handle_nat_timer(&mut self, poll: &Poll) {
        while let Some(nat_timer) = self.timer.poll() {
            if let Some(nat_state) = self.state(nat_timer.associated_nat_state) {
                nat_state.borrow_mut().timeout(
                    self,
                    poll,
                    nat_timer.timer_id,
                );
            }
        }
    }

    fn handle_readiness(&mut self, poll: &Poll, token: Token, kind: Ready) {
        if let Some(nat_state) = self.state(token) {
            return nat_state.borrow_mut().ready(self, poll, kind);
        }
        if let Some(peer_state) = self.peer_states.get(&token).cloned() {
            return peer_state.borrow_mut().ready(self, poll, kind);
        }
    }
}

impl Interface for Core {
    fn insert_state(
        &mut self,
        token: Token,
        state: Rc<RefCell<NatState>>,
    ) -> Result<(), (Rc<RefCell<NatState>>, String)> {
        if let Entry::Vacant(ve) = self.nat_states.entry(token) {
            ve.insert(state);
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

    fn set_timeout(
        &mut self,
        duration: Duration,
        timer_detail: NatTimer,
    ) -> Result<Timeout, TimerError> {
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
}

pub trait CoreState {
    fn ready(&mut self, &mut Core, &Poll, Ready);
    fn terminate(&mut self, &mut Core, &Poll);
    fn write(&mut self, &mut Core, &Poll, String);
}

pub struct CoreMsg(Option<Box<FnMut(&mut Core, &Poll) + Send + 'static>>);
impl CoreMsg {
    #[allow(unused)]
    pub fn new<F: FnOnce(&mut Core, &Poll) + Send + 'static>(f: F) -> Self {
        let mut f = Some(f);
        CoreMsg(Some(Box::new(
            move |core: &mut Core, poll: &Poll| if let Some(f) =
                f.take()
            {
                f(core, poll);
            },
        )))
    }
}

pub struct El {
    pub nat_tx: Sender<NatMsg>,
    pub core_tx: Sender<CoreMsg>,
    joiner: Option<JoinHandle<()>>,
}

impl Drop for El {
    fn drop(&mut self) {
        let _ = self.core_tx.send(CoreMsg(None));
        let joiner = unwrap!(self.joiner.take());
        unwrap!(joiner.join());
    }
}

pub fn spawn_event_loop() -> El {
    let (core_tx, core_rx) = channel::channel::<CoreMsg>();
    let (nat_tx, nat_rx) = channel::channel();
    let nat_tx_cloned = nat_tx.clone();

    let joiner = thread::spawn(move || {
        const TIMER_TOKEN: usize = 0;
        const CORE_RX_TOKEN: usize = TIMER_TOKEN + 1;
        const NAT_RX_TOKEN: usize = CORE_RX_TOKEN + 1;

        let poll = unwrap!(Poll::new());

        let mut file = unwrap!(File::open("./sample-config"));
        let mut content = String::new();
        unwrap!(file.read_to_string(&mut content));
        let config = unwrap!(serde_json::from_str(&content));

        let (enc_pk, enc_sk) = box_::gen_keypair();
        let timer = Timer::default();

        unwrap!(poll.register(
            &timer,
            Token(TIMER_TOKEN),
            Ready::readable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        ));
        unwrap!(poll.register(
            &core_rx,
            Token(CORE_RX_TOKEN),
            Ready::readable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        ));
        unwrap!(poll.register(
            &nat_rx,
            Token(NAT_RX_TOKEN),
            Ready::readable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        ));

        let mut core = Core {
            nat_states: HashMap::with_capacity(10),
            peer_states: HashMap::with_capacity(5),
            timer: timer,
            token: NAT_RX_TOKEN + 1,
            config: config,
            enc_pk: enc_pk,
            enc_sk: enc_sk,
            tx: nat_tx,
        };

        let mut events = Events::with_capacity(1024);

        'event_loop: loop {
            unwrap!(poll.poll(&mut events, None));

            for event in events.iter() {
                match event.token() {
                    Token(t) if t == TIMER_TOKEN => {
                        assert!(event.kind().is_readable());
                        core.handle_nat_timer(&poll);
                    }
                    Token(t) if t == CORE_RX_TOKEN => {
                        assert!(event.kind().is_readable());
                        while let Ok(f) = core_rx.try_recv() {
                            if let Some(mut f) = f.0 {
                                f(&mut core, &poll);
                            } else {
                                break 'event_loop;
                            }
                        }
                    }
                    Token(t) if t == NAT_RX_TOKEN => {
                        assert!(event.kind().is_readable());
                        while let Ok(f) = nat_rx.try_recv() {
                            f.invoke(&mut core, &poll);
                        }
                    }
                    t => core.handle_readiness(&poll, t, event.kind()),
                }
            }
        }

    });

    El {
        nat_tx: nat_tx_cloned,
        core_tx: core_tx,
        joiner: Some(joiner),
    }
}
