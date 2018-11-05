use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::channel::{self, Sender};
use mio_extras::timer::{Timeout, Timer};
use p2p::{Config, Interface, NatMsg, NatState, NatTimer};
use safe_crypto::{gen_encrypt_keypair, PublicEncryptKey, SecretEncryptKey};
use std::any::Any;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::rc::Rc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct Core {
    nat_states: HashMap<Token, Rc<RefCell<NatState>>>,
    peer_states: HashMap<Token, Rc<RefCell<CoreState>>>,
    core_timer: Timer<CoreTimer>,
    nat_timer: Timer<NatTimer>,
    token: usize,
    config: Config,
    enc_pk: PublicEncryptKey,
    enc_sk: SecretEncryptKey,
    tx: Sender<NatMsg>,
    // udt_epoll_handle: Handle,
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

    pub fn remove_peer_state(&mut self, token: Token) -> Option<Rc<RefCell<CoreState>>> {
        self.peer_states.remove(&token)
    }

    // pub fn udt_epoll_handle(&self) -> Handle {
    //     unreachable!("For later");
    //     //self.udt_epoll_handle.clone()
    // }

    pub fn peer_state(&mut self, token: Token) -> Option<Rc<RefCell<CoreState>>> {
        self.peer_states.get(&token).cloned()
    }

    pub fn set_core_timeout(&mut self, duration: Duration, timer_detail: CoreTimer) -> Timeout {
        self.core_timer.set_timeout(duration, timer_detail)
    }

    pub fn cancel_core_timeout(&mut self, timeout: &Timeout) -> Option<CoreTimer> {
        self.core_timer.cancel_timeout(timeout)
    }

    fn handle_core_timer(&mut self, poll: &Poll) {
        while let Some(core_timer) = self.core_timer.poll() {
            if let Some(peer_state) = self.peer_state(core_timer.associated_peer_state) {
                peer_state
                    .borrow_mut()
                    .timeout(self, poll, core_timer.timer_id);
            }
        }
    }

    fn handle_nat_timer(&mut self, poll: &Poll) {
        while let Some(nat_timer) = self.nat_timer.poll() {
            if let Some(nat_state) = self.state(nat_timer.associated_nat_state) {
                nat_state
                    .borrow_mut()
                    .timeout(self, poll, nat_timer.timer_id);
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

    fn set_timeout(&mut self, duration: Duration, timer_detail: NatTimer) -> Timeout {
        self.nat_timer.set_timeout(duration, timer_detail)
    }

    fn cancel_timeout(&mut self, timeout: &Timeout) -> Option<NatTimer> {
        self.nat_timer.cancel_timeout(timeout)
    }

    fn new_token(&mut self) -> Token {
        self.token += 1;
        Token(self.token)
    }

    fn config(&self) -> &Config {
        &self.config
    }

    fn enc_pk(&self) -> &PublicEncryptKey {
        &self.enc_pk
    }

    fn enc_sk(&self) -> &SecretEncryptKey {
        &self.enc_sk
    }

    fn sender(&self) -> &Sender<NatMsg> {
        &self.tx
    }

    fn as_any(&mut self) -> &mut Any {
        self
    }
}

pub trait CoreState {
    fn ready(&mut self, &mut Core, &Poll, Ready);
    fn write(&mut self, &mut Core, &Poll, Vec<u8>) {}
    fn timeout(&mut self, &mut Core, &Poll, u8) {}
    fn terminate(&mut self, &mut Core, &Poll);
    fn as_any(&mut self) -> &mut Any;
}

pub struct CoreTimer {
    pub associated_peer_state: Token,
    pub timer_id: u8,
}

impl CoreTimer {
    pub fn new(associated_peer_state: Token, timer_id: u8) -> Self {
        CoreTimer {
            associated_peer_state,
            timer_id,
        }
    }
}
pub struct CoreMsg(Option<Box<FnMut(&mut Core, &Poll) + Send + 'static>>);
impl CoreMsg {
    pub fn new<F: FnOnce(&mut Core, &Poll) + Send + 'static>(f: F) -> Self {
        let mut f = Some(f);
        CoreMsg(Some(Box::new(move |core: &mut Core, poll: &Poll| {
            if let Some(f) = f.take() {
                f(core, poll);
            }
        })))
    }
}

// pub struct Notify(Sender<CoreMsg>);
// impl Notifier for Notify {
//     fn notify(&self, event: Event) {
//         unwrap!(self.0.send(CoreMsg::new(move |core, poll| {
//             core.handle_readiness(poll, event.token(), event.kind());
//         })));
//     }
// }

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
        println!("Gracefully shut down mio event loop");
    }
}

pub fn spawn_event_loop(p2p_cfg: Config) -> El {
    let (core_tx, core_rx) = channel::channel::<CoreMsg>();
    let (nat_tx, nat_rx) = channel::channel();
    let nat_tx_cloned = nat_tx.clone();
    let core_tx_cloned = core_tx.clone();

    let joiner = thread::spawn(move || {
        const CORE_TIMER_TOKEN: usize = 0;
        const NAT_TIMER_TOKEN: usize = CORE_TIMER_TOKEN + 1;
        const CORE_RX_TOKEN: usize = NAT_TIMER_TOKEN + 1;
        const NAT_RX_TOKEN: usize = CORE_RX_TOKEN + 1;

        let poll = unwrap!(Poll::new());

        let (enc_pk, enc_sk) = gen_encrypt_keypair();
        let core_timer = Timer::default();
        let nat_timer = Timer::default();

        unwrap!(poll.register(
            &core_timer,
            Token(CORE_TIMER_TOKEN),
            Ready::readable() | Ready::error() | Ready::hup(),
            PollOpt::edge(),
        ));
        unwrap!(poll.register(
            &nat_timer,
            Token(NAT_TIMER_TOKEN),
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

        // let notifier = Notify(core_tx);
        // let epoll_loop = unwrap!(EpollLoop::start_event_loop(notifier));
        // let udt_epoll_handle = epoll_loop.handle();

        let mut core = Core {
            nat_states: HashMap::with_capacity(10),
            peer_states: HashMap::with_capacity(5),
            core_timer,
            nat_timer,
            token: NAT_RX_TOKEN + 1,
            config: p2p_cfg,
            enc_pk: enc_pk,
            enc_sk: enc_sk,
            tx: nat_tx,
            // udt_epoll_handle,
        };

        let mut events = Events::with_capacity(1024);

        'event_loop: loop {
            unwrap!(poll.poll(&mut events, None));

            for event in events.iter() {
                match event.token() {
                    Token(t) if t == CORE_TIMER_TOKEN => {
                        assert!(event.kind().is_readable());
                        core.handle_core_timer(&poll);
                    }
                    Token(t) if t == NAT_TIMER_TOKEN => {
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
        core_tx: core_tx_cloned,
        joiner: Some(joiner),
    }
}
