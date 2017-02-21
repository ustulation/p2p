use mio::{Events, Poll, PollOpt, Ready, Token};
use mio::channel::{self, Sender};
use mio::timer::{Timeout, Timer, TimerError};
use p2p::{Config, Interface, NatMsg, NatState, NatTimer};
use p2p::config::UdpHolePuncher;
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::FromStr;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const UDP_RENDEZVOUS_SERVER_0: &'static str = "174.138.70.126:5484";
const UDP_RENDEZVOUS_SERVER_1: &'static str = "104.236.84.160:5484";

struct Core {
    nat_states: HashMap<Token, Rc<RefCell<NatState>>>,
    timer: Timer<NatTimer>,
    token: usize,
    config: Config,
    enc_pk: box_::PublicKey,
    enc_sk: box_::SecretKey,
    tx: Sender<NatMsg>,
}

impl Core {
    fn handle_nat_timer(&mut self, poll: &Poll) {
        while let Some(nat_timer) = self.timer.poll() {
            if let Some(nat_state) = self.state(nat_timer.associated_nat_state) {
                nat_state.borrow_mut().timeout(self, poll, nat_timer.timer_id);
            }
        }
    }

    fn handle_readiness(&mut self, poll: &Poll, token: Token, kind: Ready) {
        if let Some(nat_state) = self.state(token) {
            nat_state.borrow_mut().ready(self, poll, kind);
        }
    }
}

impl Interface for Core {
    fn insert_state(&mut self,
                    token: Token,
                    state: Rc<RefCell<NatState>>)
                    -> Result<(), (Rc<RefCell<NatState>>, String)> {
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

    fn set_timeout(&mut self,
                   duration: Duration,
                   timer_detail: NatTimer)
                   -> Result<Timeout, TimerError> {
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

pub struct El {
    pub nat_tx: Sender<NatMsg>,
    tx: Sender<()>,
    joiner: Option<JoinHandle<()>>,
}

impl Drop for El {
    fn drop(&mut self) {
        let _ = self.tx.send(());
        let joiner = unwrap!(self.joiner.take());
        unwrap!(joiner.join());
    }
}

pub fn spawn_event_loop() -> El {
    let (core_tx, core_rx) = channel::channel::<()>();
    let (nat_tx, nat_rx) = channel::channel::<NatMsg>();
    let nat_tx_cloned = nat_tx.clone();

    let joiner = thread::spawn(move || {
        const TIMER_TOKEN: usize = 0;
        const CORE_RX_TOKEN: usize = TIMER_TOKEN + 1;
        const NAT_RX_TOKEN: usize = CORE_RX_TOKEN + 1;

        let poll = unwrap!(Poll::new());

        let puncher_0 = UdpHolePuncher {
            starting_ttl: 2,
            ttl_increment_delay_ms: 500,
        };
        let puncher_1 = UdpHolePuncher {
            starting_ttl: 5,
            ttl_increment_delay_ms: 500,
        };
        let puncher_2 = UdpHolePuncher {
            starting_ttl: 10,
            ttl_increment_delay_ms: 500,
        };
        let config = Config {
            rendezvous_timeout_sec: None,
            hole_punch_timeout_sec: None,
            udp_rendezvous_port: None,
            remote_udp_rendezvous_servers:
                vec![unwrap!(SocketAddr::from_str(UDP_RENDEZVOUS_SERVER_0)),
                     unwrap!(SocketAddr::from_str(UDP_RENDEZVOUS_SERVER_1))],
            udp_hole_punchers: vec![puncher_0, puncher_1, puncher_2],
        };

        let (pk, sk) = box_::gen_keypair();
        let timer = Timer::default();

        unwrap!(poll.register(&timer,
                              Token(TIMER_TOKEN),
                              Ready::readable() | Ready::error() | Ready::hup(),
                              PollOpt::edge()));
        unwrap!(poll.register(&core_rx,
                              Token(CORE_RX_TOKEN),
                              Ready::readable() | Ready::error() | Ready::hup(),
                              PollOpt::edge()));
        unwrap!(poll.register(&nat_rx,
                              Token(NAT_RX_TOKEN),
                              Ready::readable() | Ready::error() | Ready::hup(),
                              PollOpt::edge()));

        let mut core = Core {
            nat_states: HashMap::with_capacity(10),
            timer: timer,
            token: NAT_RX_TOKEN + 1,
            config: config,
            enc_pk: pk,
            enc_sk: sk,
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
                        break 'event_loop;
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
        tx: core_tx,
        joiner: Some(joiner),
    }
}
