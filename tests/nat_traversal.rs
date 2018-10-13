extern crate maidsafe_utilities;
extern crate mio;
extern crate p2p;
extern crate rust_sodium as sodium;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

use maidsafe_utilities::thread::{self, Joiner};
use mio::channel::{self, Sender};
use mio::timer::{Timeout, Timer, TimerError};
use mio::{Event, Events, Poll, PollOpt, Ready, Token};
use p2p::{
    Config, Handle, HolePunchMediator, Interface, NatMsg, NatState, NatTimer, RendezvousInfo, Res,
    TcpRendezvousServer, UdpRendezvousServer,
};
use sodium::crypto::box_;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

pub struct StateMachine {
    nat_states: HashMap<Token, Rc<RefCell<NatState>>>,
    timer: Timer<NatTimer>,
    token: usize,
    config: Config,
    enc_pk: box_::PublicKey,
    enc_sk: box_::SecretKey,
    tx: Sender<NatMsg>,
}

impl StateMachine {
    fn handle_nat_timer(&mut self, poll: &Poll) {
        while let Some(nat_timer) = self.timer.poll() {
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
    }
}

impl Interface for StateMachine {
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

pub struct CoreMsg(Option<Box<FnMut(&mut StateMachine, &Poll) + Send + 'static>>);
impl CoreMsg {
    #[allow(unused)]
    pub fn new<F: FnOnce(&mut StateMachine, &Poll) + Send + 'static>(f: F) -> Self {
        let mut f = Some(f);
        CoreMsg(Some(Box::new(move |sm: &mut StateMachine, poll: &Poll| {
            if let Some(f) = f.take() {
                f(sm, poll);
            }
        })))
    }
}

pub struct El {
    pub nat_tx: Sender<NatMsg>,
    pub core_tx: Sender<CoreMsg>,
    _j: Joiner,
}

impl Drop for El {
    fn drop(&mut self) {
        unwrap!(self.core_tx.send(CoreMsg(None)));
    }
}

pub fn spawn_event_loop(config_path: String) -> El {
    let (core_tx, core_rx) = channel::channel::<CoreMsg>();
    let (nat_tx, nat_rx) = channel::channel();
    let nat_tx_cloned = nat_tx.clone();
    let core_tx_cloned = core_tx.clone();

    let j = thread::named("Event-Loop", move || {
        const TIMER_TOKEN: usize = 0;
        const CORE_RX_TOKEN: usize = TIMER_TOKEN + 1;
        const NAT_RX_TOKEN: usize = CORE_RX_TOKEN + 1;

        let poll = unwrap!(Poll::new());

        let mut file = unwrap!(File::open(&config_path));
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

        let mut sm = StateMachine {
            nat_states: HashMap::with_capacity(10),
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
                    Token(TIMER_TOKEN) => {
                        assert!(event.kind().is_readable());
                        sm.handle_nat_timer(&poll);
                    }
                    Token(CORE_RX_TOKEN) => {
                        assert!(event.kind().is_readable());
                        while let Ok(f) = core_rx.try_recv() {
                            if let Some(mut f) = f.0 {
                                f(&mut sm, &poll);
                            } else {
                                break 'event_loop;
                            }
                        }
                    }
                    Token(NAT_RX_TOKEN) => {
                        assert!(event.kind().is_readable());
                        while let Ok(f) = nat_rx.try_recv() {
                            f.invoke(&mut sm, &poll);
                        }
                    }
                    t => sm.handle_readiness(&poll, t, event.kind()),
                }
            }
        }
    });

    El {
        nat_tx: nat_tx_cloned,
        core_tx: core_tx_cloned,
        _j: j,
    }
}

fn start_rendezvous_servers() -> Vec<El> {
    const NUM_RENDEZVOUS_SERVERS: usize = 3;

    let mut els = Vec::new();

    for i in 0..NUM_RENDEZVOUS_SERVERS {
        let el = spawn_event_loop(format!(
            "./tests/nat-traversal-test-configs/config-rendezvous-server-{}",
            i,
        ));

        let (tx, rx) = mpsc::channel();
        unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
            let udp_server_token = unwrap!(UdpRendezvousServer::start(ifc, poll));
            let tcp_server_token = unwrap!(TcpRendezvousServer::start(ifc, poll));
            unwrap!(tx.send((udp_server_token, tcp_server_token)));
        })));

        let (udp_server_token, tcp_server_token) = unwrap!(rx.recv());

        els.push(el);
    }

    els
}

fn get_rendezvous_info(el: &El) -> mpsc::Receiver<Res<(Handle, RendezvousInfo)>> {
    let (tx, rx) = mpsc::channel();
    unwrap!(el.nat_tx.send(NatMsg::new(move |ifc, poll| {
        let handler = move |_: &mut Interface, _: &Poll, res| {
            unwrap!(tx.send(res));
        };
        unwrap!(HolePunchMediator::start(ifc, poll, Box::new(handler)));
    })));

    rx
}

#[test]
fn nat_traverse() {
    unwrap!(maidsafe_utilities::log::init(true));

    let els_rendezvous_servers = start_rendezvous_servers();

    let peer_config_path = "./tests/nat-traversal-test-configs/config-peers".to_string();
    let el_peer0 = spawn_event_loop(peer_config_path.clone());
    let el_peer1 = spawn_event_loop(peer_config_path);

    // Get `RendezvousInfo` in parallel
    let rendezvous_rx0 = get_rendezvous_info(&el_peer0);
    let rendezvous_rx1 = get_rendezvous_info(&el_peer1);

    let (handle0, rendezvous_info0) = unwrap!(unwrap!(rendezvous_rx0.recv()));
    let (handle1, rendezvous_info1) = unwrap!(unwrap!(rendezvous_rx1.recv()));

    // NAT Traverse in parallel
    let (hole_punch_tx0, hole_punch_rx0) = mpsc::channel();
    handle0.fire_hole_punch(
        rendezvous_info1,
        Box::new(move |_, _, res| {
            unwrap!(hole_punch_tx0.send(res));
        }),
    );
    let (hole_punch_tx1, hole_punch_rx1) = mpsc::channel();
    handle1.fire_hole_punch(
        rendezvous_info0,
        Box::new(move |_, _, res| {
            unwrap!(hole_punch_tx1.send(res));
        }),
    );

    let hole_punch_info0 = unwrap!(unwrap!(hole_punch_rx0.recv()));
    let hole_punch_info1 = unwrap!(unwrap!(hole_punch_rx1.recv()));

    assert!(hole_punch_info0.tcp.is_some());
    assert!(hole_punch_info0.udp.is_some());
    assert!(hole_punch_info1.tcp.is_some());
    assert!(hole_punch_info1.udp.is_some());
}
