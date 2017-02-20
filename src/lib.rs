#![cfg_attr(feature="cargo-clippy", allow(too_many_arguments))]

#[macro_use]
extern crate log;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate serde_derive;

extern crate bincode;
extern crate mio;
extern crate rust_sodium as sodium;
extern crate serde;

use mio::{Poll, Ready, Token};
use mio::channel::Sender;
use mio::timer::{Timeout, TimerError};
use sodium::crypto::box_;
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

pub mod config;

mod error;
mod hole_punch;
mod tcp;
mod udp;

pub use config::Config;
pub use error::NatError;
pub use hole_punch::{GetInfo, Handle, HolePunchFinsih, HolePunchInfo, HolePunchMediator,
                     RendezvousInfo};
pub use udp::UdpRendezvousServer;

pub type Res<T> = Result<T, NatError>;

pub struct NatTimer {
    pub associated_nat_state: Token,
    pub timer_id: u8,
}
impl NatTimer {
    pub fn new(state: Token, timer_id: u8) -> Self {
        NatTimer {
            associated_nat_state: state,
            timer_id: timer_id,
        }
    }
}

pub type NatMsg = Box<FnMut(&mut Interface, &Poll) + Send + 'static>;

pub trait NatState {
    fn ready(&mut self, &mut Interface, &Poll, Ready) {}
    fn terminate(&mut self, &mut Interface, &Poll) {}
    fn timeout(&mut self, &mut Interface, &Poll, u8) {}
    fn as_any(&mut self) -> &mut Any;
}

pub trait Interface {
    fn insert_state(&mut self,
                    token: Token,
                    state: Rc<RefCell<NatState>>)
                    -> Result<(), (Rc<RefCell<NatState>>, String)>;
    fn remove_state(&mut self, token: Token) -> Option<Rc<RefCell<NatState>>>;
    fn state(&mut self, token: Token) -> Option<Rc<RefCell<NatState>>>;
    fn set_timeout(&mut self,
                   duration: Duration,
                   timer_detail: NatTimer)
                   -> Result<Timeout, TimerError>;
    fn cancel_timeout(&mut self, timeout: &Timeout) -> Option<NatTimer>;
    fn new_token(&mut self) -> Token;
    fn config(&self) -> &Config;
    fn enc_pk(&self) -> &box_::PublicKey;
    fn enc_sk(&self) -> &box_::SecretKey;
    fn sender(&self) -> &Sender<NatMsg>;
}
