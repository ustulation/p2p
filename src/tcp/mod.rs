use NatState;
use std::any::Any;

pub struct TcpHolePunchMediator;

impl NatState for TcpHolePunchMediator {
    fn as_any(&mut self) -> &mut Any {
        self
    }
}
