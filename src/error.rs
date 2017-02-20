use bincode;
use mio::timer::TimerError;
use std::io;

quick_error! {
    /// Nat-traversal's universal error type.
    #[derive(Debug)]
    pub enum NatError {
        /// Io Error
        Io(e: io::Error) {
            description(e.description())
            display("{}", e)
            cause(e)
            from()
        }
        /// Timer error
        Timer(e: TimerError) {
            description(e.description())
            display("{}", e)
            cause(e)
            from()
        }
        /// Serialization errors
        Serialisation(e: bincode::Error) {
            description(e.description())
            display("{}", e)
            cause(e)
            from()
        }
        /// Udp Rendezvous with server failed - could not obtain our external address
        UdpRendezvousFailed {
            description("Udp Rendezvous with server failed - could not obtain our external address")
        }
        /// Booting up Udp Rendezvous Server failed
        UdpRendezvousServerStartFailed {
            description("Booting Udp Rendezvous Server Failed")
        }
        /// Udp Hole punch error
        UdpHolePunchError {
            description("Udp Hole punch error")
        }
        /// Timer ID is invalid
        InvalidTimerId {
            description("Timer ID is invalid")
        }
        /// Unknown error
        Unknown {
            description("Unknown Error in Nat Traversal")
        }
    }
}
