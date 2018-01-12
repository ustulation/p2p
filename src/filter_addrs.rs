use priv_prelude::*;

pub fn filter_addrs(
    our_addrs: &HashSet<SocketAddr>,
    their_addrs: &HashSet<SocketAddr>,
) -> HashSet<SocketAddr> {
    let our_global_addrs = {
        our_addrs
            .iter()
            .cloned()
            .filter(|addr| IpAddrExt::is_global(&addr.ip()))
            .collect::<HashSet<_>>()
    };
    let our_private_addrs = {
        our_addrs
            .iter()
            .cloned()
            .filter(|addr| addr.ip().is_private())
            .collect::<HashSet<_>>()
    };
    let their_global_addrs = {
        their_addrs
            .iter()
            .cloned()
            .filter(|addr| IpAddrExt::is_global(&addr.ip()))
            .collect::<HashSet<_>>()
    };
    let any_global_ips_in_common = {
        their_global_addrs.iter().any(|a0| {
            our_global_addrs.iter().any(|a1| a0.ip() == a1.ip())
        })
    };
    let maybe_same_subnet = any_global_ips_in_common ||
        (their_global_addrs.is_empty() && our_global_addrs.is_empty());
    let their_filtered_private_addrs = {
        if maybe_same_subnet {
            their_addrs
                .iter()
                .cloned()
                .filter(|addr| addr.ip().is_private())
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        }
    };
    let any_private_ips_in_common = {
        their_filtered_private_addrs.iter().any(|a0| {
            our_private_addrs.iter().any(|a1| a0.ip() == a1.ip())
        })
    };
    let maybe_same_machine = any_private_ips_in_common ||
        (their_filtered_private_addrs.is_empty() && our_private_addrs.is_empty() &&
             maybe_same_subnet);
    let their_filtered_loopback_addr = {
        if maybe_same_machine {
            their_addrs.iter().cloned().find(
                |addr| addr.ip().is_loopback(),
            )
        } else {
            None
        }
    };

    their_global_addrs
        .into_iter()
        .chain({
            their_filtered_private_addrs.into_iter().chain(
                their_filtered_loopback_addr,
            )
        })
        .collect()
}

#[cfg(test)]
#[test]
fn test() {
    let our_addrs =
        hashset!{
        addr!("78.60.234.207:45666"),
        addr!("192.168.0.1:45666"),
        addr!("127.0.0.1:45666"),
    };


    let their_addrs =
        hashset!{
        addr!("78.60.234.208:45667"),
        addr!("192.168.0.1:45667"),
        addr!("127.0.0.1:45667"),
    };
    let supposed_addrs =
        hashset!{
        addr!("78.60.234.208:45667"),
    };
    let result = filter_addrs(&our_addrs, &their_addrs);
    assert_eq!(result, supposed_addrs);


    let their_addrs =
        hashset!{
        addr!("78.60.234.207:45667"),
        addr!("192.168.0.2:45667"),
        addr!("127.0.0.1:45667"),
    };
    let supposed_addrs =
        hashset!{
        addr!("78.60.234.207:45667"),
        addr!("192.168.0.2:45667"),
    };
    let result = filter_addrs(&our_addrs, &their_addrs);
    assert_eq!(result, supposed_addrs);


    let their_addrs =
        hashset!{
        addr!("78.60.234.207:45667"),
        addr!("192.168.0.1:45667"),
        addr!("127.0.0.1:45667"),
    };
    let supposed_addrs =
        hashset!{
        addr!("78.60.234.207:45667"),
        addr!("192.168.0.1:45667"),
        addr!("127.0.0.1:45667"),
    };
    let result = filter_addrs(&our_addrs, &their_addrs);
    assert_eq!(result, supposed_addrs);
}
