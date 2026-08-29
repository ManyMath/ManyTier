//! Local endpoints advertised with PUSH_DIRECT_PATHS.

use std::net::{IpAddr, SocketAddr};

/// Tunnels and container/VM bridges are never advertised.
fn is_tunnel_interface(name: &str) -> bool {
    [
        "utun", "zt", "tun", "tap", "feth", "wg", "ipsec", "ppp", "docker", "br-", "virbr", "veth",
        "lxc", "lxd", "cni", "flannel", "podman", "awdl", "llw", "bridge", "anpi", "ap", "gif",
        "stf",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn is_advertisable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Reachable endpoints on `port`, sorted and deduplicated.
pub fn local_udp_endpoints(port: u16) -> Vec<SocketAddr> {
    let mut endpoints: Vec<SocketAddr> = local_addresses()
        .into_iter()
        .filter(|(name, ip)| !is_tunnel_interface(name) && is_advertisable(*ip))
        .map(|(_, ip)| SocketAddr::new(ip, port))
        .collect();
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

/// `(name, address)` for every up interface.
#[cfg(unix)]
fn local_addresses() -> Vec<(String, IpAddr)> {
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return out;
    }
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: node of the live list.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() {
            continue;
        }
        let flags = entry.ifa_flags as libc::c_int;
        if flags & libc::IFF_UP == 0 || flags & libc::IFF_LOOPBACK != 0 {
            continue;
        }
        // SAFETY: NUL-terminated.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: non-null.
        let family = unsafe { (*entry.ifa_addr).sa_family } as libc::c_int;
        let ip = match family {
            libc::AF_INET => {
                // SAFETY: AF_INET => sockaddr_in.
                let sa = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                // SAFETY: AF_INET6 => sockaddr_in6.
                let sa = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        out.push((name, ip));
    }
    // SAFETY: freed once.
    unsafe { libc::freeifaddrs(list) };
    out
}

#[cfg(not(unix))]
fn local_addresses() -> Vec<(String, IpAddr)> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_and_special_addresses_are_excluded() {
        assert!(is_tunnel_interface("utun0"));
        assert!(is_tunnel_interface("zt0894e035ae76"));
        assert!(is_tunnel_interface("docker0"));
        assert!(is_tunnel_interface("br-3f2a9c1d7e4b"));
        assert!(is_tunnel_interface("virbr0"));
        assert!(is_tunnel_interface("vethabc123"));
        assert!(!is_tunnel_interface("en0"));
        assert!(!is_tunnel_interface("eth0"));
        assert!(!is_tunnel_interface("enp3s0"));
        assert!(!is_tunnel_interface("wlan0"));
        assert!(!is_advertisable("127.0.0.1".parse().unwrap()));
        assert!(!is_advertisable("169.254.10.1".parse().unwrap()));
        assert!(!is_advertisable("fe80::1".parse().unwrap()));
        assert!(!is_advertisable("::1".parse().unwrap()));
        assert!(is_advertisable("192.168.1.218".parse().unwrap()));
        assert!(is_advertisable("2001:db8::7".parse().unwrap()));
    }

    #[test]
    fn endpoints_carry_the_port_and_never_loopback() {
        for endpoint in local_udp_endpoints(9993) {
            assert_eq!(endpoint.port(), 9993);
            assert!(!endpoint.ip().is_loopback(), "{endpoint}");
        }
    }
}
