//! TUN backends: Linux via tun2 (/dev/net/tun), macOS via utun.

use std::net::IpAddr;

use zerotier_node::traits::TunDevice;

#[cfg(target_os = "linux")]
use std::sync::{Mutex as StdMutex, OnceLock};
#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
#[cfg(target_os = "linux")]
use tun2::AbstractDevice;

// ---------------------------------------------------------------------------
// Linux: Full NativeTun implementation via tun2
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub struct NativeTun {
    control: StdMutex<Option<tun2::AsyncDevice>>,
    reader: OnceLock<tokio::sync::Mutex<ReadHalf<tun2::AsyncDevice>>>,
    writer: OnceLock<tokio::sync::Mutex<WriteHalf<tun2::AsyncDevice>>>,
    name: String,
    mtu: usize,
}

#[cfg(target_os = "linux")]
impl TunDevice for NativeTun {
    type Error = std::io::Error;

    async fn create(name: &str, mtu: usize) -> Result<Self, Self::Error> {
        let mut config = tun2::Configuration::default();
        config.tun_name(name).mtu(mtu as u16).up();
        let device = tun2::create_as_async(&config)?;

        // Retrieve the actual interface name (tun2 may adjust it)
        let actual_name = device
            .as_ref()
            .tun_name()
            .unwrap_or_else(|_| name.to_string());

        Ok(NativeTun {
            control: StdMutex::new(Some(device)),
            reader: OnceLock::new(),
            writer: OnceLock::new(),
            name: actual_name,
            mtu,
        })
    }

    async fn read(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.ensure_halves()?;
        let reader = self
            .reader
            .get()
            .ok_or_else(|| std::io::Error::other("TUN reader unavailable"))?;
        let mut reader = reader.lock().await;
        reader.read(buf).await
    }

    async fn write(&self, data: &[u8]) -> Result<usize, Self::Error> {
        self.ensure_halves()?;
        let writer = self
            .writer
            .get()
            .ok_or_else(|| std::io::Error::other("TUN writer unavailable"))?;
        let mut writer = writer.lock().await;
        writer.write(data).await
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn set_ip(&self, addr: IpAddr, prefix_len: u8) -> Result<(), Self::Error> {
        let mut control = self
            .control
            .lock()
            .map_err(|_| std::io::Error::other("TUN control lock poisoned"))?;
        let device = control
            .as_mut()
            .ok_or_else(|| std::io::Error::other("cannot configure TUN after I/O has started"))?;
        device.as_mut().set_address(addr)?;

        if addr.is_ipv4() {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len as u32)
            };
            device
                .as_mut()
                .set_netmask(IpAddr::V4(std::net::Ipv4Addr::from(mask)))?;
        }

        Ok(())
    }

    async fn add_route(&self, target: &str, gateway: Option<IpAddr>) -> Result<(), Self::Error> {
        // Validate CIDR notation
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "route target must be in CIDR notation (e.g., 10.0.0.0/24)",
            ));
        }

        // tun2 does not expose a post-creation route addition API on AsyncDevice.
        // Fall back to `ip route add`.
        let target = target.to_string();
        let name = self.name.clone();

        tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new("ip");
            cmd.args(["route", "add", &target, "dev", &name]);
            if let Some(gw) = gateway {
                cmd.args(["via", &gw.to_string()]);
            }

            let output = cmd.output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // "RTNETLINK answers: File exists" means route already exists -- not an error
                if !stderr.contains("File exists") {
                    return Err(std::io::Error::other(format!(
                        "ip route add failed: {}",
                        stderr.trim()
                    )));
                }
            }
            Ok(())
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

#[cfg(target_os = "linux")]
impl NativeTun {
    fn ensure_halves(&self) -> Result<(), std::io::Error> {
        if self.reader.get().is_some() && self.writer.get().is_some() {
            return Ok(());
        }

        let mut control = self
            .control
            .lock()
            .map_err(|_| std::io::Error::other("TUN control lock poisoned"))?;

        if self.reader.get().is_none() || self.writer.get().is_none() {
            let device = control
                .take()
                .ok_or_else(|| std::io::Error::other("TUN runtime already taken"))?;
            let (reader, writer) = tokio::io::split(device);
            let _ = self.reader.set(tokio::sync::Mutex::new(reader));
            let _ = self.writer.set(tokio::sync::Mutex::new(writer));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// macOS: utun via the com.apple.net.utun_control kernel control
// ---------------------------------------------------------------------------
//
// Packets carry a 4-byte address-family header. Names are kernel-assigned.
// Needs root.

#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "macos")]
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "macos")]
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
#[cfg(target_os = "macos")]
const UTUN_HEADER_LEN: usize = 4;

#[cfg(target_os = "macos")]
pub struct NativeTun {
    fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: usize,
}

#[cfg(target_os = "macos")]
impl TunDevice for NativeTun {
    type Error = std::io::Error;

    async fn create(name: &str, mtu: usize) -> Result<Self, Self::Error> {
        let (fd, actual_name) = open_utun(utun_unit_for_name(name))?;
        if actual_name != name {
            tracing::debug!(
                requested = %name,
                actual = %actual_name,
                "macOS assigns utun interface names; requested name not applied"
            );
        }

        // Fall back to the kernel MTU if utun rejects ours.
        let mtu = match run_command(
            "ifconfig",
            vec![
                actual_name.clone(),
                "mtu".to_string(),
                mtu.to_string(),
                "up".to_string(),
            ],
        )
        .await
        {
            Ok(_) => mtu,
            Err(error) => {
                run_command("ifconfig", vec![actual_name.clone(), "up".to_string()]).await?;
                let actual_mtu = query_mtu(&actual_name).await.unwrap_or(mtu);
                tracing::warn!(
                    error = %error,
                    interface = %actual_name,
                    requested_mtu = mtu,
                    actual_mtu,
                    "could not set utun MTU; keeping the kernel default"
                );
                actual_mtu
            }
        };

        Ok(NativeTun {
            fd: AsyncFd::new(fd)?,
            name: actual_name,
            mtu,
        })
    }

    async fn read(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| read_utun_packet(fd.as_raw_fd(), buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    async fn write(&self, data: &[u8]) -> Result<usize, Self::Error> {
        let header = utun_header_for_packet(data).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "utun only carries IPv4 and IPv6 packets",
            )
        })?;
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| write_utun_packet(fd.as_raw_fd(), &header, data)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn set_ip(&self, addr: IpAddr, prefix_len: u8) -> Result<(), Self::Error> {
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("prefix length {prefix_len} is invalid for {addr}"),
            ));
        }

        run_command(
            "ifconfig",
            ifconfig_address_args(&self.name, addr, prefix_len),
        )
        .await?;

        // Point-to-point: add the prefix route, plus an interface-scoped one for
        // IP_BOUND_IF sockets.
        let cidr = format!("{}/{}", network_address(addr, prefix_len), prefix_len);
        add_route_ignoring_existing(route_add_args(&self.name, &cidr, None, false)).await?;
        if let Err(error) =
            add_route_ignoring_existing(route_add_args(&self.name, &cidr, None, true)).await
        {
            tracing::warn!(
                error = %error,
                interface = %self.name,
                target = %cidr,
                "could not add interface-scoped route for the connected prefix"
            );
        }
        Ok(())
    }

    async fn add_route(&self, target: &str, gateway: Option<IpAddr>) -> Result<(), Self::Error> {
        validate_cidr(target)?;
        add_route_ignoring_existing(route_add_args(&self.name, target, gateway, false)).await
    }
}

/// `unit` 0 lets the kernel pick; N+1 asks for `utunN`.
#[cfg(target_os = "macos")]
fn open_utun(unit: u32) -> std::io::Result<(OwnedFd, String)> {
    // SAFETY: plain syscall.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fresh, unowned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: POD; zero is valid.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME.as_bytes()) {
        *dst = *src as libc::c_char;
    }
    // SAFETY: ioctl takes one ctl_info.
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::CTLIOCGINFO,
            &mut info as *mut libc::ctl_info,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: POD; zero is valid.
    let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar;
    addr.sc_family = libc::AF_SYSTEM as libc::c_uchar;
    addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = unit;
    // SAFETY: initialised, length matches.
    let connected = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if connected < 0 {
        let error = std::io::Error::last_os_error();
        return Err(if error.kind() == std::io::ErrorKind::PermissionDenied {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "creating a macOS utun interface requires root (connect to \
                     {UTUN_CONTROL_NAME}: {error}); run `manytier service` with sudo or \
                     as a launchd daemon"
                ),
            )
        } else {
            error
        });
    }

    let mut name = [0u8; libc::IFNAMSIZ];
    let mut len = name.len() as libc::socklen_t;
    // SAFETY: buffer and length are valid.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let name = String::from_utf8_lossy(&name[..(len as usize).min(name.len())])
        .trim_end_matches('\0')
        .to_string();

    set_nonblocking_cloexec(&fd)?;
    Ok((fd, name))
}

#[cfg(target_os = "macos")]
fn set_nonblocking_cloexec(fd: &OwnedFd) -> std::io::Result<()> {
    // SAFETY: valid descriptor.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Strips the AF header; `Ok(0)` for non-IP families.
#[cfg(target_os = "macos")]
fn read_utun_packet(fd: libc::c_int, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut header = [0u8; UTUN_HEADER_LEN];
    let mut iov = [
        libc::iovec {
            iov_base: header.as_mut_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        },
    ];
    // SAFETY: iovecs point at live buffers.
    let n = unsafe { libc::readv(fd, iov.as_mut_ptr(), iov.len() as libc::c_int) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let n = n as usize;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "utun interface closed",
        ));
    }
    if n < UTUN_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("utun read returned {n} bytes, shorter than the address-family header"),
        ));
    }
    if !utun_header_is_ip(&header) {
        return Ok(0);
    }
    Ok(n - UTUN_HEADER_LEN)
}

/// Prepends the AF header.
#[cfg(target_os = "macos")]
fn write_utun_packet(
    fd: libc::c_int,
    header: &[u8; UTUN_HEADER_LEN],
    data: &[u8],
) -> std::io::Result<usize> {
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        },
    ];
    // SAFETY: iovecs point at live buffers.
    let n = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((n as usize).saturating_sub(UTUN_HEADER_LEN))
}

/// `utunN` -> N+1; anything else -> 0.
#[cfg(target_os = "macos")]
fn utun_unit_for_name(name: &str) -> u32 {
    name.strip_prefix("utun")
        .and_then(|unit| unit.parse::<u32>().ok())
        .and_then(|unit| unit.checked_add(1))
        .unwrap_or(0)
}

/// AF header from the IP version nibble.
#[cfg(target_os = "macos")]
fn utun_header_for_packet(packet: &[u8]) -> Option<[u8; UTUN_HEADER_LEN]> {
    match packet.first()? >> 4 {
        4 => Some((libc::AF_INET as u32).to_be_bytes()),
        6 => Some((libc::AF_INET6 as u32).to_be_bytes()),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn utun_header_is_ip(header: &[u8; UTUN_HEADER_LEN]) -> bool {
    let family = u32::from_be_bytes(*header);
    family == libc::AF_INET as u32 || family == libc::AF_INET6 as u32
}

/// The network address of `addr` under `prefix_len`.
#[cfg(target_os = "macos")]
fn network_address(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(ip) => {
            let mask = match prefix_len {
                0 => 0,
                len => u32::MAX << (32 - len.min(32) as u32),
            };
            IpAddr::V4(std::net::Ipv4Addr::from(u32::from(ip) & mask))
        }
        IpAddr::V6(ip) => {
            let mask = match prefix_len {
                0 => 0,
                len => u128::MAX << (128 - len.min(128) as u32),
            };
            IpAddr::V6(std::net::Ipv6Addr::from(u128::from(ip) & mask))
        }
    }
}

/// IPv4 uses the address as its own peer.
#[cfg(target_os = "macos")]
fn ifconfig_address_args(name: &str, addr: IpAddr, prefix_len: u8) -> Vec<String> {
    match addr {
        IpAddr::V4(_) => vec![
            name.to_string(),
            "inet".to_string(),
            format!("{addr}/{prefix_len}"),
            addr.to_string(),
            "alias".to_string(),
        ],
        IpAddr::V6(_) => vec![
            name.to_string(),
            "inet6".to_string(),
            addr.to_string(),
            "prefixlen".to_string(),
            prefix_len.to_string(),
            "alias".to_string(),
        ],
    }
}

#[cfg(target_os = "macos")]
fn route_add_args(name: &str, cidr: &str, gateway: Option<IpAddr>, scoped: bool) -> Vec<String> {
    let family = if cidr.contains(':') {
        "-inet6"
    } else {
        "-inet"
    };
    let mut args = vec!["-q".to_string(), "-n".to_string(), "add".to_string()];
    if scoped {
        args.push("-ifscope".to_string());
        args.push(name.to_string());
    }
    args.push(family.to_string());
    args.push(cidr.to_string());
    match gateway {
        Some(gateway) => args.push(gateway.to_string()),
        None => {
            args.push("-interface".to_string());
            args.push(name.to_string());
        }
    }
    args
}

#[cfg(target_os = "macos")]
fn validate_cidr(target: &str) -> std::io::Result<()> {
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "route target must be in CIDR notation (e.g., 10.0.0.0/24)",
        )
    };
    let (addr, prefix) = target.split_once('/').ok_or_else(invalid)?;
    let addr: IpAddr = addr.parse().map_err(|_| invalid())?;
    let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn route_already_exists(stderr: &str) -> bool {
    stderr.contains("File exists") || stderr.contains("already in table")
}

#[cfg(target_os = "macos")]
async fn run_command_output(
    program: &'static str,
    args: Vec<String>,
) -> std::io::Result<std::process::Output> {
    tokio::task::spawn_blocking(move || std::process::Command::new(program).args(&args).output())
        .await
        .map_err(std::io::Error::other)?
}

#[cfg(target_os = "macos")]
async fn run_command(program: &'static str, args: Vec<String>) -> std::io::Result<String> {
    let rendered = format!("{program} {}", args.join(" "));
    let output = run_command_output(program, args).await?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "`{rendered}` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
async fn add_route_ignoring_existing(args: Vec<String>) -> std::io::Result<()> {
    let rendered = format!("route {}", args.join(" "));
    let output = run_command_output("route", args).await?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() || route_already_exists(&stderr) {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "`{rendered}` failed ({}): {}",
        output.status,
        stderr.trim()
    )))
}

#[cfg(target_os = "macos")]
async fn query_mtu(name: &str) -> Option<usize> {
    let output = run_command("ifconfig", vec![name.to_string()]).await.ok()?;
    parse_ifconfig_mtu(&output)
}

#[cfg(target_os = "macos")]
fn parse_ifconfig_mtu(output: &str) -> Option<usize> {
    let mut words = output.split_whitespace();
    while let Some(word) = words.next() {
        if word == "mtu" {
            return words.next()?.parse().ok();
        }
    }
    None
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    #[test]
    fn utun_unit_maps_utun_names_and_lets_kernel_pick_otherwise() {
        assert_eq!(utun_unit_for_name("utun0"), 1);
        assert_eq!(utun_unit_for_name("utun7"), 8);
        assert_eq!(utun_unit_for_name("zt0894e035ae76"), 0);
        assert_eq!(utun_unit_for_name("utun"), 0);
        assert_eq!(utun_unit_for_name(""), 0);
    }

    #[test]
    fn utun_header_follows_ip_version_nibble() {
        assert_eq!(
            utun_header_for_packet(&[0x45, 0, 0, 20]),
            Some([0, 0, 0, 2])
        );
        assert_eq!(
            utun_header_for_packet(&[0x60, 0, 0, 0]),
            Some([0, 0, 0, 30])
        );
        assert_eq!(utun_header_for_packet(&[0x00]), None);
        assert_eq!(utun_header_for_packet(&[]), None);
        assert!(utun_header_is_ip(&[0, 0, 0, 2]));
        assert!(utun_header_is_ip(&[0, 0, 0, 30]));
        assert!(!utun_header_is_ip(&[0, 0, 0, 18]));
        assert!(!utun_header_is_ip(&[2, 0, 0, 0]));
    }

    #[test]
    fn network_address_masks_host_bits() {
        assert_eq!(
            network_address("10.147.20.7".parse().unwrap(), 24),
            "10.147.20.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            network_address("10.147.20.7".parse().unwrap(), 32),
            "10.147.20.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            network_address("10.147.20.7".parse().unwrap(), 0),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            network_address("fd00:1234::abcd:1".parse().unwrap(), 64),
            "fd00:1234::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            network_address("fd00::1".parse().unwrap(), 128),
            "fd00::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ifconfig_args_use_self_as_peer_for_ipv4() {
        assert_eq!(
            ifconfig_address_args("utun9", "10.147.20.7".parse().unwrap(), 24),
            ["utun9", "inet", "10.147.20.7/24", "10.147.20.7", "alias"]
        );
        assert_eq!(
            ifconfig_address_args("utun9", "fd00::1".parse().unwrap(), 88),
            ["utun9", "inet6", "fd00::1", "prefixlen", "88", "alias"]
        );
    }

    #[test]
    fn route_args_cover_direct_gateway_and_scoped_forms() {
        assert_eq!(
            route_add_args("utun9", "10.147.20.0/24", None, false),
            [
                "-q",
                "-n",
                "add",
                "-inet",
                "10.147.20.0/24",
                "-interface",
                "utun9"
            ]
        );
        assert_eq!(
            route_add_args("utun9", "10.147.20.0/24", None, true),
            [
                "-q",
                "-n",
                "add",
                "-ifscope",
                "utun9",
                "-inet",
                "10.147.20.0/24",
                "-interface",
                "utun9"
            ]
        );
        assert_eq!(
            route_add_args(
                "utun9",
                "192.168.50.0/24",
                Some("10.147.20.1".parse().unwrap()),
                false
            ),
            ["-q", "-n", "add", "-inet", "192.168.50.0/24", "10.147.20.1"]
        );
        assert_eq!(
            route_add_args("utun9", "fd00::/64", None, false),
            [
                "-q",
                "-n",
                "add",
                "-inet6",
                "fd00::/64",
                "-interface",
                "utun9"
            ]
        );
    }

    #[test]
    fn cidr_validation_matches_linux_backend() {
        assert!(validate_cidr("10.0.0.0/24").is_ok());
        assert!(validate_cidr("fd00::/64").is_ok());
        assert!(validate_cidr("10.0.0.0").is_err());
        assert!(validate_cidr("10.0.0.0/33").is_err());
        assert!(validate_cidr("nope/24").is_err());
    }

    #[test]
    fn existing_route_errors_are_recognised() {
        assert!(route_already_exists(
            "route: writing to routing socket: File exists\nadd net 10.0.0.0: gateway utun9: File exists"
        ));
        assert!(route_already_exists("add net 10.0.0.0: already in table"));
        assert!(!route_already_exists(
            "route: writing to routing socket: Network is unreachable"
        ));
    }

    #[test]
    fn parses_mtu_from_ifconfig_output() {
        let output = "utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n\tinet 10.0.0.1 --> 10.0.0.1 netmask 0xffffff00\n";
        assert_eq!(parse_ifconfig_mtu(output), Some(1500));
        assert_eq!(parse_ifconfig_mtu("garbage"), None);
    }

    fn ones_complement_sum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in bytes.chunks(2) {
            let word = match chunk {
                [hi, lo] => u16::from_be_bytes([*hi, *lo]),
                [hi] => u16::from_be_bytes([*hi, 0]),
                _ => 0,
            };
            sum += u32::from(word);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn icmpv6_echo_request(src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
        let payload = b"manytier";
        let icmp_len = 8 + payload.len();
        let mut packet = vec![0u8; 40 + icmp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);

        let icmp = &mut packet[40..];
        icmp[0] = 128;
        icmp[4..6].copy_from_slice(&0x4d54u16.to_be_bytes());
        icmp[6..8].copy_from_slice(&1u16.to_be_bytes());
        icmp[8..].copy_from_slice(payload);

        // ICMPv6 checksum covers the IPv6 pseudo-header.
        let mut pseudo = Vec::with_capacity(40 + icmp_len);
        pseudo.extend_from_slice(&src);
        pseudo.extend_from_slice(&dst);
        pseudo.extend_from_slice(&(icmp_len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58]);
        pseudo.extend_from_slice(&packet[40..]);
        let checksum = ones_complement_sum(&pseudo);
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn icmp_echo_request(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let payload = b"manytier";
        let icmp_len = 8 + payload.len();
        let mut packet = vec![0u8; 20 + icmp_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + icmp_len) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        let checksum = ones_complement_sum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        let icmp = &mut packet[20..];
        icmp[0] = 8;
        icmp[4..6].copy_from_slice(&0x4d54u16.to_be_bytes());
        icmp[6..8].copy_from_slice(&1u16.to_be_bytes());
        icmp[8..].copy_from_slice(payload);
        let checksum = ones_complement_sum(icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    /// Needs root: `sudo cargo test -p zerotier-service --lib -- --ignored utun_roundtrip`.
    #[tokio::test]
    #[ignore = "requires root: creates and configures a real utun interface"]
    async fn utun_roundtrip_requires_root() {
        const LOCAL: [u8; 4] = [10, 213, 7, 1];
        const PEER: [u8; 4] = [10, 213, 7, 2];

        let tun = NativeTun::create("zt-roundtrip", 1500)
            .await
            .expect("utun creation (are you root?)");
        assert!(tun.name().starts_with("utun"), "name = {}", tun.name());
        assert_eq!(tun.mtu(), 1500);
        tun.set_ip(IpAddr::V4(LOCAL.into()), 30)
            .await
            .expect("ifconfig/route configuration");
        tun.add_route("10.213.8.0/24", None)
            .await
            .expect("managed route");

        // Kernel -> tunnel.
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::from(LOCAL), 0))
            .expect("bind to utun address");
        socket
            .send_to(b"manytier", (std::net::Ipv4Addr::from(PEER), 4242))
            .expect("send into tunnel");
        let mut buf = [0u8; 2048];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_udp = false;
        while std::time::Instant::now() < deadline {
            let n = tokio::time::timeout(deadline - std::time::Instant::now(), tun.read(&mut buf))
                .await
                .expect("timed out waiting for the UDP datagram")
                .expect("utun read");
            if n >= 28 && buf[0] >> 4 == 4 && buf[9] == 17 && buf[16..20] == PEER {
                saw_udp = true;
                break;
            }
        }
        assert!(
            saw_udp,
            "no IPv4/UDP packet for {PEER:?} came out of the tunnel"
        );

        // Tunnel -> kernel -> tunnel.
        let request = icmp_echo_request(PEER, LOCAL);
        let written = tun.write(&request).await.expect("utun write");
        assert_eq!(written, request.len());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_reply = false;
        while std::time::Instant::now() < deadline {
            let n = tokio::time::timeout(deadline - std::time::Instant::now(), tun.read(&mut buf))
                .await
                .expect("timed out waiting for the echo reply")
                .expect("utun read");
            if n >= 28
                && buf[0] >> 4 == 4
                && buf[9] == 1
                && buf[12..16] == LOCAL
                && buf[16..20] == PEER
                && buf[20] == 0
            {
                saw_reply = true;
                break;
            }
        }
        assert!(
            saw_reply,
            "no ICMP echo reply for the injected request came back"
        );

        // IPv6. The address is tentative during DAD, so retry the bind.
        const LOCAL6: [u8; 16] = [
            0xfd, 0x4d, 0x61, 0x6e, 0x79, 0x74, 0x69, 0x65, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        const PEER6: [u8; 16] = [
            0xfd, 0x4d, 0x61, 0x6e, 0x79, 0x74, 0x69, 0x65, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        tun.set_ip(IpAddr::V6(LOCAL6.into()), 64)
            .await
            .expect("inet6 ifconfig/route configuration");
        let mut socket6 = None;
        for _ in 0..20 {
            match std::net::UdpSocket::bind((std::net::Ipv6Addr::from(LOCAL6), 0)) {
                Ok(socket) => {
                    socket6 = Some(socket);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            }
        }
        let socket6 = socket6.expect("bind to utun IPv6 address (still tentative?)");
        socket6
            .send_to(b"manytier", (std::net::Ipv6Addr::from(PEER6), 4242))
            .expect("send IPv6 into tunnel");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_udp6 = false;
        while std::time::Instant::now() < deadline {
            let n = tokio::time::timeout(deadline - std::time::Instant::now(), tun.read(&mut buf))
                .await
                .expect("timed out waiting for the IPv6 UDP datagram")
                .expect("utun read");
            if n >= 48 && buf[0] >> 4 == 6 && buf[6] == 17 && buf[24..40] == PEER6 {
                saw_udp6 = true;
                break;
            }
        }
        assert!(
            saw_udp6,
            "no IPv6/UDP packet for the peer came out of the tunnel"
        );

        let request6 = icmpv6_echo_request(PEER6, LOCAL6);
        let written = tun.write(&request6).await.expect("utun IPv6 write");
        assert_eq!(written, request6.len());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_reply6 = false;
        while std::time::Instant::now() < deadline {
            let n = tokio::time::timeout(deadline - std::time::Instant::now(), tun.read(&mut buf))
                .await
                .expect("timed out waiting for the ICMPv6 echo reply")
                .expect("utun read");
            if n >= 48
                && buf[0] >> 4 == 6
                && buf[6] == 58
                && buf[8..24] == LOCAL6
                && buf[24..40] == PEER6
                && buf[40] == 129
            {
                saw_reply6 = true;
                break;
            }
        }
        assert!(
            saw_reply6,
            "no ICMPv6 echo reply for the injected request came back"
        );
    }
}
