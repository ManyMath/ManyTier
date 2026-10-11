//! The ManyTier node engine.
//!
//! Platform-independent (`no_std`) protocol state machine: peer and path
//! tracking, root/moon topology, HELLO/WHOIS/relay handling, network config
//! consumption, the VL2 Ethernet layer (switching, ARP/NDP, multicast), and
//! an embedded network controller. All I/O goes through the traits in
//! [`traits`], so the same engine runs on native sockets, WASM, or WASI.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod arp;
pub mod controller;
pub mod ethernet;
pub mod filter;
pub mod multicast;
pub mod ndp;
pub mod network;
#[cfg(feature = "native")]
pub mod network_config;
pub mod node;
pub mod path;
pub mod peer;
pub mod platform;
pub mod root;
pub mod switch;
pub mod topology;
pub mod traits;
pub mod vl2;
