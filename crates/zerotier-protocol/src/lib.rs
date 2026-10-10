//! ZeroTier V1 wire-format types and protocol definitions.
//!
//! `no_std` parsing and serialization for the V1 protocol: packet and
//! fragment headers, verb payloads, identity wire format, `InetAddress`
//! serialization, and world (planet/moon) files. Network config
//! dictionaries live in `zerotier-node`.
//! All layouts are byte-for-byte compatible with official ZeroTier.

#![no_std]

extern crate alloc;

pub mod constants;
pub mod error;
pub mod fragment;
pub mod header;
pub mod identity_wire;
pub mod inet_address;
#[cfg(feature = "v2")]
pub mod v2;
pub mod verb;
pub mod verbs;
pub mod world;

pub use constants::*;
pub use error::ProtocolError;
pub use header::{is_fragment, FragmentHeader, PacketHeader};
pub use verb::Verb;
pub use world::World;
