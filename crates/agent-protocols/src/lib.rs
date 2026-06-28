//! Rust SDK for the Agent Identity, Agent Profile, and Agent Discourse protocols.
//!
//! The crate intentionally keeps the core protocol logic framework-neutral so the
//! same types and verification helpers can be used by clients, servers, tests,
//! and conformance tooling.

pub mod discourse;
pub mod error;
#[cfg(feature = "http-client")]
pub mod http_client;
pub mod identity;
#[cfg(feature = "local-connector")]
pub mod local_connector;
pub mod profile;

pub use error::{Result, SdkError};
