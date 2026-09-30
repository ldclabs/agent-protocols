//! Rust SDK for the Agent Identity, Agent Profile, Agent Delegation, Agent Discourse, Agent Knowledge, and Agent Mail protocols.
//!
//! The crate intentionally keeps the core protocol logic framework-neutral so the
//! same types and verification helpers can be used by clients, servers, tests,
//! and conformance tooling.

pub mod delegation;
pub mod discourse;
pub mod error;
#[cfg(feature = "http-client")]
pub mod http_client;
pub mod identity;
pub mod knowledge;
#[cfg(feature = "local-connector")]
pub mod local_connector;
pub mod mail;
pub mod profile;

pub use error::{Result, SdkError};
