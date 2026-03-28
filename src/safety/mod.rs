//! Safety layer for prompt injection defense.
//!
//! This module re-exports everything from the `optimclaw_safety` crate,
//! keeping `crate::safety::*` imports working throughout the codebase.

pub use optimclaw_safety::*;
