//! MCP (Model Context Protocol) integration for probe.
//!
//! Implements a JSON-RPC 2.0 server over stdio that exposes probe's
//! binary-analysis capabilities as MCP tools.
//!
//! Protocol version: 2025-06-18
//! Spec: https://modelcontextprotocol.io/specification/2025-06-18/

pub mod adapter;
pub mod handlers;
pub mod protocol;
pub mod server;
pub mod tools;