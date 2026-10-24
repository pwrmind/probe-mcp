//! JSON-RPC 2.0 + MCP protocol types (spec: 2025-06-18).
//!
//! This module is intentionally self-contained: it does not reference
//! probe's internal types (context, executor, ...). All translation
//! between protocol JSON and native types happens in `mcp::adapter`
//! and `mcp::server`.
//!
//! `#![allow(dead_code)]` is set because this module is being built up
//! incrementally: some protocol helpers (`McpError::internal`,
//! `McpError::with_data`, ...) are only wired into the server in later
//! steps.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP protocol version this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

// =========================================================================
// JSON-RPC 2.0 envelopes
// =========================================================================

/// Incoming request or notification from the MCP client.
///
/// A notification is distinguished by the absence of `id`
/// (see [`JsonRpcRequest::is_notification`]).
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// Outgoing response to the MCP client. Exactly one of `result` / `error`
/// is populated, per JSON-RPC 2.0.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl From<McpError> for JsonRpcError {
    fn from(e: McpError) -> Self {
        Self {
            code: e.code,
            message: e.message,
            data: e.data,
        }
    }
}

// =========================================================================
// Standard JSON-RPC 2.0 error codes
// =========================================================================

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// Internal error type used throughout the server. Converted to
/// [`JsonRpcError`] at the protocol boundary.
#[derive(Debug)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl McpError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn parse(detail: impl Into<String>) -> Self {
        Self::new(PARSE_ERROR, format!("Parse error: {}", detail.into()))
    }

    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::new(INVALID_REQUEST, format!("Invalid request: {}", detail.into()))
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("Method not found: {}", method))
    }

    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, format!("Invalid params: {}", detail.into()))
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, detail.into())
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for McpError {}

// =========================================================================
// MCP lifecycle: initialize
// =========================================================================

/// Params sent by the client in the `initialize` request. Only the fields
/// probe-mcp actually consumes are typed; the rest is kept as `Value`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    #[serde(default)]
    pub capabilities: Value,
    #[serde(default)]
    pub client_info: Option<ClientInfo>,
}

#[derive(Debug, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

impl ServerInfo {
    pub fn probe() -> Self {
        Self {
            name: "probe-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Server capabilities advertised during `initialize`. For probe-mcp we
/// only expose tools — no resources, prompts, sampling, etc.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    /// We never mutate the tool list at runtime, so this is `None` (omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

// =========================================================================
// MCP tools: list and call
// =========================================================================

/// One tool descriptor, as returned by `tools/list`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

/// Safety hints attached to a tool. See MCP spec 2025-06-18, section
/// "Tool Annotations".
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ListToolsResult {
    pub tools: Vec<Tool>,
}

/// Params of the `tools/call` request.
#[derive(Debug, Deserialize)]
pub struct CallToolParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

/// Result of `tools/call`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
}

impl CallToolResult {
    pub fn ok(summary: impl Into<String>, structured: Value) -> Self {
        Self {
            content: vec![Content::Text { text: summary.into() }],
            is_error: None,
            structured_content: Some(structured),
        }
    }

    pub fn tool_error(detail: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text { text: detail.into() }],
            is_error: Some(true),
            structured_content: None,
        }
    }

    pub fn with_structured(mut self, structured: Value) -> Self {
        self.structured_content = Some(structured);
        self
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Content {
    Text { text: String },
}