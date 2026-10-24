//! MCP server main loop: reads line-delimited JSON-RPC from stdin,
//! writes responses to stdout, logs to stderr.
//!
//! Step 4: `tools/call` is wired to `handlers::dispatch`. Domain errors
//! surface as `isError: true` tool results; only an unknown tool name
//! produces a JSON-RPC error (`-32602`).

use std::io::{self, BufRead, Write};

use crate::context::SandboxContext;

use super::handlers;
use super::protocol::*;
use super::tools;

pub fn run(mut ctx: SandboxContext) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut initialized = false;
    let mut line = String::new();

    eprintln!("[probe-mcp] server ready (protocol {})", PROTOCOL_VERSION);

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            eprintln!("[probe-mcp] stdin closed, shutting down");
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse::error(
                    serde_json::Value::Null,
                    McpError::parse(e.to_string()).into(),
                );
                emit(&mut writer, &resp)?;
                continue;
            }
        };

        if req.is_notification() {
            if req.method == "notifications/initialized" {
                initialized = true;
                eprintln!("[probe-mcp] client initialized");
            } else {
                eprintln!("[probe-mcp] ignoring notification: {}", req.method);
            }
            continue;
        }

        let id = req.id.clone().unwrap_or(serde_json::Value::Null);
        let response = handle_request(&req, &mut ctx, &mut initialized, id);
        emit(&mut writer, &response)?;
    }

    Ok(())
}

fn emit<W: Write>(writer: &mut W, resp: &JsonRpcResponse) -> io::Result<()> {
    let s = serde_json::to_string(resp).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("serialize response: {}", e))
    })?;
    writer.write_all(s.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn handle_request(
    req: &JsonRpcRequest,
    ctx: &mut SandboxContext,
    initialized: &mut bool,
    id: serde_json::Value,
) -> JsonRpcResponse {
    match req.method.as_str() {
        "initialize" => handle_initialize(req, id),
        "ping" => JsonRpcResponse::success(id, serde_json::json!({})),
        "tools/list" => {
            if !*initialized {
                return JsonRpcResponse::error(
                    id,
                    McpError::invalid_request("server not initialized").into(),
                );
            }
            let tools = tools::list_tools();
            let payload = serde_json::to_value(ListToolsResult { tools })
                .expect("ListToolsResult always serializes");
            JsonRpcResponse::success(id, payload)
        }
        "tools/call" => {
            if !*initialized {
                return JsonRpcResponse::error(
                    id,
                    McpError::invalid_request("server not initialized").into(),
                );
            }
            handle_tools_call(req, ctx, id)
        }
        other => JsonRpcResponse::error(id, McpError::method_not_found(other).into()),
    }
}

fn handle_tools_call(
    req: &JsonRpcRequest,
    ctx: &mut SandboxContext,
    id: serde_json::Value,
) -> JsonRpcResponse {
    let params: CallToolParams = match req
        .params
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        Some(p) => p,
        None => {
            return JsonRpcResponse::error(
                id,
                McpError::invalid_params(
                    "tools/call: missing or invalid params (need {name, arguments?})",
                )
                .into(),
            );
        }
    };

    match handlers::dispatch(ctx, &params.name, params.arguments.as_ref()) {
        Ok(result) => {
            let payload = serde_json::to_value(result)
                .expect("CallToolResult always serializes");
            JsonRpcResponse::success(id, payload)
        }
        Err(e) => JsonRpcResponse::error(id, e.into()),
    }
}

fn handle_initialize(req: &JsonRpcRequest, id: serde_json::Value) -> JsonRpcResponse {
    let params: InitializeParams = match req
        .params
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        Some(p) => p,
        None => {
            return JsonRpcResponse::error(
                id,
                McpError::invalid_params("initialize: missing or invalid params").into(),
            );
        }
    };

    eprintln!(
        "[probe-mcp] initialize: client={:?} protocol={}",
        params.client_info.as_ref().map(|c| (&c.name, &c.version)),
        params.protocol_version
    );

    let result = InitializeResult {
        protocol_version: PROTOCOL_VERSION.to_string(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability::default()),
        },
        server_info: ServerInfo::probe(),
        instructions: Some(
            "probe-mcp: sandboxed runtime for PE32/x86 binaries. \
             The target binary is loaded at server startup (argv[1]). \
             Tools: \
             probe_list_functions, probe_inspect_function, probe_disasm, probe_peek, \
             probe_poke, probe_alloc, probe_set_mock, probe_reset_mock, probe_invoke, \
             probe_invoke_mock, probe_call_log, probe_call_log_clear. \
             Call tools/list for full schemas."
                .to_string(),
        ),
    };

    let payload = serde_json::to_value(result).expect("InitializeResult always serializes");
    JsonRpcResponse::success(id, payload)
}