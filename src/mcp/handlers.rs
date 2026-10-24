//! Tool handlers — one function per MCP tool.
//!
//! Step 5 (final): all 12 tools are wired up. Each handler produces a
//! `CallToolResult` (success or tool-error). Only `dispatch` returns a
//! `McpError`, and only for an unknown tool name — every domain error
//! (missing function, unreadable memory, invalid argument value) is
//! surfaced as `isError: true` so the LLM can reason about it and retry.
//!
//! A sandbox crash is NOT an error: `probe_invoke` succeeds and reports
//! the crash in `structuredContent.crash`.

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use serde_json::{json, Value};

use crate::context::{
    CallingConvention, FunctionMeta, MockBehavior, SandboxContext,
};
use crate::executor;
use crate::ffi;
use crate::mock_engine;
use crate::parser::Argument;

use super::adapter::*;
use super::protocol::{CallToolResult, McpError};
use super::tools;

// =========================================================================
// Entry point
// =========================================================================

pub fn dispatch(
    ctx: &mut SandboxContext,
    name: &str,
    arguments: Option<&Value>,
) -> Result<CallToolResult, McpError> {
    // Bind the fallback in a local so `&Value::Null` has a real owner.
    let null = Value::Null;
    let args: &Value = arguments.unwrap_or(&null);

    let result = match name {
        tools::LIST_FUNCTIONS => list_functions(ctx, args),
        tools::INSPECT_FUNCTION => inspect_function(ctx, args),
        tools::DISASM => disasm(ctx, args),
        tools::PEEK => peek(args),
        tools::POKE => poke(args),
        tools::ALLOC => alloc(ctx, args),
        tools::SET_MOCK => set_mock(ctx, args),
        tools::RESET_MOCK => reset_mock(ctx, args),
        tools::INVOKE => invoke(ctx, args, false),
        tools::INVOKE_MOCK => invoke(ctx, args, true),
        tools::CALL_LOG => call_log(ctx),
        tools::CALL_LOG_CLEAR => call_log_clear(ctx),
        other => {
            return Err(McpError::invalid_params(format!(
                "unknown tool '{}'",
                other
            )));
        }
    };

    Ok(match result {
        Ok(r) => r,
        Err(e) => CallToolResult::tool_error(e),
    })
}

// =========================================================================
// Small helpers
// =========================================================================

fn obj<'a>(v: &'a Value, what: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    v.as_object()
        .ok_or_else(|| format!("{}: arguments must be a JSON object", what))
}

fn get_str<'a>(
    o: &'a serde_json::Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<&'a str, String> {
    o.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{}: missing or non-string '{}'", what, key))
}

fn get_u32_opt(
    o: &serde_json::Map<String, Value>,
    key: &str,
    what: &str,
    default: Option<u32>,
) -> Result<Option<u32>, String> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| format!("{}: '{}' must be a non-negative integer", what, key))?;
            let n = u32::try_from(n)
                .map_err(|_| format!("{}: '{}' out of u32 range", what, key))?;
            Ok(Some(n))
        }
    }
}

fn get_bool_opt(
    o: &serde_json::Map<String, Value>,
    key: &str,
    default: bool,
) -> bool {
    o.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

fn format_convention(c: CallingConvention) -> String {
    match c {
        CallingConvention::Cdecl => "cdecl".to_string(),
        CallingConvention::StdCall { arg_bytes } => format!("stdcall {}", arg_bytes),
    }
}

fn mock_state_str(ctx: &SandboxContext, addr: u32) -> Value {
    match ctx.mocks.get(&addr) {
        Some(m) => match m.behavior {
            MockBehavior::Default => Value::String("default".to_string()),
            MockBehavior::Custom(_) => Value::String("custom".to_string()),
            MockBehavior::Passthrough => Value::String("passthrough".to_string()),
        },
        None => Value::Null,
    }
}

fn name_or_dash(ctx: &SandboxContext, addr: u32) -> String {
    ctx.name_of(addr)
        .cloned()
        .unwrap_or_else(|| "-".to_string())
}

// =========================================================================
// 1. probe_list_functions
// =========================================================================

fn list_functions(ctx: &SandboxContext, args: &Value) -> Result<CallToolResult, String> {
    let o = obj(args, "probe_list_functions")?;

    let sort_by = o
        .get("sort_by")
        .and_then(|v| v.as_str())
        .unwrap_or("address")
        .to_string();

    let name_contains = o
        .get("name_contains")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let min_size = get_u32_opt(o, "min_size", "probe_list_functions", None)?;
    let max_size = get_u32_opt(o, "max_size", "probe_list_functions", None)?;
    let min_calls = get_u32_opt(o, "min_calls", "probe_list_functions", None)?;
    let max_calls = get_u32_opt(o, "max_calls", "probe_list_functions", None)?;
    let limit = get_u32_opt(o, "limit", "probe_list_functions", Some(500))?
        .unwrap_or(500) as usize;

    let mut items: Vec<_> = ctx.functions.values().collect();

    if let Some(sub) = &name_contains {
        items.retain(|f| {
            ctx.name_of(f.address)
                .map(|n| n.contains(sub.as_str()))
                .unwrap_or(false)
        });
    }
    if let Some(lo) = min_size {
        items.retain(|f| (f.size as u32) >= lo);
    }
    if let Some(hi) = max_size {
        items.retain(|f| (f.size as u32) <= hi);
    }
    if let Some(lo) = min_calls {
        items.retain(|f| (f.calls.len() as u32) >= lo);
    }
    if let Some(hi) = max_calls {
        items.retain(|f| (f.calls.len() as u32) <= hi);
    }

    match sort_by.as_str() {
        "address" => items.sort_by_key(|f| f.address),
        "name" => items.sort_by_key(|f| name_or_dash(ctx, f.address)),
        "size" => items.sort_by_key(|f| std::cmp::Reverse(f.size)),
        "calls" => items.sort_by_key(|f| std::cmp::Reverse(f.calls.len())),
        other => {
            return Err(format!(
                "probe_list_functions: sort_by '{}' not in {{address, name, size, calls}}",
                other
            ))
        }
    }

    let total = items.len();
    items.truncate(limit);

    let functions: Vec<Value> = items
        .iter()
        .map(|f| {
            json!({
                "address": format_address(f.address),
                "name": name_or_dash(ctx, f.address),
                "size": f.size,
                "calls_count": f.calls.len(),
                "convention": format_convention(f.convention),
                "has_mock": ctx.mocks.contains_key(&f.address),
            })
        })
        .collect();

    let summary = format!(
        "{} function(s) returned (of {} matching), sorted by {}",
        functions.len(),
        total,
        sort_by
    );

    Ok(CallToolResult::ok(
        summary,
        json!({
            "total": total,
            "returned": functions.len(),
            "functions": functions,
        }),
    ))
}

// =========================================================================
// 2. probe_inspect_function
// =========================================================================

fn inspect_function(ctx: &SandboxContext, args: &Value) -> Result<CallToolResult, String> {
    let o = obj(args, "probe_inspect_function")?;
    let target = get_str(o, "target", "probe_inspect_function")?;
    let (addr, name) = resolve_function(ctx, target)?;

    let f = ctx
        .functions
        .get(&addr)
        .expect("resolve_function guarantees presence");

    let calls: Vec<Value> = f
        .calls
        .iter()
        .map(|c| {
            json!({
                "at": format_address(c.address),
                "target": format_address(c.target),
                "target_name": name_or_dash(ctx, c.target),
            })
        })
        .collect();

    let mock_state = mock_state_str(ctx, addr);
    let mock_label = match &mock_state {
        Value::String(s) => s.clone(),
        Value::Null => "none".to_string(),
        _ => "?".to_string(),
    };

    let summary = format!(
        "{} ({}) — {} direct call(s), mock={}",
        name,
        format_address(addr),
        f.calls.len(),
        mock_label
    );

    Ok(CallToolResult::ok(
        summary,
        json!({
            "address": format_address(addr),
            "name": name,
            "size": f.size,
            "convention": format_convention(f.convention),
            "mock": mock_state,
            "calls": calls,
        }),
    ))
}

// =========================================================================
// 3. probe_disasm
// =========================================================================

fn disasm(ctx: &SandboxContext, args: &Value) -> Result<CallToolResult, String> {
    let o = obj(args, "probe_disasm")?;
    let target = get_str(o, "target", "probe_disasm")?;
    let count = get_u32_opt(o, "count", "probe_disasm", Some(30))?.unwrap_or(30);

    let (addr, name) = resolve_function(ctx, target)?;

    let want_bytes = ((count as usize) * 15).clamp(64, 2048);
    let bytes = unsafe { ffi::read_self(addr, want_bytes) }.ok_or_else(|| {
        format!(
            "probe_disasm: cannot read memory at {} ({} bytes)",
            format_address(addr),
            want_bytes
        )
    })?;

    let mut decoder = Decoder::with_ip(32, &bytes, addr as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut formatter = IntelFormatter::new();
    let mut buf = String::new();
    let mut out: Vec<Value> = Vec::new();

    for _ in 0..count {
        if !decoder.can_decode() {
            break;
        }
        let start = decoder.position();
        decoder.decode_out(&mut instr);
        let end = decoder.position();
        let ip = instr.ip() as u32;
        let hx: Vec<String> = bytes[start..end]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        buf.clear();
        formatter.format(&instr, &mut buf);
        out.push(json!({
            "address": format_address(ip),
            "bytes": hx.join(" "),
            "text": buf.clone(),
        }));
    }

    let summary = format!(
        "disassembled {} instruction(s) of {} ({}), starting at {}",
        out.len(),
        name,
        format_address(addr),
        format_address(addr)
    );

    Ok(CallToolResult::ok(
        summary,
        json!({
            "address": format_address(addr),
            "instructions": out,
        }),
    ))
}

// =========================================================================
// 4. probe_peek
// =========================================================================

fn peek(args: &Value) -> Result<CallToolResult, String> {
    let o = obj(args, "probe_peek")?;
    let addr = parse_address(get_str(o, "address", "probe_peek")?)?;
    let size = get_u32_opt(o, "size", "probe_peek", Some(64))?.unwrap_or(64);
    let size = size.clamp(1, 4096);

    let bytes = unsafe { ffi::read_self(addr, size as usize) }.ok_or_else(|| {
        format!(
            "probe_peek: cannot read {} byte(s) at {}",
            size,
            format_address(addr)
        )
    })?;

    let actual = bytes.len();
    let summary = format!("read {} byte(s) from {}", actual, format_address(addr));

    Ok(CallToolResult::ok(
        summary,
        json!({
            "address": format_address(addr),
            "size": actual,
            "hex": format_hex(&bytes),
            "ascii": format_ascii(&bytes),
        }),
    ))
}

// =========================================================================
// 5. probe_poke
// =========================================================================

fn poke(args: &Value) -> Result<CallToolResult, String> {
    let o = obj(args, "probe_poke")?;
    let addr = parse_address(get_str(o, "address", "probe_poke")?)?;
    let bytes = parse_poke_payload(args)?;

    let written = unsafe { ffi::write_self(addr, &bytes) }
        .ok_or_else(|| format!("probe_poke: write failed at {}", format_address(addr)))?;

    if written != bytes.len() {
        return Err(format!(
            "probe_poke: partial write {}/{} byte(s) at {}",
            written,
            bytes.len(),
            format_address(addr)
        ));
    }

    let summary = format!("wrote {} byte(s) to {}", written, format_address(addr));

    Ok(CallToolResult::ok(
        summary,
        json!({
            "address": format_address(addr),
            "written": written,
        }),
    ))
}

// =========================================================================
// 6. probe_alloc
// =========================================================================

fn alloc(ctx: &mut SandboxContext, args: &Value) -> Result<CallToolResult, String> {
    let o = obj(args, "probe_alloc")?;
    let size = get_u32_opt(o, "size", "probe_alloc", None)?
        .ok_or_else(|| "probe_alloc: 'size' is required".to_string())?;
    if size == 0 {
        return Err("probe_alloc: 'size' must be > 0".to_string());
    }
    if size > 1_048_576 {
        return Err("probe_alloc: 'size' must be ≤ 1048576".to_string());
    }

    let p = unsafe { ffi::alloc_rwx(size as usize) }
        .ok_or_else(|| format!("probe_alloc: VirtualAlloc({}) failed", size))?;
    let addr = p as u32;
    ctx.allocated.insert(addr, size as usize);

    let summary = format!("allocated {} byte(s) at {}", size, format_address(addr));

    Ok(CallToolResult::ok(
        summary,
        json!({
            "address": format_address(addr),
            "size": size,
        }),
    ))
}

// =========================================================================
// 7. probe_set_mock
// =========================================================================

fn set_mock(ctx: &mut SandboxContext, args: &Value) -> Result<CallToolResult, String> {
    let o = obj(args, "probe_set_mock")?;
    let target = get_str(o, "target", "probe_set_mock")?;
    let mode = get_str(o, "mode", "probe_set_mock")?;

    let (addr, name) = resolve_function(ctx, target)?;
    let conv = ctx
        .functions
        .get(&addr)
        .expect("resolve_function guarantees presence")
        .convention;

    let (behavior, return_value): (MockBehavior, Option<u32>) = match mode {
        "return" => {
            let v = get_u32_opt(o, "return_value", "probe_set_mock", None)?
                .ok_or_else(|| {
                    "probe_set_mock: 'return_value' is required when mode='return'"
                        .to_string()
                })?;
            (MockBehavior::Custom(v), Some(v))
        }
        "passthrough" => (MockBehavior::Passthrough, None),
        other => {
            return Err(format!(
                "probe_set_mock: mode '{}' not in {{return, passthrough}}",
                other
            ))
        }
    };

    let applied = mock_engine::create_mock(behavior, conv)
        .map_err(|e| format!("probe_set_mock: {}", e))?;

    match applied {
        Some(m) => {
            ctx.mocks.insert(addr, m);
        }
        None => {
            ctx.mocks.remove(&addr);
        }
    }

    let summary = match return_value {
        Some(v) => format!(
            "set mock {} ({}) → return {}",
            name,
            format_address(addr),
            v
        ),
        None => format!(
            "removed mock (passthrough) for {} ({})",
            name,
            format_address(addr)
        ),
    };

    Ok(CallToolResult::ok(
        summary,
        json!({
            "target": name,
            "address": format_address(addr),
            "mode": mode,
            "return_value": return_value,
        }),
    ))
}

// =========================================================================
// 8. probe_reset_mock
// =========================================================================

fn reset_mock(ctx: &mut SandboxContext, args: &Value) -> Result<CallToolResult, String> {
    let o = obj(args, "probe_reset_mock")?;

    let target = o.get("target").and_then(|v| v.as_str());
    let all = get_bool_opt(o, "all", false);

    if target.is_some() && all {
        return Err(
            "probe_reset_mock: 'target' and 'all' are mutually exclusive".to_string(),
        );
    }
    if target.is_none() && !all {
        return Err(
            "probe_reset_mock: provide either 'target' or {\"all\": true}".to_string(),
        );
    }

    if all {
        // Collect (addr, convention) pairs BEFORE mutating ctx.mocks, so we
        // don't hold an immutable borrow of ctx across the mutation.
        let pairs: Vec<(u32, CallingConvention)> = ctx
            .export_names
            .keys()
            .filter_map(|a| ctx.functions.get(a).map(|m| (*a, m.convention)))
            .collect();

        ctx.mocks.clear();
        let mut count = 0;
        for (addr, conv) in pairs {
            if let Ok(Some(m)) = mock_engine::create_mock(MockBehavior::Default, conv) {
                ctx.mocks.insert(addr, m);
                count += 1;
            }
        }

        let summary = format!("reset {} mock(s) (all exports)", count);
        Ok(CallToolResult::ok(
            summary,
            json!({
                "scope": "all",
                "target": Value::Null,
                "count": count,
            }),
        ))
    } else {
        let target = target.unwrap();
        let (addr, name) = resolve_function(ctx, target)?;
        let conv = ctx
            .functions
            .get(&addr)
            .expect("resolve_function guarantees presence")
            .convention;

        match mock_engine::create_mock(MockBehavior::Default, conv) {
            Ok(Some(m)) => {
                ctx.mocks.insert(addr, m);
            }
            Ok(None) => {
                return Err(
                    "probe_reset_mock: unexpected None from mock_engine".to_string()
                );
            }
            Err(e) => return Err(format!("probe_reset_mock: {}", e)),
        }

        let summary = format!("reset mock {} ({}) to Default", name, format_address(addr));
        Ok(CallToolResult::ok(
            summary,
            json!({
                "scope": "one",
                "target": name,
                "count": 1,
            }),
        ))
    }
}

// =========================================================================
// 9 + 10. probe_invoke / probe_invoke_mock
// =========================================================================

fn invoke(
    ctx: &mut SandboxContext,
    args: &Value,
    is_mock: bool,
) -> Result<CallToolResult, String> {
    let what = if is_mock {
        "probe_invoke_mock"
    } else {
        "probe_invoke"
    };

    let o = obj(args, what)?;
    let target = get_str(o, "target", what)?;
    let (addr, name) = resolve_function(ctx, target)?;

    let parsed_args =
        parse_args_opt(o.get("args")).map_err(|e| format!("{}: {}", what, e))?;

    // Clone the target's metadata before touching ctx.mocks/ctx.call_log so
    // we never hold a shared borrow across the unsafe invoke call.
    let func_meta = ctx
        .functions
        .get(&addr)
        .expect("resolve_function guarantees presence")
        .clone();

    let (call_meta, log_name, log_addr) = if is_mock {
        let Some(mock) = ctx.mocks.get(&addr) else {
            return Err(format!(
                "probe_invoke_mock: no mock installed for {} ({}); use probe_set_mock first",
                name,
                format_address(addr)
            ));
        };
        let meta = FunctionMeta {
            address: mock.addr,
            size: mock.size,
            calls: Vec::new(),
            internal_calls: Vec::new(),
            import_calls: Vec::new(),
            convention: func_meta.convention,
        };
        let log_addr = mock.addr;
        (meta, format!("mock:{}", name), log_addr)
    } else {
        let log_addr = func_meta.address;
        (func_meta, name.clone(), log_addr)
    };

    let watch_diff = !is_mock && get_bool_opt(o, "watch_diff", false);
    let diff_window = if watch_diff {
        let w = get_u32_opt(o, "diff_window", what, None)?;
        Some(w.unwrap_or(64))
    } else {
        None
    };

    // Warn (do not fail) on unreadable pointer args — matches REPL behavior.
    let mut warnings: Vec<String> = Vec::new();
    if !is_mock {
        for (i, a) in parsed_args.iter().enumerate() {
            if let Argument::Pointer(p) = a {
                if *p == 0 {
                    continue;
                }
                let ok = unsafe { ffi::read_self(*p, 1).is_some() };
                if !ok {
                    warnings.push(format!(
                        "arg #{} ({}) is not readable; any dereference will fault",
                        i,
                        format_address(*p)
                    ));
                }
            }
        }
    }

    let result = unsafe {
        executor::invoke(
            &call_meta,
            &parsed_args,
            &ctx.mocks,
            diff_window,
            &ctx.allocated,
        )
    }
    .map_err(|e| format!("{}: {}", what, e))?;

    // ---- structured response -----------------------------------------
    let runtime_hits: Vec<Value> = result
        .runtime_hits
        .iter()
        .map(|(a, count)| {
            json!({
                "address": format_address(*a),
                "name": name_or_dash(ctx, *a),
                "count": *count,
            })
        })
        .collect();

    let mock_targets: Vec<Value> = result
        .patched_targets
        .iter()
        .map(|a| Value::String(name_or_dash(ctx, *a)))
        .collect();

    let buffer_diffs: Vec<Value> = result
        .buffer_diffs
        .iter()
        .map(|d| {
            let changed = d.changed();
            let before_hex = d.before.as_deref().map(format_hex);
            let after_hex = d.after.as_deref().map(format_hex);
            json!({
                "address": format_address(d.address),
                "size": d.size,
                "changed": changed,
                "before_hex": before_hex,
                "after_hex": after_hex,
            })
        })
        .collect();

    let crash = if result.crash {
        Some(json!({
            "code": format_address(result.fault_code.unwrap_or(0)),
            "fault_instruction": format_address(result.fault_instr.unwrap_or(0)),
            "fault_memory_access": result.fault_data.map(format_address),
        }))
    } else {
        None
    };

    let status = if result.crash {
        "crashed"
    } else if result.abnormal {
        "abnormal"
    } else {
        "ok"
    };

    let mut structured = json!({
        "status": status,
        "eax": format_address(result.eax),
        "patched_call_sites": result.patch_count,
        "mock_targets": mock_targets,
        "runtime_hits": runtime_hits,
        "buffer_diffs": buffer_diffs,
    });
    if let Some(c) = crash {
        structured["crash"] = c;
    }

    // ---- push to call log --------------------------------------------
    let total_hits: u32 = result.runtime_hits.iter().map(|(_, c)| c).sum();
    ctx.call_log.push(crate::context::CallLogEntry {
        index: ctx.call_log.len() as u32 + 1,
        address: log_addr,
        name: log_name.clone(),
        eax: result.eax,
        crash: result.crash,
        crash_code: result.fault_code,
        patch_count: result.patch_count,
        total_hits,
    });

    // ---- content[0].text — human-readable summary ---------------------
    let mut lines = Vec::new();
    lines.push(format!(
        "{} {} ({}) with {} arg(s) → {}",
        what,
        name,
        format_address(addr),
        parsed_args.len(),
        status,
    ));
    lines.push(format!(
        "  EAX = {} ({})",
        format_address(result.eax),
        result.eax as i32
    ));
    for w in &warnings {
        lines.push(format!("  warning: {}", w));
    }
    if result.patch_count > 0 {
        let target_names: Vec<String> = result
            .patched_targets
            .iter()
            .map(|a| format!("{}@{}", name_or_dash(ctx, *a), format_address(*a)))
            .collect();
        lines.push(format!(
            "  patched {} call site(s): {}",
            result.patch_count,
            target_names.join(", ")
        ));
    }
    if !result.runtime_hits.is_empty() {
        let hits: Vec<String> = result
            .runtime_hits
            .iter()
            .map(|(a, c)| {
                format!("{}@{} x{}", name_or_dash(ctx, *a), format_address(*a), c)
            })
            .collect();
        lines.push(format!("  runtime hits: {}", hits.join(", ")));
    }
    if result.crash {
        lines.push(format!(
            "  crash: code={} at {}",
            format_address(result.fault_code.unwrap_or(0)),
            format_address(result.fault_instr.unwrap_or(0))
        ));
        if let Some(data) = result.fault_data {
            lines.push(format!("         faulting memory = {}", format_address(data)));
        }
    }
    if !result.buffer_diffs.is_empty() {
        let changed_count = result.buffer_diffs.iter().filter(|d| d.changed()).count();
        lines.push(format!(
            "  buffer diffs: {} watched, {} changed",
            result.buffer_diffs.len(),
            changed_count
        ));
    }
    let summary = lines.join("\n");

    Ok(CallToolResult::ok(summary, structured))
}

// =========================================================================
// 11. probe_call_log
// =========================================================================

fn call_log(ctx: &SandboxContext) -> Result<CallToolResult, String> {
    let entries: Vec<Value> = ctx
        .call_log
        .iter()
        .map(|e| {
            json!({
                "index": e.index,
                "function": e.name,
                "address": format_address(e.address),
                "eax": format_address(e.eax),
                "status": if e.crash { "crash" } else { "ok" },
                "crash_code": e.crash_code.map(format_address),
                "patch_count": e.patch_count,
                "total_hits": e.total_hits,
            })
        })
        .collect();

    let summary = format!("{} entries in call log", entries.len());

    Ok(CallToolResult::ok(
        summary,
        json!({
            "count": entries.len(),
            "entries": entries,
        }),
    ))
}

// =========================================================================
// 12. probe_call_log_clear
// =========================================================================

fn call_log_clear(ctx: &mut SandboxContext) -> Result<CallToolResult, String> {
    let cleared = ctx.call_log.len();
    ctx.call_log.clear();

    let summary = format!("cleared {} entries from call log", cleared);

    Ok(CallToolResult::ok(
        summary,
        json!({ "cleared": cleared }),
    ))
}