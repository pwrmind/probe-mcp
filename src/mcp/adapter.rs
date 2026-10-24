//! Adapter layer: JSON values <-> probe-native types.
//!
//! Pure translation, no I/O, no side effects. Every function here is
//! deterministic and self-contained, which makes it easy to reason about
//! and test in isolation.
//!
//! # Error convention
//!
//! All functions return `Result<_, String>`. The error message is aimed
//! at the LLM, not the human: it should say what went wrong and what the
//! accepted form is. On the server side (step 4), these errors become
//! `isError: true` tool results — the JSON-RPC envelope itself stays a
//! success.
//!
//! `#![allow(dead_code)]` because the dispatcher lands in step 4.

#![allow(dead_code)]

use serde_json::Value;

use crate::context::SandboxContext;
use crate::parser::{Argument, TargetRef};

// =========================================================================
// Scalar parsers
// =========================================================================

/// Parse a `0x...`-prefixed 32-bit hex address.
///
/// Accepts: `"0x100018B0"`, `"0X100018B0"`, `"0x0"`, `"0xFFFFFFFF"`.
/// Rejects: missing prefix, non-hex characters, overflow, empty.
pub fn parse_address(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| {
            format!(
                "address '{}' must be 0x-prefixed (e.g. 0x100018B0)",
                s
            )
        })?;
    u32::from_str_radix(hex, 16).map_err(|_| {
        format!(
            "invalid hex address '{}': expected 0x + up to 8 hex digits",
            s
        )
    })
}

/// Parse a target: a function name, or a `0x...` address.
///
/// A non-prefixed string is treated as a name (may or may not resolve —
/// that's `resolve_function`'s job).
pub fn parse_target(s: &str) -> Result<TargetRef, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("target must be non-empty".to_string());
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        Ok(TargetRef::Addr(parse_address(s)?))
    } else {
        Ok(TargetRef::Name(s.to_string()))
    }
}

/// Parse a 32-bit integer from a JSON string value.
///
/// For `type="int"` we are lenient: both decimal (`"42"`) and hex
/// (`"0x2A"`) are accepted, since LLMs often confuse the two. For
/// `type="pointer"` the rules are strict (see `parse_argument`).
fn parse_u32_lenient(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid hex '{}': expected 0x + up to 8 hex digits", s))
    } else {
        s.parse::<u32>()
            .map_err(|_| format!("invalid decimal '{}': expected 0..=4294967295", s))
    }
}

// =========================================================================
// Argument parsing
// =========================================================================

/// Parse one entry from the `args` array of `probe_invoke` /
/// `probe_invoke_mock`.
///
/// Shape: `{ "type": "int"|"pointer"|"string"|"wstring", "value": "<string>" }`.
pub fn parse_argument(v: &Value) -> Result<Argument, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "argument must be an object with 'type' and 'value'".to_string())?;

    let ty = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "argument.type must be a string".to_string())?;

    let val = obj
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "argument.value must be a string".to_string())?;

    match ty {
        "int" => {
            let n = parse_u32_lenient(val)
                .map_err(|e| format!("argument int: {}", e))?;
            Ok(Argument::Integer(n))
        }
        "pointer" => {
            let n = parse_address(val)
                .map_err(|e| format!("argument pointer: {}", e))?;
            Ok(Argument::Pointer(n))
        }
        "string" => Ok(Argument::StringLiteral(val.to_string())),
        "wstring" => Ok(Argument::WideString(val.to_string())),
        other => Err(format!(
            "argument.type '{}' not in {{int, pointer, string, wstring}}",
            other
        )),
    }
}

/// Parse the optional `args` array. `None` or `null` → empty vector.
pub fn parse_args_opt(v: Option<&Value>) -> Result<Vec<Argument>, String> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(arr) => parse_args_array(arr),
    }
}

fn parse_args_array(v: &Value) -> Result<Vec<Argument>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| "'args' must be a JSON array".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let parsed = parse_argument(item).map_err(|e| format!("args[{}]: {}", i, e))?;
        out.push(parsed);
    }
    Ok(out)
}

// =========================================================================
// Poke payload parsing
// =========================================================================

/// Parse the `{ "hex": ... }` / `{ "ascii": ... }` payload of `probe_poke`.
///
/// Exactly one of the two keys must be present. `hex` accepts an even-length
/// hex string; whitespace is ignored and an optional `0x` prefix per token
/// is allowed (`"41 42"`, `"0x41 0x42"`, `"4142"` — all equivalent).
pub fn parse_poke_payload(arguments: &Value) -> Result<Vec<u8>, String> {
    let obj = arguments
        .as_object()
        .ok_or_else(|| "poke: arguments must be a JSON object".to_string())?;

    let hex = obj.get("hex").and_then(|v| v.as_str());
    let ascii = obj.get("ascii").and_then(|v| v.as_str());

    match (hex, ascii) {
        (Some(_), Some(_)) => {
            Err("poke: 'hex' and 'ascii' are mutually exclusive".to_string())
        }
        (None, None) => {
            Err("poke: one of 'hex' or 'ascii' is required".to_string())
        }
        (Some(h), None) => parse_hex_payload(h),
        (None, Some(a)) => Ok(a.as_bytes().to_vec()),
    }
}

fn parse_hex_payload(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Split-by-whitespace mode if there is any whitespace; otherwise treat
    // the whole string as one contiguous block.
    if trimmed.chars().any(|c| c.is_whitespace()) {
        let mut out = Vec::new();
        for tok in trimmed.split_whitespace() {
            let tok = strip_0x(tok);
            let mut part = parse_contiguous_hex(tok)?;
            out.append(&mut part);
        }
        Ok(out)
    } else {
        parse_contiguous_hex(strip_0x(trimmed))
    }
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn parse_contiguous_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Err("hex token is empty".to_string());
    }
    if s.len() % 2 != 0 {
        return Err(format!(
            "hex string '{}' has odd length ({}), expected even",
            s,
            s.len()
        ));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or_else(|| {
            format!(
                "invalid hex char '{}' at offset {}",
                bytes[i] as char, i
            )
        })?;
        let lo = hex_nibble(bytes[i + 1]).ok_or_else(|| {
            format!(
                "invalid hex char '{}' at offset {}",
                bytes[i + 1] as char,
                i + 1
            )
        })?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// =========================================================================
// Target resolution (needs the sandbox context)
// =========================================================================

/// Resolve a string to `(address, display_name)` of a known function.
///
/// A successful return guarantees `ctx.functions.contains_key(&address)`.
/// The display name is the export name if available, `-` otherwise
/// (matching the REPL convention).
///
/// All failures here are tool-execution errors, not protocol errors:
/// the JSON was well-formed, but the target does not identify a function.
pub fn resolve_function(
    ctx: &SandboxContext,
    s: &str,
) -> Result<(u32, String), String> {
    let tref = parse_target(s)?;
    let addr = ctx.resolve_target(&tref).ok_or_else(|| {
        format!(
            "cannot resolve function '{}': no export with this name, \
             and no function at this address",
            s
        )
    })?;
    if !ctx.functions.contains_key(&addr) {
        return Err(format!(
            "no function metadata at 0x{:08X} ('{}' resolves to an address \
             but not to a discovered function)",
            addr, s
        ));
    }
    let name = ctx
        .name_of(addr)
        .cloned()
        .unwrap_or_else(|| "-".to_string());
    Ok((addr, name))
}

// =========================================================================
// Formatters (native -> JSON-safe strings)
// =========================================================================

/// Format an address as `0x%08X` — the canonical form used throughout
/// probe-mcp responses.
pub fn format_address(addr: u32) -> String {
    format!("0x{:08X}", addr)
}

/// Format bytes as a contiguous uppercase hex string: `"41424344"`.
pub fn format_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

/// Format bytes as a space-separated uppercase hex string: `"41 42 43 44"`.
/// Used in human-readable summary lines embedded in `content`.
pub fn format_hex_spaced(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    if bytes.is_empty() {
        return String::new();
    }
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

/// Format bytes as printable ASCII; non-printables become `.`.
pub fn format_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..=0x7E).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}