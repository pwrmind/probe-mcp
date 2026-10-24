//! Tool descriptors exposed to the MCP client via `tools/list`.
//!
//! Each tool maps to one capability of the probe runtime. The `input_schema`
//! and `output_schema` fields are JSON Schema (2020-12) objects. The
//! `annotations` field carries MCP safety hints so the host can decide
//! whether to auto-approve a call or ask the user.
//!
//! Tool names are exposed as `pub const` so the dispatcher (step 4) can
//! match on them without stringly-typed literals scattered around.

use serde_json::{json, Value};

use super::protocol::{Tool, ToolAnnotations};

// =========================================================================
// Tool names
// =========================================================================

pub const LIST_FUNCTIONS: &str = "probe_list_functions";
pub const INSPECT_FUNCTION: &str = "probe_inspect_function";
pub const DISASM: &str = "probe_disasm";
pub const PEEK: &str = "probe_peek";
pub const POKE: &str = "probe_poke";
pub const ALLOC: &str = "probe_alloc";
pub const SET_MOCK: &str = "probe_set_mock";
pub const RESET_MOCK: &str = "probe_reset_mock";
pub const INVOKE: &str = "probe_invoke";
pub const INVOKE_MOCK: &str = "probe_invoke_mock";
pub const CALL_LOG: &str = "probe_call_log";
pub const CALL_LOG_CLEAR: &str = "probe_call_log_clear";

// =========================================================================
// Reusable schema fragments
// =========================================================================

/// A single argument passed to `probe_invoke` / `probe_invoke_mock`.
///
/// Discriminated by `type`:
/// - `int`      — 32-bit unsigned integer, `value` is decimal string
/// - `pointer`  — 32-bit address, `value` is 0x-prefixed hex string
/// - `string`   — ANSI (UTF-8 bytes + NUL), allocated by the sandbox
/// - `wstring`  — UTF-16LE wide string + NUL NUL, for Windows W-APIs
fn schema_argument() -> Value {
    json!({
        "type": "object",
        "description": "Typed argument for a sandboxed function call.",
        "properties": {
            "type": {
                "type": "string",
                "enum": ["int", "pointer", "string", "wstring"],
                "description": "Argument kind. Determines how 'value' is parsed and passed."
            },
            "value": {
                "type": "string",
                "description": "String representation. \
                    int: decimal (e.g. '42'). \
                    pointer: 0x-prefixed hex (e.g. '0x01650000'). \
                    string: raw ANSI text. \
                    wstring: raw text, sandbox encodes it as UTF-16LE."
            }
        },
        "required": ["type", "value"]
    })
}

/// Output for a crash inside `probe_invoke`. Always present when
/// `status == "crashed"`, absent otherwise.
fn schema_crash() -> Value {
    json!({
        "type": "object",
        "description": "Sandbox exception details. The sandbox remained alive.",
        "properties": {
            "code": {
                "type": "string",
                "pattern": "^0x[0-9A-Fa-f]{8}$",
                "description": "NTSTATUS exception code (e.g. 0xC0000005 for AV)."
            },
            "fault_instruction": {
                "type": "string",
                "pattern": "^0x[0-9A-Fa-f]{8}$",
                "description": "EIP at the moment of the fault."
            },
            "fault_memory_access": {
                "type": ["string", "null"],
                "description": "Faulting data address (only for ACCESS_VIOLATION)."
            }
        },
        "required": ["code", "fault_instruction"]
    })
}

/// Output shared by `probe_invoke` and `probe_invoke_mock`.
fn schema_invoke_output() -> Value {
    json!({
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["ok", "crashed", "abnormal"],
                "description": "ok = clean return; crashed = VEH caught an exception; \
                    abnormal = thread died without a catchable exception."
            },
            "eax": {
                "type": "string",
                "pattern": "^0x[0-9A-Fa-f]{8}$",
                "description": "EAX at return. 0xDEADFA11 when status == 'crashed'."
            },
            "patched_call_sites": {
                "type": "integer",
                "description": "Number of CALL instructions rewritten to mock stubs during this invoke."
            },
            "mock_targets": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Function names targeted by the patches (one per patched call site)."
            },
            "runtime_hits": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "address": { "type": "string" },
                        "name": { "type": "string" },
                        "count": { "type": "integer", "minimum": 1 }
                    },
                    "required": ["address", "name", "count"]
                },
                "description": "Stub invocation counters, reset before each invoke. \
                    Empty when all patched branches were skipped."
            },
            "buffer_diffs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "address": { "type": "string" },
                        "size": { "type": "integer" },
                        "changed": { "type": "boolean" },
                        "before_hex": { "type": ["string", "null"] },
                        "after_hex": { "type": ["string", "null"] }
                    },
                    "required": ["address", "size", "changed"]
                },
                "description": "Present only when watch_diff was true."
            },
            "crash": schema_crash()
        },
        "required": ["status", "eax", "patched_call_sites"]
    })
}

// =========================================================================
// Annotations helper
// =========================================================================

fn ann(title: &str, read_only: bool, destructive: bool, idempotent: bool) -> ToolAnnotations {
    ToolAnnotations {
        title: Some(title.to_string()),
        read_only_hint: Some(read_only),
        destructive_hint: Some(destructive),
        idempotent_hint: Some(idempotent),
        // probe never contacts the outside world — this is a closed sandbox.
        open_world_hint: Some(false),
    }
}

// =========================================================================
// Tool list
// =========================================================================

pub fn list_tools() -> Vec<Tool> {
    vec![
        tool_list_functions(),
        tool_inspect_function(),
        tool_disasm(),
        tool_peek(),
        tool_poke(),
        tool_alloc(),
        tool_set_mock(),
        tool_reset_mock(),
        tool_invoke(),
        tool_invoke_mock(),
        tool_call_log(),
        tool_call_log_clear(),
    ]
}

// ---------- 1. list functions -----------------------------------------------

fn tool_list_functions() -> Tool {
    Tool {
        name: LIST_FUNCTIONS.to_string(),
        description: "List functions discovered in the loaded PE32 binary. \
            Returns address, name (or '-' for unnamed internal), size, direct-call count, \
            and calling convention. Use this as the first step of reconnaissance. \
            Filters and sorting are server-side, so prefer them over fetching the full list."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "sort_by": {
                    "type": "string",
                    "enum": ["address", "name", "size", "calls"],
                    "default": "address",
                    "description": "Sort order for the returned list."
                },
                "name_contains": {
                    "type": "string",
                    "description": "Case-sensitive substring match on function name. Unnamed functions never match."
                },
                "min_size": { "type": "integer", "minimum": 0 },
                "max_size": { "type": "integer", "minimum": 0 },
                "min_calls": { "type": "integer", "minimum": 0 },
                "max_calls": { "type": "integer", "minimum": 0 },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 500,
                    "description": "Max entries to return after filtering. The response's 'total' field reports the pre-limit count."
                }
            }
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "total": { "type": "integer" },
                "returned": { "type": "integer" },
                "functions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "address": { "type": "string" },
                            "name": { "type": "string" },
                            "size": { "type": "integer" },
                            "calls_count": { "type": "integer" },
                            "convention": {
                                "type": "string",
                                "description": "'cdecl' or 'stdcall N' (N = arg bytes)."
                            },
                            "has_mock": {
                                "type": "boolean",
                                "description": "True if a stub is currently installed for this address."
                            }
                        },
                        "required": ["address", "name", "size", "calls_count", "convention", "has_mock"]
                    }
                }
            },
            "required": ["total", "returned", "functions"]
        })),
        annotations: Some(ann("List functions", true, false, true)),
    }
}

// ---------- 2. inspect function ---------------------------------------------

fn tool_inspect_function() -> Tool {
    Tool {
        name: INSPECT_FUNCTION.to_string(),
        description: "Show detailed metadata for a single function: size, calling convention, \
            current mock state, and the list of direct CALL sites with their resolved targets. \
            Use this after probe_list_functions to understand the call graph before mocking."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name (e.g. 'login') or 0x-prefixed address (e.g. '0x100018B0')."
                }
            },
            "required": ["target"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "address": { "type": "string" },
                "name": { "type": "string" },
                "size": { "type": "integer" },
                "convention": { "type": "string" },
                "mock": {
                    "type": ["string", "null"],
                    "enum": ["default", "custom", "passthrough", null],
                    "description": "Current mock behavior for this function, or null if none."
                },
                "calls": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "at": { "type": "string", "description": "Address of the CALL instruction." },
                            "target": { "type": "string", "description": "Address of the callee." },
                            "target_name": { "type": "string" }
                        },
                        "required": ["at", "target", "target_name"]
                    }
                }
            },
            "required": ["address", "name", "size", "convention", "calls"]
        })),
        annotations: Some(ann("Inspect function", true, false, true)),
    }
}

// ---------- 3. disasm -------------------------------------------------------

fn tool_disasm() -> Tool {
    Tool {
        name: DISASM.to_string(),
        description: "Disassemble up to N instructions starting at a function or address, \
            using iced-x86 Intel syntax. Returns one entry per instruction with its \
            address, raw bytes, and formatted text. Useful to recover XOR masks, \
            stack-frame sizes, and constant arguments."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name or 0x-prefixed address."
                },
                "count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 30,
                    "description": "Number of instructions to decode."
                }
            },
            "required": ["target"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "address": { "type": "string" },
                "instructions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "address": { "type": "string" },
                            "bytes": { "type": "string", "description": "Hex bytes, space-separated." },
                            "text": { "type": "string", "description": "Intel syntax." }
                        },
                        "required": ["address", "bytes", "text"]
                    }
                }
            },
            "required": ["address", "instructions"]
        })),
        annotations: Some(ann("Disassemble", true, false, true)),
    }
}

// ---------- 4. peek ---------------------------------------------------------

fn tool_peek() -> Tool {
    Tool {
        name: PEEK.to_string(),
        description: "Read memory from the sandbox process and return it as a hex string \
            with an ASCII preview. Use to inspect buffers written by probe_invoke --diff, \
            global variables (e.g. G_LICENSE_KEY), or the stub page for a mock."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "0x-prefixed address to read."
                },
                "size": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                    "default": 64,
                    "description": "Number of bytes to read."
                }
            },
            "required": ["address"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "address": { "type": "string" },
                "size": { "type": "integer" },
                "hex": { "type": "string", "description": "Contiguous hex bytes, e.g. '41424344'." },
                "ascii": { "type": "string", "description": "Printable ASCII, non-printables shown as '.'." }
            },
            "required": ["address", "size", "hex", "ascii"]
        })),
        annotations: Some(ann("Read memory", true, false, true)),
    }
}

// ---------- 5. poke ---------------------------------------------------------

fn tool_poke() -> Tool {
    Tool {
        name: POKE.to_string(),
        description: "Write bytes to sandbox memory. Provide exactly one of 'hex' \
            (even-length hex string) or 'ascii' (UTF-8 text). Use after probe_alloc \
            to prepare arguments, or to overwrite a stub, or to seed a buffer for a \
            fuzzing campaign."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "0x-prefixed destination address."
                },
                "hex": {
                    "type": "string",
                    "description": "Hex bytes, even length. E.g. '41424344' writes 'ABCD'. Mutually exclusive with 'ascii'."
                },
                "ascii": {
                    "type": "string",
                    "description": "UTF-8 text, written as raw bytes. Mutually exclusive with 'hex'."
                }
            },
            "required": ["address"],
            "oneOf": [
                { "required": ["hex"] },
                { "required": ["ascii"] }
            ]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "address": { "type": "string" },
                "written": { "type": "integer", "description": "Number of bytes actually written." }
            },
            "required": ["address", "written"]
        })),
        annotations: Some(ann("Write memory", false, false, true)),
    }
}

// ---------- 6. alloc --------------------------------------------------------

fn tool_alloc() -> Tool {
    Tool {
        name: ALLOC.to_string(),
        description: "Allocate RWX memory inside the sandbox and return its address. \
            Use the returned address as a pointer argument to probe_invoke or as the \
            destination of probe_poke. The sandbox remembers each allocation's size, \
            so a subsequent probe_invoke --watch_diff knows exactly how many bytes \
            to compare."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "size": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1048576,
                    "description": "Number of bytes to allocate."
                }
            },
            "required": ["size"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "address": { "type": "string" },
                "size": { "type": "integer" }
            },
            "required": ["address", "size"]
        })),
        annotations: Some(ann("Allocate memory", false, false, false)),
    }
}

// ---------- 7. set mock -----------------------------------------------------

fn tool_set_mock() -> Tool {
    Tool {
        name: SET_MOCK.to_string(),
        description: "Install a stub for a function. The stub replaces every direct CALL \
            to the target inside a function invoked via probe_invoke. Two modes: \
            'return' (stub returns the given value in EAX) or 'passthrough' (remove the \
            stub so the real code runs). Stubs are created per-call in RWX memory and \
            carry a hit counter visible in probe_invoke's 'runtime_hits'. \
            IMPORTANT: stubs intercept CALLs from other functions, not from probe_invoke \
            targeting the mocked function itself — use probe_invoke_mock to exercise a stub directly."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name or 0x-prefixed address."
                },
                "mode": {
                    "type": "string",
                    "enum": ["return", "passthrough"]
                },
                "return_value": {
                    "type": "integer",
                    "minimum": 0,
                    // NOTE: `u32` suffix is required here. Without it, the
                    // literal is inferred as `i32`, which cannot represent
                    // u32::MAX, and `json!` fails to compile with
                    // "literal out of range for i32".
                    "maximum": 4294967295u32,
                    "description": "Required when mode='return'. Ignored when mode='passthrough'."
                }
            },
            "required": ["target", "mode"],
            "allOf": [
                {
                    "if": { "properties": { "mode": { "const": "return" } } },
                    "then": { "required": ["return_value"] }
                }
            ]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "target": { "type": "string" },
                "address": { "type": "string" },
                "mode": { "type": "string", "enum": ["return", "passthrough", "default"] },
                "return_value": { "type": ["integer", "null"] }
            },
            "required": ["target", "address", "mode"]
        })),
        annotations: Some(ann("Set mock", false, false, true)),
    }
}

// ---------- 8. reset mock ---------------------------------------------------

fn tool_reset_mock() -> Tool {
    Tool {
        name: RESET_MOCK.to_string(),
        description: "Reset one function's mock to the auto-generated Default (EAX=0), \
            or reset every export's mock with { all: true }. Internal functions are \
            not auto-mocked; to un-mock an internal function use probe_set_mock with \
            mode='passthrough'."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name or 0x-prefixed address. Mutually exclusive with 'all'."
                },
                "all": {
                    "type": "boolean",
                    "description": "If true, reset every export's mock. Mutually exclusive with 'target'."
                }
            },
            "oneOf": [
                { "required": ["target"] },
                { "required": ["all"], "properties": { "all": { "const": true } } }
            ]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "scope": { "type": "string", "enum": ["one", "all"] },
                "target": { "type": ["string", "null"] },
                "count": { "type": "integer", "description": "Number of mocks reset (1 for scope='one', N for scope='all')." }
            },
            "required": ["scope", "count"]
        })),
        annotations: Some(ann("Reset mock", false, false, true)),
    }
}

// ---------- 9. invoke -------------------------------------------------------

fn tool_invoke() -> Tool {
    Tool {
        name: INVOKE.to_string(),
        description: "Execute a function in the sandbox with the given arguments. Real code \
            runs on a dedicated thread; mocks on direct-call targets are patched in for \
            the duration of the call. A crash inside the function is caught by VEH and \
            returned in 'crash' — the server stays alive. \
            Set 'watch_diff' to snapshot every pointer/string argument before and after, \
            revealing out-parameters (e.g. decrypted buffers). \
            NOTE: mocks set for the target function itself are NOT applied here. \
            Use probe_invoke_mock to run a stub directly."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name or 0x-prefixed address."
                },
                "args": {
                    "type": "array",
                    "items": schema_argument(),
                    "description": "Positional arguments, cdecl order (left to right)."
                },
                "watch_diff": {
                    "type": "boolean",
                    "default": false,
                    "description": "If true, capture before/after snapshots of every pointer/string argument."
                },
                "diff_window": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4096,
                    "description": "Override window size for --diff on pointers whose allocation size is unknown. Ignored when watch_diff is false."
                }
            },
            "required": ["target"]
        }),
        output_schema: Some(schema_invoke_output()),
        annotations: Some(ann("Invoke function", false, true, false)),
    }
}

// ---------- 10. invoke mock -------------------------------------------------

fn tool_invoke_mock() -> Tool {
    Tool {
        name: INVOKE_MOCK.to_string(),
        description: "Run the STUB currently installed for a function (the code emitted by \
            probe_set_mock), rather than the real function body. Useful to verify that a \
            mock returns the expected value before relying on it in a larger call chain. \
            The stub increments its hit counter and returns the mocked EAX."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name or 0x-prefixed address. A mock must already be installed."
                },
                "args": {
                    "type": "array",
                    "items": schema_argument(),
                    "description": "Arguments are passed so that stdcall stubs can pop the correct stack bytes."
                }
            },
            "required": ["target"]
        }),
        output_schema: Some(schema_invoke_output()),
        annotations: Some(ann("Invoke mock stub", false, false, false)),
    }
}

// ---------- 11. call log (read) ---------------------------------------------

fn tool_call_log() -> Tool {
    Tool {
        name: CALL_LOG.to_string(),
        description: "Return the experiment journal: every probe_invoke / probe_invoke_mock \
            since the last clear, with function, EAX, status, patch count, and total mock \
            hits. This is the primary evidence trail for the LLM's reasoning. \
            Use probe_call_log_clear to start a fresh experiment."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {}
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" },
                "entries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "index": { "type": "integer", "minimum": 1 },
                            "function": { "type": "string", "description": "Name, or 'mock:<name>' for stub invocations." },
                            "address": { "type": "string" },
                            "eax": { "type": "string" },
                            "status": { "type": "string", "enum": ["ok", "crash"] },
                            "crash_code": { "type": ["string", "null"] },
                            "patch_count": { "type": "integer" },
                            "total_hits": { "type": "integer" }
                        },
                        "required": ["index", "function", "address", "eax", "status", "patch_count", "total_hits"]
                    }
                }
            },
            "required": ["count", "entries"]
        })),
        annotations: Some(ann("Read call log", true, false, true)),
    }
}

// ---------- 12. call log clear ----------------------------------------------

fn tool_call_log_clear() -> Tool {
    Tool {
        name: CALL_LOG_CLEAR.to_string(),
        description: "Clear the call log. Use before starting a new experiment so that the \
            evidence trail contains only calls relevant to the current hypothesis."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {}
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "cleared": { "type": "integer", "description": "Number of entries removed." }
            },
            "required": ["cleared"]
        })),
        annotations: Some(ann("Clear call log", false, false, false)),
    }
}