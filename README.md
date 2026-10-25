# 🧪 probe-mcp

**Sandboxed PE32/x86 binary analysis for AI agents.**

`probe-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server that runs a live, sandboxed instance of a Windows PE32/x86 binary
and exposes it to an AI agent as a set of 13 tools. The agent can load
any PE32 binary at runtime, inspect its functions, disassemble code,
patch call sites, execute real code with arbitrary arguments, and read
memory — all without restarting the server.

A crash inside the target does not crash the server: a vectored exception
handler catches access violations, illegal instructions, and divide-by-zero,
restores the stack, and reports the fault through the tool response.

---

## Highlights

- **Real execution.** Target code runs on a real thread with a real stack,
  after imports are resolved and the image is mapped at its preferred base.
  This is not static analysis.
- **Per-call mocking.** Install a stub for any function; the next
  `probe_invoke` on any *caller* rewrites every direct `CALL` to that
  function into a call to the stub. Stubs carry hit counters, so you can
  see exactly which branch executed — including timing side-channels.
- **Crash recovery.** Every invocation is wrapped in a VEH. Faults are
  reported in `structuredContent.crash` with the NTSTATUS code, faulting
  EIP, and (for AVs) the faulting data address. The server stays alive.
- **Buffer diffs.** `watch_diff: true` on any pointer or string argument
  snapshots the buffer before and after, revealing out-parameters such as
  decrypted passwords, generated session keys, and mutated state.
- **Reusable session.** The server starts with **no target loaded** and
  stays up. Call `probe_open` with a path; call it again with a different
  path to switch targets. The old image, its mocks, and every buffer
  allocated via `probe_alloc` are freed automatically.

The architecture mirrors [REA (morluto/rea)](https://github.com/morluto/rea):
a long-lived MCP server whose target is chosen by the agent through an
`open_binary`-style tool, not through the command line.

---

## Requirements

- **Windows** (the VEH, `VirtualAlloc`, `CreateThread`, and SEH machinery
  are Win32-specific).
- **Rust 1.75 or newer** with the `i686-pc-windows-msvc` target installed:

  ```
  rustup target add i686-pc-windows-msvc
  ```

- **MSVC build tools** (`link.exe` must be on `PATH`; the `x86_64-pc-windows-msvc`
  toolchain provides them via `rustup`, or install Visual Studio Build Tools).

---

## Build

```powershell
cargo build --release --target i686-pc-windows-msvc
```

The binary lands at:

```
target\i686-pc-windows-msvc\release\probe-mcp.exe
```

> **Note:** 32-bit is mandatory. `src/main.rs` contains a
> `compile_error!` guard if you try to build for `x86_64`. The sandbox
> executes 32-bit code by calling into the target with a manually built
> `cdecl` stack frame, which requires the host process itself to be 32-bit.

---

## Run

The server is a stdio MCP server. It reads newline-delimited JSON-RPC 2.0
from `stdin` and writes responses to `stdout`. All logging goes to `stderr`.

### Without a target (normal use)

```powershell
.\probe-mcp.exe
```

Output:

```
[*] No target pre-loaded. Call probe_open to load a PE32/x86 binary.
[probe-mcp] server ready (protocol 2025-06-18)
```

The agent then calls `probe_open` to load a binary. **This is the only
supported mode for agent use.**

### With a target (debugging)

```powershell
.\probe-mcp.exe .\crackme\crackme.dll
```

The file is loaded at startup, and the agent can still call `probe_open`
later to switch targets. This mode exists for manual debugging and for
CI pipelines that always analyze the same file.

---

## MCP client setup

`probe-mcp` works with any MCP client. Pass **no arguments**; the client
should let the agent supply the target path via `probe_open`.

### Claude Desktop

`%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "probe": {
      "command": "C:\\projects\\rust\\probe-mcp\\target\\i686-pc-windows-msvc\\release\\probe-mcp.exe",
      "args": []
    }
  }
}
```

Restart Claude Desktop fully after editing.

### Cursor

`.cursor\mcp.json` (project-local) or `~\.cursor\mcp.json` (global):

```json
{
  "mcpServers": {
    "probe": {
      "command": "C:\\projects\\rust\\probe-mcp\\target\\i686-pc-windows-msvc\\release\\probe-mcp.exe",
      "args": []
    }
  }
}
```

### Cline (VS Code)

`%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "probe": {
      "command": "C:\\projects\\rust\\probe-mcp\\target\\i686-pc-windows-msvc\\release\\probe-mcp.exe",
      "args": [],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Using the `SKILL.md`

The repository ships with a `SKILL.md` at the root. Add it to your client's
skills directory (`~/.claude/skills/probe-binary-analysis/SKILL.md` for
Claude Desktop) to teach the agent the standard workflows: bypassing
password checks, recovering timing side-channels, extracting XOR-obfuscated
strings, forcing multi-level license checks, probing memory-safety bugs,
and switching targets mid-session.

Without the skill, the agent can still use the tools — the tool
descriptions are detailed enough for most queries. The skill reduces
improvising on multi-step analysis.

---

## Tool catalog

| Tool | Purpose |
|------|---------|
| `probe_open` | Load a PE32/x86 binary. Replaces any previous target; frees its image, mocks, and allocations. |
| `probe_list_functions` | List discovered functions with filters (`name_contains`, size range, call-count range) and sorting. |
| `probe_inspect_function` | Metadata for one function: size, calling convention, mock state, and every direct `CALL` site with its resolved target. |
| `probe_disasm` | Disassemble N instructions at a function or address (iced-x86, Intel syntax). |
| `probe_peek` | Read memory and return `{hex, ascii}`. Max 4096 bytes. |
| `probe_poke` | Write bytes (`hex` or `ascii`) to any readable address. |
| `probe_alloc` | Allocate RWX scratch memory; the sandbox remembers the size for later `watch_diff`. Max 1 MiB. |
| `probe_set_mock` | Install a stub for a function: `mode: "return"` (set EAX) or `mode: "passthrough"` (remove). |
| `probe_reset_mock` | Reset one function or all exports to the auto-generated default stub. |
| `probe_invoke` | Execute the real function body with typed arguments; optionally snapshot pointer/string args via `watch_diff`. |
| `probe_invoke_mock` | Execute the stub directly (verifies what a mock returns before relying on it). |
| `probe_call_log` | Read the experiment journal: every invoke since the last clear. |
| `probe_call_log_clear` | Clear the journal. |

Every tool returns `content` (human-readable summary) and `structuredContent`
(machine-readable). A domain error (missing function, unreadable memory,
bad argument) is `isError: true` with a clear message; the JSON-RPC
envelope stays a success. A target crash is **not** an error — it is
`status: "crashed"` inside a successful response.

---

## Quick start

```text
Agent → probe_open({"path": "C:\\path\\to\\target.dll"})
      ← loaded target.dll (114688 bytes) at 0x10000000; 152 function(s),
        19 export(s), 19 mock(s); entry = 0x10012F4D

Agent → probe_list_functions({"name_contains": "verify"})
      ← [{address: "0x100015B0", name: "verify_serial_timing", size: 106, ...}]

Agent → probe_invoke({"target": "verify_serial_timing",
                      "args": [{"type": "string", "value": "PR0BE42"}]})
      ← status: "ok", eax: "0x00000001",
        patched_call_sites: 7,
        runtime_hits: [{name: "__loop_marker", count: 7}]
```

---

## Example: cracking `crackme.dll`

The repository ships with `crackme/crackme.rs`, a reference target that
demonstrates 11 classes of bug (CWE / CAPEC / OWASP). Compile it with:

```powershell
cd crackme
rustc --crate-type=cdylib --target i686-pc-windows-msvc -O crackme.rs `
  -C link-arg=/BASE:0x10000000 `
  -C link-arg=/DYNAMICBASE:NO `
  -C link-arg=/FIXED:NO `
  -o crackme.dll
```

> **Note on the KEEP table.** MSVC's `/OPT:REF` eliminates every
> `#[no_mangle] extern "C"` function that isn't reachable from another
> function in the crate. `crackme.rs` keeps its 22 functions alive with a
> `#[used] static _CRACKME_KEEP: [KeepPtr; 22]`, where `KeepPtr` is a
> `#[repr(transparent)]` newtype around `*const ()` with an
> `unsafe impl Sync`. Using `fn as usize` directly would fail to compile
> because function addresses are not known at const-eval time; casting
> to a pointer type is allowed and produces the same linker relocation.

Then walk through the four scenarios in `probe-test.ps1`:

1. **Reconnaissance** — `probe_list_functions` filtered on
   `crash`/`verify`/`decrypt`.
2. **Crash recovery** — `probe_invoke("crash_null_deref")` returns
   `status: "crashed", code: "0xC0000005", EAX = 0xDEADFA11`.
3. **Timing side-channel** — `probe_invoke("verify_serial_timing", ["AAAAAAA"])`
   returns `runtime_hits: [__loop_marker x1]`; incrementing the prefix
   recovers `PR0BE42` character by character without reading any assembly.
4. **Buffer mutation** — `probe_alloc` → `probe_poke` → `probe_invoke` on
   `decrypt_inplace` → `probe_peek` reveals the plaintext `probe42`.

Other scenarios to explore (all documented in the `crackme.rs` comments):

- `login` with mocks on `is_admin` (backdoor) or `check_password` (honest)
- `validate_premium_user` with three mocks short-circuiting on the first zero
- `verify_license` XOR recovery via `disasm` + `peek`
- `parse_user_bio` with `size: 40` triggers a stack overflow (CWE-121)
- `process_custom_packet` with a forged length byte triggers an OOB read (CWE-125)
- `check_obfuscated_password` fails when `decrypt_inplace` is mocked away

---

## Design notes

**Why no target at startup?** Because an MCP server should be a
long-lived resource, not a one-shot process bound to a single file. The
agent decides which binary to analyze, and can switch targets without a
round-trip through the client's process manager. This is the same pattern
`rea mcp` uses with `open_binary`.

**Why per-invoke patching?** The target's bytes are modified in place
(`CALL rel32` → `CALL stub`), executed, then restored. Original bytes are
saved before the patch and copied back unconditionally. This means a
crash mid-invoke still restores the code — the VEH recovery path is
followed by the same `Drop` that restores patches. You can call
`probe_invoke` on the same function as many times as you want; no state
accumulates.

**Why VEH instead of SEH?** VEH runs before the target's own `__try/__except`
or SEH frame. If the target installs its own handler, the VEH still runs
first and gets a chance to record the fault and restore EIP/ESP/EAX.
`SetUnhandledExceptionFilter` is used as a fallback to log anything the
VEH missed, but the primary catch is always at the VEH level.

**Why `0xDEADFA11`?** It is the `EAX` value written to the context when
a fault is caught. `0xDEADFA11` is not a valid return value for any
sensible function, so seeing `EAX = 0xDEADFA11` in the response is an
unambiguous "this crashed" marker. The full `crash` object carries the
NTSTATUS code and the faulting instruction address.

**Why keep `import_calls`?** A vestigial field from the REPL version of
probe. The MCP layer currently doesn't use it. It exists so a future
"import-aware" tool can be added without changing `FunctionMeta`.

---

## Limitations

- **PE32/x86 only.** No x86_64, no ARM, no .NET.
- **Single active target.** `probe_open` replaces the current one. Multiple
  simultaneous targets are not supported (this could change if the
  context became `HashMap<TargetId, SandboxContext>`).
- **No syscall interception.** The target executes in your process. If it
  calls `CreateFileW`, `InternetOpenW`, or `RegOpenKeyExW`, those calls go
  to the real OS. To analyze a hostile binary, run `probe-mcp` in a VM or
  under a system-wide sandbox.
- **No thread concurrency.** The executor runs the target on a dedicated
  thread and waits for it with `WaitForSingleObject(INFINITE)`. If the
  target spawns its own worker threads that call into your mocked code,
  those calls are not tracked (their CALL sites are not patched; the
  patch window is only the function you invoked).
- **`watch_diff` requires readable memory.** Pointers that aren't readable
  at snapshot time produce `before: null` and are reported with
  `changed: false`. They are not fatal; you get a warning in `content`.
- **`fault_memory_access` is `null` for many access violations.** The VEH
  reads `rec.info[1]` (the faulting address for AV-on-write); for
  AV-on-read this is often zero. Use `fault_instruction` and the
  surrounding disassembly to infer the access.

---

## Security

**The sandbox is not a security boundary.** It catches *execution*
exceptions (VEH) but does not virtualize the filesystem, registry, network,
or process tokens. Do not load binaries you do not trust.

The `probe_open` tool accepts any path the server process can read. If
you're exposing `probe-mcp` to an untrusted agent, add a `--allowed-dir`
guard (not yet implemented; see the "MCP client setup" section for how
other RE-MCP servers handle this).

---

## Testing

The repository includes `probe-test.ps1`, a PowerShell harness that
launches a fresh server, runs `probe_open`, and exercises four scenarios
(reconnaissance, crash recovery, timing side-channel, buffer mutation).
It uses UTF-8 output to render `→` correctly in Windows consoles.

For interactive testing, launch the server and pipe JSON-RPC manually:

```powershell
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual","version":"0.1"}}}' `
  | .\probe-mcp.exe .\crackme\crackme.dll
```

---

## License
