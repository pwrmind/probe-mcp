---
name: probe-binary-analysis
description: Analyze PE32/x86 binaries in a sandboxed runtime using the probe-mcp tool family. Use this skill when the user asks to reverse engineer, crack, disassemble, dynamically test, or fuzz a Windows PE32 executable or DLL — including finding password checks, bypassing license validation, extracting XOR-obfuscated strings, tracing mock call hits, or probing vulnerabilities such as buffer overflows, NULL dereferences, out-of-bounds reads, and timing side-channels. The binary runs in a live sandbox; crashes are caught and reported, not fatal.
---

# probe-mcp — sandboxed PE32/x86 binary analysis

`probe-mcp` runs a **live, sandboxed instance** of a PE32/x86 binary (a DLL
or EXE) inside the MCP server process. You can inspect its functions,
disassemble them, patch call sites, execute real code with arbitrary
arguments, and read memory — all through the tools below. Every PE image
is mapped at its preferred `ImageBase`, imports are resolved, and every
exported function gets a default stub (`EAX=0`) pre-installed.

## Mandatory first step

**Always call `probe_open` before any other tool.** The server starts
with no target loaded. Calling anything else first returns
`isError: true` with the message *"no target loaded"*.

```
probe_open({ "path": "C:\\absolute\\path\\to\\target.dll" })
```

`probe_open` replaces the active target. Previous mocks, allocations, and
the mapped image are freed automatically. You can switch targets at any
time within a session — no restart needed.

## Key concepts

- **Crash is not an error.** The sandbox installs a VEH; `EXCEPTION_ACCESS_VIOLATION`,
  `ILLEGAL_INSTRUCTION`, `INT_DIVIDE_BY_ZERO`, etc. are caught, EIP/ESP are
  restored, and the tool returns `status: "crashed"` with the exception code.
  The server stays alive. Do not retry blindly — read `crash` fields first.
- **Mocks are patched per-invoke.** `probe_set_mock` installs a stub in RWX
  memory. `probe_invoke` on a *caller* rewrites every direct `CALL` to the
  mocked target into a call to the stub. The stub increments a hit counter.
  After the invoke returns, original bytes are restored.
- **Mocks do NOT apply to the target itself.** `probe_invoke("login")` runs
  the real `login`. Mocks intercept `login`'s `CALL` sites to *other* functions.
  To run a stub directly, use `probe_invoke_mock("login")`.
- **`runtime_hits` is the control-flow signal.** After every invoke, it tells
  you exactly which mocks were called and how many times — this is how you
  recover timing side-channel secrets and detect which `&&`/`||` branch fired.
- **All addresses are `0x`-prefixed 8-digit hex strings** (e.g. `"0x10001250"`).
  All sizes are JSON integers.

## Tool catalog

### 1. `probe_open` — load target (call first, always)

```json
{ "path": "C:\\projects\\crackme.dll" }
```

Returns `path` (canonical, no `\\?\` noise), `image_base`, `image_size`,
`entry_point`, `functions_count`, `exports_count`, `mocks_count`.
Replaces any currently loaded target; the old one is freed.

### 2. `probe_list_functions` — reconnaissance

```json
{ "name_contains": "verify", "sort_by": "size", "limit": 20 }
```

Filters: `sort_by` (`address|name|size|calls`), `name_contains`
(case-sensitive substring; unnamed internals never match), `min_size`,
`max_size`, `min_calls`, `max_calls`, `limit` (default 500).
Returns `{ total, returned, functions: [{address, name, size,
calls_count, convention, has_mock}] }`.
Use as the second call after `probe_open` to discover entry points.
Functions named `-` are internal (not exported); you can still inspect,
disassemble, and mock them by address.

### 3. `probe_inspect_function` — call graph + mock state

```json
{ "target": "login" }
```

Returns `address`, `name`, `size`, `convention` (`cdecl` or `stdcall N`
with N = popped arg bytes), `mock` (`default|custom|passthrough|null`), and
`calls: [{at, target, target_name}]` — every direct `CALL` in the body
with its resolved destination. **Read this before mocking**: it tells you
what to mock so that `probe_invoke` will actually hit your stub.

### 4. `probe_disasm` — instruction listing

```json
{ "target": "verify_license", "count": 40 }
```

Returns `instructions: [{address, bytes, text}]` in Intel syntax.
Use to recover XOR constants (`xor al, 0x3D`), stack-frame layout,
comparison literals, and `call` offsets. Combine with `probe_peek`
at a `mov reg, [0x1000XXXX]` operand to recover XOR-obfuscated globals.

### 5. `probe_peek` — read memory

```json
{ "address": "0x10001250", "size": 64 }
```

Returns `{hex, ascii, size}`. Use to read global buffers (`G_LICENSE_KEY`),
out-parameters after `probe_invoke --watch_diff`, or the mock stub bytes.
Max size 4096. Returns `isError: true` if the range isn't readable.

### 6. `probe_poke` — write memory

```json
{ "address": "0x01670000", "hex": "595B464B4C1D1B29" }
```
or
```json
{ "address": "0x01670000", "ascii": "hello" }
```

Provide exactly one of `hex` (even-length) or `ascii`. Returns `written`.
Use to seed a buffer before `probe_invoke`, or to patch code in place.

### 7. `probe_alloc` — allocate RWX scratch buffer

```json
{ "size": 64 }
```

Returns `{address, size}`. The sandbox remembers the size, so a later
`probe_invoke --watch_diff` knows exactly how many bytes to compare.
Max size 1 MiB. Pair with `probe_poke` to prepare arguments, or use the
address directly as a pointer argument.

### 8. `probe_set_mock` — install a stub

```json
{ "target": "check_hardware_id", "mode": "return", "return_value": 1 }
```
or
```json
{ "target": "check_hardware_id", "mode": "passthrough" }
```

- `mode: "return"` — stub returns `return_value` in `EAX`.
- `mode: "passthrough"` — removes the stub; real code runs.

Preserves the target's calling convention (`cdecl` vs `stdcall N`), so the
stub pops the correct number of stack bytes. Every stub has a hit counter,
visible in the caller's `runtime_hits`. Use this to bypass license checks,
simulate anti-debug detection, or force a specific branch.

### 9. `probe_reset_mock` — restore default stubs

```json
{ "target": "check_hardware_id" }
```
or
```json
{ "all": true }
```

`target` resets one function to the auto-generated default stub (`EAX=0`).
`all: true` resets every exported function. Cannot reset an internal
function via `all` (only exports are auto-mocked); use
`probe_set_mock mode="passthrough"` to un-mock internal functions.

### 10. `probe_invoke` — execute real function body

```json
{
  "target": "login",
  "args": [
    { "type": "string", "value": "alice" },
    { "type": "string", "value": "wrong" }
  ],
  "watch_diff": true
}
```

**Argument types:**
- `int` — 32-bit unsigned, `value` is a decimal or hex string
- `pointer` — 0x-prefixed hex, must be readable (warns if not)
- `string` — sandbox allocates a NUL-terminated ANSI buffer
- `wstring` — sandbox allocates a NUL-terminated UTF-16LE buffer

**`watch_diff: true`** snapshots every pointer/string arg before and after,
so you can see what the function wrote to out-parameters. The
`buffer_diffs[].changed` boolean plus `before_hex`/`after_hex` reveal
decrypted buffers, generated keys, and mutated state.

**Response:**
```json
{
  "status": "ok" | "crashed" | "abnormal",
  "eax": "0x00000001",
  "patched_call_sites": 3,
  "mock_targets": ["check_hardware_id", ...],
  "runtime_hits": [{ "address": "0x10001000", "name": "__loop_marker", "count": 7 }],
  "buffer_diffs": [{ "address": "...", "size": 16, "changed": true, ... }],
  "crash": { "code": "0xC0000005", "fault_instruction": "...", ... }
}
```

`runtime_hits[].count` is per-mock, not per-call-site: if `login` has 3
CALL sites to `is_admin` but only one executes, `count` is `1`.
`status: "abnormal"` means the thread exited without a catchable exception
(rare; treat as a hard bug in the target).

### 11. `probe_invoke_mock` — execute the stub directly

```json
{ "target": "check_password", "args": [...] }
```

Runs the stub, not the real body. Useful to verify a mock returns what
you set before relying on it inside a larger chain. Hit counter increments
same as in `probe_invoke`. Requires a mock to already be installed.

### 12. `probe_call_log` — experiment journal

```json
{}
```

Returns every `probe_invoke` / `probe_invoke_mock` since the last clear:
`index, function, address, eax, status, crash_code, patch_count, total_hits`.
This is your evidence trail — read it at the end of a multi-step experiment
to confirm the sequence of calls actually happened.

### 13. `probe_call_log_clear` — start a fresh experiment

```json
{}
```

Returns `{cleared: N}`. Call before a new hypothesis so the journal only
contains calls relevant to it.

## Standard workflows

### A. Bypass a password check

1. `probe_list_functions({ name_contains: "login" })` — find the caller.
2. `probe_inspect_function({ target: "login" })` — see that it CALLs
   `is_admin` and `check_password`.
3. `probe_set_mock({ target: "is_admin", mode: "return", return_value: 1 })`
4. `probe_invoke({ target: "login", args: [...] })`
5. Confirm `eax == "0x00000001"` and `runtime_hits` shows `is_admin x1`,
   no `check_password` hit (the `&&` branch was skipped).

### B. Recover a timing side-channel secret

If a function CALLs a marker stub inside a loop and returns early on
mismatch (e.g. `verify_serial_timing`), the hit count reveals how many
bytes matched before return:

1. `probe_invoke({ target: "verify_serial_timing", args: [{type:"string", value:"AAAAAAAA"}] })`
   → `runtime_hits: marker x1` → first char wrong.
2. Try `"PAAAAAAA"` → `x2` → first char is `P`.
3. Continue: `"PR0BE42"` → `x7`, `eax == 1` → full serial recovered
   without ever reading the disassembly.

This works because the default mock (`EAX=0`) still increments its counter.

### C. Extract an XOR-obfuscated global

1. `probe_disasm({ target: "verify_license", count: 30 })` — spot
   `movzx eax, byte ptr [0x1000XXXX]` followed by `xor al, 0x3D`.
2. `probe_peek({ address: "0x1000XXXX", size: 8 })` — read the masked bytes.
3. XOR each byte with `0x3D` offline; the result is the valid license key.
4. Verify: `probe_invoke({ target: "verify_license", args: [{type:"string", value:"pr0be!1"}] })`
   → `eax == 1`.

### D. Force a multi-level check to succeed

`validate_premium_user` requires `check_hardware_id`,
`check_network_token`, and `check_subscription_status` to all return 1,
short-circuiting on the first 0.

1. `probe_invoke({ target: "validate_premium_user" })` → `eax == 0`,
   `runtime_hits` shows only `check_hardware_id x1` (short-circuit).
2. Set all three mocks to `return 1`.
3. `probe_invoke({ target: "validate_premium_user" })` → `eax == 1`,
   all three mocks show `x1`.

### E. Confirm dependency invalidation

`check_obfuscated_password` CALLs `decrypt_inplace` on a local buffer,
then compares. Mocking `decrypt_inplace` breaks the check even with the
correct password:

1. `probe_invoke({ target: "check_obfuscated_password", args: [{type:"string", value:"probe42"}] })`
   → `eax == 1`.
2. `probe_set_mock({ target: "decrypt_inplace", mode: "return", return_value: 0 })`
3. `probe_invoke({ target: "check_obfuscated_password", args: [{type:"string", value:"probe42"}] })`
   → `eax == 0` — decrypt was suppressed, password never matched.

This proves the caller really depends on the callee, not on a hardcoded
copy of the decrypted value.

### F. Probe for memory-safety bugs

1. `probe_alloc({ size: 64 })` → e.g. `0x01670000`.
2. `probe_poke({ address: "0x01670000", hex: "41".repeat(64) })`
3. `probe_invoke({ target: "parse_user_bio", args: [{type:"pointer", value:"0x01670000"}, {type:"int", value:"40"}] })`
   → `status: "crashed"`, `crash.code == "0xC0000005"` — stack overflow
   confirmed. Function's local buffer is 32 bytes; 40 writes past it.
4. Try `size: 16` → `status: "ok"` — safe range.
5. Same technique works for out-of-bounds reads
   (`process_custom_packet` with a forged length byte) and NULL derefs.

### G. Switch target mid-session

```
probe_open({ path: "C:\\projects\\first.dll" })
probe_list_functions({ ... })
probe_open({ path: "C:\\projects\\second.dll" })   // frees first.dll
probe_list_functions({ ... })                       // now returns second's functions
```

The old image, its mocks, and every `probe_alloc`'d buffer are freed
automatically. There is no explicit "close" tool.

## Pitfalls

- **Never call another tool before `probe_open`.** The guard returns
  `isError: true` with `"no target loaded"`. Read it as a hint, not a
  fatal error.
- **Do not `probe_invoke` a function with unfilled `len` arguments.**
  If a function takes `(buf, len)` and you pass only `buf`, the sandbox
  reads garbage from the stack as `len`, walks past the allocation, and
  crashes with `0xC0000005`. Always provide all positional arguments.
- **`probe_open` replaces, it doesn't add.** A second `probe_open`
  discards all mocks and allocations from the first target. If you need
  two targets, open them in two separate sessions.
- **Do not assume `patched_call_sites == runtime_hits`.** Patch count is
  the number of CALL instructions *rewritten*. Hit count is the number
  that actually *executed* — `patched_call_sites: 7, runtime_hits: [{count: 1}]`
  means the function returned after the first call.
- **`fault_memory_access` is `null` for many AVs.** The current VEH reads
  `info[1]`; for read-only AVs this is often zero. Rely on `fault_instruction`
  plus the context of what the function was doing.
- **`probe_set_mock` does not affect `probe_invoke_mock` of the same target.**
  `set_mock(X)` then `invoke_mock(X)` runs the stub you just installed
  — this is correct and intentional.
- **`passthrough` removes the stub, but the target still has a mock state
  of `null`.** `probe_inspect_function` will show `mock: null` afterwards.
  To restore a default stub, use `probe_reset_mock`.
- **`watch_diff` only diffs pointer/string arguments.** Return-value structs
  and buffers reached via pointer arithmetic are not automatically tracked.
  Snapshot with `probe_peek` before and after if you need custom ranges.
- **The sandbox is not a security boundary.** It catches *execution*
  exceptions (VEH) but does not virtualize the filesystem, registry, or
  network. A target that calls `CreateFile` / `InternetOpen` will hit the
  real system. Only analyze binaries you trust.

## Reading the response

Every tool returns `content` (human-readable summary, always present) and
`structuredContent` (machine-readable, present on success). Parse
`structuredContent` — the summary is for humans and may be truncated.

- `isError: true` → domain error (missing function, bad argument, unreadable
  memory). Read `content[0].text` for the reason, adjust, retry.
- JSON-RPC `error` (top-level, not in `result`) → protocol error (bad
  arguments shape, unknown tool). This is a bug in your call, not the target.
- `status: "crashed"` is **not** `isError`. It's a successful invocation
  that happened to fault; read `crash.code`, `crash.fault_instruction`,
  `crash.fault_memory_access`.
