use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::context::{FunctionMeta, Mock};
use crate::ffi;
use crate::parser::Argument;

#[repr(C)]
pub struct SandboxCtx {
    pub active: u32,
    pub saved_esp: u32,
    pub recovery_eip: u32,
    pub last_fault_code: u32,
    pub last_fault_instr: u32,
    pub last_fault_data: u32,
}

const FAULT_MARKER: u32 = 0xDEAD_FA11;
const DEFAULT_DIFF_WINDOW: u32 = 64;

thread_local! {
    static CURRENT_CTX: Cell<*mut SandboxCtx> = const { Cell::new(std::ptr::null_mut()) };
}

fn is_catchable(code: u32) -> bool {
    matches!(
        code,
        ffi::EXCEPTION_ACCESS_VIOLATION
            | ffi::EXCEPTION_ILLEGAL_INSTRUCTION
            | ffi::EXCEPTION_PRIV_INSTRUCTION
            | ffi::EXCEPTION_INT_DIVIDE_BY_ZERO
            | ffi::EXCEPTION_BREAKPOINT
            | ffi::EXCEPTION_SINGLE_STEP
            | ffi::EXCEPTION_IN_PAGE_ERROR
    )
}

unsafe extern "system" fn veh_handler(info: *mut ffi::ExceptionPointers) -> i32 {
    if info.is_null() { return ffi::EXCEPTION_CONTINUE_SEARCH; }
    let info = &*info;
    if info.exception.is_null() || info.context.is_null() {
        return ffi::EXCEPTION_CONTINUE_SEARCH;
    }
    let ctx_ptr = CURRENT_CTX.with(|c| c.get());
    if ctx_ptr.is_null() { return ffi::EXCEPTION_CONTINUE_SEARCH; }
    let sbx = &mut *ctx_ptr;
    if sbx.active != 1 { return ffi::EXCEPTION_CONTINUE_SEARCH; }

    let rec = &*info.exception;
    if !is_catchable(rec.code) { return ffi::EXCEPTION_CONTINUE_SEARCH; }

    let fault_data = if rec.code == ffi::EXCEPTION_ACCESS_VIOLATION && rec.num_params >= 2 {
        rec.info[1]
    } else {
        0
    };

    sbx.last_fault_code = rec.code;
    sbx.last_fault_instr = rec.address as u32;
    sbx.last_fault_data = fault_data;
    sbx.active = 0;

    let ctx = &mut *info.context;
    ctx.eip = sbx.recovery_eip;
    ctx.esp = sbx.saved_esp;
    ctx.eax = FAULT_MARKER;

    ffi::EXCEPTION_CONTINUE_EXECUTION
}

unsafe extern "system" fn uef_handler(info: *mut ffi::ExceptionPointers) -> i32 {
    let ctx_ptr = CURRENT_CTX.with(|c| c.get());
    let in_sandbox = !ctx_ptr.is_null();
    if in_sandbox && !info.is_null() {
        let info_ref = &*info;
        if !info_ref.exception.is_null() {
            let rec = &*info_ref.exception;
            eprintln!(
                "[UEF] sandbox exception deferred to WoW64: code=0x{:08X} eip=0x{:08X}",
                rec.code, rec.address as u32
            );
        }
    }
    ffi::EXCEPTION_CONTINUE_SEARCH
}

pub fn install_veh() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) { return; }
    unsafe {
        let vh = ffi::AddVectoredExceptionHandler(1, veh_handler);
        if vh.is_null() {
            eprintln!("[!] AddVectoredExceptionHandler failed, err={}", ffi::GetLastError());
        }
        let _ = ffi::SetUnhandledExceptionFilter(uef_handler);
    }
}

#[cfg(target_arch = "x86")]
std::arch::global_asm!(
    r#"
    .global _probe_call_with_stack
_probe_call_with_stack:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov ebx, esp
    mov edx, [ebp+20]
    lea eax, [probe_recovery_stub]
    mov [edx + 4], ebx
    mov [edx + 8], eax
    mov dword ptr [edx + 0], 1

    mov esi, [ebp+12]
    mov edi, [ebp+16]

1:
    test edi, edi
    jz 2f
    dec edi
    push dword ptr [esi + edi*4]
    jmp 1b
2:
    call dword ptr [ebp+8]

    mov edx, [ebp+20]
    mov dword ptr [edx + 0], 0

    mov esp, ebx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

probe_recovery_stub:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
"#
);

#[cfg(target_arch = "x86")]
extern "C" {
    fn probe_call_with_stack(
        func: u32,
        args_ptr: *const u32,
        arg_count: u32,
        sandbox_ctx: *mut SandboxCtx,
    ) -> u32;
}

#[repr(C)]
struct ThreadParams {
    func: u32,
    args_ptr: *const u32,
    arg_count: u32,
    sandbox_ctx: *mut SandboxCtx,
    result_eax: u32,
    completed: u32,
}

unsafe extern "system" fn thread_trampoline(param: *mut c_void) -> u32 {
    let params = &mut *(param as *mut ThreadParams);
    let prev = CURRENT_CTX.with(|c| {
        let old = c.get();
        c.set(params.sandbox_ctx);
        old
    });
    let raw_eax = probe_call_with_stack(
        params.func,
        params.args_ptr,
        params.arg_count,
        params.sandbox_ctx,
    );
    CURRENT_CTX.with(|c| c.set(prev));
    params.result_eax = raw_eax;
    params.completed = 1;
    0
}

struct Patch {
    address: u32,
    original: [u8; 5],
}

#[derive(Debug, Clone)]
pub struct BufferDiff {
    pub address: u32,
    pub size: usize,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
}

impl BufferDiff {
    /// Vestigial: the REPL's `print_buffer_diffs` used this. The MCP
    /// handler builds its own summary from `changed()`.
    #[allow(dead_code)]
    pub fn readable(&self) -> bool { self.before.is_some() && self.after.is_some() }
    pub fn changed(&self) -> bool {
        match (&self.before, &self.after) { (Some(a), Some(b)) => a != b, _ => false }
    }
    /// Vestigial: the REPL printed "N bytes changed" — the MCP
    /// `buffer_diffs[].changed` boolean is enough for the LLM.
    #[allow(dead_code)]
    pub fn changed_count(&self) -> usize {
        match (&self.before, &self.after) {
            (Some(a), Some(b)) => a.iter().zip(b.iter()).filter(|(x, y)| x != y).count(),
            _ => 0,
        }
    }
}

pub struct InvokeResult {
    pub eax: u32,
    pub crash: bool,
    pub fault_code: Option<u32>,
    pub fault_instr: Option<u32>,
    pub fault_data: Option<u32>,
    pub abnormal: bool,
    pub patch_count: usize,
    pub patched_targets: Vec<u32>,
    pub runtime_hits: Vec<(u32, u32)>,
    pub buffer_diffs: Vec<BufferDiff>,
}

pub unsafe fn invoke(
    function: &FunctionMeta,
    args: &[Argument],
    mocks: &HashMap<u32, Mock>,
    diff_window: Option<u32>,
    allocated: &HashMap<u32, usize>,
) -> Result<InvokeResult, String> {
    install_veh();

    let window = diff_window.unwrap_or(DEFAULT_DIFF_WINDOW) as usize;
    let diff = diff_window.is_some();

    for mock in mocks.values() {
        std::ptr::write(mock.counter_addr as *mut u32, 0);
    }

    let mut patches: Vec<Patch> = Vec::new();
    let mut patched_targets: Vec<u32> = Vec::new();
    for call in &function.calls {
        if let Some(mock) = mocks.get(&call.target) {
            let p = call.address as *mut u8;
            let mut orig = [0u8; 5];
            std::ptr::copy_nonoverlapping(p, orig.as_mut_ptr(), 5);
            let rel = (mock.addr as i64 - (call.address as i64 + 5)) as i32;
            let mut newbytes = [0u8; 5];
            newbytes[0] = 0xE8;
            newbytes[1..5].copy_from_slice(&rel.to_le_bytes());
            std::ptr::copy_nonoverlapping(newbytes.as_ptr(), p, 5);
            patches.push(Patch { address: call.address, original: orig });
            patched_targets.push(call.target);
        }
    }

    let mut heap_ptrs: Vec<*mut u8> = Vec::new();
    let mut arg_vals: Vec<u32> = Vec::with_capacity(args.len());
    let mut watch: Vec<(u32, usize)> = Vec::new();

    for a in args {
        match a {
            Argument::Integer(v) => arg_vals.push(*v),
            Argument::Pointer(p) => {
                arg_vals.push(*p);
                if diff && *p != 0 {
                    let size = allocated.get(p).copied().unwrap_or(window);
                    watch.push((*p, size));
                }
            }
            Argument::StringLiteral(s) => {
                let mut bytes = s.as_bytes().to_vec();
                bytes.push(0);
                let p = ffi::alloc_rwx(bytes.len())
                    .ok_or_else(|| "string alloc failed".to_string())?;
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
                heap_ptrs.push(p);
                arg_vals.push(p as u32);
                if diff { watch.push((p as u32, bytes.len())); }
            }
            Argument::WideString(s) => {
                let mut bytes: Vec<u8> = Vec::new();
                for unit in s.encode_utf16() {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                bytes.extend_from_slice(&[0, 0]);
                let p = ffi::alloc_rwx(bytes.len())
                    .ok_or_else(|| "wide string alloc failed".to_string())?;
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
                heap_ptrs.push(p);
                arg_vals.push(p as u32);
                if diff { watch.push((p as u32, bytes.len())); }
            }
        }
    }

    let mut before_snaps: Vec<(u32, usize, Option<Vec<u8>>)> = Vec::new();
    if diff {
        for (addr, size) in &watch {
            let snap = ffi::read_self(*addr, *size);
            before_snaps.push((*addr, *size, snap));
        }
    }

    let mut sbx = SandboxCtx {
        active: 0, saved_esp: 0, recovery_eip: 0,
        last_fault_code: 0, last_fault_instr: 0, last_fault_data: 0,
    };

    let params = Box::into_raw(Box::new(ThreadParams {
        func: function.address,
        args_ptr: arg_vals.as_ptr(),
        arg_count: arg_vals.len() as u32,
        sandbox_ctx: &mut sbx as *mut _,
        result_eax: 0,
        completed: 0,
    }));

    let mut tid: u32 = 0;
    let thread = ffi::CreateThread(
        std::ptr::null_mut(), 0, Some(thread_trampoline),
        params as *mut c_void, 0, &mut tid,
    );

    if thread.is_null() {
        let err = ffi::GetLastError();
        let _ = Box::from_raw(params);
        for p in &patches {
            std::ptr::copy_nonoverlapping(p.original.as_ptr(), p.address as *mut u8, 5);
        }
        for p in heap_ptrs { ffi::VirtualFree(p as *mut _, 0, ffi::MEM_RELEASE); }
        return Err(format!("CreateThread failed err={}", err));
    }

    ffi::WaitForSingleObject(thread, ffi::INFINITE);
    ffi::CloseHandle(thread);

    let params = Box::from_raw(params);
    let raw_eax = params.result_eax;
    let completed = params.completed == 1;

    let crash = sbx.last_fault_code != 0;
    let abnormal = !crash && !completed;
    let eax = if crash { FAULT_MARKER } else { raw_eax };

    let mut runtime_hits: Vec<(u32, u32)> = Vec::new();
    for (target, mock) in mocks {
        let count = std::ptr::read(mock.counter_addr as *const u32);
        if count > 0 { runtime_hits.push((*target, count)); }
    }
    runtime_hits.sort_by_key(|(a, _)| *a);

    let mut buffer_diffs: Vec<BufferDiff> = Vec::new();
    if diff {
        for (addr, size, before) in before_snaps {
            let after = ffi::read_self(addr, size);
            buffer_diffs.push(BufferDiff { address: addr, size, before, after });
        }
    }

    for p in &patches {
        std::ptr::copy_nonoverlapping(p.original.as_ptr(), p.address as *mut u8, 5);
    }
    for p in heap_ptrs { ffi::VirtualFree(p as *mut _, 0, ffi::MEM_RELEASE); }

    Ok(InvokeResult {
        eax, crash,
        fault_code: if crash { Some(sbx.last_fault_code) } else { None },
        fault_instr: if crash { Some(sbx.last_fault_instr) } else { None },
        fault_data: if crash && sbx.last_fault_data != 0 { Some(sbx.last_fault_data) } else { None },
        abnormal,
        patch_count: patches.len(),
        patched_targets,
        runtime_hits,
        buffer_diffs,
    })
}