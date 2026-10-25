use std::collections::HashMap;
use std::path::PathBuf;

use crate::ffi;
use crate::parser::TargetRef;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CallingConvention {
    Cdecl,
    StdCall { arg_bytes: u16 },
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub address: u32,
    pub target: u32,
}

#[derive(Debug, Clone)]
pub struct FunctionMeta {
    pub address: u32,
    pub size: usize,
    pub calls: Vec<CallSite>,
    pub internal_calls: Vec<u32>,
    /// Vestigial field from the REPL version of probe. Kept for
    /// forward-compatibility with future import-aware tools.
    #[allow(dead_code)]
    pub import_calls: Vec<String>,
    pub convention: CallingConvention,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MockBehavior {
    Default,
    Custom(u32),
    Passthrough,
}

pub struct Mock {
    pub addr: u32,
    #[allow(dead_code)]
    pub size: usize,
    pub behavior: MockBehavior,
    pub counter_addr: u32,
}

impl Drop for Mock {
    fn drop(&mut self) {
        unsafe {
            ffi::VirtualFree(self.addr as *mut _, 0, ffi::MEM_RELEASE);
        }
    }
}

#[derive(Debug, Clone)]
pub struct CallLogEntry {
    pub index: u32,
    pub address: u32,
    pub name: String,
    pub eax: u32,
    pub crash: bool,
    pub crash_code: Option<u32>,
    pub patch_count: usize,
    pub total_hits: u32,
}

pub struct SandboxContext {
    pub file_path: PathBuf,
    pub image_base: u32,
    pub image_size: usize,
    pub entry_point: u32,
    /// `false` until `probe_open` (or the argv pre-load path) succeeds.
    /// Every other tool rejects with a clear tool-error while this is `false`.
    pub is_loaded: bool,
    pub functions: HashMap<u32, FunctionMeta>,
    pub mocks: HashMap<u32, Mock>,
    pub export_names: HashMap<u32, String>,
    pub allocated: HashMap<u32, usize>,
    pub call_log: Vec<CallLogEntry>,
}

impl SandboxContext {
    /// A context with no target loaded. The server starts in this state
    /// when invoked without `argv[1]`; the agent is expected to call
    /// `probe_open` before any other tool.
    pub fn empty() -> Self {
        Self {
            file_path: PathBuf::new(),
            image_base: 0,
            image_size: 0,
            entry_point: 0,
            is_loaded: false,
            functions: HashMap::new(),
            mocks: HashMap::new(),
            export_names: HashMap::new(),
            allocated: HashMap::new(),
            call_log: Vec::new(),
        }
    }

    pub fn name_of(&self, addr: u32) -> Option<&String> {
        self.export_names.get(&addr)
    }

    pub fn resolve_target(&self, t: &TargetRef) -> Option<u32> {
        match t {
            TargetRef::Addr(a) => Some(*a),
            TargetRef::Name(n) => self
                .export_names
                .iter()
                .find(|(_, v)| v.as_str() == n.as_str())
                .map(|(k, _)| *k),
        }
    }
}

/// `probe_open` replaces the active context with `*ctx = new_ctx`. The old
/// value is dropped here, which reclaims:
///
///   - every mock stub (each `Mock` has its own `Drop` doing `VirtualFree`),
///   - every buffer allocated via `probe_alloc`,
///   - the mapped PE image itself (`VirtualAlloc`'d at a fixed base).
///
/// If the context was created via `empty()` (image_base == 0, no
/// allocations), all three branches are no-ops.
///
/// Safety: at `Drop` time the executor is guaranteed idle — `probe_invoke`
/// is synchronous and joins its worker thread before returning, so no
/// thread is executing code inside the image being freed.
impl Drop for SandboxContext {
    fn drop(&mut self) {
        unsafe {
            // Free allocations made by probe_alloc.
            for (&addr, _size) in self.allocated.iter() {
                ffi::VirtualFree(addr as *mut _, 0, ffi::MEM_RELEASE);
            }
            // Free the mapped PE image.
            if self.image_base != 0 && self.image_size != 0 {
                ffi::VirtualFree(self.image_base as *mut _, 0, ffi::MEM_RELEASE);
            }
            // Mocks are freed by `Mock::drop` when `self.mocks` is dropped
            // immediately after this `Drop::drop` returns; nothing to do here.
        }
    }
}