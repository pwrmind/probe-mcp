#![allow(non_snake_case)]

use std::ffi::c_void;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const EXCEPTION_IN_PAGE_ERROR: u32 = 0xC000_0006;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const EXCEPTION_PRIV_INSTRUCTION: u32 = 0xC000_0096;
pub const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
pub const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
pub const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;

pub const EXCEPTION_CONTINUE_SEARCH: i32 = -1;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = 0;

pub const INFINITE: u32 = 0xFFFF_FFFF;

#[repr(C)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub record: *mut ExceptionRecord,
    pub address: *mut c_void,
    pub num_params: u32,
    pub info: [u32; 15],
}

#[repr(C)]
pub struct ExceptionPointers {
    pub exception: *mut ExceptionRecord,
    pub context: *mut ContextRecord,
}

#[repr(C, align(16))]
pub struct ContextRecord {
    pub context_flags: u32,
    pub dr0: u32,
    pub dr1: u32,
    pub dr2: u32,
    pub dr3: u32,
    pub dr6: u32,
    pub dr7: u32,
    pub float_save: [u8; 112],
    pub seg_gs: u32,
    pub seg_fs: u32,
    pub seg_es: u32,
    pub seg_ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub ebp: u32,
    pub eip: u32,
    pub seg_cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub seg_ss: u32,
    pub extended: [u8; 512],
}

#[link(name = "kernel32")]
extern "system" {
    pub fn VirtualAlloc(
        addr: *const c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut c_void;

    pub fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;

    pub fn LoadLibraryA(name: *const u8) -> *mut c_void;
    pub fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;

    pub fn GetCurrentProcess() -> *mut c_void;

    pub fn ReadProcessMemory(
        process: *mut c_void,
        base_address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        bytes_read: *mut usize,
    ) -> i32;

    pub fn WriteProcessMemory(
        process: *mut c_void,
        base_address: *mut c_void,
        buffer: *const c_void,
        size: usize,
        bytes_written: *mut usize,
    ) -> i32;

    pub fn AddVectoredExceptionHandler(
        first: u32,
        handler: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
    ) -> *mut c_void;

    pub fn SetUnhandledExceptionFilter(
        filter: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
    ) -> *mut c_void;

    pub fn GetLastError() -> u32;

    pub fn CreateThread(
        attrs: *mut c_void,
        stack_size: usize,
        start: Option<unsafe extern "system" fn(*mut c_void) -> u32>,
        param: *mut c_void,
        flags: u32,
        thread_id: *mut u32,
    ) -> *mut c_void;

    pub fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32;
    pub fn CloseHandle(handle: *mut c_void) -> i32;
}

pub unsafe fn alloc_rwx(size: usize) -> Option<*mut u8> {
    let p = VirtualAlloc(
        std::ptr::null(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if p.is_null() { None } else { Some(p as *mut u8) }
}

pub unsafe fn alloc_at(addr: usize, size: usize, protect: u32) -> Option<*mut u8> {
    let p = VirtualAlloc(
        addr as *const c_void,
        size,
        MEM_COMMIT | MEM_RESERVE,
        protect,
    );
    if p.is_null() { None } else { Some(p as *mut u8) }
}

pub unsafe fn read_self(addr: u32, size: usize) -> Option<Vec<u8>> {
    if addr == 0 || size == 0 { return None; }
    let mut buf = vec![0u8; size];
    let mut read = 0usize;
    let ok = ReadProcessMemory(
        GetCurrentProcess(),
        addr as *const _,
        buf.as_mut_ptr() as *mut _,
        size,
        &mut read,
    );
    if ok == 0 || read == 0 { return None; }
    buf.truncate(read);
    Some(buf)
}

pub unsafe fn write_self(addr: u32, data: &[u8]) -> Option<usize> {
    if addr == 0 || data.is_empty() { return None; }
    let mut written = 0usize;
    let ok = WriteProcessMemory(
        GetCurrentProcess(),
        addr as *mut _,
        data.as_ptr() as *const _,
        data.len(),
        &mut written,
    );
    if ok == 0 || written == 0 { return None; }
    Some(written)
}