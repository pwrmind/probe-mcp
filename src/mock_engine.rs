use crate::context::{CallingConvention, Mock, MockBehavior};
use crate::ffi;

const COUNTER_OFFSET: usize = 16;
const MOCK_SIZE: usize = COUNTER_OFFSET + 4;

fn generate(
    behavior: MockBehavior,
    conv: CallingConvention,
    counter_addr: u32,
) -> [u8; MOCK_SIZE] {
    let val = match behavior {
        MockBehavior::Passthrough => 0,
        MockBehavior::Default => 0,
        MockBehavior::Custom(v) => v,
    };

    let mut buf = [0u8; MOCK_SIZE];
    let mut off = 0usize;

    // inc dword ptr [counter_addr]
    buf[off] = 0xFF;
    off += 1;
    buf[off] = 0x05;
    off += 1;
    buf[off..off + 4].copy_from_slice(&counter_addr.to_le_bytes());
    off += 4;

    // mov eax, retval
    buf[off] = 0xB8;
    off += 1;
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
    off += 4;

    // ret / ret imm16
    match conv {
        CallingConvention::Cdecl => {
            buf[off] = 0xC3;
        }
        CallingConvention::StdCall { arg_bytes } => {
            if arg_bytes == 0 {
                buf[off] = 0xC3;
            } else {
                buf[off] = 0xC2;
                buf[off + 1..off + 3].copy_from_slice(&arg_bytes.to_le_bytes());
            }
        }
    }

    buf
}

pub fn create_mock(
    behavior: MockBehavior,
    conv: CallingConvention,
) -> Result<Option<Mock>, String> {
    if matches!(behavior, MockBehavior::Passthrough) {
        return Ok(None);
    }

    unsafe {
        let p = ffi::alloc_rwx(MOCK_SIZE)
            .ok_or_else(|| "VirtualAlloc for mock failed".to_string())?;
        let addr = p as u32;
        let counter_addr = addr + COUNTER_OFFSET as u32;

        let bytes = generate(behavior, conv, counter_addr);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, MOCK_SIZE);

        Ok(Some(Mock {
            addr,
            size: MOCK_SIZE,
            behavior,
            counter_addr,
        }))
    }
}