use std::collections::{HashMap, HashSet};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::context::{CallSite, CallingConvention, FunctionMeta};

pub fn discover_functions(
    text_start: u32,
    text_end: u32,
    seeds: Vec<u32>,
) -> HashMap<u32, FunctionMeta> {
    let mut functions: HashMap<u32, FunctionMeta> = HashMap::new();
    let mut pending: Vec<u32> = seeds.clone();
    let mut seen: HashSet<u32> = HashSet::new();
    let mut queued: HashSet<u32> = seeds.into_iter().collect();

    while let Some(addr) = pending.pop() {
        queued.remove(&addr);

        if !seen.insert(addr) {
            continue;
        }
        if addr < text_start || addr >= text_end {
            continue;
        }
        if functions.len() >= 5000 {
            break;
        }

        let meta = analyze_function_at(addr, text_start, text_end);
        for target in &meta.internal_calls {
            if !seen.contains(target) && queued.insert(*target) {
                pending.push(*target);
            }
        }
        functions.insert(addr, meta);
    }

    functions
}

fn analyze_function_at(start: u32, text_start: u32, text_end: u32) -> FunctionMeta {
    let max_len = ((text_end - start) as usize).min(8192);
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(start as *const u8, max_len) };

    let mut decoder = Decoder::with_ip(32, bytes, start as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();

    let mut calls: Vec<CallSite> = Vec::new();
    let mut internal_calls: Vec<u32> = Vec::new();
    let import_calls: Vec<String> = Vec::new();
    let mut end_offset: usize = max_len;
    let mut convention = CallingConvention::Cdecl;

    while decoder.can_decode() {
        let pos_before = decoder.position();
        decoder.decode_out(&mut instr);

        if pos_before == 0
            && instr.mnemonic() == Mnemonic::Jmp
            && instr.op0_kind() == OpKind::Memory
            && instr.memory_base() == Register::None
            && instr.memory_index() == Register::None
        {
            end_offset = decoder.position();
            break;
        }

        let ip = instr.ip() as u32;

        if instr.is_call_near() && instr.op0_kind() == OpKind::NearBranch32 {
            let target = instr.near_branch32();
            calls.push(CallSite {
                address: ip,
                target,
            });
            if target >= text_start && target < text_end {
                internal_calls.push(target);
            }
        }

        if instr.mnemonic() == Mnemonic::Ret {
            if instr.op0_kind() == OpKind::Immediate16 {
                convention = CallingConvention::StdCall {
                    arg_bytes: instr.immediate16(),
                };
            }
            let next_pos = decoder.position();
            let is_end = if next_pos + 4 > bytes.len() {
                true
            } else {
                let tail = &bytes[next_pos..next_pos + 4];
                let is_padding = tail.iter().all(|&b| b == 0xCC || b == 0x00 || b == 0x90);
                let is_prologue = tail[0] == 0x55;
                is_padding || is_prologue
            };
            if is_end {
                end_offset = next_pos;
                break;
            }
        }

        if instr.mnemonic() == Mnemonic::Int3
            || instr.mnemonic() == Mnemonic::Iret
            || instr.mnemonic() == Mnemonic::Hlt
        {
            end_offset = pos_before;
            break;
        }
    }

    FunctionMeta {
        address: start,
        size: end_offset,
        calls,
        internal_calls,
        import_calls,
        convention,
    }
}