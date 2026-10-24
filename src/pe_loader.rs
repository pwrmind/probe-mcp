use std::collections::HashMap;
use std::fs;
use std::path::Path;

use goblin::pe::PE;

use crate::context::{FunctionMeta, MockBehavior, SandboxContext};
use crate::ffi;
use crate::function_discovery::discover_functions;
use crate::mock_engine;

pub fn load_and_analyze(path: &Path) -> Result<SandboxContext, String> {
    let file_data = fs::read(path).map_err(|e| format!("read: {}", e))?;
    let pe = PE::parse(&file_data).map_err(|e| format!("PE parse: {}", e))?;

    if pe.header.coff_header.machine != 0x14c {
        return Err(format!(
            "not x86 PE (machine=0x{:04X}, want 0x014c)",
            pe.header.coff_header.machine
        ));
    }

    let image_base = pe.image_base as u32;
    let image_size = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.size_of_image as usize)
        .ok_or("missing optional header")?;

    let img_ptr = unsafe {
        ffi::alloc_at(image_base as usize, image_size, ffi::PAGE_EXECUTE_READWRITE)
            .ok_or_else(|| format!("VirtualAlloc at 0x{:08X} failed", image_base))?
    };

    let header_size = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.size_of_headers as usize)
        .unwrap_or(0x400);
    unsafe {
        let copy_len = header_size.min(file_data.len());
        std::ptr::copy_nonoverlapping(file_data.as_ptr(), img_ptr, copy_len);
    }

    for section in &pe.sections {
        let va = section.virtual_address as usize;
        let vsize = section.virtual_size as usize;
        let raw_size = section.size_of_raw_data as usize;
        let raw_off = section.pointer_to_raw_data as usize;

        if raw_size == 0 || raw_off == 0 || raw_off + raw_size > file_data.len() {
            continue;
        }
        let copy_len = raw_size.min(vsize.max(raw_size));
        unsafe {
            let dst = img_ptr.add(va);
            std::ptr::copy_nonoverlapping(
                file_data[raw_off..raw_off + copy_len].as_ptr(),
                dst,
                copy_len,
            );
        }
    }

    resolve_imports(&pe, img_ptr)?;

    let text_section = pe
        .sections
        .iter()
        .find(|s| s.name.starts_with(b".text"))
        .ok_or("no .text section")?;
    let text_va = text_section.virtual_address as usize;
    let text_size = {
        let vs = text_section.virtual_size as usize;
        let rs = text_section.size_of_raw_data as usize;
        let raw = if vs > 0 { vs } else { rs };
        raw.min(image_size.saturating_sub(text_va))
    };
    let text_start = image_base.wrapping_add(text_va as u32);
    let text_end = text_start.wrapping_add(text_size as u32);

    let entry = image_base.wrapping_add(pe.entry as u32);
    let mut seeds: Vec<u32> = vec![entry];
    let mut export_names: HashMap<u32, String> = HashMap::new();
    for exp in &pe.exports {
        let addr = image_base.wrapping_add(exp.rva as u32);
        if addr < text_start || addr >= text_end {
            continue;
        }
        seeds.push(addr);
        if let Some(name) = exp.name.as_ref() {
            export_names.insert(addr, name.to_string());
        }
    }
    seeds.sort_unstable();
    seeds.dedup();

    let functions: HashMap<u32, FunctionMeta> =
        discover_functions(text_start, text_end, seeds);

    let mut mocks = HashMap::new();
    for addr in export_names.keys() {
        if let Some(meta) = functions.get(addr) {
            if let Ok(Some(mock)) =
                mock_engine::create_mock(MockBehavior::Default, meta.convention)
            {
                mocks.insert(*addr, mock);
            }
        }
    }

    Ok(SandboxContext {
        file_path: path.to_path_buf(),
        image_base,
        image_size,
        entry_point: entry,
        is_loaded: true,
        functions,
        mocks,
        export_names,
        allocated: HashMap::new(),
        call_log: Vec::new(),
    })
}

fn read_cstr_img(img: *mut u8, rva: usize) -> Result<Vec<u8>, String> {
    unsafe {
        let mut result = Vec::with_capacity(64);
        let mut p = img.add(rva);
        for _ in 0..1024 {
            let b = *p;
            if b == 0 {
                result.push(0);
                return Ok(result);
            }
            result.push(b);
            p = p.add(1);
        }
        Err(format!("unterminated string at RVA 0x{:X}", rva))
    }
}

fn resolve_imports(pe: &PE, img: *mut u8) -> Result<(), String> {
    let opt = pe.header.optional_header.as_ref().ok_or("no optional header")?;
    let imp_dir = opt
        .data_directories
        .get_import_table()
        .ok_or("no import table directory")?;
    let imp_rva = imp_dir.virtual_address as usize;
    let imp_size = imp_dir.size as usize;

    if imp_rva == 0 || imp_size == 0 {
        eprintln!("[+] imports: none");
        return Ok(());
    }

    let mut resolved_count = 0usize;
    let mut failed_count = 0usize;

    let max_desc = 256.min(imp_size / 20);

    for i in 0..max_desc {
        let desc_off = imp_rva + i * 20;
        let mut desc = [0u8; 20];
        unsafe {
            std::ptr::copy_nonoverlapping(img.add(desc_off), desc.as_mut_ptr(), 20);
        }

        let original_first_thunk =
            u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]) as usize;
        let name_rva =
            u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]) as usize;
        let first_thunk =
            u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]) as usize;

        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if name_rva == 0 || first_thunk == 0 {
            continue;
        }

        let dll_cstr = read_cstr_img(img, name_rva)?;
        let dll_display = String::from_utf8_lossy(&dll_cstr[..dll_cstr.len() - 1]).to_string();
        let h = unsafe { ffi::LoadLibraryA(dll_cstr.as_ptr()) };
        if h.is_null() {
            eprintln!("[!] LoadLibraryA({}) failed", dll_display);
            failed_count += 1;
            continue;
        }

        let ilt_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let mut j = 0usize;
        loop {
            let ilt_entry_rva = ilt_rva + j * 4;
            let iat_slot_rva = first_thunk + j * 4;

            let entry = unsafe {
                std::ptr::read_unaligned(img.add(ilt_entry_rva) as *const u32)
            };
            if entry == 0 {
                break;
            }

            let resolved: u32 = if entry & 0x8000_0000 != 0 {
                let ordinal = (entry & 0xFFFF) as u16;
                let p = unsafe {
                    ffi::GetProcAddress(h, ordinal as usize as *const u8)
                };
                if p.is_null() {
                    eprintln!("[!] ordinal {} in {} not resolved", ordinal, dll_display);
                    failed_count += 1;
                    j += 1;
                    continue;
                }
                p as u32
            } else {
                let name_at = entry as usize + 2;
                let fn_cstr = read_cstr_img(img, name_at)?;
                let fn_display =
                    String::from_utf8_lossy(&fn_cstr[..fn_cstr.len() - 1]).to_string();
                let p = unsafe { ffi::GetProcAddress(h, fn_cstr.as_ptr()) };
                if p.is_null() {
                    eprintln!("[!] {}.{} not resolved", dll_display, fn_display);
                    failed_count += 1;
                    j += 1;
                    continue;
                }
                p as u32
            };

            unsafe {
                std::ptr::write_unaligned(img.add(iat_slot_rva) as *mut u32, resolved);
            }
            resolved_count += 1;
            j += 1;
            if j > 4096 {
                return Err("too many imports in one descriptor".into());
            }
        }
    }

    eprintln!(
        "[+] imports: resolved={}, failed={}",
        resolved_count, failed_count
    );
    Ok(())
}