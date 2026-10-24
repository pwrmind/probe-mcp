#[cfg(not(target_arch = "x86"))]
compile_error!("probe must be built for i686-pc-windows-msvc (32-bit)");

mod context;
mod executor;
mod ffi;
mod function_discovery;
mod mcp;
mod mock_engine;
mod parser;
mod pe_loader;

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("[!] Usage: probe.exe <target.exe>");
        eprintln!("    probe-mcp reads JSON-RPC from stdin and writes to stdout.");
        std::process::exit(2);
    }

    let path = PathBuf::from(&args[1]);
    eprintln!("[*] Loading PE image: {}", path.display());

    let ctx = match pe_loader::load_and_analyze(&path) {
        Ok(ctx) => {
            eprintln!(
                "[+] Mapped {} ({} bytes) at 0x{:08X}; {} functions; entry = 0x{:08X}",
                ctx.file_path.display(),
                ctx.image_size,
                ctx.image_base,
                ctx.functions.len(),
                ctx.entry_point,
            );
            eprintln!(
                "[+] Default mocks generated for {} functions (EAX=0)",
                ctx.mocks.len()
            );
            ctx
        }
        Err(e) => {
            eprintln!("[-] Fatal: {}", e);
            std::process::exit(1);
        }
    };

    mcp::server::run(ctx)?;
    Ok(())
}