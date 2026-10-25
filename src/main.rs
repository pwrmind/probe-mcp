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

use context::SandboxContext;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Start-of-day behaviour (mirrors https://github.com/morluto/rea):
    //
    //   probe-mcp               → server starts with NO target loaded.
    //                             The agent calls `probe_open` with a path.
    //   probe-mcp <path>        → optional pre-load, for debugging and
    //                             backward compatibility with the old
    //                             one-shot mode.
    //
    // The MCP session outlives any particular target: `probe_open` can be
    // called repeatedly to switch binaries without restarting the server.

    let mut ctx: SandboxContext = if let Some(path) = args.get(1) {
        let p = PathBuf::from(path);
        eprintln!("[*] Pre-loading PE image from argv: {}", p.display());

        match pe_loader::load_and_analyze(&p) {
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
        }
    } else {
        eprintln!(
            "[*] No target pre-loaded. Call probe_open to load a PE32/x86 binary."
        );
        SandboxContext::empty()
    };

    // Silence the "unused mut" warning when nothing preloads.
    let _ = &mut ctx;

    mcp::server::run(ctx)?;
    Ok(())
}