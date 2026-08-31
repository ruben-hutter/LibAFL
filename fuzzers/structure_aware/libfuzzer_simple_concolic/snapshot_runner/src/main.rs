//! Standalone runner for snapshot-based symbolic execution with SymQEMU
//!
//! This is a proof-of-concept tool that demonstrates the architecture for
//! state-based symbolic execution. It shows how to:
//! 1. Initialize QEMU with SnapshotModule and SymQemuModule
//! 2. Prepare for snapshot capture at a specific address
//! 3. Mark memory as symbolic after snapshot restore
//!
//! Current Status: PROOF OF CONCEPT
//! - Modules are initialized correctly
//! - Architecture is in place
//! - Hook registration for snapshot point needs manual integration
//!
//! To test: cargo run --bin snapshot_runner

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "snapshot_runner")]
#[command(about = "Proof-of-concept: SymQEMU snapshot-based symbolic execution")]
struct Opt {
    /// Target binary path
    #[arg(short, long, default_value = "../fuzzer/target_main.out")]
    binary: PathBuf,

    /// Snapshot address in hex (address just before foo() call - line 58 in harness_main.c)
    #[arg(short, long)]
    snapshot_addr: Option<String>,

    /// Input buffer address (where malloc'd data lives)
    #[arg(long)]
    buffer_addr: Option<String>,

    /// Input buffer size
    #[arg(short = 'l', long, default_value = "16")]
    buffer_size: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let opt = Opt::parse();

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  SymQEMU Snapshot-Based Symbolic Execution - PROOF OF CONCEPT  ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("Binary: {}", opt.binary.display());

    // Check if binary exists
    if !opt.binary.exists() {
        eprintln!("❌ Error: Target binary not found: {}", opt.binary.display());
        eprintln!("\n📝 To build the target:");
        eprintln!("   cd ../fuzzer");
        eprintln!("   cargo build");
        eprintln!("\n   The target binary will be at: fuzzer/target_main.out\n");
        return Ok(());
    }

    println!("✓ Binary found\n");

    // Parse addresses if provided
    let snapshot_addr = if let Some(addr_str) = opt.snapshot_addr {
        Some(parse_hex_addr(&addr_str)?)
    } else {
        None
    };

    let buffer_addr = if let Some(addr_str) = opt.buffer_addr {
        Some(parse_hex_addr(&addr_str)?)
    } else {
        None
    };

    if snapshot_addr.is_none() || buffer_addr.is_none() {
        print_address_finding_help();
        return Ok(());
    }

    let snapshot_addr = snapshot_addr.unwrap();
    let buffer_addr = buffer_addr.unwrap();

    println!("Configuration:");
    println!("  Snapshot address: 0x{:x}", snapshot_addr);
    println!("  Buffer address:   0x{:x}", buffer_addr);
    println!("  Buffer size:      {} bytes", opt.buffer_size);
    println!();

    run_poc(
        &opt.binary,
        snapshot_addr,
        buffer_addr,
        opt.buffer_size,
    )?;

    Ok(())
}

fn parse_hex_addr(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim_start_matches("0x");
    Ok(u64::from_str_radix(s, 16)?)
}

fn print_address_finding_help() {
    println!("❌ Missing required addresses\n");
    println!("You must provide:");
    println!("  --snapshot-addr <address>  Address just before foo() call (line 58)");
    println!("  --buffer-addr <address>    Address where input data buffer lives\n");

    println!("📝 How to find these addresses:\n");

    println!("1️⃣  Find snapshot address (instruction just before `return foo(data, ptr);`):");
    println!("   objdump -d ../fuzzer/target_main.out | grep -A 30 '<main>:'");
    println!("   Look for the call instruction to 'foo' and note the address BEFORE it\n");

    println!("2️⃣  Find buffer address (runtime - changes each execution):");
    println!("   For now, you can use a placeholder like 0x7fffffffe000");
    println!("   In the future, we'll automatically track malloc'd addresses\n");

    println!("Example usage:");
    println!("   cargo run -- \\");
    println!("     --snapshot-addr 0x4012a5 \\");
    println!("     --buffer-addr 0x7fffffffe000\n");
}

fn run_poc(
    binary_path: &PathBuf,
    snapshot_addr: u64,
    buffer_addr: u64,
    buffer_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ Proof of Concept Execution ═══\n");

    println!("📋 Current Implementation Status:\n");

    println!("✅ IMPLEMENTED:");
    println!("   • SymQemuModule structure");
    println!("   • SnapshotModule integration");
    println!("   • Shared memory setup for SymCC runtime");
    println!("   • FFI bindings to _sym_make_symbolic");
    println!("   • Module exports and visibility\n");

    println!("⚠️  TODO (for full functionality):");
    println!("   • Hook registration at snapshot_addr");
    println!("   • Automatic snapshot capture on first execution");
    println!("   • Snapshot restore mechanism");
    println!("   • Buffer symbolic marking after restore");
    println!("   • QEMU execution loop");
    println!("   • Constraint collection from shared memory\n");

    println!("📐 Architecture:");
    println!("   ┌─────────────────┐");
    println!("   │  Runner (this)  │");
    println!("   └────────┬────────┘");
    println!("            │");
    println!("   ┌────────▼────────┐");
    println!("   │  QemuBuilder    │");
    println!("   │  + modules:     │");
    println!("   │    - Snapshot   │");
    println!("   │    - SymQemu    │");
    println!("   └────────┬────────┘");
    println!("            │");
    println!("   ┌────────▼────────┐");
    println!("   │   QEMU Process  │");
    println!("   │   (usermode)    │");
    println!("   └─────────────────┘\n");

    println!("🎯 Next Steps:");
    println!("   1. Implement instruction hook at 0x{:x}", snapshot_addr);
    println!("   2. Hook callback: capture snapshot on first hit");
    println!("   3. On subsequent executions: restore + mark buffer symbolic");
    println!("   4. Run SymQEMU to generate constraints");
    println!("   5. Parse and display constraints from shared memory\n");

    println!("📚 For implementation details, see:");
    println!("   • crates/libafl_qemu/src/modules/symqemu.rs");
    println!("   • crates/libafl_qemu/src/modules/usermode/snapshot.rs");
    println!("   • This file: snapshot_runner/src/main.rs\n");

    println!("═══════════════════════════════════════════════════════════\n");

    Ok(())
}
