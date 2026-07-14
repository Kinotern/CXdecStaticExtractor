use std::env;
use std::path::PathBuf;
use hxv4_xp3_extractor_rust::extractor::{extract_all, ExtractOptions};

fn print_usage() {
    println!("Usage: cxdec-cli.exe <xp3_path> <drip_program_json> <out_dir> [lst_path]");
    println!("Example:");
    println!("  cxdec-cli.exe data.xp3 drip_program.json output YuzuSoft.lst");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 || args.len() > 5 {
        print_usage();
        std::process::exit(1);
    }

    let xp3_path = PathBuf::from(&args[1]);
    let drip_program_path = PathBuf::from(&args[2]);
    let out_dir = PathBuf::from(&args[3]);
    let lst_path = if args.len() == 5 {
        Some(PathBuf::from(&args[4]))
    } else {
        None
    };

    if !xp3_path.exists() {
        eprintln!("Error: XP3 file does not exist: {}", xp3_path.display());
        std::process::exit(1);
    }
    if !drip_program_path.exists() {
        eprintln!("Error: Drip program JSON does not exist: {}", drip_program_path.display());
        std::process::exit(1);
    }

    println!("======================================");
    println!("  HXV4 XP3 Extractor CLI (Rust)       ");
    println!("======================================");
    println!("XP3 Path:      {}", xp3_path.display());
    println!("Drip Program:  {}", drip_program_path.display());
    println!("Output Dir:    {}", out_dir.display());
    if let Some(l) = &lst_path {
        println!("LST Path:      {}", l.display());
    }
    println!("--------------------------------------");

    let opt = ExtractOptions {
        xp3_path,
        out_dir,
        drip_program_path,
        lst_path,
    };

    match extract_all(opt, |current, total| {
        if current % 100 == 0 || current == total {
            print!("\rProgress: {} / {}", current, total);
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    }) {
        Ok(msg) => {
            println!("\nExtraction complete! {}", msg);
        }
        Err(e) => {
            eprintln!("\nExtraction failed: {}", e);
            std::process::exit(1);
        }
    }
}
