use hxv4_xp3_extractor_rust::cxdec_tools::lst_scanner;
use std::path::PathBuf;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if !(5..=6).contains(&args.len()) {
        eprintln!("Usage: lst_scan_cli.exe <game_dir> <drip_program.json> <unique> <output.lst> [base.lst]");
        std::process::exit(1);
    }
    let game_dir = PathBuf::from(&args[1]);
    let drip = PathBuf::from(&args[2]);
    let output = PathBuf::from(&args[4]);
    let scan_dir = output.parent().unwrap_or_else(|| std::path::Path::new(".")).join("scan-cache");
    let base = args.get(5).map(PathBuf::from);
    match lst_scanner::run(
        &game_dir,
        &scan_dir,
        &drip,
        &args[3],
        base.as_deref(),
        &output,
        |message| print!("{message}"),
    ) {
        Ok(stats) => println!(
            "Done: archives={}, files={}, candidates={}, restored={}, unresolved={}",
            stats.archives, stats.files, stats.candidates, stats.restored, stats.unresolved
        ),
        Err(error) => {
            eprintln!("LST scan failed: {error}");
            std::process::exit(1);
        }
    }
}
