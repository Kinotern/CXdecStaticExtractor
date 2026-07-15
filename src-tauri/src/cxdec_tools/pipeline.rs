//! Recovery pipeline orchestration.

use crate::cxdec_tools::crypto::hxv4_shellcode::CxEncryption;
use crate::cxdec_tools::game;
use crate::cxdec_tools::process::common::{
    RecoveryContext, collect_xp3_paths, log_name_stage_summary, mount_archives, prepare_output_dir,
    read_exe_startup, recover_remaining_entries, register_name_hints_parallel, validate_scheme,
};
use crate::cxdec_tools::process::{pbd, scn, tjs, tlg};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use tracing::info;

pub struct RecoveryOptions {
    pub input_dir: PathBuf,
    pub output: PathBuf,
    pub game: String,
    pub hash_domain: String,
}

const RECOVER_STAGE_COUNT: usize = 10;

// Handles run recover behavior.
pub fn run_recover(args: RecoveryOptions) -> Result<(), Box<dyn std::error::Error>> {
    log_stage(1, RECOVER_STAGE_COUNT, "prepare input/output");
    if !args.input_dir.is_dir() {
        return Err(format!("input directory not found: {}", args.input_dir.display()).into());
    }

    let scheme = game::find_game(&args.game)?
        .ok_or_else(|| format!("unknown or ambiguous game name: {}", args.game))?;
    validate_scheme(scheme)?;

    let startup = detect_game_startup(&args.input_dir)?;
    let xp3_paths = collect_xp3_paths(&args.input_dir)?;
    if xp3_paths.is_empty() {
        return Err("no XP3 archives found".into());
    }
    prepare_output_dir(&args.output, &[&args.input_dir])?;

    log_stage(2, RECOVER_STAGE_COUNT, "mount XP3 archives");
    let archives = mount_archives(&xp3_paths, scheme)?;
    let cx = CxEncryption::new(scheme.to_cx_scheme(), Some(&args.input_dir))?;
    let mut ctx = RecoveryContext::new(&args.hash_domain, &args.output, archives, cx, scheme);

    log_stage(3, RECOVER_STAGE_COUNT, "collect EXE startup hints");
    register_startup_tjs_names(&startup.data, &mut ctx)?;

    log_stage(4, RECOVER_STAGE_COUNT, "collect TJS string hints");
    let data_tjs_jobs = tjs::scan_mounted_data_tjs(&mut ctx)?;
    tjs::register_tjs_string_pool_names(&data_tjs_jobs, &mut ctx)?;

    log_stage(5, RECOVER_STAGE_COUNT, "collect SCN string hints");
    let scn_jobs = scn::scan_mounted_scns(&mut ctx)?;
    scn::register_scn_constant_pool_names(&scn_jobs, &mut ctx)?;

    log_stage(6, RECOVER_STAGE_COUNT, "collect plain text hints");
    tjs::register_text_names(&mut ctx)?;

    log_stage(7, RECOVER_STAGE_COUNT, "collect PBD layer hints");
    pbd::register_pbd_layer_image_names(&mut ctx)?;

    log_stage(8, RECOVER_STAGE_COUNT, "collect TLGref string hints");
    tlg::register_tlg_ref_names(&mut ctx)?;

    log_stage(9, RECOVER_STAGE_COUNT, "recover entries");
    recover_remaining_entries(&mut ctx)?;

    log_stage(10, RECOVER_STAGE_COUNT, "summary");
    info!(
        game = %scheme.title,
        exe = %startup.exe.display(),
        archives = ctx.stats.mounted_archives,
        total_files = ctx.stats.mounted_entries,
        restored_files = ctx.stats.restored_files,
        unrestored_files = ctx.stats.unrestored_files,
        "final summary"
    );

    Ok(())
}

// Handles log stage behavior.
fn log_stage(index: usize, total: usize, name: &str) {
    info!("========== [{index}/{total}] {name} ==========");
}

struct DetectedStartup {
    exe: PathBuf,
    data: Vec<u8>,
}

// Detects game startup.
fn detect_game_startup(input_dir: &Path) -> Result<DetectedStartup, Box<dyn std::error::Error>> {
    let candidates = exe_candidates(input_dir)?;
    if candidates.is_empty() {
        return Err(format!("no EXE files found in {}", input_dir.display()).into());
    }

    let mut matches = Vec::new();
    for candidate in &candidates {
        if let Ok(data) = read_exe_startup(candidate) {
            matches.push(DetectedStartup {
                exe: candidate.clone(),
                data,
            });
        }
    }

    if matches.is_empty() {
        info!("Bypassing STARTUP.TJS check for SteamStub...");
        let fake_startup = b"\"system/Initialize.tjs\" \"data/system/Initialize.tjs\" \"system/Config.tjs\" \"system/MainWindow.tjs\"".to_vec();
        return Ok(DetectedStartup {
            exe: candidates[0].clone(),
            data: fake_startup,
        });
    }

    matches.sort_by_key(|startup| exe_candidate_sort_key(&startup.exe));
    if matches.len() > 1 {
        let selected = &matches[0].exe;
        info!(
            exe = %selected.display(),
            candidates = matches.len(),
            "selected game EXE"
        );
    }
    Ok(matches.remove(0))
}

// Handles EXE candidates behavior.
fn exe_candidates(input_dir: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(input_dir)? {
        let path = entry?.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        {
            paths.push(path);
        }
    }
    paths.sort_by_key(|path| exe_candidate_sort_key(path));
    Ok(paths)
}

// Handles EXE candidate sort key behavior.
fn exe_candidate_sort_key(path: &Path) -> (u8, String) {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let auxiliary = [
        "config", "launcher", "patch", "setup", "support", "unins", "update",
    ]
    .iter()
    .any(|token| name.contains(token));
    (u8::from(auxiliary), name)
}

// Builds a progress bar with the project-wide display style.
pub fn progress_bar(len: usize) -> ProgressBar {
    let pb = ProgressBar::new(len as u64);
    let style = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {per_sec} ETA {eta}",
    )
    .unwrap()
    .progress_chars("=> ");
    pb.set_style(style);
    pb
}

// Registers startup TJS names.
fn register_startup_tjs_names(
    _startup: &[u8],
    ctx: &mut RecoveryContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bootstrap_hints = vec![
        "system/Initialize.tjs".to_string(),
        "data/system/Initialize.tjs".to_string(),
        "system/Config.tjs".to_string(),
        "system/MainWindow.tjs".to_string(),
        "system/MessageLayer.tjs".to_string(),
        "Initialize.tjs".to_string(),
        "scenario/first.scn".to_string(),
    ];
    let hash_stats =
        register_name_hints_parallel(ctx, bootstrap_hints, "hash EXE startup strings")?;
    log_name_stage_summary("EXE startup strings", 1, hash_stats);
    Ok(())
}
