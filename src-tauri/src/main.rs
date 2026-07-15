#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

// use tauri::Manager;
use serde::{Deserialize, Serialize};

mod xp3;
mod vm;
mod crypto;
mod extractor;
mod cxdec_tools;
mod tauri_logger;

use std::sync::Mutex;
use once_cell::sync::Lazy;

static LOG_FILE_PATH: Lazy<Mutex<Option<std::path::PathBuf>>> = Lazy::new(|| Mutex::new(None));

fn runtime_root() -> std::path::PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf));
    if let Some(dir) = exe_dir.as_ref() {
        if dir.join("scheme").is_dir() || dir.join("formats.json").is_file() {
            return dir.clone();
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("scheme").is_dir() || cwd.join("formats.json").is_file() {
            return cwd;
        }
        if cwd.file_name().is_some_and(|name| name.eq_ignore_ascii_case("src-tauri")) {
            if let Some(parent) = cwd.parent() {
                if parent.join("scheme").is_dir() || parent.join("formats.json").is_file() {
                    return parent.to_path_buf();
                }
            }
        }
    }

    exe_dir.unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn executable_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn cleanup_temp_dir(path: &std::path::Path) {
    if path.exists() {
        if let Err(error) = std::fs::remove_dir_all(path) {
            app_log(&format!("[WARN] Failed to clean temporary directory {:?}: {}", path, error));
        }
    }
}

fn locate_cxdec_analyzer(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut candidates = vec![
        root.join("scheme").join("Cxdecanalyzer.exe"),
        root.join("cxdec-rs-analyzer")
            .join("target")
            .join("i686-pc-windows-msvc")
            .join("release")
            .join("Cxdecanalyzer.exe"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("scheme").join("Cxdecanalyzer.exe"));
        }
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn extract_unique_with_analyzer(
    root: &std::path::Path,
    exe_path: &std::path::Path,
    temp_dir: &std::path::Path,
    window: &tauri::Window,
) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let analyzer = locate_cxdec_analyzer(root).ok_or_else(|| {
        format!(
            "找不到 Cxdecanalyzer.exe；已检查 {} 和开发构建目录",
            root.join("scheme").display()
        )
    })?;
    let args = [
        "--exe".to_string(),
        exe_path.to_string_lossy().to_string(),
        "--work-dir".to_string(),
        temp_dir.to_string_lossy().to_string(),
    ];
    let _ = window.emit("backend-message", serde_json::json!({
        "type": "recoveryLog",
        "text": format!("运行新 HXV4 静态分析器: {}\n工作缓存: {}\n", analyzer.display(), temp_dir.display())
    }));

    let output = Command::new(&analyzer)
        .args(&args)
        .creation_flags(0x08000000)
        .output()
        .map_err(|error| format!("启动 Cxdecanalyzer.exe 失败: {}", error))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.is_empty() {
        let _ = window.emit("backend-message", serde_json::json!({
            "type": "recoveryLog", "text": stdout.to_string()
        }));
    }
    if !stderr.is_empty() {
        let _ = window.emit("backend-message", serde_json::json!({
            "type": "recoveryLog", "text": stderr.to_string()
        }));
    }
    if !output.status.success() {
        return Err(format!(
            "Cxdecanalyzer.exe 执行失败，退出码 {:?}: {}",
            output.status.code(),
            stderr.trim()
        ));
    }

    let summary_path = temp_dir.join("static_recover.summary.json");
    let summary_text = std::fs::read_to_string(&summary_path)
        .map_err(|error| format!("分析器未生成有效摘要 {}: {}", summary_path.display(), error))?;
    let summary: serde_json::Value = serde_json::from_str(&summary_text)
        .map_err(|error| format!("分析器摘要 JSON 无效: {}", error))?;
    let unique = summary
        .get("archive_unique_key")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "分析器摘要缺少 archive_unique_key".to_string())?;
    let unique = unique.to_string();
    let exe_name = exe_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "无法取得 EXE 文件名".to_string())?;
    let prefix = exe_name;
    let source_drip = temp_dir.join("drip_program.json");
    let target_drip = temp_dir.join(format!("{}_drip_program.json", prefix));
    let target_summary = temp_dir.join(format!("{}_static_recover.summary.json", prefix));
    let target_scheme = temp_dir.join(format!("{}_scheme.json", prefix));

    let drip_text = std::fs::read_to_string(&source_drip)
        .map_err(|error| format!("分析器未生成 drip_program.json: {}", error))?;
    let drip: serde_json::Value = serde_json::from_str(&drip_text)
        .map_err(|error| format!("drip_program.json 无效: {}", error))?;
    std::fs::copy(&source_drip, &target_drip)
        .map_err(|error| format!("保存临时 Drip 配置失败: {}", error))?;
    if !convert_drip_json_to_bin(&target_drip) {
        return Err("生成临时 Drip 二进制文件失败".to_string());
    }
    std::fs::copy(&summary_path, &target_summary)
        .map_err(|error| format!("保存临时分析摘要失败: {}", error))?;

    use sha2::{Digest, Sha256};
    let exe_hash = std::fs::read(exe_path)
        .map(|bytes| {
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>()
        })
        .map_err(|error| format!("计算 EXE SHA-256 失败: {}", error))?;
    let is_steam = summary.get("is_steam").and_then(|value| value.as_bool()).unwrap_or(false);
    let scheme = serde_json::json!({
        "id": prefix,
        "name": prefix,
        "company": "",
        "game": prefix,
        "version": if is_steam { "Steam" } else { "Local" },
        "is_steam": is_steam,
        "engine": "Kirikiri/Krkrz XP3 HXV4",
        "exe": {
            "default_path": prefix,
            "sha256": exe_hash,
            "note": "temporary LST analyzer scheme"
        },
        "bres": {
            "startup_key": summary.get("startup_key").cloned().unwrap_or(serde_json::Value::String(String::new())),
            "bootstrap_key": summary.get("bootstrap_key").cloned().unwrap_or(serde_json::Value::String(String::new())),
            "bootstrap_url": summary.get("bootstrap_url").cloned().unwrap_or(serde_json::Value::String(String::new())),
            "bootstrap_zlib_offset": 8,
            "salt": { "mode": "auto", "size": 8192 }
        },
        "bootstrap": {
            "prefix": summary.get("bootstrap_prefix").cloned().unwrap_or(serde_json::Value::String(String::new())),
            "warning": summary.get("warning").cloned().unwrap_or(serde_json::Value::String(String::new())),
            "archive_unique_key": unique.clone()
        },
        "hxv4": {
            "key": drip.get("hxv4_key").cloned().unwrap_or(serde_json::Value::String(String::new())),
            "nonce0": drip.get("hxv4_nonce0").cloned().unwrap_or(serde_json::Value::String(String::new())),
            "nonce1": drip.get("hxv4_nonce1").cloned().unwrap_or(serde_json::Value::String(String::new())),
            "open_flag_source": "descriptor.flags & 1"
        },
        "derive": {
            "drip_program": target_drip.file_name().unwrap_or_default().to_string_lossy(),
            "mode": "Cxdecanalyzer.exe temporary analysis"
        }
    });
    std::fs::write(&target_scheme, serde_json::to_string_pretty(&scheme).unwrap())
        .map_err(|error| format!("保存临时 Scheme 失败: {}", error))?;

    let _ = std::fs::remove_file(source_drip);
    let _ = std::fs::remove_file(summary_path);
    let _ = std::fs::remove_file(temp_dir.join("bootstrap.dll"));
    Ok(unique)
}

pub fn init_logger() {
    let exe_dir = std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new("")).to_path_buf();
    let log_dir = exe_dir.join("logs");
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("app.log");
    if let Ok(mut lock) = LOG_FILE_PATH.lock() {
        *lock = Some(log_path);
    }
    tauri_logger::init();
}

pub fn app_log(msg: &str) {
    println!("{}", msg); // Also print to console
    if let Ok(lock) = LOG_FILE_PATH.lock() {
        if let Some(path) = lock.as_ref() {
            use std::io::Write;
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let line = format!("[{}] {}\n", timestamp, msg);
            let _ = std::fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| {
                f.write_all(line.as_bytes())
            });
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct Scheme {
    id: String,
    company: Option<String>,
    game: Option<String>,
    name: Option<String>,
    version: Option<String>,
    has_drip: bool,
    has_hxv4_key: bool,
    is_steam: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct ExtractItem {
    id: String,
    path: String,
    scheme: Option<String>,
    out_dir: String,
}



#[tauri::command]
fn get_schemes() -> Vec<Scheme> {
    let mut schemes = Vec::new();
    let mut scheme_dir = std::env::current_exe()
        .unwrap_or_default()
        .parent()
        .unwrap_or(std::path::Path::new(""))
        .join("scheme");

    if !scheme_dir.exists() {
        // Fallback for development (cargo run)
        scheme_dir = std::path::PathBuf::from("../scheme");
    }

    app_log(&format!("Looking for schemes in: {:?}", scheme_dir));

    for entry in walkdir::WalkDir::new(&scheme_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.file_name().to_string_lossy().ends_with("_scheme.json") {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(json) => {
                        let id = json["id"].as_str().unwrap_or("unknown").to_string();
                        let company = json["company"].as_str().map(|s| s.to_string());
                        let game = json["game"].as_str().map(|s| s.to_string());
                        let name = json["name"].as_str().map(|s| s.to_string());
                        let version = json["version"].as_str().map(|s| s.to_string());
                        let has_drip = json["derive"]["drip_program"].is_string();
                        let has_hxv4_key = json["hxv4"]["key"].is_string();
                        let is_steam = json["is_steam"].as_bool();

                        app_log(&format!("[OK] Loaded scheme: {} from {:?}", id, entry.path()));

                        schemes.push(Scheme {
                            id, company, game, name, version, has_drip, has_hxv4_key, is_steam,
                        });
                    }
                    Err(e) => {
                        app_log(&format!("[ERROR] Failed to parse scheme JSON {:?}: {}", entry.path(), e));
                    }
                }
            } else {
                app_log(&format!("[ERROR] Failed to read file: {:?}", entry.path()));
            }
        }
    }
    schemes
}

#[tauri::command]
fn run_extract_queue(window: tauri::Window, items: Vec<ExtractItem>) {
    std::thread::spawn(move || {
        let exe_dir = std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new("")).to_path_buf();

        for item in items {
            // Log to file
            app_log(&format!("[START] Extract Job ID: {}, XP3: {}, Out: {}", item.id, item.path, item.out_dir));

            let out_dir = std::path::PathBuf::from(&item.out_dir);
            let _ = window.emit("backend-message", serde_json::json!({
                "type": "progress",
                "jobId": item.id,
                "current": 0,
                "total": 0
            }));

            let scheme_id = item.scheme.clone().unwrap_or_default();
            let mut drip_path = std::path::PathBuf::new();
            let mut lst_path: Option<std::path::PathBuf> = None;
            
            let mut scheme_dir = exe_dir.join("scheme");
            if !scheme_dir.exists() { scheme_dir = std::path::PathBuf::from("../scheme"); }
            
            for entry in walkdir::WalkDir::new(&scheme_dir).into_iter().filter_map(|e| e.ok()) {
                if entry.file_name().to_string_lossy().ends_with("_scheme.json") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if json["id"].as_str().unwrap_or("") == scheme_id {
                                if let Some(drip_name) = json["derive"]["drip_program"].as_str() {
                                    drip_path = entry.path().parent().unwrap().join(drip_name);
                                    app_log(&format!("Found drip program at: {:?}", drip_path));
                                }
                                if let Some(lst_name) = json["lst"].as_str() {
                                    if !lst_name.is_empty() {
                                        lst_path = Some(entry.path().parent().unwrap().join(lst_name));
                                        app_log(&format!("Found LST at: {:?}", lst_path));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let opt = extractor::ExtractOptions {
                xp3_path: std::path::PathBuf::from(&item.path),
                drip_program_path: drip_path,
                out_dir,
                lst_path,
            };

            let w = window.clone();
            let i_id = item.id.clone();
            let res = extractor::extract_all(opt, move |written, total| {
                let _ = w.emit("backend-message", serde_json::json!({
                    "type": "progress",
                    "jobId": i_id,
                    "current": written,
                    "total": total
                }));
            });

            match res {
                Ok(_) => {
                    app_log(&format!("[DONE] Job ID: {}", item.id));
                    let _ = window.emit("backend-message", serde_json::json!({
                        "type": "done",
                        "ok": true
                    }));
                }
                Err(e) => {
                    app_log(&format!("[ERROR] Job ID: {} - Error: {}", item.id, e));
                    let _ = window.emit("backend-message", serde_json::json!({
                        "type": "done",
                        "ok": false,
                        "error": e
                    }));
                }
            }
        }
    });
}


#[tauri::command]
fn handle_post_message(message: serde_json::Value, window: tauri::Window) {
    app_log(&format!("Received message from frontend: {:?}", message));
    
    if let Some(msg_type) = message.get("type").and_then(|t| t.as_str()) {
        if msg_type == "ready" {
            if let Ok(mut lock) = tauri_logger::LOG_WINDOW.lock() {
                *lock = Some(window.clone());
            }
            let schemes = get_schemes();
            let init_msg = serde_json::json!({
                "type": "init",
                "schemes": schemes,
                "selectedScheme": if schemes.is_empty() { "" } else { &schemes[0].id },
                "outRoot": std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new("")).join("output").to_string_lossy()
            });
            window.emit("backend-message", init_msg).unwrap();
        } else if msg_type == "pick" {
            let target = message.get("target").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let window_clone = window.clone();
            
            if target == "schemeExe" || target == "subExe" || target == "lstExe" {
                tauri::api::dialog::FileDialogBuilder::new().add_filter("Executable", &["exe"]).pick_file(move |file_path| {
                    if let Some(path) = file_path {
                        let _ = window_clone.emit("backend-message", serde_json::json!({
                            "type": "picked", "target": target, "path": path.to_string_lossy()
                        }));
                    }
                });
            } else if target == "schemeLst" || target == "lstBase" {
                tauri::api::dialog::FileDialogBuilder::new().add_filter("List File", &["lst", "txt"]).pick_file(move |file_path| {
                    if let Some(path) = file_path {
                        let _ = window_clone.emit("backend-message", serde_json::json!({
                            "type": "picked", "target": target, "path": path.to_string_lossy()
                        }));
                    }
                });
            } else if target == "queueXp3" {
                tauri::api::dialog::FileDialogBuilder::new().add_filter("XP3 Archive", &["xp3", "arc"]).pick_files(move |file_paths| {
                    if let Some(paths) = file_paths {
                        let str_paths: Vec<String> = paths.into_iter().map(|p| p.to_string_lossy().to_string()).collect();
                        let _ = window_clone.emit("backend-message", serde_json::json!({
                            "type": "pickedMulti", "target": target, "paths": str_paths
                        }));
                    }
                });
            } else if target == "queueOutRoot" {
                tauri::api::dialog::FileDialogBuilder::new().pick_folder(move |folder_path| {
                    if let Some(path) = folder_path {
                        let _ = window_clone.emit("backend-message", serde_json::json!({
                            "type": "picked", "target": target, "path": path.to_string_lossy()
                        }));
                    }
                });
            }
        } else if msg_type == "createScheme" {
            let exe = message.get("exe").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let comp = message.get("company").and_then(|t| t.as_str()).map(|s| s.to_string());
            let game = message.get("game").and_then(|t| t.as_str()).map(|s| s.to_string());
            let vers = message.get("version").and_then(|t| t.as_str()).map(|s| s.to_string());
            let lst = message.get("lst").and_then(|t| t.as_str()).map(|s| s.to_string());
            let res = create_scheme_from_exe(window.clone(), CreateSchemeOptions {
                exe_path: exe,
                company: comp,
                game: game,
                version: vers,
                lst: lst,
            });
            
            let msg = match res {
                Ok(msg) => serde_json::json!({ "type": "schemeCreated", "ok": true, "message": msg, "schemes": get_schemes() }),
                Err(e) => serde_json::json!({ "type": "schemeCreated", "ok": false, "message": format!("错误: {}", e) })
            };
            let _ = window.emit("backend-message", msg);
        } else if msg_type == "deleteScheme" {
            let scheme_id = message.get("schemeId").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let mut deleted = false;
            let mut scheme_dir = std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new("")).join("scheme");
            if !scheme_dir.exists() { scheme_dir = std::path::PathBuf::from("../scheme"); }
            
            let mut scheme_name = "未知方案".to_string();
            let mut found_path = None;
            let mut drip_program = None;
            
            for entry in walkdir::WalkDir::new(&scheme_dir).into_iter().filter_map(|e| e.ok()) {
                if entry.file_name().to_string_lossy().ends_with("_scheme.json") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if json["id"].as_str().unwrap_or("") == scheme_id {
                                scheme_name = json["name"].as_str().unwrap_or("未知方案").to_string();
                                found_path = Some(entry.path().to_path_buf());
                                drip_program = json["derive"]["drip_program"].as_str().map(|s| s.to_string());
                                break;
                            }
                        }
                    }
                }
            }
            
            if let Some(path) = found_path {
                use tauri::api::dialog::blocking::MessageDialogBuilder;
                use tauri::api::dialog::{MessageDialogButtons, MessageDialogKind};
                
                let confirm = MessageDialogBuilder::new(
                    "确认要删除方案吗？",
                    &format!("确认要删除方案 \"{}\" 吗？\n删除后不可恢复。", scheme_name)
                )
                .buttons(MessageDialogButtons::YesNo)
                .kind(MessageDialogKind::Warning)
                .show();
                
                if confirm {
                    let version_path = path.parent().unwrap();
                    app_log(&format!("Deleting scheme files in: {:?}", version_path));
                    
                    let _ = std::fs::remove_file(&path); // _scheme.json
                    
                    if let Some(drip_name) = drip_program {
                        let drip_path = version_path.join(drip_name);
                        let _ = std::fs::remove_file(&drip_path);
                        let _ = std::fs::remove_file(drip_path.with_extension("bin"));
                    }
                    
                    let prefix = version_path.file_name().unwrap().to_string_lossy();
                    let _ = std::fs::remove_file(version_path.join(format!("{}_static_recover.summary.json", prefix)));
                    
                    if std::fs::read_dir(version_path).map(|mut i| i.next().is_none()).unwrap_or(false) {
                        let _ = std::fs::remove_dir(version_path);
                        if let Some(game_path) = version_path.parent() {
                            if std::fs::read_dir(game_path).map(|mut i| i.next().is_none()).unwrap_or(false) {
                                let _ = std::fs::remove_dir(game_path);
                                if let Some(company_path) = game_path.parent() {
                                    if std::fs::read_dir(company_path).map(|mut i| i.next().is_none()).unwrap_or(false) {
                                        let _ = std::fs::remove_dir(company_path);
                                    }
                                }
                            }
                        }
                    }
                    deleted = true;
                }
            }
            
            let msg = if deleted {
                app_log(&format!("[OK] Scheme {} successfully deleted.", scheme_id));
                serde_json::json!({ "type": "schemeDeleted", "ok": true, "message": "方案已删除", "schemes": get_schemes() })
            } else {
                app_log(&format!("[ERROR] Scheme {} not found for deletion or cancelled.", scheme_id));
                serde_json::json!({ "type": "schemeDeleted", "ok": false, "message": "已取消删除或方案不存在" })
            };
            let _ = window.emit("backend-message", msg);
        } else if msg_type == "duplicateScheme" {
            let base_id = message.get("baseSchemeId").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let new_ver = message.get("newVersion").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let new_exe = message.get("newExe").and_then(|t| t.as_str()).unwrap_or("").to_string();
            
            let window_clone = window.clone();
            std::thread::spawn(move || {
                let res = duplicate_scheme(window_clone.clone(), &base_id, &new_ver, &new_exe);
                let msg = match res {
                    Ok((new_id, msg_str)) => serde_json::json!({
                        "type": "schemeDuplicated",
                        "ok": true,
                        "message": msg_str,
                        "schemes": get_schemes(),
                        "scheme": { "id": new_id }
                    }),
                    Err(e) => serde_json::json!({
                        "type": "schemeDuplicated",
                        "ok": false,
                        "message": format!("子版本创建失败: {}", e)
                    })
                };
                let _ = window_clone.emit("backend-message", msg);
            });
        } else if msg_type == "renameScheme" {
            let scheme_id = message.get("schemeId").and_then(|t| t.as_str()).unwrap_or("");
            let company = message.get("company").and_then(|t| t.as_str()).unwrap_or("");
            let game = message.get("game").and_then(|t| t.as_str()).unwrap_or("");
            let version = message.get("version").and_then(|t| t.as_str()).unwrap_or("");
            
            let mut renamed = false;
            let exe_dir = std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new("")).to_path_buf();
            let mut scheme_dir = exe_dir.join("scheme");
            if !scheme_dir.exists() { scheme_dir = std::path::PathBuf::from("../scheme"); }
            
            for entry in walkdir::WalkDir::new(&scheme_dir).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() && entry.file_name().to_string_lossy().ends_with("_scheme.json") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if json["id"].as_str().unwrap_or("") == scheme_id {
                                let disp_name = format!("{} {} {} HXV4", company, game, version).trim().to_string();
                                if let Some(obj) = json.as_object_mut() {
                                    obj.insert("company".to_string(), serde_json::json!(company));
                                    obj.insert("game".to_string(), serde_json::json!(game));
                                    obj.insert("version".to_string(), serde_json::json!(version));
                                    obj.insert("name".to_string(), serde_json::json!(disp_name));
                                }
                                let _ = std::fs::write(entry.path(), serde_json::to_string_pretty(&json).unwrap());
                                renamed = true;
                                break;
                            }
                        }
                    }
                }
            }
            
            let msg = if renamed {
                serde_json::json!({ "type": "schemeRenamed", "ok": true, "message": "方案已重命名", "schemes": get_schemes() })
            } else {
                serde_json::json!({ "type": "schemeRenamed", "ok": false, "message": "找不到该方案" })
            };
            let _ = window.emit("backend-message", msg);
        } else if msg_type == "recoverScheme" {
            let scheme_id = message.get("schemeId").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let exe_path = message.get("exe").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let window_clone = window.clone();
            std::thread::spawn(move || {
                let res = run_static_recover(&scheme_id, &exe_path, &window_clone);
                let msg = match res {
                    Ok(msg) => serde_json::json!({ "type": "schemeRecovered", "ok": true, "message": msg, "schemes": get_schemes() }),
                    Err(e) => serde_json::json!({ "type": "schemeRecovered", "ok": false, "message": format!("自动分析失败: {}", e) })
                };
                let _ = window_clone.emit("backend-message", msg);
            });
        } else if msg_type == "action" && message.get("action").and_then(|t| t.as_str()) == Some("extract") {
            let id = message.get("jobId").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let xp3 = message.get("xp3").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let out = message.get("out").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let scheme_id = message.get("schemeId").and_then(|t| t.as_str()).map(|s| s.to_string());
            run_extract_queue(window, vec![ExtractItem { id, path: xp3, scheme: scheme_id, out_dir: out }]);
        } else if msg_type == "generateLst" {
            let exe_path = message.get("exePath").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let base_lst = message.get("baseLst").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let output_name = message.get("outputName").and_then(|t| t.as_str()).unwrap_or("default.lst").to_string();
            
            let window_clone = window.clone();
            std::thread::spawn(move || {
                let current_dir = runtime_root();
                let out_dir = executable_dir().join("lstoutput");
                if !out_dir.exists() {
                    let _ = std::fs::create_dir_all(&out_dir);
                }
                
                // Temporary analyzer/recovery artifacts always live next to the
                // running hxv4xp3Extractor.exe, in both dev and release builds.
                let temp_root = executable_dir().join("_temp");
                let exe_name = std::path::Path::new(&exe_path)
                    .file_name()
                    .unwrap_or_default();
                let temp_dir = temp_root.join(exe_name);
                cleanup_temp_dir(&temp_dir);
                if let Err(error) = std::fs::create_dir_all(&temp_dir) {
                    let _ = window_clone.emit("backend-message", serde_json::json!({
                        "type": "recoveryDone", "ok": false, "error": format!("创建临时方案目录失败: {}", error)
                    }));
                    return;
                }
                
                let game_dir = std::path::PathBuf::from(&exe_path).parent().unwrap_or(std::path::Path::new("")).to_path_buf();
                if game_dir.as_os_str().is_empty() || !game_dir.exists() {
                    let _ = window_clone.emit("backend-message", serde_json::json!({
                        "type": "recoveryDone", "ok": false, "error": "无法找到游戏目录，请确认 EXE 路径"
                    }));
                    cleanup_temp_dir(&temp_dir);
                    return;
                }

                let hash_domain = match extract_unique_with_analyzer(
                    &current_dir,
                    std::path::Path::new(&exe_path),
                    &temp_dir,
                    &window_clone,
                ) {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = window_clone.emit("backend-message", serde_json::json!({
                            "type": "recoveryDone", "ok": false, "error": format!("新 HXV4 分析器提取 UNIQUE 失败: {}", e)
                        }));
                        cleanup_temp_dir(&temp_dir);
                        return;
                    }
                };

                let exe_name_text = std::path::Path::new(&exe_path)
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("game.exe");
                let drip_path = temp_dir.join(format!("{}_drip_program.json", exe_name_text));
                let scan_dir = temp_dir.join("scan");
                let final_lst = out_dir.join(&output_name);
                let base_lst_path = (!base_lst.is_empty()).then(|| std::path::Path::new(&base_lst));
                let _ = window_clone.emit("backend-message", serde_json::json!({
                    "type": "recoveryLog", "text": format!("游戏目录: {}\n临时方案: {}\nDrip 程序: {}\n扫描缓存: {}\nUNIQUE: {}\n基础 LST: {}\n", game_dir.display(), temp_dir.display(), drip_path.display(), scan_dir.display(), hash_domain, base_lst)
                }));

                let log_window = window_clone.clone();
                let result = crate::cxdec_tools::lst_scanner::run(
                    &game_dir,
                    &scan_dir,
                    &drip_path,
                    &hash_domain,
                    base_lst_path,
                    &final_lst,
                    move |text| {
                        let _ = log_window.emit("backend-message", serde_json::json!({
                            "type": "recoveryLog", "text": text
                        }));
                    },
                );
                match result {
                    Ok(stats) => {
                        let size = std::fs::metadata(&final_lst).map(|metadata| metadata.len()).unwrap_or(0);
                        let _ = window_clone.emit("backend-message", serde_json::json!({
                            "type": "recoveryLog",
                            "text": format!("扫描完成: {} 个归档，{} 个索引条目，{} 个候选，恢复 {}，未恢复 {}\n实际读取正文: {} 个条目 / {} bytes\nLST 已生成: {} ({} bytes)\n", stats.archives, stats.files, stats.candidates, stats.restored, stats.unresolved, stats.entries_read, stats.bytes_read, final_lst.display(), size)
                        }));
                        cleanup_temp_dir(&temp_dir);
                        let _ = window_clone.emit("backend-message", serde_json::json!({
                            "type": "recoveryDone", "ok": true, "unique": hash_domain, "path": final_lst.to_string_lossy(), "size": size
                        }));
                    }
                    Err(error) => {
                        let _ = window_clone.emit("backend-message", serde_json::json!({
                            "type": "recoveryDone", "ok": false, "error": error
                        }));
                    }
                }
            });
        }
    }
}

fn duplicate_scheme(
    window: tauri::Window,
    base_scheme_id: &str,
    new_version: &str,
    new_exe: &str,
) -> Result<(String, String), String> {
    let exe_dir = std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new("")).to_path_buf();
    let mut scheme_dir = exe_dir.join("scheme");
    if !scheme_dir.exists() { scheme_dir = std::path::PathBuf::from("../scheme"); }
    
    let mut base_scheme_path = None;
    let mut base_folder = None;
    
    for entry in walkdir::WalkDir::new(&scheme_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_name().to_string_lossy().ends_with("_scheme.json") {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if json["id"].as_str().unwrap_or("") == base_scheme_id {
                        base_scheme_path = Some(entry.path().to_path_buf());
                        base_folder = Some(entry.path().parent().unwrap().to_path_buf());
                        break;
                    }
                }
            }
        }
    }
    
    let base_scheme_path = base_scheme_path.ok_or_else(|| "未找到基础方案".to_string())?;
    let base_folder = base_folder.ok_or_else(|| "未找到基础方案文件夹".to_string())?;
    
    let base_content = std::fs::read_to_string(&base_scheme_path).map_err(|e| e.to_string())?;
    let mut base_json: serde_json::Value = serde_json::from_str(&base_content).map_err(|e| e.to_string())?;
    
    let company = base_json["company"].as_str().unwrap_or("").to_string();
    let game = base_json["game"].as_str().unwrap_or("").to_string();
    let version = new_version.trim().to_string();
    
    let disp_name = format!("{} {} {} HXV4", company, game, version).trim().to_string();
    
    let raw_id = format!("{} {} {}", company, game, version).to_lowercase();
    let new_id = raw_id.replace(|c: char| !c.is_alphanumeric() && c != ' ', "").replace(" ", "-");
    
    let clean_company = company.replace(|c: char| !c.is_alphanumeric() && c != ' ', "").trim().to_string();
    let clean_game = game.replace(|c: char| !c.is_alphanumeric() && c != ' ', "").trim().to_string();
    let clean_version = version.replace(|c: char| !c.is_alphanumeric() && c != ' ', "").trim().to_string();
    
    let mut folder = scheme_dir.clone();
    if !clean_company.is_empty() {
        folder = folder.join(&clean_company);
    }
    folder = folder.join(&clean_game);
    
    let version_dir = format!("{}[{}]", clean_game, clean_version);
    folder = folder.join(&version_dir);
    
    std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
    
    let new_scheme_path = folder.join(format!("{}_scheme.json", version_dir));
    
    let mut new_lst_rel = "".to_string();
    if let Some(base_lst) = base_json["lst"].as_str() {
        if !base_lst.is_empty() {
            let src_lst = base_folder.join(base_lst);
            if src_lst.exists() && src_lst.is_file() {
                let dest_lst = folder.join(src_lst.file_name().unwrap());
                let _ = std::fs::copy(&src_lst, &dest_lst);
                new_lst_rel = dest_lst.file_name().unwrap().to_string_lossy().to_string();
            }
        }
    }
    
    if let Some(obj) = base_json.as_object_mut() {
        obj.insert("id".to_string(), serde_json::json!(new_id));
        obj.insert("name".to_string(), serde_json::json!(disp_name));
        obj.insert("version".to_string(), serde_json::json!(version));
        obj.insert("lst".to_string(), serde_json::json!(new_lst_rel));
        
        if let Some(exe_obj) = obj.get_mut("exe").and_then(|v| v.as_object_mut()) {
            let new_exe_path = std::path::Path::new(new_exe);
            exe_obj.insert("default_path".to_string(), serde_json::json!(new_exe_path.file_name().unwrap_or_default().to_string_lossy().to_string()));
            
            if let Ok(mut file) = std::fs::File::open(new_exe) {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                let mut buf = vec![0u8; 8192];
                while let Ok(n) = std::io::Read::read(&mut file, &mut buf) {
                    if n == 0 { break; }
                    hasher.update(&buf[..n]);
                }
                let hash = hasher.finalize();
                let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
                exe_obj.insert("sha256".to_string(), serde_json::json!(hash_hex));
            }
        }
        
        if let Some(derive_obj) = obj.get_mut("derive").and_then(|v| v.as_object_mut()) {
            derive_obj.insert("drip_program".to_string(), serde_json::json!(format!("{}_drip_program.json", version_dir)));
        }
    }
    
    std::fs::write(&new_scheme_path, serde_json::to_string_pretty(&base_json).unwrap()).map_err(|e| e.to_string())?;
    
    let new_drip_path = folder.join(format!("{}_drip_program.json", version_dir));
    let mut copied_drip = false;
    if let Some(base_drip_name) = base_json["derive"]["drip_program"].as_str() {
        let src_drip = base_folder.join(base_drip_name);
        if src_drip.exists() && src_drip.is_file() {
            if std::fs::copy(&src_drip, &new_drip_path).is_ok() {
                copied_drip = true;
                let src_bin = src_drip.with_extension("bin");
                if src_bin.exists() && src_bin.is_file() {
                    let _ = std::fs::copy(&src_bin, new_drip_path.with_extension("bin"));
                }
            }
        }
    }
    
    if !copied_drip {
        let drip_content = serde_json::json!({
            "holder_words": [],
            "context_u32": [],
            "lanes": [],
            "hxv4_key": "",
            "hxv4_nonce0": "",
            "hxv4_nonce1": ""
        });
        std::fs::write(&new_drip_path, serde_json::to_string_pretty(&drip_content).unwrap()).map_err(|e| e.to_string())?;
    }
    
    let _ = run_static_recover(&new_id, new_exe, &window);
    
    Ok((new_id, format!("子版本已创建并自动提取完成: {}", disp_name)))
}

#[derive(Serialize, Deserialize)]
struct CreateSchemeOptions {
    exe_path: String,
    company: Option<String>,
    game: Option<String>,
    version: Option<String>,
    lst: Option<String>,
}

#[tauri::command]
fn create_scheme_from_exe(window: tauri::Window, options: CreateSchemeOptions) -> Result<String, String> {
    let exe_path = std::path::PathBuf::from(&options.exe_path);
    if !exe_path.exists() || !exe_path.is_file() {
        return Err("EXE file not found".to_string());
    }

    let stem = exe_path.file_stem().unwrap_or_default().to_string_lossy().to_string();
    let company = options.company.unwrap_or_default();
    let game = options.game.unwrap_or(stem.clone());
    let version = options.version.unwrap_or_else(|| "Local".to_string());

    let safe_name = |s: &str, fallback: &str| -> String {
        let mut out = s.trim().to_string();
        if out.is_empty() { out = fallback.to_string(); }
        out.replace(|c: char| "<>:\"/\\|?*".contains(c) || c < ' ', "_")
    };

    let company_safe = safe_name(&company, "");
    let game_safe = safe_name(&game, &stem);
    let version_safe = safe_name(&version, "Local");

    let game_dir = game_safe.clone();
    let version_dir = format!("{}[{}]", game_dir, version_safe);

    let mut scheme_dir = std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new("")).join("scheme");
    if !scheme_dir.exists() {
        scheme_dir = std::path::PathBuf::from("../scheme");
    }

    let folder = if company_safe.is_empty() {
        scheme_dir.join(&game_dir).join(&version_dir)
    } else {
        scheme_dir.join(&company_safe).join(&game_dir).join(&version_dir)
    };

    let scheme_path = folder.join(format!("{}_scheme.json", version_dir));
    if scheme_path.exists() {
        return Err(format!("方案已存在 {}", scheme_path.display()));
    }

    std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;

    let id = format!("{}_{}_{}", company_safe, game_safe, version_safe)
        .replace(" ", "-")
        .to_lowercase();
    
    let disp_name = format!("{} {} {} HXV4", company, game, version).trim().to_string();

    let game_dir = scheme_dir.join(&company).join(&game);

    let mut lst_rel = String::new();
    if let Some(lst_str) = options.lst {
        let lst_p = std::path::PathBuf::from(lst_str.trim());
        if !lst_p.as_os_str().is_empty() {
            let mut final_lst_path = lst_p.clone();
            if lst_p.is_file() {
                if let Some(file_name) = lst_p.file_name() {
                    let _ = std::fs::create_dir_all(&game_dir);
                    let target_lst = game_dir.join(file_name);
                    let is_same = lst_p.canonicalize().unwrap_or_default() == target_lst.canonicalize().unwrap_or_default() && target_lst.exists();
                    if !is_same {
                        let _ = std::fs::copy(&lst_p, &target_lst);
                    }
                    final_lst_path = target_lst;
                }
            }
            if let Some(rel) = pathdiff::diff_paths(&final_lst_path, &folder) {
                lst_rel = rel.to_string_lossy().replace("\\", "/");
            } else {
                lst_rel = final_lst_path.to_string_lossy().replace("\\", "/");
            }
        }
    }

    let json_content = serde_json::json!({
        "id": id,
        "name": disp_name,
        "company": company,
        "game": game,
        "version": version,
        "is_steam": false,
        "engine": "Kirikiri/Krkrz XP3 HXV4",
        "lst": lst_rel,
        "exe": {
            "note": "created from local executable",
            "default_path": exe_path.file_name().unwrap_or_default().to_string_lossy()
        },
        "resources": {
            "startup": {"name": "STARTUP.TJS", "type": "RCDATA"},
            "plugin": {"optional": true, "name": "PLUGIN", "type": "RCDATA"},
            "text": {"name": "127", "type": "TEXT"},
            "bootstrap": {"name": "BOOTSTRAP", "type": "RCDATA"}
        },
        "bres": {
            "bootstrap_url": "",
            "bootstrap_zlib_offset": 8,
            "bootstrap_key": "",
            "startup_key": "",
            "salt": {"size": 8192, "verified_file_offset": "", "verified_rva": "", "mode": "auto"}
        },
        "bootstrap": {
            "prefix": "",
            "warning": "",
            "archive_seed": "",
            "config_table_rva": "",
            "archive_unique_key": ""
        },
        "hxv4": {
            "open_flag_source": "descriptor.flags & 1",
            "nonce0": "",
            "key": "",
            "nonce1": ""
        },
        "derive": {
            "drip_program": format!("{}_drip_program.json", version_dir)
        }
    });

    let formatted_json = serde_json::to_string_pretty(&json_content).unwrap();
    std::fs::write(&scheme_path, formatted_json).map_err(|e| e.to_string())?;

    // Create an empty drip program JSON as well
    let drip_path = folder.join(format!("{}_drip_program.json", version_dir));
    let drip_content = serde_json::json!({
        "holder_words": [],
        "context_u32": [],
        "lanes": [],
        "hxv4_key": "",
        "hxv4_nonce0": "",
        "hxv4_nonce1": ""
    });
    std::fs::write(&drip_path, serde_json::to_string_pretty(&drip_content).unwrap()).map_err(|e| e.to_string())?;

    // Auto-run static recover just like C++
    let _ = run_static_recover(&id, &exe_path.to_string_lossy(), &window);

    Ok(format!("方案已创建 {}", scheme_path.display()))
}

fn convert_drip_json_to_bin(json_path: &std::path::Path) -> bool {
    use std::fs::File;
    use std::io::{Read, Write};
    let mut file = match File::open(json_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut content = String::new();
    if file.read_to_string(&mut content).is_err() { return false; }
    
    let mut dj: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let holder_words = match dj.get("holder_words").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect::<Vec<u32>>(),
        None => return false,
    };
    let context_u32 = match dj.get("context_u32").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect::<Vec<u32>>(),
        None => return false,
    };
    
    let lanes_array = match dj.get("lanes").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return false,
    };

    let mut lanes: Vec<Vec<(u32, u32)>> = Vec::new();
    for lane in lanes_array {
        let mut records = Vec::new();
        if let Some(records_arr) = lane.get("records").and_then(|v| v.as_array()) {
            for r in records_arr {
                if let Some(pair) = r.as_array() {
                    if pair.len() == 2 {
                        if let (Some(p0), Some(p1)) = (pair[0].as_u64(), pair[1].as_u64()) {
                            records.push((p0 as u32, p1 as u32));
                        }
                    }
                }
            }
        }
        lanes.push(records);
    }

    let bin_path = json_path.with_extension("bin");
    let mut bf = match File::create(bin_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let magic: u32 = 0x50495244; // 'DRIP'
    let hlen = holder_words.len() as u32;
    let clen = context_u32.len() as u32;
    let lane_count = lanes.len() as u32;

    let _ = bf.write_all(&magic.to_le_bytes());
    let _ = bf.write_all(&hlen.to_le_bytes());
    let _ = bf.write_all(&clen.to_le_bytes());
    let _ = bf.write_all(&lane_count.to_le_bytes());

    for h in holder_words { let _ = bf.write_all(&h.to_le_bytes()); }
    for c in context_u32 { let _ = bf.write_all(&c.to_le_bytes()); }

    for lane in lanes {
        let rcount = lane.len() as u32;
        let _ = bf.write_all(&rcount.to_le_bytes());
        for (p, o) in lane {
            let _ = bf.write_all(&p.to_le_bytes());
            let _ = bf.write_all(&o.to_le_bytes());
        }
    }

    if let Some(obj) = dj.as_object_mut() {
        obj.remove("holder_words");
        obj.remove("context_u32");
        obj.remove("lanes");
    }

    if let Ok(mut jf) = File::create(json_path) {
        let _ = jf.write_all(serde_json::to_string_pretty(&dj).unwrap().as_bytes());
    }

    true
}

fn run_static_recover(scheme_id: &str, exe_path: &str, window: &tauri::Window) -> Result<String, String> {
    use std::process::{Command, Stdio};
    use std::io::{BufRead, BufReader};
    use std::path::PathBuf;
    use std::os::windows::process::CommandExt;

    let exe_dir = std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new("")).to_path_buf();
    
    // Find scheme folder
    let mut scheme_dir = exe_dir.join("scheme");
    if !scheme_dir.exists() { scheme_dir = PathBuf::from("../scheme"); }
    
    let mut target_scheme_path = None;
    let mut target_folder = None;
    let mut default_exe = String::new();
    
    for entry in walkdir::WalkDir::new(&scheme_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_name().to_string_lossy().ends_with("_scheme.json") {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if json["id"].as_str().unwrap_or("") == scheme_id {
                        target_scheme_path = Some(entry.path().to_path_buf());
                        target_folder = Some(entry.path().parent().unwrap().to_path_buf());
                        if let Some(exe) = json["defaultExe"].as_str() {
                            default_exe = exe.to_string();
                        }
                        break;
                    }
                }
            }
        }
    }

    let folder = target_folder.ok_or("找不到方案目录")?;
    let scheme_path = target_scheme_path.unwrap();
    
    let use_exe = if exe_path.is_empty() { default_exe } else { exe_path.to_string() };
    let use_exe_path = if use_exe.is_empty() {
        std::path::PathBuf::new()
    } else {
        let p = std::path::PathBuf::from(&use_exe);
        if p.is_absolute() { p } else { folder.join(&use_exe) }
    };
    
    if use_exe_path.as_os_str().is_empty() || !use_exe_path.exists() {
        return Err(format!("exe not found: {:?}", use_exe_path));
    }

    let work_dir = folder.join("_static_recover");
    let _ = std::fs::create_dir_all(&work_dir);

    // Locate Rust analyzer
    let mut analyzer_exe = exe_dir.join("scheme").join("Cxdecanalyzer.exe");
    if !analyzer_exe.exists() {
        let mut repo_root = exe_dir.clone();
        loop {
            if repo_root.join("rustsrc/cxdec-rs-analyzer/target/i686-pc-windows-msvc/release/Cxdecanalyzer.exe").exists() { break; }
            if !repo_root.pop() { repo_root = exe_dir.clone(); break; }
        }
        analyzer_exe = repo_root.join("rustsrc/cxdec-rs-analyzer/target/i686-pc-windows-msvc/release/Cxdecanalyzer.exe");
    }

    if !analyzer_exe.exists() {
        return Err(format!("找不到独立纯 Rust 分析核心: {:?}", analyzer_exe));
    }

    let args = vec![
        "--exe".to_string(),
        use_exe_path.to_string_lossy().to_string(),
        "--work-dir".to_string(),
        work_dir.to_string_lossy().to_string(),
    ];

    app_log(&format!("Running Rust Analyzer: {:?} {:?}", analyzer_exe, args));
    let _ = window.emit("backend-message", serde_json::json!({
        "type": "console", "text": format!("$ {:?} {:?}\n", analyzer_exe.file_name().unwrap(), args)
    }));

    let mut child = Command::new(&analyzer_exe)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|e| format!("启动 Rust 分析核心失败: {}", e))?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let w_clone1 = window.clone();
    let w_clone2 = window.clone();
    
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().filter_map(|l| l.ok()) {
            let _ = w_clone1.emit("backend-message", serde_json::json!({ "type": "console", "text": format!("{}\n", line) }));
        }
    });

    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().filter_map(|l| l.ok()) {
            let _ = w_clone2.emit("backend-message", serde_json::json!({ "type": "console", "text": format!("{}\n", line) }));
        }
    });

    let status = child.wait().map_err(|e| format!("等待进程失败: {}", e))?;
    let _ = window.emit("backend-message", serde_json::json!({ "type": "console", "text": format!("\n[exit {}]\n", status.code().unwrap_or(-1)) }));
    
    if !status.success() {
        return Err(format!("Rust 分析核心执行失败，退出码: {:?}", status.code()));
    }

    let source_drip = work_dir.join("drip_program.json");
    let source_summary = work_dir.join("static_recover.summary.json");
    
    let prefix = folder.file_name().unwrap().to_string_lossy();
    let target_drip = folder.join(format!("{}_drip_program.json", prefix));
    let target_summary = folder.join(format!("{}_static_recover.summary.json", prefix));

    if !source_drip.exists() {
        return Err("分析成功但找不到 drip_program.json".to_string());
    }

    std::fs::copy(&source_drip, &target_drip).map_err(|e| e.to_string())?;
    convert_drip_json_to_bin(&target_drip);
    
    if source_summary.exists() {
        let _ = std::fs::copy(&source_summary, &target_summary);
    }

    // Merge metadata into _scheme.json
    let mut scheme_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&scheme_path).unwrap_or_default()).unwrap_or(serde_json::json!({}));
    let drip_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&target_drip).unwrap_or_default()).unwrap_or(serde_json::json!({}));
    let summary_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&target_summary).unwrap_or_default()).unwrap_or(serde_json::json!({}));

    if let Some(exe_obj) = scheme_json.get_mut("exe").and_then(|v| v.as_object_mut()) {
        use sha2::{Sha256, Digest};
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open(exe_path) {
            let mut hasher = Sha256::new();
            let mut buffer = [0; 8192];
            while let Ok(n) = f.read(&mut buffer) {
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            let hash = hasher.finalize();
            let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
            exe_obj.insert("sha256".to_string(), serde_json::json!(hash_hex));
        }
    }
    
    if let Some(bres_obj) = scheme_json.get_mut("bres").and_then(|v| v.as_object_mut()) {
        if let Some(s) = summary_json.get("startup_key").and_then(|v| v.as_str()) { bres_obj.insert("startup_key".to_string(), serde_json::json!(s)); }
        if let Some(s) = summary_json.get("bootstrap_key").and_then(|v| v.as_str()) { bres_obj.insert("bootstrap_key".to_string(), serde_json::json!(s)); }
        if let Some(s) = summary_json.get("bootstrap_url").and_then(|v| v.as_str()) { bres_obj.insert("bootstrap_url".to_string(), serde_json::json!(s)); }
    }

    if let Some(boot_obj) = scheme_json.get_mut("bootstrap").and_then(|v| v.as_object_mut()) {
        if let Some(s) = summary_json.get("bootstrap_prefix").and_then(|v| v.as_str()) { boot_obj.insert("prefix".to_string(), serde_json::json!(s)); }
        if let Some(s) = summary_json.get("warning").and_then(|v| v.as_str()) { boot_obj.insert("warning".to_string(), serde_json::json!(s)); }
        if let Some(s) = summary_json.get("archive_unique_key").and_then(|v| v.as_str()) { boot_obj.insert("archive_unique_key".to_string(), serde_json::json!(s)); }
    }

    if let Some(hxv4_obj) = scheme_json.get_mut("hxv4").and_then(|v| v.as_object_mut()) {
        if let Some(s) = drip_json.get("hxv4_key").and_then(|v| v.as_str()) { hxv4_obj.insert("key".to_string(), serde_json::json!(s)); }
        if let Some(s) = drip_json.get("hxv4_nonce0").and_then(|v| v.as_str()) { hxv4_obj.insert("nonce0".to_string(), serde_json::json!(s)); }
        if let Some(s) = drip_json.get("hxv4_nonce1").and_then(|v| v.as_str()) { hxv4_obj.insert("nonce1".to_string(), serde_json::json!(s)); }
    }

    if let Some(derive_obj) = scheme_json.get_mut("derive").and_then(|v| v.as_object_mut()) {
        derive_obj.insert("drip_program".to_string(), serde_json::json!(target_drip.file_name().unwrap().to_string_lossy().to_string()));
    }

    if let Some(is_s) = summary_json.get("is_steam").and_then(|v| v.as_bool()) {
        if let Some(obj) = scheme_json.as_object_mut() {
            obj.insert("is_steam".to_string(), serde_json::json!(is_s));
        }
    }

    let _ = std::fs::write(&scheme_path, serde_json::to_string_pretty(&scheme_json).unwrap());
    let _ = std::fs::remove_dir_all(&work_dir);

    Ok(format!("自动分析已完成并写入方案: {}", scheme_path.display()))
}

fn main() {
    init_logger();
    app_log("=== HXV4 XP3 Extractor Started ===");
    
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_schemes,
            run_extract_queue,
            handle_post_message,
            create_scheme_from_exe
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
