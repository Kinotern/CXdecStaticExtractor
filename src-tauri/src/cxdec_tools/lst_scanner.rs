use crate::cxdec_tools::crypto::cx_hash::{file_hash, hex_upper, path_hash};
use crate::cxdec_tools::drip_archive::DripArchive;
use crate::cxdec_tools::r#struct::pbd::{Pbd, PbdValue};
use crate::cxdec_tools::r#struct::tjs::load_tjs2_bytecode;
use crate::vm::DripProgram;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;

#[derive(Debug, Default)]
pub struct ScanStats {
    pub archives: usize,
    pub files: usize,
    pub candidates: usize,
    pub restored: usize,
    pub unresolved: usize,
    pub entries_read: usize,
    pub bytes_read: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MountedEntry {
    archive: usize,
    entry: usize,
}

pub fn run<F>(
    game_dir: &Path,
    _scan_dir: &Path,
    drip_path: &Path,
    hash_domain: &str,
    base_lst: Option<&Path>,
    final_lst: &Path,
    mut log: F,
) -> Result<ScanStats, String>
where
    F: FnMut(String),
{
    log("[1/7] 加载 Drip VM\n".to_string());
    let drip = DripProgram::load(drip_path)?;
    let mut paths = std::fs::read_dir(game_dir)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("xp3")))
        .collect::<Vec<_>>();
    paths.sort_by_key(|path| archive_priority(path));
    if paths.is_empty() { return Err("游戏目录中没有 XP3".to_string()); }

    log(format!("[2/7] 挂载 {} 个 XP3 索引\n", paths.len()));
    let mut archives = Vec::new();
    for path in &paths {
        let archive = DripArchive::open(path, &drip)?;
        log(format!("已挂载 {}: {} 个索引条目\n", path.display(), archive.records.len()));
        archives.push(archive);
    }

    let mut index: HashMap<(String, String), Vec<MountedEntry>> = HashMap::new();
    for (archive_index, archive) in archives.iter().enumerate() {
        for (&entry_index, record) in &archive.records {
            index.entry((record.domain_hash.to_ascii_uppercase(), record.file_hash.to_ascii_uppercase()))
                .or_default()
                .push(MountedEntry { archive: archive_index, entry: entry_index });
        }
    }
    let total_files = index.values().map(Vec::len).sum::<usize>();

    let mut known_dirs: HashMap<String, String> = HashMap::new();
    let mut known_files: HashMap<String, String> = HashMap::new();
    let mut output_dirs = BTreeMap::new();
    let mut output_files = BTreeMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    for candidate in default_candidates() { enqueue(candidate, &mut queue, &mut queued); }

    if let Some(path) = base_lst.filter(|path| path.is_file()) {
        log(format!("[3/7] 加载基础 LST: {}\n", path.display()));
        let content = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
        for line in content.lines() {
            let Some((hash, raw_name)) = line.split_once(':') else { continue };
            let hash = hash.trim().to_ascii_uppercase();
            let raw_name = raw_name.trim();
            let name = normalize_path(raw_name);
            if hash.len() == 16 {
                known_dirs.insert(hash.clone(), name.clone());
                output_dirs.insert(hash, if raw_name == "/" { "/".to_string() } else { name.clone() });
            } else if hash.len() == 64 {
                known_files.insert(hash.clone(), name.clone());
                output_files.insert(hash, name.clone());
            }
            if !name.is_empty() { enqueue(name, &mut queue, &mut queued); }
        }
    } else {
        log("[3/7] 无基础 LST，从启动名称开始恢复\n".to_string());
    }

    log("[4/7] 按候选哈希读取脚本和元数据\n".to_string());
    let mut read_entries = HashSet::new();
    let mut bytes_read = 0u64;
    while let Some(candidate) = queue.pop_front() {
        let Some((dir, file)) = split_candidate(&candidate) else { continue };
        let dir_hash = hex_upper(&path_hash(&dir, hash_domain));
        let file_hash_value = hex_upper(&file_hash(&file, hash_domain));
        known_dirs.entry(dir_hash.clone()).or_insert(dir.clone());
        known_files.entry(file_hash_value.clone()).or_insert(file.clone());
        let Some(matches) = index.get(&(dir_hash, file_hash_value)) else { continue };
        if matches.len() != 1 || !read_entries.insert(matches[0]) { continue; }
        let mounted = matches[0];
        let archive = &archives[mounted.archive];
        let entry_size = archive.entries[mounted.entry].original_size;
        // Candidate-driven entries are expected to be scripts or metadata. Avoid
        // accidentally reading a huge media file even if a noisy string matches it.
        if entry_size > 64 * 1024 * 1024 { continue; }
        let data = archive.read_entry(mounted.entry)?;
        bytes_read += data.len() as u64;
        collect_content_candidates(&data, &mut queue, &mut queued);
    }

    log(format!("[5/7] 名称传播完成: {} 个候选，按需读取 {} 个条目 / {} bytes\n", queued.len(), read_entries.len(), bytes_read));
    let mut restored = 0usize;
    for ((path_key, file_key), matches) in &index {
        if matches.len() != 1 { continue; }
        let Some(dir) = known_dirs.get(path_key) else { continue };
        let Some(file) = known_files.get(file_key) else { continue };
        output_dirs.insert(path_key.clone(), if dir.is_empty() { "/".to_string() } else { dir.trim_end_matches('/').to_string() });
        output_files.insert(file_key.clone(), file.clone());
        restored += 1;
    }

    if restored == 0 && output_dirs.is_empty() && output_files.is_empty() {
        return Err("没有恢复任何名称；该游戏需要基础 LST 或更多启动名称提示".to_string());
    }

    log("[6/7] 写入 LST\n".to_string());
    if let Some(parent) = final_lst.parent() { std::fs::create_dir_all(parent).map_err(|error| error.to_string())?; }
    let temp = final_lst.with_extension("lst.tmp");
    let mut text = String::new();
    for (hash, name) in &output_dirs { text.push_str(&format!("{hash}:{name}\r\n")); }
    for (hash, name) in &output_files { text.push_str(&format!("{hash}:{name}\r\n")); }
    std::fs::write(&temp, text).map_err(|error| error.to_string())?;
    if final_lst.exists() { std::fs::remove_file(final_lst).map_err(|error| error.to_string())?; }
    std::fs::rename(&temp, final_lst).map_err(|error| error.to_string())?;
    log("[7/7] LST 生成完成\n".to_string());

    Ok(ScanStats {
        archives: archives.len(), files: total_files, candidates: queued.len(), restored,
        unresolved: total_files.saturating_sub(restored), entries_read: read_entries.len(), bytes_read,
    })
}

fn archive_priority(path: &Path) -> (u8, String) {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default().to_ascii_lowercase();
    let priority = if name == "main.xp3" { 0 }
        else if name == "data.xp3" { 1 }
        else if name.contains("patch") { 2 }
        else if name.contains("scn") { 3 }
        else { 4 };
    (priority, name)
}

fn enqueue(value: String, queue: &mut VecDeque<String>, seen: &mut HashSet<String>) {
    let value = normalize_path(&value);
    if looks_like_name(&value) && seen.insert(value.clone()) { queue.push_back(value); }
}

fn split_candidate(value: &str) -> Option<(String, String)> {
    let value = normalize_path(value);
    let (dir, file) = value.rsplit_once('/').map(|(dir, file)| (format!("{dir}/"), file.to_string()))
        .unwrap_or_else(|| (String::new(), value));
    (!file.is_empty()).then_some((dir, file))
}

fn collect_content_candidates(data: &[u8], queue: &mut VecDeque<String>, seen: &mut HashSet<String>) {
    if let Ok(tjs) = load_tjs2_bytecode(data) {
        for value in tjs.string_constants() { add_tokens(value, queue, seen); }
    }
    if let Ok(pbd) = Pbd::parse(data) { collect_pbd(&pbd.root, queue, seen); }
    collect_ascii(data, queue, seen);
    collect_utf16(data, queue, seen);
}

fn collect_pbd(value: &PbdValue, queue: &mut VecDeque<String>, seen: &mut HashSet<String>) {
    match value {
        PbdValue::String(value) => add_tokens(value, queue, seen),
        PbdValue::Array(values) => for value in values { collect_pbd(value, queue, seen); },
        PbdValue::Dictionary(values) => for (key, value) in values { add_tokens(key, queue, seen); collect_pbd(value, queue, seen); },
        _ => {}
    }
}

fn collect_ascii(data: &[u8], queue: &mut VecDeque<String>, seen: &mut HashSet<String>) {
    for bytes in data.split(|byte| !byte.is_ascii_graphic() && *byte != b' ') {
        if bytes.len() >= 4 { if let Ok(value) = std::str::from_utf8(bytes) { add_tokens(value, queue, seen); } }
    }
}

fn collect_utf16(data: &[u8], queue: &mut VecDeque<String>, seen: &mut HashSet<String>) {
    for alignment in 0..=1 {
        let mut words = Vec::new();
        for pair in data[alignment..].chunks_exact(2) {
            let word = u16::from_le_bytes([pair[0], pair[1]]);
            if word >= 0x20 && word != 0x7f { words.push(word); }
            else { if words.len() >= 4 { if let Ok(value) = String::from_utf16(&words) { add_tokens(&value, queue, seen); } } words.clear(); }
        }
    }
}

fn add_tokens(value: &str, queue: &mut VecDeque<String>, seen: &mut HashSet<String>) {
    for token in value.split(['"', '\'', '<', '>', '|', '\r', '\n', '\t', '=', ',', ';', '(', ')', '[', ']']) {
        enqueue(token.to_string(), queue, seen);
    }
}

fn normalize_path(value: &str) -> String {
    let value = value.trim().trim_matches('\0').replace('\\', "/");
    let value = value.strip_prefix("file://./").or_else(|| value.strip_prefix("storage://./")).unwrap_or(&value);
    value.trim_start_matches("./").split('/').filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .map(str::to_lowercase).collect::<Vec<_>>().join("/")
}

fn looks_like_name(value: &str) -> bool {
    if value.len() < 3 || value.len() > 512 { return false; }
    let leaf = value.rsplit('/').next().unwrap_or(value);
    value.contains('/') || leaf.rsplit_once('.').is_some_and(|(stem, ext)| !stem.is_empty() && (1..=8).contains(&ext.len()) && ext.chars().all(|ch| ch.is_ascii_alphanumeric()))
}

fn default_candidates() -> Vec<String> {
    ["system/Initialize.tjs", "data/system/Initialize.tjs", "system/Config.tjs", "system/MainWindow.tjs",
     "system/MessageLayer.tjs", "Initialize.tjs", "!scnlist.txt", "scenario/!scnlist.txt", "scn/!scnlist.txt",
     "scenario/first.scn", "data/system/Config.tjs", "data/system/MainWindow.tjs"]
        .into_iter().map(str::to_string).collect()
}
