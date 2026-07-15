//! Runtime game-specific KiriKiri schemes exported from GARbro Formats.dat.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const FORMATS_JSON_NAME: &str = "formats.json";
const SOURCE_FORMATS_JSON: &str = "src/bin/formats.json";
const DEFAULT_FORMATS_JSON: &str = "target/formats.json";
const FALLBACK_FORMATS_JSON: &str = "target/cx_schemes_resources.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptVariant {
    CxEncryption,
    SenrenCxCrypt,
    CabbageCxCrypt,
    NanaCxCrypt,
    RiddleCxCrypt,
    HxCrypt,
    HxCryptLite,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct GameScheme {
    pub title: String,
    pub variant: CryptVariant,
    pub mask: u32,
    pub offset: u32,
    pub prolog_order: [u8; 3],
    pub odd_branch_order: [u8; 6],
    pub even_branch_order: [u8; 8],
    pub control_block: Option<Vec<u32>>,
    pub tpm_file_name: Option<String>,
    pub startup_tjs_not_encrypted: bool,
    pub obfuscated_index: bool,
    pub hash_after_crypt: bool,
    pub nana_random_seed: Option<u32>,
    pub yuz_key: Option<Vec<u32>>,
    pub riddle_key1: Option<u32>,
    pub riddle_key2: Option<u32>,
    pub hx_filter_key: Option<u64>,
    pub hx_random_type: Option<i32>,
    pub hx_names_file: Option<String>,
    pub hx_index_key1: Option<Vec<u8>>,
    pub hx_index_key2: Option<Vec<u8>>,
    pub hx_index_key_dict: HashMap<String, HxIndexKey>,
}

#[derive(Debug, Clone)]
pub struct HxIndexKey {
    pub key1: Vec<u8>,
    pub key2: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct FormatsJson {
    items: Vec<JsonGameScheme>,
}

#[derive(Debug, Deserialize)]
struct JsonGameScheme {
    title: String,
    #[serde(rename = "type")]
    kind: String,
    mask: u32,
    offset: u32,
    prolog_order: Option<Vec<u8>>,
    odd_branch_order: Option<Vec<u8>>,
    even_branch_order: Option<Vec<u8>>,
    control_block: Option<Vec<u32>>,
    tpm_file_name: Option<String>,
    startup_tjs_not_encrypted: bool,
    obfuscated_index: bool,
    hash_after_crypt: bool,
    nana_random_seed: Option<u32>,
    yuz_key: Option<Vec<u32>>,
    riddle_key1: Option<u32>,
    riddle_key2: Option<u32>,
    hx_filter_key: Option<u64>,
    hx_random_type: Option<i32>,
    hx_names_file: Option<String>,
    hx_index_key1: Option<Vec<u8>>,
    hx_index_key2: Option<Vec<u8>>,
    hx_index_key_dict: Option<HashMap<String, JsonHxIndexKey>>,
}

#[derive(Debug, Deserialize)]
struct JsonHxIndexKey {
    key1: Option<Vec<u8>>,
    key2: Option<Vec<u8>>,
}

static GAMES: OnceLock<Vec<GameScheme>> = OnceLock::new();

impl GameScheme {
    // Returns whether supported by CX decoder.
    pub fn is_supported_by_cx_decoder(&self) -> bool {
        match self.variant {
            CryptVariant::CxEncryption
            | CryptVariant::SenrenCxCrypt
            | CryptVariant::CabbageCxCrypt
            | CryptVariant::NanaCxCrypt => true,
            CryptVariant::HxCrypt => {
                self.hx_filter_key.is_some()
                    && ((self.hx_index_key1.is_some() && self.hx_index_key2.is_some())
                        || !self.hx_index_key_dict.is_empty())
            }
            _ => false,
        }
    }

    // Converts this value to CX scheme.
    pub fn to_cx_scheme(&self) -> crate::cxdec_tools::crypto::hxv4_shellcode::CxScheme {
        crate::cxdec_tools::crypto::hxv4_shellcode::CxScheme {
            mask: self.mask,
            offset: self.offset,
            prolog_order: self.prolog_order,
            odd_branch_order: self.odd_branch_order,
            even_branch_order: self.even_branch_order,
            control_block: self.control_block.clone(),
            tpm_file_name: self.tpm_file_name.clone(),
            nana_random_seed: self.nana_random_seed,
            hx_random_type: self.hx_random_type,
        }
    }

    // Converts this value to XP3 HX options.
    pub fn to_xp3_hx_options(
        &self,
        archive_dir: Option<&Path>,
    ) -> crate::cxdec_tools::r#struct::xp3::Xp3HxOptions {
        let names_file = self
            .hx_names_file
            .as_deref()
            .map(|name| archive_dir.map_or_else(|| name.into(), |dir| dir.join(name)));
        let index_key_dict = self
            .hx_index_key_dict
            .iter()
            .map(|(name, key)| {
                (
                    name.clone(),
                    crate::cxdec_tools::r#struct::xp3::Xp3HxIndexKey {
                        key1: key.key1.clone(),
                        key2: key.key2.clone(),
                    },
                )
            })
            .collect();
        crate::cxdec_tools::r#struct::xp3::Xp3HxOptions {
            index_key1: self.hx_index_key1.clone(),
            index_key2: self.hx_index_key2.clone(),
            index_key_dict,
            names_file,
        }
    }
}

// Handles games behavior.
pub fn games() -> Result<&'static [GameScheme], Box<dyn std::error::Error>> {
    if let Some(games) = GAMES.get() {
        return Ok(games);
    }
    let loaded = load_games(default_formats_json_path()?)?;
    let _ = GAMES.set(loaded);
    Ok(GAMES.get().unwrap())
}

// Finds game.
pub fn find_game(name: &str) -> Result<Option<&'static GameScheme>, Box<dyn std::error::Error>> {
    let games = games()?;
    if let Some(game) = games
        .iter()
        .find(|game| game.title.eq_ignore_ascii_case(name))
    {
        return Ok(Some(game));
    }
    let needle = name.to_lowercase();
    let mut matches = games
        .iter()
        .filter(|game| game.title.to_lowercase().contains(&needle));
    let first = matches.next();
    if first.is_some() && matches.next().is_none() {
        Ok(first)
    } else {
        Ok(None)
    }
}

// Loads games.
pub fn load_games(path: impl AsRef<Path>) -> Result<Vec<GameScheme>, Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)?;
    let json: FormatsJson = serde_json::from_str(&data)?;
    Ok(json.items.into_iter().map(GameScheme::from).collect())
}

// Handles default formats JSON path behavior.
fn default_formats_json_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(path) = std::env::var("CXDEC_FORMATS_JSON") {
        return Ok(path.into());
    }
    if let Some(path) = executable_formats_json_path() {
        return Ok(path);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let direct = cwd.join(FORMATS_JSON_NAME);
        if direct.is_file() {
            return Ok(direct);
        }
        if cwd.file_name().is_some_and(|name| name.eq_ignore_ascii_case("src-tauri")) {
            if let Some(parent) = cwd.parent() {
                let project = parent.join(FORMATS_JSON_NAME);
                if project.is_file() {
                    return Ok(project);
                }
            }
        }
    }
    let source = PathBuf::from(SOURCE_FORMATS_JSON);
    if source.exists() {
        return Ok(source);
    }
    let primary = PathBuf::from(DEFAULT_FORMATS_JSON);
    if primary.exists() {
        return Ok(primary);
    }
    let fallback = PathBuf::from(FALLBACK_FORMATS_JSON);
    if fallback.exists() {
        return Ok(fallback);
    }
    Err(
        format!("formats JSON not found: set CXDEC_FORMATS_JSON or create {SOURCE_FORMATS_JSON}")
            .into(),
    )
}

// Handles executable formats JSON path behavior.
fn executable_formats_json_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.join(FORMATS_JSON_NAME);
    path.exists().then_some(path)
}

// Handles variant behavior.
fn variant(name: &str) -> CryptVariant {
    match name {
        "CxEncryption" => CryptVariant::CxEncryption,
        "SenrenCxCrypt" => CryptVariant::SenrenCxCrypt,
        "CabbageCxCrypt" => CryptVariant::CabbageCxCrypt,
        "NanaCxCrypt" => CryptVariant::NanaCxCrypt,
        "RiddleCxCrypt" => CryptVariant::RiddleCxCrypt,
        "HxCrypt" => CryptVariant::HxCrypt,
        "HxCryptLite" => CryptVariant::HxCryptLite,
        _ => CryptVariant::Unknown,
    }
}

// Handles array behavior.
fn array<const N: usize>(value: Option<Vec<u8>>, default: [u8; N]) -> [u8; N] {
    let Some(value) = value else {
        return default;
    };
    value.try_into().unwrap_or(default)
}

impl From<JsonGameScheme> for GameScheme {
    // Converts the source value into this type.
    fn from(value: JsonGameScheme) -> Self {
        let hx_index_key_dict = value
            .hx_index_key_dict
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(name, key)| {
                Some((
                    name,
                    HxIndexKey {
                        key1: key.key1?,
                        key2: key.key2?,
                    },
                ))
            })
            .collect();
        GameScheme {
            title: value.title,
            variant: variant(&value.kind),
            mask: value.mask,
            offset: value.offset,
            prolog_order: array(value.prolog_order, [0, 1, 2]),
            odd_branch_order: array(value.odd_branch_order, [0, 1, 2, 3, 4, 5]),
            even_branch_order: array(value.even_branch_order, [0, 1, 2, 3, 4, 5, 6, 7]),
            control_block: value.control_block,
            tpm_file_name: value.tpm_file_name,
            startup_tjs_not_encrypted: value.startup_tjs_not_encrypted,
            obfuscated_index: value.obfuscated_index,
            hash_after_crypt: value.hash_after_crypt,
            nana_random_seed: value.nana_random_seed,
            yuz_key: value.yuz_key,
            riddle_key1: value.riddle_key1,
            riddle_key2: value.riddle_key2,
            hx_filter_key: value.hx_filter_key,
            hx_random_type: value.hx_random_type,
            hx_names_file: value.hx_names_file,
            hx_index_key1: value.hx_index_key1,
            hx_index_key2: value.hx_index_key2,
            hx_index_key_dict,
        }
    }
}
