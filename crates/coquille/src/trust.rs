//! Trusting a directory's configuration, as direnv does `.envrc` files: a
//! `.cq.yaml` (or what it sources, or a script its `source-env` runs) is only
//! applied once the user has trusted that file *with that content*. Trusted
//! contents are remembered by file (a few versions each, so that going back
//! and forth between branches doesn't ask again), here:
//!
//!   $XDG_DATA_HOME/cq/trusted.json (~/.local/share/cq/trusted.json)
//!
//! The global configuration (and what it sources) is the user's own: it is
//! always trusted.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::util::home;

/// How many contents of a file are remembered (the last trusted).
const VERSIONS_KEPT: usize = 32;

pub fn trust_file() -> PathBuf {
    let data = std::env::var_os("XDG_DATA_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local").join("share"));
    data.join("cq").join("trusted.json")
}

/// A file, as it was (or is to be) trusted: its path and content's SHA-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedFile {
    pub file: String,
    pub hash: String,
}

impl TrustedFile {
    /// The file with this content, as a key.
    pub fn key(&self) -> String {
        format!("{}\0{}", self.file, self.hash)
    }
}

/// The trusted contents, by file (read anew each time: another shell may
/// have trusted some meanwhile).
fn read() -> BTreeMap<String, Vec<String>> {
    let Ok(text) = std::fs::read_to_string(trust_file()) else {
        return BTreeMap::new();
    };
    let Ok(data) = serde_json::from_str::<Value>(&text) else {
        return BTreeMap::new();
    };
    let Some(files) = data.get("files").and_then(Value::as_object) else {
        return BTreeMap::new();
    };
    files
        .iter()
        .filter_map(|(file, hashes)| {
            let hashes = hashes.as_array()?.iter().filter_map(|h| h.as_str().map(str::to_owned));
            Some((file.clone(), hashes.collect()))
        })
        .collect()
}

/// Whether `file` was trusted with the content of this hash.
pub fn is_trusted(file: &str, hash: &str) -> bool {
    read().get(file).is_some_and(|h| h.iter().any(|x| x == hash))
}

/// Whether some content of `file` was ever trusted.
pub fn was_trusted(file: &str) -> bool {
    read().get(file).is_some_and(|h| !h.is_empty())
}

/// Trust these files with these contents.
pub fn trust(files: &[TrustedFile]) -> std::io::Result<()> {
    let mut data = read();
    for TrustedFile { file, hash } in files {
        let hashes = data.entry(file.clone()).or_default();
        hashes.retain(|h| h != hash);
        hashes.push(hash.clone());
        let excess = hashes.len().saturating_sub(VERSIONS_KEPT);
        hashes.drain(..excess);
    }
    let path = trust_file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let text = serde_json::to_string_pretty(&json!({ "files": data }))?;
    std::fs::write(&tmp, format!("{text}\n"))?;
    std::fs::rename(&tmp, &path)
}
