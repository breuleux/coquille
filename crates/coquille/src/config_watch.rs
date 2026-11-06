//! Noticing configuration changes. The shell snapshots the files its
//! configuration depends on when it loads it, then polls them: when they no
//! longer match, it asks the user (a pending request: see requests.rs)
//! whether to reload. The answer holds for the exact version of the files it
//! was asked about.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::util::sha256_hex;

/// The state of a set of files: a hash of each one's content (None: absent).
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// One hash for the whole set: equal versions, identical files.
    pub version: String,
    pub files: BTreeMap<String, Option<String>>,
}

pub fn snapshot<'a>(paths: impl IntoIterator<Item = &'a String>) -> Snapshot {
    let mut files = BTreeMap::new();
    for file in paths {
        // (Absent, or unreadable: loading says why.)
        let hash = std::fs::read(file).ok().map(|data| sha256_hex(&data));
        files.insert(file.clone(), hash);
    }
    let mut whole = Sha256::new();
    for (file, hash) in &files {
        whole.update(format!("{file}\0{}\0", hash.as_deref().unwrap_or("-")));
    }
    let version = hex::encode(whole.finalize())[..16].to_owned();
    Snapshot { version, files }
}

#[derive(Clone, Debug)]
pub struct FileChange {
    pub file: String,
    pub change: &'static str,
}

/// What changed from `before` to `after` (which watch the same files).
pub fn changes(before: &Snapshot, after: &Snapshot) -> Vec<FileChange> {
    let mut result = Vec::new();
    for (file, hash) in &after.files {
        let old = before.files.get(file).cloned().flatten();
        if old == *hash {
            continue;
        }
        let change = match (&old, hash) {
            (None, _) => "created",
            (_, None) => "deleted",
            _ => "modified",
        };
        result.push(FileChange { file: file.clone(), change });
    }
    result
}
