//! Libraries: groups of files a process wants served to its GUI at
//! `lib://<id>/<path>` (see buche's src/library.ts for the whole scheme).
//!
//! Each process gets a salt of its own (BUCHE_LIB_SALT). It declares a
//! library on its control channel with, for each file, a *proof* that it can
//! read it — HMAC-SHA256(key: the salt, message: the content), in hex:
//!
//!   {"type": "library", "from": ["$proc"], "id": "<16-63 chars of [a-z0-9-]>",
//!    "files": {"js/main.js": {"file": "/abs/path/main.js",
//!                             "mimetype": "text/javascript",
//!                             "proof": "<hex>"}}}
//!
//! The shell reads every file, checks the proofs, and passes the declaration
//! on with the files' SHA-256 in place of the proofs.
//!
//! A file may instead come with its content, inline — `{"mimetype": ...,
//! "content": "...", "encoding": "utf-8" | "base64"}` — which needs no proof
//! (and no salt): it is passed on as is, with its hash. A hash alone proves
//! nothing (hashes of files leak: git indexes, package databases...); a proof
//! can only be computed from the content, by the process that got the salt.
//!
//! Under buche, the shell is then the library's authority: asked for a file
//! by hash (`library_fetch`), it reads it again and sends it if it still has
//! that hash (`library_content`). Under another shell (which gave this one a
//! salt of its own), it proves the files to that shell in turn, which becomes
//! the authority.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::util::sha256_hex;

/// The environment variable a process finds its salt in.
pub const LIB_SALT_ENV: &str = "BUCHE_LIB_SALT";

/// The largest file a library may hold.
const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;

pub fn new_salt() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

pub fn library_proof(salt: &str, data: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt.as_bytes()).expect("HMAC takes any key");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// The content of `file`, an absolute path to a regular file, read through a
/// single descriptor (what is checked is what is sent). Opened non-blocking,
/// so a FIFO can't hang the shell before it is refused.
pub fn read_regular_file(file: &Path) -> anyhow::Result<Vec<u8>> {
    if !file.is_absolute() {
        bail!("not an absolute path: {}", file.display());
    }
    let mut handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(file)
        .with_context(|| file.display().to_string())?;
    let meta = handle.metadata()?;
    if !meta.is_file() {
        bail!("not a regular file: {}", file.display());
    }
    if meta.len() > MAX_FILE_SIZE {
        bail!("too large: {}", file.display());
    }
    let mut data = Vec::new();
    (&mut handle).take(MAX_FILE_SIZE + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_FILE_SIZE {
        bail!("too large: {}", file.display());
    }
    Ok(data)
}

/// A file of a library, its proof checked (or its content given).
pub struct VerifiedFile {
    /// The file, absent for inline content.
    file: Option<PathBuf>,
    mimetype: String,
    data: Vec<u8>,
    /// The content and its encoding, as given inline, if it was.
    inline: Option<(String, String)>,
}

/// Check a process's library declaration against the files, with the salt
/// it was given: its id, and the files, by path in the library.
pub async fn verify_library(message: &Value, salt: &str) -> anyhow::Result<(String, Vec<(String, VerifiedFile)>)> {
    let id = message.get("id").and_then(Value::as_str).ok_or_else(|| anyhow!("library: `id` must be a string"))?;
    let files = message
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("library {id}: `files` must be an object"))?;
    let mut verified = Vec::new();
    for (lib_path, entry) in files {
        let field = |name: &str| entry.get(name).and_then(Value::as_str);
        if let (Some(content), Some(mimetype)) = (field("content"), field("mimetype")) {
            let encoding = match entry.get("encoding") {
                None => "utf-8",
                Some(Value::String(e)) if e == "utf-8" || e == "base64" => e.as_str(),
                Some(other) => bail!("library {id}: {lib_path}: unknown encoding {other}"),
            };
            let data = if encoding == "base64" {
                BASE64.decode(content).with_context(|| format!("library {id}: {lib_path}"))?
            } else {
                content.as_bytes().to_vec()
            };
            let inline = Some((content.to_owned(), encoding.to_owned()));
            verified.push((lib_path.clone(), VerifiedFile { file: None, mimetype: mimetype.into(), data, inline }));
            continue;
        }
        let (Some(file), Some(mimetype), Some(proof)) = (field("file"), field("mimetype"), field("proof")) else {
            bail!("library {id}: {lib_path} needs `mimetype`, and `file` and `proof` or `content`");
        };
        let path = PathBuf::from(file);
        let data = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || read_regular_file(&path)).await?
        }
        .map_err(|err| anyhow!("library {id}: {lib_path}: {err:#}"))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(salt.as_bytes()).expect("HMAC takes any key");
        mac.update(&data);
        let given = hex::decode(proof.to_lowercase()).unwrap_or_default();
        if mac.verify_slice(&given).is_err() {
            bail!("library {id}: {lib_path}: the proof does not match {file}");
        }
        verified.push((lib_path.clone(), VerifiedFile { file: Some(path), mimetype: mimetype.into(), data, inline: None }));
    }
    Ok((id.to_owned(), verified))
}

/// The files of the libraries this shell is the authority for, by content
/// hash: where to read a content again when buche asks for it.
#[derive(Default)]
pub struct LibraryFiles {
    by_hash: RefCell<HashMap<String, HashSet<PathBuf>>>,
}

impl LibraryFiles {
    pub fn add(&self, hash: String, file: PathBuf) {
        self.by_hash.borrow_mut().entry(hash).or_default().insert(file);
    }

    /// The content with SHA-256 `hash`, from a file declared with it (if one
    /// still has it).
    pub async fn read(&self, hash: &str) -> anyhow::Result<Vec<u8>> {
        let files: Vec<PathBuf> = self.by_hash.borrow().get(hash).into_iter().flatten().cloned().collect();
        let wanted = hash.to_owned();
        tokio::task::spawn_blocking(move || {
            files
                .iter()
                .filter_map(|f| read_regular_file(f).ok())
                .find(|data| sha256_hex(data) == wanted)
        })
        .await?
        .ok_or_else(|| anyhow!("no declared file has the content {hash} anymore"))
    }
}

/// What a verified declaration becomes on the way up: for buche (no salt of
/// our own), the files' hashes, this shell becoming their authority; for a
/// shell above us, the files with our own proofs.
pub fn forward_library(
    id: &str,
    files: Vec<(String, VerifiedFile)>,
    authority: &LibraryFiles,
    parent_salt: Option<&str>,
) -> anyhow::Result<Value> {
    let mut out = Map::new();
    for (lib_path, VerifiedFile { file, mimetype, data, inline }) in files {
        let entry = match (inline, file, parent_salt) {
            // Inline: for whoever is above, as is (buche checks the hash).
            (Some((content, encoding)), _, salt) => {
                let mut e = json!({ "mimetype": mimetype, "content": content, "encoding": encoding });
                if salt.is_none() {
                    e["hash"] = json!(sha256_hex(&data));
                }
                e
            }
            (None, None, _) => bail!("library {id}: {lib_path}: no file"),
            (None, Some(file), Some(salt)) => {
                json!({ "file": file, "mimetype": mimetype, "proof": library_proof(salt, &data) })
            }
            (None, Some(file), None) => {
                let hash = sha256_hex(&data);
                authority.add(hash.clone(), file);
                json!({ "hash": hash, "mimetype": mimetype })
            }
        };
        out.insert(lib_path, entry);
    }
    Ok(json!({ "type": "library", "id": id, "files": out }))
}
