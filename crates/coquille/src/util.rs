//! Small helpers: paths, hashes, JSON objects, UTF-16 offsets.

use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The user's home directory.
pub fn home() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(home);
    }
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|u| u.dir)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// The home directory of `user`, if there is such a user.
pub fn user_home(user: &str) -> Option<PathBuf> {
    nix::unistd::User::from_name(user).ok().flatten().map(|u| u.dir)
}

/// The working directory (`/` if it can't be had).
pub fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
}

/// `path` made absolute against `base` and normalized lexically (`.` and
/// `..` resolved, symlinks left alone), as node's `path.resolve`.
pub fn resolve(base: &Path, path: impl AsRef<Path>) -> PathBuf {
    let joined = base.join(path);
    let mut out = PathBuf::from("/");
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(c) => out.push(c),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// `~` and `~/...` expanded to the home directory.
pub fn expand_home(word: &str) -> String {
    if word == "~" {
        home().to_string_lossy().into_owned()
    } else if let Some(rest) = word.strip_prefix("~/") {
        home().join(rest).to_string_lossy().into_owned()
    } else {
        word.to_owned()
    }
}

/// A path with the home directory as `~`.
pub fn tildify(file: &str) -> String {
    let home = home();
    let home = home.to_string_lossy();
    if file == home {
        return "~".into();
    }
    match file.strip_prefix(&*home) {
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => file.to_owned(),
    }
}

/// Whether `path` is a regular file this user may execute.
pub fn is_executable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            meta.permissions().mode() & 0o111 != 0
                && nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
        }
        _ => false,
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The length of `s` in UTF-16 code units (JavaScript's `length`: what the
/// terminal counts selections in).
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// The byte offset in `s` of UTF-16 offset `n` (clamped to the text, and
/// down to a character boundary).
pub fn utf16_to_byte(s: &str, n: usize) -> usize {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        if units >= n {
            return i;
        }
        units += c.len_utf16();
    }
    s.len()
}

/// Describe a JSON value's kind, for error messages.
pub fn describe(x: &Value) -> &'static str {
    match x {
        Value::Null => "null",
        Value::Array(_) => "a list",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Object(_) => "object",
    }
}

/// `base` with the fields of `extra` set over it (JavaScript's `{...base,
/// ...extra}`: a field already there keeps its place).
pub fn merged(base: Value, extra: Value) -> Value {
    match (base, extra) {
        (Value::Object(mut a), Value::Object(b)) => {
            for (k, v) in b {
                a.insert(k, v);
            }
            Value::Object(a)
        }
        (a, Value::Null) => a,
        (_, b) => b,
    }
}

/// Insert `key: value` in `obj`, if `value` is some.
pub fn put_opt(obj: &mut Map<String, Value>, key: &str, value: Option<impl Into<Value>>) {
    if let Some(value) = value {
        obj.insert(key.to_owned(), value.into());
    }
}

/// The segments of an address (a JSON array of strings), if it is one.
pub fn address_of(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|s| s.as_str().map(str::to_owned))
        .collect()
}

/// Incremental UTF-8 decoding of a byte stream: a character split between
/// two reads is decoded whole, with the second.
#[derive(Default)]
pub struct Utf8Decoder {
    pending: Vec<u8>,
}

impl Utf8Decoder {
    pub fn decode(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        let valid = match std::str::from_utf8(&self.pending) {
            Ok(_) => self.pending.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => self.pending.len(), // invalid, not merely cut: replacement characters
        };
        let rest = self.pending.split_off(valid);
        let text = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending = rest;
        text
    }

    /// What is left at the end of the stream.
    pub fn finish(&mut self) -> String {
        let text = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_paths() {
        assert_eq!(resolve(Path::new("/a/b"), "../c/./d"), PathBuf::from("/a/c/d"));
        assert_eq!(resolve(Path::new("/a"), "/x/../y"), PathBuf::from("/y"));
        assert_eq!(resolve(Path::new("/"), ".."), PathBuf::from("/"));
    }

    #[test]
    fn utf16_offsets() {
        let s = "a😀b";
        assert_eq!(utf16_len(s), 4);
        assert_eq!(utf16_to_byte(s, 1), 1);
        assert_eq!(utf16_to_byte(s, 3), 5);
        assert_eq!(utf16_to_byte(s, 9), 6);
    }

    #[test]
    fn decodes_split_characters() {
        let mut d = Utf8Decoder::default();
        let bytes = "é!".as_bytes();
        assert_eq!(d.decode(&bytes[..1]), "");
        assert_eq!(d.decode(&bytes[1..]), "é!");
    }
}
