//! Control commands: the programs allowed to address the shell (["$shell"]):
//! to submit commands, change the prompt, start daemons... Any other process
//! may only switch its own stdout's mode (see OPEN_TO_ALL).
//!
//! They are listed in the global configuration (`control-commands`: see
//! config.rs), as {path, hash}: a full path, and the SHA-256 of the file, or
//! null to take it whatever it holds (a program of one's own, often changed).
//! A process gets the privilege when this shell starts it from a listed file
//! (resolved as execvp would, symlinks followed) whose content matches: the
//! shell then runs that very file (by its real path), and the privilege is
//! that process's alone: what it starts gets none, unless it hands its own
//! channel (fd 5) on — whatever speaks on it speaks as it — so a control
//! command that runs other programs must not relay their messages to
//! ["$shell"].

use std::cell::RefCell;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::util::{is_executable, resolve, sha256_hex};

/// An approved file: its full path, and its SHA-256 (hex), or None for any
/// content.
#[derive(Clone, Debug)]
pub struct ControlCommand {
    pub path: PathBuf,
    pub hash: Option<String>,
}

/// The messages to ["$shell"] any process may send: those about itself.
pub const OPEN_TO_ALL: &[&str] = &["stdout_mode"];

/// Whether a SHA-256 is written as the configuration takes it.
pub fn is_hash(x: &str) -> bool {
    x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What starting a command is allowed: where to run it from, and whether it
/// may address the shell (and if not, why: for the error it then gets).
#[derive(Clone, Debug)]
pub struct Approval {
    /// The command to run: the checked path, if the command was approved.
    pub cmd: String,
    pub privileged: bool,
    pub refusal: String,
}

/// The file `cmd` runs, as execvp finds it (in `path`, from `cwd`).
pub fn resolve_executable(cmd: &str, path: &str, cwd: &Path) -> Option<PathBuf> {
    if cmd.contains('/') {
        return Some(resolve(cwd, cmd));
    }
    path.split(':')
        .map(|dir| resolve(cwd, if dir.is_empty() { "." } else { dir }).join(cmd))
        .find(|candidate| is_executable(candidate))
}

thread_local! {
    /// Hashes already computed, by file and state (a change of content
    /// changes the ctime, which can't be set back).
    static HASHES: RefCell<HashMap<(u64, u64, u64, i64, i64), String>> = RefCell::default();
}

fn sha256_file(file: &Path) -> std::io::Result<String> {
    let st = std::fs::metadata(file)?;
    let key = (st.dev(), st.ino(), st.size(), st.ctime(), st.ctime_nsec());
    if let Some(hash) = HASHES.with(|h| h.borrow().get(&key).cloned()) {
        return Ok(hash);
    }
    let hash = sha256_hex(&std::fs::read(file)?);
    HASHES.with(|h| h.borrow_mut().insert(key, hash.clone()));
    Ok(hash)
}

/// Whether `cmd`, started from `cwd` with `path` (PATH), is a control
/// command (see above). One that is runs from the real path checked, not
/// looked up again. (A file changed between the check and the exec runs as
/// changed: whoever can write it can as well make it what is approved.)
pub fn approve(cmd: &str, path: &str, cwd: &Path, commands: &[ControlCommand]) -> Approval {
    let refuse = |refusal: String| Approval { cmd: cmd.to_owned(), privileged: false, refusal };
    let exe = resolve_executable(cmd, path, cwd);
    let Some((exe, real)) = exe.and_then(|e| std::fs::canonicalize(&e).ok().map(|r| (e, r))) else {
        return refuse(format!("{cmd:?} is not a control command"));
    };
    let exe = exe.display();
    let entries: Vec<_> = commands
        .iter()
        .filter(|c| std::fs::canonicalize(&c.path).ok().as_ref() == Some(&real))
        .collect();
    if entries.is_empty() {
        return refuse(format!("{exe} is not a control command (see control-commands)"));
    }
    if !entries.iter().any(|c| c.hash.is_none()) {
        let actual = match sha256_file(&real) {
            Ok(hash) => hash,
            Err(err) => return refuse(format!("{exe} could not be checked: {err}")),
        };
        let matches = |c: &&ControlCommand| c.hash.as_ref().is_some_and(|h| h.to_lowercase() == actual);
        if !entries.iter().any(matches) {
            return refuse(format!(
                "{exe} does not match its hash in control-commands; it is now {actual}"
            ));
        }
    }
    // (Its real path: a symlink to it could be pointed elsewhere meanwhile.)
    Approval { cmd: real.to_string_lossy().into_owned(), privileged: true, refusal: String::new() }
}
