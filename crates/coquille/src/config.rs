//! Configuration: `.cq.yaml` files from the working directory up to the root,
//! then the global config (~/.config/cq/config.yaml, /etc/xdg/cq/config.yaml),
//! then coquille's own defaults (resources/default-config.yaml), merged key by
//! key with the nearest file winning. A directory's files (not the global
//! ones) are only used if the user trusted them with what they hold (see
//! trust.rs); the others are left out, as if absent, and reported
//! (`untrusted`).
//!
//! Loading never fails: a file or entry that can't be used is skipped and
//! reported in `errors` (the shell sends them to the terminal).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::approval::{ControlCommand, is_hash};
use crate::prompt::template_problem;
use crate::trust::{TrustedFile, is_trusted};
use crate::util::{describe, expand_home, home, resolve, sha256_hex};

const DEFAULT_CONFIG: &str = include_str!("../resources/default-config.yaml");
const DEFAULT_CONFIG_NAME: &str = "<default configuration>";

#[derive(Clone, Debug, PartialEq)]
pub struct EnvValue {
    pub value: String,
    pub export: bool,
}

/// A daemon, as configured (see `daemons`).
#[derive(Clone, Debug, PartialEq)]
pub struct DaemonSpec {
    pub cmd: String,
    pub args: Vec<String>,
    /// Directory of the config file that declared it.
    pub config_dir: String,
}

/// The prompt actions coquille implements itself (`{builtin: <name>}`).
pub const BUILTIN_ACTIONS: &[&str] = &["submit", "run", "previous", "next", "complete", "close", "requests"];

/// Actions that freeze the prompt by default when they fire.
const FREEZING_ACTIONS: &[&str] = &["submit", "close"];

/// A problem with the configuration: what was skipped, and where.
#[derive(Clone, Debug)]
pub struct ConfigError {
    /// The file it is in, if any.
    pub file: Option<String>,
    pub message: String,
}

/// One part of the prompt's text, as configured (see PromptSpec). Its `text`
/// and `style` are templates (see prompt.rs: `$NAME`, `${NAME|filter|...}`,
/// `$$`). Nothing is run. In `action`, the variables are expanded (the rest
/// is a command line, run when clicked).
#[derive(Clone, Debug)]
pub enum PartSpec {
    Text { text: String, style: Option<String>, action: Option<Value> },
    Spacer { action: Option<Value> },
    /// Parts taken together: shown only if every substitution in them comes
    /// out non-empty (e.g. a separator and the git branch, outside of a
    /// repository; a group in it that hides doesn't hide it), styled
    /// together and one click target for its action (see buche's
    /// GroupPart). Its style is a template, like a text's.
    Group { group: Vec<PartSpec>, style: Option<String>, action: Option<Value> },
}

/// The prompt's look, as configured: its variables (templates, like the
/// parts' texts, expanded in order: each can use those before it), COLOR
/// being its accent; and its parts.
#[derive(Clone, Debug, Default)]
pub struct PromptSpec {
    pub vars: Vec<(String, String)>,
    pub parts: Vec<PartSpec>,
}

#[derive(Debug, Default)]
pub struct ResolvedConfig {
    pub env: IndexMap<String, EnvValue>,
    /// The daemons: processes run along with the shell, by name.
    pub daemons: IndexMap<String, DaemonSpec>,
    /// Key chord → what it does (a validated action: see parse_action).
    pub bindings: IndexMap<String, Value>,
    /// How the prompt looks.
    pub prompt: PromptSpec,
    /// How many commands the history keeps (see `history.size`).
    pub history_size: usize,
    /// The programs that may address the shell (see approval.rs).
    pub control_commands: Vec<ControlCommand>,
    pub errors: Vec<ConfigError>,
    /// Every file the configuration depends on: those read, and those looked
    /// for but absent (a `.cq.yaml` that would apply if created), including
    /// `source-env` scripts. Watching them tells when to reload.
    pub files: Vec<String>,
    /// Of those, the ones that need the user's trust (see trust.rs): a
    /// directory's, not the global configuration's.
    pub local: Vec<String>,
    /// The ones of those that were applied: trusted with the content read.
    pub trusted: Vec<String>,
    /// And the ones that weren't: present, but not trusted with the content
    /// they have (as read).
    pub untrusted: Vec<TrustedFile>,
}

struct ConfigEntry {
    data: Map<String, Value>,
    dir: PathBuf,
    file: String,
    /// Whether it is coquille's defaults, a global file, or one a global
    /// file sources: the user's, wherever they are (not a directory's).
    global: bool,
}

/// Collects the errors found while loading the configuration, and the files
/// it looked at.
struct Problems<'a> {
    errors: Vec<ConfigError>,
    files: IndexSet<String>,
    local: IndexSet<String>,
    trusted: IndexSet<String>,
    untrusted: Vec<TrustedFile>,
    /// The working directory the configuration is loaded for.
    cwd: &'a Path,
    /// The environment it is loaded in (the shell's original one).
    env: &'a HashMap<String, String>,
}

impl Problems<'_> {
    fn add(&mut self, file: Option<&str>, message: impl Into<String>) {
        self.errors.push(ConfigError { file: file.map(str::to_owned), message: message.into() });
    }

    fn add_untrusted(&mut self, file: &str, hash: String) {
        if !self.untrusted.iter().any(|u| u.file == file) {
            self.untrusted.push(TrustedFile { file: file.to_owned(), hash });
        }
    }

    /// Whether a directory's file (see trust.rs) may be used, with `content`
    /// (read once: what is checked is what is used). Recorded either way.
    fn trust(&mut self, file: &str, content: &[u8]) -> bool {
        let hash = sha256_hex(content);
        if is_trusted(file, &hash) {
            self.trusted.insert(file.to_owned());
            return true;
        }
        self.add_untrusted(file, hash);
        false
    }

    /// An untrusted config file's own dependencies: what it sources, and the
    /// scripts its source-env runs (and theirs, on down), found by reading it
    /// (nothing in it is used, nor run). Those not trusted either are asked
    /// about along with it, so that a single answer covers what it needs.
    fn discover(&mut self, file: &str, content: &[u8], seen: &mut HashSet<String>) {
        if !seen.insert(file.to_owned()) {
            return;
        }
        // (What can't be read is asked about as is.)
        let Some(Value::Object(data)) = parse_yaml(content).ok().flatten() else { return };
        let dir = Path::new(file).parent().unwrap_or(Path::new("/"));
        let mut deps: Vec<(String, bool)> = Vec::new();
        for src in data.get("sources").and_then(Value::as_array).into_iter().flatten() {
            if let Some(src) = src.as_str() {
                deps.push((resolve(dir, src).to_string_lossy().into_owned(), true));
            }
        }
        for item in data.get("source-env").and_then(Value::as_array).into_iter().flatten() {
            if let (Some(source), Some("bash")) =
                (item.get("source").and_then(Value::as_str), item.get("language").and_then(Value::as_str))
            {
                let path = resolve(dir, expand_source_path(source, self.cwd, self.env));
                deps.push((path.to_string_lossy().into_owned(), false));
            }
        }
        for (dep, config) in deps {
            self.files.insert(dep.clone());
            self.local.insert(dep.clone());
            let Ok(bytes) = std::fs::read(&dep) else { continue };
            let hash = sha256_hex(&bytes);
            if !is_trusted(&dep, &hash) {
                self.add_untrusted(&dep, hash);
            }
            if config {
                self.discover(&dep, &bytes, seen);
            }
        }
    }
}

/// Parse YAML into JSON (None: an empty document).
fn parse_yaml(content: &[u8]) -> Result<Option<Value>, String> {
    let text = std::str::from_utf8(content).map_err(|e| e.to_string())?;
    let all_comments = text.lines().all(|l| {
        let l = l.trim();
        l.is_empty() || l.starts_with('#') || l == "---"
    });
    if all_comments {
        return Ok(None);
    }
    match serde_norway::from_str::<Value>(text) {
        Ok(Value::Null) => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(e) => Err(e.to_string()),
    }
}

/// A value as JavaScript's `String(value)` makes it.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Config file paths in XDG priority order (highest first).
/// XDG_CONFIG_HOME defaults to ~/.config; XDG_CONFIG_DIRS defaults to /etc/xdg.
fn xdg_config_paths(env: &HashMap<String, String>) -> Vec<PathBuf> {
    let get = |name: &str| env.get(name).filter(|v| !v.is_empty());
    let home_dir = get("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".config"));
    let dirs = get("XDG_CONFIG_DIRS").map_or("/etc/xdg", |v| v.as_str());
    std::iter::once(home_dir)
        .chain(dirs.split(':').filter(|d| !d.is_empty()).map(PathBuf::from))
        .map(|dir| dir.join("cq").join("config.yaml"))
        .collect()
}

/// Parse a daemon's command line into its command and arguments: a single
/// simple command. Quotes are removed; `$NAME`s are left for when it runs
/// (see Shell::run_daemon); `~` is the home directory.
fn parse_daemon_cmd(raw: &Value) -> Result<(String, Vec<String>), String> {
    let Some(text) = raw.as_str() else {
        return Err(format!("expected a command line, got {}", describe(raw)));
    };
    let not_simple = || format!("{text:?} is not a simple command");
    let program = brush_parser::Parser::new(std::io::Cursor::new(text), &Default::default())
        .parse_program()
        .map_err(|e| format!("cannot parse {text:?}: {e}"))?;
    let Some(item) = program.complete_commands.first().and_then(|c| c.0.first()) else {
        return Err(not_simple());
    };
    let pipeline = &item.0.first;
    let [brush_parser::ast::Command::Simple(cmd)] = pipeline.seq.as_slice() else {
        return Err(not_simple());
    };
    let name = cmd.word_or_name.as_ref().ok_or_else(not_simple)?;
    let words = cmd.suffix.iter().flat_map(|s| &s.0).filter_map(|item| match item {
        brush_parser::ast::CommandPrefixOrSuffixItem::Word(w) => Some(w),
        _ => None,
    });
    let unquote = |w: &brush_parser::ast::Word| crate::expand::unquote_keeping_expansions(&w.value);
    Ok((unquote(name)?, words.map(unquote).collect::<Result<_, _>>()?))
}

struct EnvEntry {
    value: String,
    export: bool,
    append: bool,
    separator: String,
}

/// Parse one env entry value. Accepts:
///   "string" | number
///   { value, export?, append?, separator? }
///   { value: [...], append?, separator? }
fn parse_env_entry(raw: &Value) -> Result<EnvEntry, String> {
    if raw.is_string() || raw.is_number() {
        return Ok(EnvEntry { value: js_string(raw), export: true, append: false, separator: ":".into() });
    }
    let Some(obj) = raw.as_object() else {
        return Err(format!("expected a string, a number or {{value, ...}}, got {}", describe(raw)));
    };
    let separator = obj.get("separator").and_then(Value::as_str).unwrap_or(":").to_owned();
    let value = match obj.get("value") {
        Some(Value::Array(items)) => items.iter().map(js_string).collect::<Vec<_>>().join(&separator),
        Some(v) => js_string(v),
        None => return Err("missing `value`".into()),
    };
    Ok(EnvEntry {
        value,
        export: obj.get("export") != Some(&Value::Bool(false)),
        append: obj.get("append") == Some(&Value::Bool(true)),
        separator,
    })
}

/// Parse an action (a key binding's, from the config or the terminal, or a
/// clicked part's, from the terminal):
///   "command line"                         run it
///   { command: "command line", freeze? }   the same
///   { builtin: name, freeze? }             a built-in action (BUILTIN_ACTIONS)
/// and `inherit` (also in the cells under the prompt: see buche's). Returns
/// it validated, as the terminal takes it (a built-in's `freeze` made
/// explicit), or what is wrong with it.
pub fn parse_action(raw: &Value) -> Result<Value, String> {
    if let Some(command) = raw.as_str() {
        return if command.trim().is_empty() { Err("empty command".into()) } else { Ok(json!({ "command": command })) };
    }
    let expected =
        || format!("expected a command line, {{command: <command line>}} or {{builtin: <name>}}, got {}", describe(raw));
    let Some(obj) = raw.as_object() else { return Err(expected()) };
    if obj.contains_key("builtin") == obj.contains_key("command") {
        return Err(expected());
    }
    if let Some(extra) = obj.keys().find(|k| !["builtin", "command", "freeze", "inherit"].contains(&k.as_str())) {
        return Err(format!("unknown field {extra:?}"));
    }
    let flag = |name: &str| match obj.get(name) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(format!("`{name}` must be true or false")),
    };
    let freeze = flag("freeze")?;
    let inherit = flag("inherit")?.unwrap_or(false);
    let mut action = Map::new();
    if let Some(command) = obj.get("command") {
        match command.as_str() {
            Some(c) if !c.trim().is_empty() => action.insert("command".into(), json!(c)),
            _ => return Err("`command` must be a command line".into()),
        };
        if let Some(freeze) = freeze {
            action.insert("freeze".into(), json!(freeze));
        }
    } else {
        let name = obj["builtin"].as_str().filter(|n| BUILTIN_ACTIONS.contains(n)).ok_or_else(|| {
            format!("unknown builtin {} (expected one of: {})", obj["builtin"], BUILTIN_ACTIONS.join(", "))
        })?;
        action.insert("builtin".into(), json!(name));
        action.insert("freeze".into(), json!(freeze.unwrap_or(FREEZING_ACTIONS.contains(&name))));
    }
    if inherit {
        action.insert("inherit".into(), json!(true));
    }
    Ok(Value::Object(action))
}

/// Parse the prompt's parts (see PartSpec). Each part is a string (an
/// unstyled text), {text, style?, action?}, {spacer: grow, action?}, or
/// {group: [parts], style?, action?}. Returns an error message for the
/// first bad one.
fn parse_prompt_parts(raw: &Value, place: &str) -> Result<Vec<PartSpec>, String> {
    let Some(items) = raw.as_array() else {
        return Err(format!("{place}: expected a list of parts, got {}", describe(raw)));
    };
    let mut parts = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let here = format!("{place}[{i}]");
        if let Some(text) = item.as_str() {
            parts.push(PartSpec::Text { text: text.into(), style: None, action: None });
            continue;
        }
        let Some(obj) = item.as_object() else {
            return Err(format!("{here}: expected a string or a mapping, got {}", describe(item)));
        };
        let kinds: Vec<&str> = ["text", "spacer", "group"].into_iter().filter(|k| obj.contains_key(*k)).collect();
        let [kind] = kinds.as_slice() else {
            return Err(format!("{here}: expected exactly one of text, spacer or group"));
        };
        let allowed: &[&str] = match *kind {
            "text" => &["text", "style", "action"],
            "spacer" => &["spacer", "action"],
            _ => &["group", "style", "action"],
        };
        if let Some(extra) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
            return Err(format!("{here}: unknown field {extra:?}"));
        }
        let action = match obj.get("action") {
            None => None,
            Some(a) => {
                parse_action(a).map_err(|e| format!("{here}.action: {e}"))?;
                Some(a.clone())
            }
        };
        let style = match obj.get("style") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(other) => return Err(format!("{here}.style: expected a string, got {}", describe(other))),
        };
        for key in ["text", "style"] {
            if let Some(problem) = obj.get(key).and_then(Value::as_str).and_then(template_problem) {
                return Err(format!("{here}.{key}: {problem}"));
            }
        }
        parts.push(match *kind {
            "group" => PartSpec::Group { group: parse_prompt_parts(&obj["group"], &format!("{here}.group"))?, style, action },
            "spacer" => {
                if obj["spacer"] != "grow" {
                    return Err(format!("{here}.spacer: expected \"grow\""));
                }
                PartSpec::Spacer { action }
            }
            _ => {
                let text = &obj["text"];
                if !text.is_string() && !text.is_number() {
                    return Err(format!("{here}.text: expected a string, got {}", describe(text)));
                }
                PartSpec::Text { text: js_string(text), style, action }
            }
        });
    }
    Ok(parts)
}

/// Source a bash file in a clean environment and return all resulting env
/// vars. Uses set -a so variables don't need explicit `export`.
fn load_bash_source_env(source: &str, file: &str, problems: &mut Problems) -> Vec<(String, EnvValue)> {
    problems.files.insert(source.to_owned());
    let path = problems.env.get("PATH").map_or("/usr/bin:/bin", |p| p.as_str());
    let result = std::process::Command::new("bash")
        .args(["--norc", "--noprofile", "-c", r#"set -a; . "$1"; env -0"#, "--", source])
        .env_clear()
        .env("PATH", path)
        .stdin(std::process::Stdio::null())
        .output();
    let output = match result {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let reason = if stderr.is_empty() { format!("exit status {}", output.status) } else { stderr };
            problems.add(Some(file), format!("source-env: sourcing {source} failed: {reason}"));
            return vec![];
        }
        Err(err) => {
            problems.add(Some(file), format!("source-env: sourcing {source} failed: {err}"));
            return vec![];
        }
    };
    String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter_map(|entry| match entry.split_once('=') {
            Some((name, value)) if !name.is_empty() => {
                Some((name.to_owned(), EnvValue { value: value.to_owned(), export: true }))
            }
            _ => None,
        })
        .collect()
}

/// Load a YAML file. Returns None if absent, or (with an error) if
/// unreadable, malformed or not a mapping. Non-global files also go through
/// the trust check (see trust.rs): one not trusted with what it holds is
/// left out, as if absent.
fn read_config_file(path: &Path, problems: &mut Problems, global: bool) -> Option<ConfigEntry> {
    let resolved = resolve(problems.cwd, path).to_string_lossy().into_owned();
    let shown = path.to_string_lossy().into_owned();
    problems.files.insert(resolved.clone());
    if !global {
        problems.local.insert(resolved.clone());
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            problems.add(Some(&shown), format!("cannot read: {e}"));
            return None;
        }
    };
    if !global && !problems.trust(&resolved, &bytes) {
        problems.discover(&resolved, &bytes, &mut HashSet::new());
        return None;
    }
    entry_from(&bytes, &shown, Path::new(&resolved).parent().unwrap_or(Path::new("/")), global, problems)
}

fn entry_from(bytes: &[u8], file: &str, dir: &Path, global: bool, problems: &mut Problems) -> Option<ConfigEntry> {
    match parse_yaml(bytes) {
        Err(e) => {
            problems.add(Some(file), format!("invalid YAML, file ignored: {e}"));
            None
        }
        Ok(None) => None, // an empty file
        Ok(Some(Value::Object(data))) => Some(ConfigEntry { data, dir: dir.to_owned(), file: file.to_owned(), global }),
        Ok(Some(other)) => {
            problems.add(Some(file), format!("expected a mapping at the top level, got {}; file ignored", describe(&other)));
            None
        }
    }
}

/// Expand the `sources` list of one config entry, appending to `out`.
fn expand_sources(entry: &ConfigEntry, out: &mut Vec<ConfigEntry>, problems: &mut Problems) {
    let Some(sources) = entry.data.get("sources") else { return };
    let Some(sources) = sources.as_array() else {
        problems.add(Some(&entry.file), "`sources` must be a list of paths");
        return;
    };
    for src in sources {
        let Some(src) = src.as_str() else {
            problems.add(Some(&entry.file), format!("sources: expected a path, got {}", describe(src)));
            continue;
        };
        let path = resolve(&entry.dir, src);
        // (What the global configuration sources is the user's too.)
        match read_config_file(&path, problems, entry.global) {
            Some(source) => out.push(source),
            None if !path.exists() => problems.add(Some(&entry.file), format!("sources: {src} not found")),
            None => {}
        }
    }
}

/// Collect config entries in priority order (highest first).
fn collect_configs(problems: &mut Problems) -> Vec<ConfigEntry> {
    let mut entries = Vec::new();
    // Walk from cwd upward, stopping at the filesystem root or on
    // ignore-parents.
    let mut dir = problems.cwd.to_path_buf();
    loop {
        if let Some(entry) = read_config_file(&dir.join(".cq.yaml"), problems, false) {
            let stop = truthy(entry.data.get("ignore-parents"));
            let mut sourced = Vec::new();
            expand_sources(&entry, &mut sourced, problems);
            entries.push(entry);
            entries.extend(sourced);
            if stop {
                break;
            }
        }
        if !dir.pop() {
            break;
        }
    }
    // XDG global configs unless disabled by any higher-priority config.
    if !entries.iter().any(|e| truthy(e.data.get("ignore-global"))) {
        for path in xdg_config_paths(problems.env) {
            if let Some(entry) = read_config_file(&path, problems, true) {
                let mut sourced = Vec::new();
                expand_sources(&entry, &mut sourced, problems);
                entries.push(entry);
                entries.extend(sourced);
            }
        }
    }
    entries
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        _ => true,
    }
}

/// Expand $NAME / ${NAME} in a `source-env` path ($PWD is `cwd`).
fn expand_source_path(source: &str, cwd: &Path, env: &HashMap<String, String>) -> String {
    crate::expand::expand_env_vars(source, &|name| {
        if name == "PWD" { Some(cwd.to_string_lossy().into_owned()) } else { env.get(name).cloned() }
    })
}

const KNOWN_KEYS: &[&str] = &[
    "env",
    "source-env",
    "daemons",
    "control", // (the old name of `daemons`: reported as such)
    "bindings",
    "prompt",
    "history",
    "control-commands",
    "sources",
    "ignore-parents",
    "ignore-global",
];

/// Apply one config file on top of `config` (it wins over what is there).
fn apply_entry(config: &mut ResolvedConfig, entry: &ConfigEntry, problems: &mut Problems) {
    let ConfigEntry { data, dir, file, global } = entry;
    let file = file.as_str();
    let section = |name: &str, problems: &mut Problems| -> Option<Map<String, Value>> {
        match data.get(name) {
            None | Some(Value::Null) => None,
            Some(Value::Object(o)) => Some(o.clone()),
            Some(other) => {
                problems.add(Some(file), format!("`{name}` must be a mapping, got {}; ignored", describe(other)));
                None
            }
        }
    };

    for key in data.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            problems.add(Some(file), format!("unknown key `{key}` (ignored)"));
        }
    }

    // source-env — processed before env so the env section can override
    match data.get("source-env") {
        None => {}
        Some(Value::Array(items)) => {
            for item in items {
                let Some(source) = item.get("source").and_then(Value::as_str) else {
                    problems.add(Some(file), "source-env: each item needs a `source` path");
                    continue;
                };
                if item.get("language").and_then(Value::as_str) != Some("bash") {
                    let language = item.get("language").map_or("undefined".into(), Value::to_string);
                    problems.add(Some(file), format!("source-env: unsupported language {language} (only bash)"));
                    continue;
                }
                let source = resolve(dir, expand_source_path(source, problems.cwd, problems.env));
                let source = source.to_string_lossy().into_owned();
                // A directory's script runs only if trusted, as its
                // configuration. (Bash reads it again, after the check:
                // whoever could change it meanwhile could as well change it
                // before.)
                if !global {
                    problems.files.insert(source.clone());
                    problems.local.insert(source.clone());
                    let bytes = match std::fs::read(&source) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            problems.add(Some(file), format!("source-env: cannot read {source}: {e}"));
                            continue;
                        }
                    };
                    if !problems.trust(&source, &bytes) {
                        continue;
                    }
                }
                for (name, value) in load_bash_source_env(&source, file, problems) {
                    config.env.insert(name, value);
                }
            }
        }
        Some(_) => problems.add(Some(file), "`source-env` must be a list; ignored"),
    }

    for (name, raw) in section("env", problems).unwrap_or_default() {
        let parsed = match parse_env_entry(&raw) {
            Ok(parsed) => parsed,
            Err(e) => {
                problems.add(Some(file), format!("env.{name}: {e}; ignored"));
                continue;
            }
        };
        let mut value = parsed.value;
        if parsed.append {
            let current = config.env.get(&name).map(|v| v.value.clone()).or_else(|| problems.env.get(&name).cloned());
            if let Some(current) = current.filter(|c| !c.is_empty()) {
                value = format!("{current}{}{value}", parsed.separator);
            }
        }
        config.env.insert(name, EnvValue { value, export: parsed.export });
    }

    if data.contains_key("control") {
        problems.add(Some(file), "`control` is now `daemons` (ignored)");
    }
    for (name, raw) in section("daemons", problems).unwrap_or_default() {
        match parse_daemon_cmd(&raw) {
            Ok((cmd, args)) => {
                config.daemons.insert(name, DaemonSpec { cmd, args, config_dir: dir.to_string_lossy().into_owned() });
            }
            Err(e) => problems.add(Some(file), format!("daemons.{name}: {e}; ignored")),
        }
    }

    if let Some(prompt) = section("prompt", problems) {
        for key in prompt.keys() {
            if key == "color" {
                problems.add(Some(file), "prompt.color: the accent is now a variable: prompt.vars.COLOR (ignored)");
            } else if key != "vars" && key != "parts" {
                problems.add(Some(file), format!("prompt: unknown key `{key}` (ignored)"));
            }
        }
        match prompt.get("vars") {
            None | Some(Value::Null) => {}
            Some(Value::Object(vars)) => {
                // Merged by name, the nearest file winning (a redefined
                // variable keeps its place in the order: those after it may
                // use it).
                for (name, raw) in vars {
                    let value = if raw.is_number() { Some(js_string(raw)) } else { raw.as_str().map(str::to_owned) };
                    let problem = match &value {
                        Some(v) => template_problem(v),
                        None => Some(format!("expected a string, got {}", describe(raw))),
                    };
                    let valid_name = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                    if !valid_name {
                        problems.add(Some(file), format!("prompt.vars: {name:?} is not a variable name; ignored"));
                    } else if let Some(problem) = problem {
                        problems.add(Some(file), format!("prompt.vars.{name}: {problem}; ignored"));
                    } else {
                        let value = value.unwrap();
                        match config.prompt.vars.iter_mut().find(|(n, _)| n == name) {
                            Some(slot) => slot.1 = value,
                            None => config.prompt.vars.push((name.clone(), value)),
                        }
                    }
                }
            }
            Some(other) => {
                problems.add(Some(file), format!("prompt.vars: expected a mapping, got {}; ignored", describe(other)));
            }
        }
        if let Some(parts) = prompt.get("parts") {
            match parse_prompt_parts(parts, "prompt.parts") {
                Ok(parts) => config.prompt.parts = parts,
                Err(e) => problems.add(Some(file), format!("{e}; prompt.parts ignored")),
            }
        }
    }

    match section("history", problems) {
        // (Every directory's shell writes to the same history file.)
        Some(_) if !global => {
            problems.add(Some(file), "`history` is only read from the global configuration; ignored");
        }
        Some(history) => {
            for key in history.keys().filter(|k| *k != "size") {
                problems.add(Some(file), format!("history: unknown key `{key}` (ignored)"));
            }
            if let Some(size) = history.get("size") {
                match size.as_u64() {
                    Some(n) => config.history_size = n as usize,
                    None => problems.add(
                        Some(file),
                        format!("history.size: expected a whole number, 0 or more, got {size}; ignored"),
                    ),
                }
            }
        }
        None => {}
    }

    match data.get("control-commands") {
        None | Some(Value::Null) => {}
        // (A directory's configuration doesn't get to hand out the privilege.)
        Some(_) if !global => {
            problems.add(Some(file), "`control-commands` is only read from the global configuration; ignored");
        }
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                let here = format!("control-commands[{i}]");
                let Some(obj) = item.as_object() else {
                    problems.add(Some(file), format!("{here}: expected {{path, hash}}, got {}; ignored", describe(item)));
                    continue;
                };
                if let Some(extra) = obj.keys().find(|k| *k != "path" && *k != "hash") {
                    problems.add(Some(file), format!("{here}: unknown key `{extra}` (ignored)"));
                }
                let name = obj.get("path").and_then(Value::as_str);
                let shown = obj.get("path").map_or("undefined".into(), Value::to_string);
                let full = name.map(expand_home).filter(|p| p.starts_with('/'));
                let Some(full) = full else {
                    problems.add(Some(file), format!("{here}.path: expected a full path, got {shown}; ignored"));
                    continue;
                };
                let name = name.unwrap_or_default();
                match obj.get("hash") {
                    // (Taking a file whatever it holds is to be said: hash: null.)
                    None => problems.add(Some(file), format!(
                        "{here}: missing `hash` (the file's SHA-256: shasum -a 256 {name}; or null for any content); ignored"
                    )),
                    Some(Value::Null) => {
                        config.control_commands.push(ControlCommand { path: resolve(Path::new("/"), &full), hash: None });
                    }
                    Some(Value::String(h)) if is_hash(h) => config.control_commands.push(ControlCommand {
                        path: resolve(Path::new("/"), &full),
                        hash: Some(h.clone()),
                    }),
                    Some(other) => problems.add(Some(file), format!(
                        "{here}.hash: expected the file's SHA-256 (64 hex digits: shasum -a 256 {name}{}) or null, got {other}; ignored",
                        if other.is_string() { "" } else { ", in quotes" }
                    )),
                }
            }
        }
        Some(other) => problems.add(
            Some(file),
            format!("`control-commands` must be a list of {{path, hash}}, got {}; ignored", describe(other)),
        ),
    }

    for (key, raw) in section("bindings", problems).unwrap_or_default() {
        if raw.is_null() {
            config.bindings.shift_remove(&key);
            continue;
        }
        match parse_action(&raw) {
            Ok(binding) => {
                config.bindings.insert(key, binding);
            }
            Err(e) => problems.add(Some(file), format!("bindings.{key}: {e}; ignored")),
        }
    }
}

/// Load and merge all applicable config files for `cwd`, in `env` (the
/// shell's original environment). Never fails: what can't be used is
/// reported in `errors`.
pub fn load_config(cwd: &Path, env: &HashMap<String, String>) -> ResolvedConfig {
    let mut problems = Problems {
        errors: vec![],
        files: IndexSet::new(),
        local: IndexSet::new(),
        trusted: IndexSet::new(),
        untrusted: vec![],
        cwd,
        env,
    };
    let mut config = ResolvedConfig::default();

    // coquille's own defaults first (lowest priority).
    if let Some(defaults) = entry_from(DEFAULT_CONFIG.as_bytes(), DEFAULT_CONFIG_NAME, Path::new("/"), true, &mut problems) {
        apply_entry(&mut config, &defaults, &mut problems);
    }

    // Then the user's files, from lowest to highest priority, so that the
    // nearest file wins.
    for entry in collect_configs(&mut problems).iter().rev() {
        apply_entry(&mut config, entry, &mut problems);
    }

    config.errors = problems.errors;
    config.files = problems.files.into_iter().collect();
    config.local = problems.local.into_iter().collect();
    config.trusted = problems.trusted.into_iter().collect();
    config.untrusted = problems.untrusted;
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_loads_cleanly() {
        let dir = std::env::temp_dir().join(format!("cq-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = HashMap::from([("XDG_CONFIG_HOME".to_owned(), dir.to_string_lossy().into_owned())]);
        let config = load_config(&dir, &env);
        assert!(config.errors.is_empty(), "{:?}", config.errors);
        assert_eq!(config.bindings["Enter"], json!({"builtin": "submit", "freeze": true}));
        assert_eq!(config.bindings["Tab"], json!({"builtin": "complete", "freeze": false}));
        assert_eq!(config.history_size, 10000);
        assert_eq!(config.prompt.vars, vec![("COLOR".to_owned(), "${HOSTNAME|hue}".to_owned())]);
        assert_eq!(config.prompt.parts.len(), 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn actions() {
        assert_eq!(parse_action(&json!("ls")), Ok(json!({"command": "ls"})));
        assert_eq!(
            parse_action(&json!({"builtin": "close", "inherit": true})),
            Ok(json!({"builtin": "close", "freeze": true, "inherit": true}))
        );
        assert!(parse_action(&json!({"builtin": "nope"})).is_err());
        assert!(parse_action(&json!({"command": "x", "builtin": "submit"})).is_err());
        assert!(parse_action(&json!("  ")).is_err());
    }

    #[test]
    fn daemon_commands() {
        let home = home().to_string_lossy().into_owned();
        assert_eq!(
            parse_daemon_cmd(&json!("~/bin/w --x 'a b' $THIS_CONFIG_DIR/f")),
            Ok((format!("{home}/bin/w"), vec!["--x".into(), "a b".into(), "$THIS_CONFIG_DIR/f".into()]))
        );
        assert!(parse_daemon_cmd(&json!("a | b")).is_err());
    }
}
