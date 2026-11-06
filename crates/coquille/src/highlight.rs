//! Syntax highlighting of the command line as it is typed, and Tab
//! completion. Highlighting tokenizes loosely (the line is usually
//! incomplete: an unclosed quote is highlighted as the string it will be).

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::builtins::{BUILTIN_NAMES, is_builtin};
use crate::util::{cwd, expand_home, home, is_executable, resolve};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Arg,
    Cmd,
    Comment,
    Flag,
    Invalid,
    Op,
    Path,
    Redirect,
    String,
    Subshell,
    Var,
    Zone,
}

impl Class {
    fn style(self) -> &'static str {
        match self {
            Class::Arg => "grey L100",
            Class::Cmd => "bold yellow",
            Class::Comment => "grey L20",
            Class::Flag => "blue",
            Class::Invalid => "bold red",
            Class::Op => "grey L100",
            Class::Path => "u grey L100",
            Class::Redirect => "pink",
            Class::String => "orange",
            Class::Subshell => "magenta",
            Class::Var => "cyan green",
            Class::Zone => "bold blue",
        }
    }
}

struct Range {
    start: usize,
    end: usize,
    cls: Class,
}

// Tokens: quoted strings, variable expansions, operators, words. The `…$`
// alternatives match a quote left unclosed at the end of the line (the
// common case of typing a command one character at a time) so it highlights
// like the closed string. Command substitutions match one level of nested
// parentheses (enough for `$(f $(g x))`, deep enough not to swallow the rest
// of the line on a stray `)`).
static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*$|"(?:[^"\\]|\\.)*$"#,
        r#"|\$\{[^}]*\}|\$\((?:[^()]|\([^()]*\))*\)|`[^`]*`|\$[A-Za-z_][A-Za-z0-9_]*"#,
        r#"|&&|\|\||>>|2>|[|;&<>]|\S+"#,
    ))
    .unwrap()
});
static VAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*").unwrap());

const OPERATORS: &[&str] = &["&&", "||", "|", ";", "&"];
const REDIRECTS: &[&str] = &[">", "<", ">>", "2>"];

/// Whether `cmd` runs something: a builtin, or an executable (in `path`).
fn cmd_exists(cmd: &str, path: &str) -> bool {
    if is_builtin(cmd) {
        return true;
    }
    if cmd.contains('/') {
        return is_executable(&resolve(&cwd(), cmd));
    }
    path.split(':').filter(|d| !d.is_empty()).any(|dir| is_executable(&Path::new(dir).join(cmd)))
}

fn fs_path_exists(arg: &str) -> bool {
    if arg.is_empty() || arg.starts_with('-') {
        return false;
    }
    resolve(&cwd(), expand_home(arg)).exists()
}

/// Classed ranges as the parts of `text`: in order, the gaps between them
/// unstyled. Where ranges overlap, the one that starts first wins (a later
/// one is trimmed to what remains) — except a comment, which covers the rest
/// of the line, whatever ranges lie in it.
fn to_parts(text: &str, ranges: Vec<Range>) -> Vec<Value> {
    let comment = ranges.iter().find(|r| r.cls == Class::Comment).map(|r| r.start);
    let mut ordered: Vec<&Range> = ranges
        .iter()
        .filter(|r| r.start < r.end)
        .filter(|r| comment.is_none_or(|c| r.cls == Class::Comment || r.start < c))
        .collect();
    ordered.sort_by_key(|r| (r.start, r.end));
    let mut parts = Vec::new();
    let mut cursor = 0;
    for range in ordered {
        let start = range.start.max(cursor);
        let end = match comment {
            Some(c) if range.cls != Class::Comment => range.end.min(c),
            _ => range.end,
        };
        if start >= end {
            continue;
        }
        if cursor < start {
            parts.push(json!({ "text": &text[cursor..start] }));
        }
        parts.push(json!({ "text": &text[start..end], "style": range.cls.style() }));
        cursor = end;
    }
    if cursor < text.len() {
        parts.push(json!({ "text": &text[cursor..] }));
    }
    parts
}

/// Syntax highlighting for a command line, as the parts of its text
/// (commands are looked up in `path`, a PATH).
pub fn shell_highlight(text: &str, path: &str) -> Vec<Value> {
    if text.trim_start().starts_with('#') {
        return vec![json!({ "text": text, "style": Class::Comment.style() })];
    }
    #[derive(PartialEq)]
    enum State {
        Cmd,
        Arg,
        RedirTarget,
    }
    let mut ranges = Vec::new();
    let mut state = State::Cmd;

    for m in TOKEN.find_iter(text) {
        let token = m.as_str();
        let (start, end) = (m.start(), m.end());
        let mut push = |cls| ranges.push(Range { start, end, cls });

        if state == State::RedirTarget {
            push(Class::Arg);
            state = State::Arg;
            continue;
        }
        if OPERATORS.contains(&token) {
            push(Class::Op);
            state = State::Cmd;
        } else if REDIRECTS.contains(&token) {
            push(Class::Redirect);
            state = State::RedirTarget;
        } else if token.starts_with('\'') || token.starts_with('"') {
            push(Class::String);
            if state == State::Cmd {
                state = State::Arg;
            }
        } else if token.starts_with("$(") || token.starts_with('`') {
            push(Class::Subshell);
            state = State::Arg;
        } else if token.starts_with('$') {
            push(Class::Var);
        } else if state == State::Cmd && token.len() > 1 && token.starts_with('@') {
            // Any `@name` in command position is a zone prefix; the state
            // stays Cmd so the following token is highlighted as the command.
            push(Class::Zone);
        } else if state == State::Cmd {
            push(Class::Cmd);
            state = State::Arg;
        } else if token.starts_with('-') {
            push(Class::Flag);
        } else {
            push(Class::Arg);
        }

        // Overlapping: variable references inside double-quoted strings and
        // plain words.
        let (inner, offset) = if let Some(rest) = token.strip_prefix('"') {
            (rest.strip_suffix('"').unwrap_or(rest), 1)
        } else if !token.starts_with('\'') && !token.starts_with('$') {
            (token, 0)
        } else {
            ("", 0)
        };
        for vm in VAR.find_iter(inner) {
            ranges.push(Range {
                start: start + offset + vm.start(),
                end: start + offset + vm.end(),
                cls: Class::Var,
            });
        }
    }

    // Recolor in place: an overlapping range pushed after the command or
    // argument one would be shadowed by it (where ranges overlap, the first
    // one wins: see to_parts, so the overlay would never show).
    for range in &mut ranges {
        let token = &text[range.start..range.end];
        if range.cls == Class::Cmd && !cmd_exists(token, path) {
            range.cls = Class::Invalid;
        } else if range.cls == Class::Arg && fs_path_exists(token) {
            range.cls = Class::Path;
        }
    }

    // An inline comment: the first # after whitespace that isn't inside a
    // quoted string.
    let quoted: Vec<(usize, usize)> = ranges
        .iter()
        .filter(|r| matches!(r.cls, Class::String | Class::Subshell))
        .map(|r| (r.start, r.end))
        .collect();
    let mut previous: Option<char> = None;
    for (i, c) in text.char_indices() {
        if c == '#'
            && previous.is_none_or(char::is_whitespace)
            && !quoted.iter().any(|&(s, e)| i >= s && i < e)
        {
            ranges.push(Range { start: i, end: text.len(), cls: Class::Comment });
            break;
        }
        previous = Some(c);
    }

    to_parts(text, ranges)
}

/// The word being completed: the non-space run just left of byte `position`,
/// and where it starts.
pub fn word_before(text: &str, position: usize) -> (usize, &str) {
    let left = &text[..position];
    let start = left.rfind(char::is_whitespace).map_or(0, |i| i + left[i..].chars().next().unwrap().len_utf8());
    (start, &left[start..])
}

/// Completions for the word left of byte `position` in `text`: builtins
/// and executables (in `path`) in command position, else files (directories
/// first, marked with a `/`).
pub fn shell_complete(text: &str, position: usize, path: &str) -> Vec<String> {
    let (start, prefix) = word_before(text, position);
    let before = text[..start].trim_end();
    let command_position = before.is_empty() || before.ends_with(['|', '&', ';']);

    if command_position {
        let mut builtins: Vec<String> =
            BUILTIN_NAMES.iter().filter(|b| b.starts_with(prefix)).map(|b| b.to_string()).collect();
        builtins.sort();
        let mut executables = std::collections::BTreeSet::new();
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let Ok(entries) = std::fs::read_dir(dir) else { continue };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(prefix) && !builtins.contains(&name) {
                    executables.insert(name);
                }
            }
        }
        builtins.extend(executables);
        return builtins;
    }

    let home = home().to_string_lossy().into_owned();
    let tilde = prefix.starts_with('~');
    let expanded = if tilde { format!("{home}{}", &prefix[1..]) } else { prefix.to_owned() };
    let pattern = format!("{}*", glob::Pattern::escape(&expanded));
    let options = glob::MatchOptions {
        require_literal_leading_dot: !prefix.rsplit('/').next().unwrap_or("").starts_with('.'),
        ..Default::default()
    };
    let Ok(paths) = glob::glob_with(&pattern, options) else { return vec![] };
    let mut results: Vec<(bool, String)> = paths
        .flatten()
        .map(|p| {
            let dir = p.is_dir();
            let mut value = p.to_string_lossy().into_owned();
            // (glob drops a leading `./`.)
            if expanded.starts_with("./") && !value.starts_with("./") {
                value.insert_str(0, "./");
            }
            if dir {
                value.push('/');
            }
            if tilde {
                value = format!("~{}", &value[home.len().min(value.len())..]);
            }
            (!dir, value)
        })
        .collect();
    results.sort();
    results.into_iter().map(|(_, v)| v).collect()
}

/// The longest common prefix of `values`.
pub fn common_prefix(values: &[String]) -> String {
    let Some(first) = values.first() else { return String::new() };
    let mut len = first.len();
    for value in &values[1..] {
        len = first
            .char_indices()
            .zip(value.chars())
            .take_while(|((_, a), b)| a == b)
            .last()
            .map_or(0, |((i, a), _)| i + a.len_utf8())
            .min(len);
    }
    first[..len].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn styles(text: &str) -> Vec<(String, Option<String>)> {
        shell_highlight(text, "/bin:/usr/bin")
            .into_iter()
            .map(|p| (p["text"].as_str().unwrap().to_owned(), p.get("style").and_then(|s| s.as_str()).map(str::to_owned)))
            .collect()
    }

    #[test]
    fn highlights_commands_and_args() {
        let parts = styles("@pop ls -la \"$HOME x\" | nosuchcommandxyz # hi");
        let get = |t: &str| parts.iter().find(|(x, _)| x == t).and_then(|(_, s)| s.clone());
        assert_eq!(get("@pop").as_deref(), Some("bold blue"));
        assert_eq!(get("ls").as_deref(), Some("bold yellow"));
        assert_eq!(get("-la").as_deref(), Some("blue"));
        assert_eq!(get("\"$HOME x\"").as_deref(), Some("orange"));
        assert_eq!(get("nosuchcommandxyz").as_deref(), Some("bold red"));
        assert_eq!(get("# hi").as_deref(), Some("grey L20"));
        let text: String = parts.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(text, "@pop ls -la \"$HOME x\" | nosuchcommandxyz # hi");
    }

    #[test]
    fn unclosed_quote_is_a_string() {
        let parts = styles("echo 'abc");
        assert_eq!(parts.last().unwrap(), &("'abc".to_owned(), Some("orange".to_owned())));
    }

    #[test]
    fn prefixes() {
        assert_eq!(common_prefix(&["abc".into(), "abd".into()]), "ab");
        assert_eq!(common_prefix(&["é1".into(), "é2".into()]), "é");
        assert_eq!(word_before("ls  fo", 6), (4, "fo"));
    }
}
