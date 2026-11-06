//! sel: run a command (a picker: fzf, say) on the prompt's selection, and put
//! its output back into the prompt.
//!
//! Run from coquille, sel finds the prompt as it stood when it was submitted
//! (its text and selection) in $CQ_CURRENT_COMMAND, the command message
//! coquille dispatched. It replaces %selection, %dirname and %basename in the
//! command's arguments, runs it, and sends the shell a prompt `configure`
//! with the output (each line shell-quoted, joined with spaces) in place of
//! the selection — or, with --submit, submits the resulting command line.
//! It addresses the shell (["$shell"]), so it must be one of coquille's
//! control-commands.
//!
//! Outside of buche (no control channel), it prints what it would insert.
//!
//! Positions (--start, --end, and the selection in $CQ_CURRENT_COMMAND) are
//! in UTF-16 code units, as buche counts them.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use clap::Parser;
use serde_json::{Value, json};

#[derive(Parser)]
#[command(name = "sel", about = "Run a command on the prompt's selection; put its output back into the prompt")]
struct Cli {
    /// Prompt text in which to replace a range (default: from $CQ_CURRENT_COMMAND)
    #[arg(long)]
    text: Option<String>,

    /// Start of the replaced range
    #[arg(long)]
    start: Option<usize>,

    /// End of the replaced range
    #[arg(long)]
    end: Option<usize>,

    /// Replace the whole prompt (not just the range)
    #[arg(long)]
    replace: bool,

    /// Widen the range to the space-separated unit(s) it is in
    #[arg(long)]
    select_unit: bool,

    /// Wrap the result in this command line (%result: where it goes) rather
    /// than put it back where the selection was
    #[arg(long)]
    pattern: Option<String>,

    /// Submit the resulting command to the shell instead of leaving it in the
    /// prompt for the user to run
    #[arg(long)]
    submit: bool,

    /// The command to run; %selection, %dirname and %basename in its
    /// arguments are replaced by the selection, its directory and its last
    /// component
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    command: Vec<String>,
}

/// The [start, end) spans (in characters) of the space-separated units of a
/// command line, as the shell splits them: spaces in quotes or after a
/// backslash don't separate.
fn units(text: &[char]) -> Vec<(usize, usize)> {
    let n = text.len();
    let find = |c: char, from: usize| (from..n).find(|&j| text[j] == c);
    let mut spans = vec![];
    let mut i = 0;
    while i < n {
        if text[i].is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && !text[i].is_whitespace() {
            let c = text[i];
            if c == '\\' {
                i += 2;
            } else if c == '\'' || c == '"' {
                let mut close = find(c, i + 1);
                while c == '"'
                    && let Some(k) = close
                    && text[k - 1] == '\\'
                {
                    close = find(c, k + 1);
                }
                i = close.map_or(n, |k| k + 1);
            } else {
                i += 1;
            }
        }
        spans.push((start, i.min(n)));
    }
    spans
}

/// Widen [start, end) to the whole units it touches. (Between two units, a
/// cursor stays an empty range.)
fn select_unit(text: &[char], mut start: usize, mut end: usize) -> (usize, usize) {
    for (s, e) in units(text) {
        if s <= start && start <= e {
            start = s;
        }
        if s <= end && end <= e {
            end = e;
        }
    }
    (start, end)
}

/// Shell words, as Python's `shlex.split` makes them (the `shlex` crate's,
/// but with `#` an ordinary character, not a comment). None: unbalanced
/// quotes.
fn split_words(text: &str) -> Option<Vec<String>> {
    const HASH: char = '\u{E000}';
    let words = shlex::split(&text.replace('#', &HASH.to_string()))?;
    Some(words.into_iter().map(|w| w.replace(HASH, "#")).collect())
}

/// The selection as the shell would read it, if it is one word ('a b' ->
/// a b); as it is otherwise.
fn unquote(text: &str) -> String {
    match split_words(text) {
        Some(words) if words.len() == 1 => words.into_iter().next().unwrap(),
        _ => text.to_owned(),
    }
}

/// A word quoted for the shell, as Python's `shlex.quote` does it: as is if
/// it is safe, else in single quotes.
fn quote(word: &str) -> String {
    if word.is_empty() {
        return "''".into();
    }
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if word.chars().all(safe) {
        return word.to_owned();
    }
    format!("'{}'", word.replace('\'', "'\"'\"'"))
}

/// `~` and `~user` at the start of a path, expanded (as Python's
/// `os.path.expanduser`: an unknown user is left as is).
fn expand_user(path: &str) -> String {
    let Some(rest) = path.strip_prefix('~') else { return path.to_owned() };
    let (user, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let home = if user.is_empty() {
        std::env::var("HOME").ok().or_else(|| home_of(None))
    } else {
        home_of(Some(user))
    };
    match home {
        Some(home) if tail.is_empty() => home,
        Some(home) => format!("{}{tail}", home.trim_end_matches('/')),
        None => path.to_owned(),
    }
}

/// A user's home directory (None: the current user's), from the password
/// database.
fn home_of(user: Option<&str>) -> Option<String> {
    let pw = unsafe {
        match user {
            None => libc::getpwuid(libc::getuid()),
            Some(user) => libc::getpwnam(std::ffi::CString::new(user).ok()?.as_ptr()),
        }
    };
    if pw.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
    Some(dir.to_string_lossy().into_owned())
}

/// A path's directory and last component, as Python's `os.path.split`.
fn split_path(path: &str) -> (String, String) {
    let i = path.rfind('/').map_or(0, |i| i + 1);
    let (head, tail) = path.split_at(i);
    let trimmed = head.trim_end_matches('/');
    let head = if trimmed.is_empty() { head } else { trimmed };
    (head.to_owned(), tail.to_owned())
}

/// %selection, %dirname and %basename in the command's arguments: the
/// selection (unquoted, ~ expanded), its directory ("." if it has none, as
/// with dirname(1)) and its last component (after the last /: a selection
/// ending in / has an empty one). %result: the output, for the --pattern
/// built once the command has run. Each argument stays one argument, even
/// if empty (`-q %basename` gives -q '').
fn substitute(command: &[String], selection: &str, result: Option<&str>) -> Vec<String> {
    let value = unquote(selection);
    let (dirname, basename) = split_path(&value);
    let dirname = if dirname.is_empty() { ".".to_owned() } else { dirname };
    let mut values = vec![
        ("%selection", expand_user(&value)),
        ("%dirname", expand_user(&dirname)),
        ("%basename", basename),
    ];
    if let Some(result) = result {
        values.push(("%result", result.to_owned()));
    }
    command
        .iter()
        .map(|arg| {
            let mut out = String::new();
            let mut rest = arg.as_str();
            while let Some(i) = rest.find('%') {
                out.push_str(&rest[..i]);
                rest = &rest[i..];
                match values.iter().find(|(key, _)| rest.starts_with(key)) {
                    Some((key, value)) => {
                        out.push_str(value);
                        rest = &rest[key.len()..];
                    }
                    None => {
                        out.push('%');
                        rest = &rest[1..];
                    }
                }
            }
            out + rest
        })
        .collect()
}

/// The lines of a text, as Python's `str.splitlines` makes them.
fn split_lines(text: &str) -> Vec<String> {
    let breaks = ['\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}'];
    let mut lines = vec![];
    let mut rest = text;
    while !rest.is_empty() {
        let Some(i) = rest.find(breaks) else {
            lines.push(rest.to_owned());
            break;
        };
        lines.push(rest[..i].to_owned());
        let len = if rest[i..].starts_with("\r\n") { 2 } else { rest[i..].chars().next().unwrap().len_utf8() };
        rest = &rest[i + len..];
    }
    lines
}

/// The character index at UTF-16 offset `n` of `text` (clamped to it).
fn char_index(text: &[char], n: usize) -> usize {
    let mut units = 0;
    for (i, c) in text.iter().enumerate() {
        if units >= n {
            return i;
        }
        units += c.len_utf16();
    }
    text.len()
}

fn utf16_len(text: &[char]) -> usize {
    text.iter().map(|c| c.len_utf16()).sum()
}

/// The control channel, if there is one (buche's, through the shell).
fn control_fd() -> Option<RawFd> {
    let fd: RawFd = std::env::var("BUCHE_CONTROL_FD").ok()?.parse().ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(fd)
}

/// Write one line on a file descriptor (which may be non-blocking).
fn write_line(fd: RawFd, line: &str) {
    let mut data = line.trim_end_matches('\n').as_bytes().to_vec();
    data.push(b'\n');
    let mut written = 0;
    while written < data.len() {
        let n = unsafe { libc::write(fd, data[written..].as_ptr().cast(), data.len() - written) };
        if n >= 0 {
            written += n as usize;
            continue;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::EINTR) => {
                let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                unsafe { libc::poll(&mut pfd, 1, -1) };
            }
            _ => return,
        }
    }
}

fn send(fd: RawFd, message: &Value) {
    write_line(fd, &message.to_string());
}

/// The relay between the command's own control socket and our channel to
/// the terminal. The command shares our channel, so, like the coquille in
/// front of us, we qualify its relative addresses on the way out (["$proc",
/// ...] -> ["$proc", "sel", <pid>, ...]) and match-and-strip them on the way
/// back, so replies reach it and our own unqualified traffic stays ours.
struct Relay {
    control_fd: RawFd,
    prefix: Vec<String>,
    lock: Mutex<()>,
}

impl Relay {
    /// Its messages, to the terminal. It speaks on our channel, so as us:
    /// the shell takes what we send it from a control command. Its messages
    /// for the shell are dropped, lest it get that privilege; and only what
    /// was checked goes.
    fn to_terminal(&self, child: UnixStream) {
        for line in BufReader::new(child).split(b'\n') {
            let Ok(line) = line else { return };
            let Ok(Value::Object(mut obj)) = serde_json::from_slice::<Value>(&line) else { continue };
            let to_shell = obj.get("to").and_then(|t| t.get(0)).and_then(Value::as_str) == Some("$shell");
            if to_shell {
                continue;
            }
            if let Some(Value::Array(from)) = obj.get("from")
                && from.first().and_then(Value::as_str) == Some("$proc")
            {
                let mut qualified: Vec<Value> = self.prefix.iter().map(|s| json!(s)).collect();
                qualified.extend(from[1..].iter().cloned());
                obj.insert("from".into(), Value::Array(qualified));
            }
            let _guard = self.lock.lock();
            write_line(self.control_fd, &Value::Object(obj).to_string());
        }
    }

    /// The terminal's messages, to it: those addressed under its prefix
    /// re-addressed relative to it, the others as they are.
    fn to_child(&self, mut child: UnixStream) {
        let fd = unsafe { libc::fcntl(self.control_fd, libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return;
        }
        let terminal = unsafe { std::fs::File::from_raw_fd(fd) };
        for line in BufReader::new(terminal).split(b'\n') {
            let Ok(line) = line else { return };
            let mut out = line.clone();
            if let Ok(Value::Object(mut obj)) = serde_json::from_slice::<Value>(&line)
                && let Some(Value::Array(to)) = obj.get("to")
                && to.len() >= self.prefix.len()
                && to.iter().zip(&self.prefix).all(|(a, b)| a.as_str() == Some(b))
            {
                let mut local = vec![json!("$proc")];
                local.extend(to[self.prefix.len()..].iter().cloned());
                obj.insert("to".into(), Value::Array(local));
                out = Value::Object(obj).to_string().into_bytes();
            }
            out.push(b'\n');
            let _guard = self.lock.lock();
            if child.write_all(&out).is_err() {
                return;
            }
        }
    }
}

/// What the command did: its exit status (128 + the signal, if one ended
/// it), and what it wrote.
struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run the command, its stdout and stderr captured (its stdin and terminal
/// are ours: a picker draws on /dev/tty). Under buche, it gets a control
/// channel of its own, relayed onto ours (see Relay).
fn run_command(command: &[String], control: Option<RawFd>) -> Result<Outcome, String> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut channel = None;
    if let Some(control_fd) = control {
        let (parent, child) = UnixStream::pair().map_err(|e| e.to_string())?;
        let child_fd = child.as_raw_fd();
        // The command finds the socket at this number, through
        // $BUCHE_CONTROL_FD, as buche itself hands out its channel.
        cmd.env("BUCHE_CONTROL_FD", child_fd.to_string());
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(child_fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        channel = Some((control_fd, parent, child));
    }
    let child = cmd.spawn().map_err(|e| format!("{}: {e}", command[0]))?;
    if let Some((control_fd, parent, child_end)) = channel {
        drop(child_end);
        let relay = Arc::new(Relay {
            control_fd,
            prefix: vec!["$proc".into(), "sel".into(), child.id().to_string()],
            lock: Mutex::new(()),
        });
        let (reader, writer) = (parent.try_clone().map_err(|e| e.to_string())?, parent);
        let r = relay.clone();
        std::thread::spawn(move || r.to_terminal(reader));
        std::thread::spawn(move || relay.to_child(writer));
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    let code = output.status.code().unwrap_or_else(|| 128 + output.status.signal().unwrap_or(0));
    Ok(Outcome {
        code,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn run(cli: Cli) -> Result<i32, String> {
    let current: Option<Value> = match std::env::var("CQ_CURRENT_COMMAND") {
        Ok(raw) => Some(serde_json::from_str(&raw).map_err(|e| format!("bad $CQ_CURRENT_COMMAND: {e}"))?),
        Err(_) => None,
    };

    // With no explicit --text/--start/--end, take the prompt as it stood when
    // sel was submitted, and its selection, from $CQ_CURRENT_COMMAND.
    let (text, start, end) = match (cli.text, cli.start, cli.end) {
        (Some(text), Some(start), Some(end)) => (text, start, end),
        (text, start, end) => {
            let current = current.as_ref().ok_or("no --text/--start/--end given and no $CQ_CURRENT_COMMAND")?;
            let text = match text {
                Some(text) => text,
                None => current.get("text").and_then(Value::as_str).ok_or("no text in $CQ_CURRENT_COMMAND")?.into(),
            };
            // A submission that never went through the prompt (`cq -c`, a
            // command we submitted ourselves) carries no selection: the
            // cursor is at the end of the text.
            let at = |name| current.pointer(&format!("/selection/{name}")).and_then(Value::as_u64).map(|n| n as usize);
            let start = start.or_else(|| at("start")).unwrap_or(text.encode_utf16().count());
            let end = end.or_else(|| at("end")).unwrap_or(start);
            (text, start, end)
        }
    };

    // Where the command running us was performed, when not in the prompt (an
    // inherited binding fired in a cell: buche's `anchor`): what we submit is
    // shown relative to that cell.
    let anchor = current
        .as_ref()
        .and_then(|c| c.get("anchor"))
        .filter(|a| !matches!(a, Value::Null) && a.as_array().is_none_or(|a| !a.is_empty()))
        .cloned();

    if cli.command.is_empty() {
        return Err("no command given".into());
    }
    let chars: Vec<char> = text.chars().collect();
    let (mut start, mut end) = (char_index(&chars, start), char_index(&chars, end));
    end = end.max(start);
    if cli.replace {
        (start, end) = (0, chars.len());
    } else if cli.select_unit {
        (start, end) = select_unit(&chars, start, end);
    }
    let selection: String = chars[start..end].iter().collect();
    let command = substitute(&cli.command, &selection, None);
    let control = control_fd();
    let outcome = run_command(&command, control)?;
    eprint!("{}", outcome.stderr);

    // Each line of output is shell-quoted; lines are joined with a space.
    let lines = if outcome.code == 0 { split_lines(&outcome.stdout) } else { vec![] };
    let mut insert = lines.iter().map(|l| quote(l)).collect::<Vec<_>>().join(" ");

    if !lines.is_empty()
        && let Some(pattern) = &cli.pattern
    {
        // The output goes into the pattern at %result, which makes a command
        // line of its own: there is no selection left to put it back into,
        // so the pattern stands for the whole prompt.
        insert = substitute(std::slice::from_ref(pattern), &selection, Some(&insert)).remove(0);
        (start, end) = (0, chars.len());
    }

    // The prompt as it would stand with the output in place of the range,
    // and the cursor after it.
    let new_text: String = chars[..start].iter().copied().chain(insert.chars()).chain(chars[end..].iter().copied()).collect();
    let new_pos = utf16_len(&chars[..start]) + insert.encode_utf16().count();

    let Some(fd) = control else {
        if !insert.is_empty() {
            println!("{insert}");
        }
        return Ok(outcome.code);
    };

    if !lines.is_empty() && cli.submit {
        // Empty the prompt and take the focus to it first: what it holds is
        // the text we were submitted with, frozen as it stood, and we may
        // well hold the focus ourselves (a `@pop` picker, say) — the command
        // is the prompt's to run, not ours. Not when we were run from a cell
        // (an anchor): the prompt's text isn't what we got (that was empty),
        // and is left alone; what we submit takes the focus instead.
        if anchor.is_none() {
            send(fd, &json!({
                "type": "configure",
                "kind": "prompt",
                "from": ["$proc"],
                "to": ["$shell"],
                "focus": true,
                "input": { "content": { "parts": [{ "text": "" }], "selection": { "start": 0, "end": 0 } } },
            }));
        }
        // Then submit it as the terminal submits what was typed: a `command`
        // for the shell with the submit action, which echoes the command,
        // records it in the history and runs it as a process of its own.
        let mut command = json!({
            "type": "command",
            "from": ["$proc"],
            "to": ["$shell"],
            "action": { "builtin": "submit" },
            "text": new_text,
        });
        if let Some(anchor) = anchor {
            command["anchor"] = anchor;
            command["focus"] = json!(true);
        }
        send(fd, &command);
        return Ok(outcome.code);
    }

    // Update the shell's prompt in place (the shell relays the configure to
    // the terminal under its own prompt address): the output replaces the
    // range, cursor after it, and the prompt takes the focus back. If the
    // command failed or printed nothing (fzf cancelled, say), the prompt is
    // left as it was, and only takes the focus back. Run from a cell (an
    // anchor), we got no text to put the output into: the prompt's own is
    // left alone.
    if anchor.is_some() {
        return Ok(outcome.code);
    }
    let mut message = json!({ "type": "configure", "kind": "prompt", "from": ["$proc"], "to": ["$shell"], "focus": true });
    if !lines.is_empty() {
        message["input"] = json!({ "content": {
            "parts": [{ "text": new_text }],
            "selection": { "start": new_pos, "end": new_pos },
        } });
    }
    send(fd, &message);
    Ok(outcome.code)
}

fn main() {
    let code = run(Cli::parse()).unwrap_or_else(|err| {
        eprintln!("sel: {err}");
        1
    });
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn splits_units() {
        assert_eq!(units(&chars(r#"ls 'a b' "c\" d" e\ f"#)), vec![(0, 2), (3, 8), (9, 16), (17, 21)]);
        assert_eq!(select_unit(&chars("cat foo/bar baz"), 6, 6), (4, 11));
        assert_eq!(select_unit(&chars("a  b"), 2, 2), (2, 2));
    }

    #[test]
    fn quotes_like_python() {
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a/b-c.d=e%f"), "a/b-c.d=e%f");
        assert_eq!(quote("it's"), r#"'it'"'"'s'"#);
        assert_eq!(quote("a b"), "'a b'");
    }

    #[test]
    fn unquotes_one_word() {
        assert_eq!(unquote("'a b'"), "a b");
        assert_eq!(unquote("#x"), "#x");
        assert_eq!(unquote("a b"), "a b");
        assert_eq!(unquote("'open"), "'open");
    }

    #[test]
    fn splits_paths_like_python() {
        assert_eq!(split_path("a/b"), ("a".into(), "b".into()));
        assert_eq!(split_path("/a"), ("/".into(), "a".into()));
        assert_eq!(split_path("a//b"), ("a".into(), "b".into()));
        assert_eq!(split_path("a/"), ("a".into(), "".into()));
        assert_eq!(split_path("b"), ("".into(), "b".into()));
    }

    #[test]
    fn substitutes() {
        let cmd = vec!["-q".into(), "%basename".into(), "%dirname/x".into(), "100%".into()];
        assert_eq!(substitute(&cmd, "'src/my file'", None), vec!["-q", "my file", "src/x", "100%"]);
        assert_eq!(substitute(&cmd, "f", None)[2], "./x");
        assert_eq!(substitute(&["bed %result".into()], "", Some("a b")), vec!["bed a b"]);
        let home = std::env::var("HOME").unwrap();
        assert_eq!(substitute(&["%selection".into()], "~/x", None), vec![format!("{home}/x")]);
    }

    #[test]
    fn lines_like_python() {
        assert_eq!(split_lines("a\nb\r\nc\rd\n"), vec!["a", "b", "c", "d"]);
        assert_eq!(split_lines(""), Vec::<String>::new());
        assert_eq!(split_lines("\n"), vec![""]);
    }

    #[test]
    fn utf16_positions() {
        let text = chars("😀 x");
        assert_eq!(char_index(&text, 3), 2);
        assert_eq!(utf16_len(&text[..2]), 3);
    }
}
