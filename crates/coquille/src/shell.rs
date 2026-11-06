//! The shell: it runs the commands the terminal (or an enclosing shell) asks
//! for, and relays what they say. Everything runs on one thread (a tokio
//! LocalSet): handlers are tasks that emit messages as they go (see emit).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use brush_parser::ast;
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, mpsc};
use tokio::task::{JoinHandle, spawn_local};

use crate::approval::{ControlCommand, approve};
use crate::builtins::{BuiltinEvent, builtin_events, is_builtin};
use crate::config::{ConfigError, PromptSpec, load_config, parse_action};
use crate::config_watch::{FileChange, Snapshot, changes, snapshot};
use crate::expand::{expand_env_vars, parse_program};
use crate::highlight::{common_prefix, shell_complete, shell_highlight, word_before};
use crate::history::{Direction, HistoryEntry, ShellHistory};
use crate::library::{LIB_SALT_ENV, LibraryFiles};
use crate::look::{command_verb, logo, parts_text, program_look, styled_all, terminal_decorations, with_program_look};
use crate::message::{Message, SELF, from_at, from_len, kind, make_error, not_implemented, to_head};
use crate::process::{Delegate, Delegations, Process, ProcessOptions, Redirect, address_key};
use crate::prompt::{prompt_context, prompt_marker, render_prompt};
use crate::requests::{Answer, PendingRequest, REQUESTS_HTML, pending_summary, render_requests};
use crate::trust::{TrustedFile, trust, was_trusted};
use crate::util::{address_of, cwd, merged, put_opt, tildify, utf16_len, utf16_to_byte};

/// How many runs are remembered, to be run again (see Shell::rerun).
const MAX_RUNS: usize = 1000;

/// The views of a process that are the shell's (not its child's): its
/// placeholder, terminal and frame.
const PROCESS_VIEWS: &[&str] = &["?", "$stdout", "$frame"];

static ZONE_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^@(\S+)\s+").unwrap());

/// A command a run is made of.
#[derive(Clone, Debug)]
struct Stage {
    cmd: String,
    args: Vec<String>,
    redirects: Vec<Redirect>,
    /// Variables assigned for it alone (`NAME=value cmd`).
    env: Vec<(String, String)>,
}

/// A process's command as it was run, the first time: what it takes to run
/// it again (see Shell::rerun), even once it has ended.
struct Run {
    /// Its command; or a pipeline's, the last of which is the process (the
    /// one whose cells show the pipeline).
    stages: Vec<Stage>,
    /// Its working directory and environment.
    cwd: PathBuf,
    env: BTreeMap<String, String>,
    /// The look of its terminal (see Process::set_stdout_look), and the
    /// colour of its program's cells (see with_program_look).
    stdout_look: RefCell<Value>,
    color: Option<String>,
    /// The requests its process left to us (see Delegations), its reruns'
    /// included: its cells outlive it.
    delegations: Rc<RefCell<Delegations>>,
    /// Its processes (its stages'), until they have all ended.
    procs: RefCell<Vec<Rc<Process>>>,
}

/// A daemon: a process run along with the shell (see `daemons`).
struct Daemon {
    cmd: String,
    args: Vec<String>,
    config_dir: Option<String>,
    restart_ms: Option<u64>,
    enabled: Cell<bool>,
    proc: RefCell<Option<Rc<Process>>>,
}

impl Daemon {
    fn stop(&self) {
        self.enabled.set(false);
        if let Some(proc) = &*self.proc.borrow() {
            proc.kill(None);
        }
    }
}

/// History-navigation state (see history_step).
struct NavState {
    anchor_id: Option<String>,
    filter: String,
    draft: String,
}

/// What to run (see Shell::submit): a command line, or a parsed command.
#[derive(Clone, Default)]
struct SubmitRequest {
    /// A command line, to parse.
    text: Option<String>,
    /// Or a parsed command, and its redirections and variables.
    command: Option<(String, Vec<String>)>,
    redirects: Vec<Redirect>,
    env: Vec<(String, String)>,

    /// The id of the terminal's "command" request, if any.
    id: Option<Value>,
    /// Where what the command shows goes.
    zone: Option<String>,
    /// What `zone` is relative to: where the command was performed, if not
    /// in the prompt (the cell an inherited binding fired in; see buche's
    /// CommandRequest).
    anchor: Option<Value>,
    /// Whether what the command shows takes the focus (buche's `focus`): for
    /// a command submitted by another one (sel, say), which the terminal
    /// didn't send, so has no `id` to expect.
    focus: bool,
    /// Whether to record `text` in the history.
    history: bool,
    /// Whether to decorate the command's cell with its echo (not when
    /// `echo_html` is explicitly null).
    echo: bool,
    prompt_color: Option<String>,

    /// For a parsed command: the process id reserved for it, its
    /// decoration...
    process_id: Option<String>,
    decoration: Option<Map<String, Value>>,
    background: bool,
}

impl SubmitRequest {
    /// The request a `command` message makes (from the terminal, from a
    /// control command, or `cq -c`, which only has the text).
    fn from_message(msg: &Value) -> Self {
        let field = |name: &str| msg.get(name).and_then(Value::as_str).map(str::to_owned);
        SubmitRequest {
            text: field("text"),
            id: msg.get("id").filter(|v| !v.is_null()).cloned(),
            zone: field("zone"),
            anchor: anchor_field(msg),
            focus: msg.get("focus") == Some(&Value::Bool(true)),
            history: true,
            echo: msg.get("echo_html") != Some(&Value::Null),
            prompt_color: field("prompt_color"),
            ..Default::default()
        }
    }
}

/// A request's `anchor`, as the `configure` of what it shows carries it:
/// nothing if it has none (or not an address).
fn anchor_field(msg: &Value) -> Option<Value> {
    address_of(msg.get("anchor")).filter(|a| !a.is_empty()).map(|a| json!(a))
}

/// A configuration problem, for the terminal.
fn config_error(ConfigError { file, message }: ConfigError) -> Message {
    let message = match file {
        Some(file) => format!("{file}: {message}"),
        None => message,
    };
    json!({ "type": "error", "from": SELF, "to": ["$term"], "error_type": "ConfigError", "message": message, "traceback": [] })
}

/// A prompt `configure` from this shell.
fn prompt_configure(fields: Value) -> Message {
    merged(json!({ "type": "configure", "kind": "prompt", "from": SELF, "to": ["$term"] }), fields)
}

fn process_addr(id: &str) -> Vec<String> {
    vec!["$proc".into(), "cq".into(), id.into()]
}

/// A process's `close`.
fn close_message(addr: &[String], success: bool, code: Option<i64>) -> Message {
    let mut outcome = json!({ "type": if success { "success" } else { "error" } });
    if let Some(code) = code {
        outcome["code"] = json!(code);
    }
    json!({ "type": "close", "from": addr, "to": ["$term"], "outcome": outcome })
}

/// The name of a compound command, for what isn't implemented.
fn compound_name(c: &ast::CompoundCommand) -> &'static str {
    use ast::CompoundCommand::*;
    match c {
        Arithmetic(_) => "arithmetic commands ((…))",
        ArithmeticForClause(_) | ForClause(_) => "for loops",
        BraceGroup(_) => "brace groups { …; }",
        Subshell(_) => "subshells (...)",
        CaseClause(_) => "case statements",
        IfClause(_) => "if statements",
        WhileClause(_) => "while loops",
        UntilClause(_) => "until loops",
        Coprocess(_) => "coprocesses",
    }
}

/// The simple command a pipeline's stage is, or what isn't implemented.
fn simple(command: &ast::Command) -> Result<&ast::SimpleCommand> {
    match command {
        ast::Command::Simple(c) => Ok(c),
        ast::Command::Compound(c, _) => Err(not_implemented(compound_name(c))),
        ast::Command::Function(_) => Err(not_implemented("function definitions")),
        ast::Command::ExtendedTest(..) => Err(not_implemented("[[ … ]] tests")),
    }
}

/// An and-or list as the one pipeline it must be (what isn't is not
/// implemented).
fn single_pipeline<'a>(list: &'a ast::AndOrList, place: &str) -> Result<&'a ast::Pipeline> {
    match list.additional.first() {
        Some(ast::AndOr::And(_)) => return Err(not_implemented(format!("logical expressions (and){place}"))),
        Some(ast::AndOr::Or(_)) => return Err(not_implemented(format!("logical expressions (or){place}"))),
        None => {}
    }
    if list.first.bang {
        return Err(not_implemented(format!("negated pipelines (!){place}")));
    }
    Ok(&list.first)
}

/// A simple command's words, expanded: its words, redirections, and the
/// variables assigned for it.
struct Expanded {
    words: Vec<String>,
    redirects: Vec<Redirect>,
    env: Vec<(String, String)>,
}

pub struct Shell {
    cols: u16,
    rows: u16,
    /// The environment coquille started in: each load of the configuration
    /// starts over from it (see apply_config_unchecked).
    original_env: HashMap<String, String>,
    out: RefCell<Option<mpsc::UnboundedSender<Message>>>,

    /// The environment, as the commands get it.
    env: RefCell<BTreeMap<String, String>>,
    /// Non-exported shell variables (the configuration's, and the user's:
    /// see user_vars).
    vars: RefCell<HashMap<String, String>>,
    /// The variables set from the shell (`export`, `set`, a control
    /// command's `set`; and OLDPWD, by `cd`): exported ones, and the others.
    /// Each load of the configuration starts the environment over, then
    /// applies these over it: they win, and outlive a `cd`.
    user_env: RefCell<IndexMap<String, String>>,
    user_vars: RefCell<IndexMap<String, String>>,

    processes: RefCell<HashMap<String, Rc<Process>>>,
    /// The runs that can be run again, by process id: the last MAX_RUNS run
    /// (or rerun), the least recently first (see remember).
    runs: RefCell<IndexMap<String, Rc<Run>>>,
    /// The ids of the processes being rerun, until their new run has started.
    rerunning: RefCell<HashSet<String>>,
    /// The files of the libraries our processes declared, which this shell
    /// supplies on request (see library.rs).
    libraries: Rc<LibraryFiles>,
    /// The look a builtin's `$stdout` is declared with, by process id (see
    /// terminal_decorations).
    stdout_looks: RefCell<HashMap<String, Value>>,
    daemons: RefCell<IndexMap<String, Rc<Daemon>>>,

    shutdown: Cell<bool>,
    /// Graceful close: prompt gone, draining processes.
    closing: Cell<bool>,
    /// Ends the input loop (see finish_if_drained).
    stop_input: Notify,
    /// The handler tasks still running (see spawn_task): the shell ends once
    /// its input has and they are done.
    active: Cell<usize>,
    idle: Notify,
    next_process_id: Cell<u64>,
    old_pwd: RefCell<Option<String>>,

    /// Accent of the current prompt (the echoes' colour).
    prompt_color: RefCell<Option<String>>,
    /// The prompt text (host, path, branch), without the time: see
    /// prompt_context, prompt_marker.
    prompt_look: RefCell<Option<Vec<Value>>>,
    /// Key chord → what it does (from the configuration).
    bindings: RefCell<IndexMap<String, Value>>,
    /// The programs that may address the shell (see approval.rs).
    control_commands: RefCell<Vec<ControlCommand>>,
    /// How the prompt looks (from the configuration).
    prompt_spec: RefCell<PromptSpec>,
    /// The files the loaded configuration depends on, as they were loaded.
    config_snapshot: RefCell<Option<Snapshot>>,
    /// The pending request to reload the configuration, if its files
    /// changed: the version of the files it asks about, and what changed.
    config_request: RefCell<Option<(String, Vec<FileChange>)>>,
    /// The requests view (see command_requests), if one is up: its process id.
    requests_view: RefCell<Option<String>>,
    /// A version of the configuration files the user chose not to load.
    ignored_version: RefCell<Option<String>>,
    /// The files of the configuration that need the user's trust (a
    /// directory's: see trust.rs), those of them that were applied
    /// (trusted), and those that weren't: present, but not trusted with what
    /// they hold — what the trust request asks about (but those ignored).
    local_files: RefCell<HashSet<String>>,
    trusted_files: RefCell<HashSet<String>>,
    untrusted: RefCell<Vec<TrustedFile>>,
    /// The untrusted contents the user chose not to trust (for now): see
    /// TrustedFile::key.
    ignored_trust: RefCell<HashSet<String>>,
    watch_task: RefCell<Option<JoinHandle<()>>>,
    history: RefCell<ShellHistory>,
    /// History-navigation state for the previous/next commands: the terminal
    /// doesn't carry an anchor, so the shell remembers where we are and
    /// resets it on submit or on a fresh parse.
    nav: RefCell<Option<NavState>>,
    /// Set by a builtin that reported its failure inline (cd into nowhere).
    builtin_failure: Cell<bool>,
}

impl Shell {
    pub fn new(out: mpsc::UnboundedSender<Message>, cols: u16, rows: u16) -> Rc<Self> {
        let original_env: HashMap<String, String> = std::env::vars().collect();
        Rc::new(Shell {
            cols,
            rows,
            env: RefCell::new(original_env.clone().into_iter().collect()),
            original_env,
            out: RefCell::new(Some(out)),
            vars: RefCell::default(),
            user_env: RefCell::default(),
            user_vars: RefCell::default(),
            processes: RefCell::default(),
            runs: RefCell::default(),
            rerunning: RefCell::default(),
            libraries: Rc::default(),
            stdout_looks: RefCell::default(),
            daemons: RefCell::default(),
            shutdown: Cell::new(false),
            closing: Cell::new(false),
            stop_input: Notify::new(),
            active: Cell::new(0),
            idle: Notify::new(),
            next_process_id: Cell::new(0),
            old_pwd: RefCell::default(),
            prompt_color: RefCell::default(),
            prompt_look: RefCell::default(),
            bindings: RefCell::default(),
            control_commands: RefCell::default(),
            prompt_spec: RefCell::default(),
            config_snapshot: RefCell::default(),
            config_request: RefCell::default(),
            requests_view: RefCell::default(),
            ignored_version: RefCell::default(),
            local_files: RefCell::default(),
            trusted_files: RefCell::default(),
            untrusted: RefCell::default(),
            ignored_trust: RefCell::default(),
            watch_task: RefCell::default(),
            history: RefCell::new(ShellHistory::load()),
            nav: RefCell::default(),
            builtin_failure: Cell::new(false),
        })
    }

    fn generate_process_id(&self) -> String {
        self.next_process_id.set(self.next_process_id.get() + 1);
        self.next_process_id.get().to_string()
    }

    /// A variable: the shell's, then the environment's.
    pub(crate) fn lookup(&self, name: &str) -> Option<String> {
        self.vars.borrow().get(name).cloned().or_else(|| self.env.borrow().get(name).cloned())
    }

    fn path_var(&self) -> String {
        self.env.borrow().get("PATH").cloned().unwrap_or_default()
    }

    /// Say something: to our parent, or — ["$shell"]: for the shell — to
    /// ourselves (a daemon's request, say).
    fn emit(self: &Rc<Self>, message: Message) {
        if to_head(&message) == Some("$shell") {
            let shell = self.clone();
            spawn_local(async move {
                if let Err(err) = shell.clone().handle(message, None).await {
                    shell.emit(make_error(&err));
                }
            });
        } else if let Some(out) = &*self.out.borrow() {
            let _ = out.send(message);
        }
    }

    /// Run a handler as a task of its own; what goes wrong in it is reported.
    fn spawn_task(self: &Rc<Self>, task: impl Future<Output = Result<()>> + 'static) {
        self.active.set(self.active.get() + 1);
        let shell = self.clone();
        spawn_local(async move {
            if let Err(err) = task.await {
                shell.emit(make_error(&err));
            }
            shell.active.set(shell.active.get() - 1);
            if shell.active.get() == 0 {
                shell.idle.notify_one();
            }
        });
    }

    /// Run the shell on the messages from its parent (the terminal, or an
    /// enclosing shell), until they end (or the shell is shut down) and what
    /// they started is done.
    pub async fn run(self: &Rc<Self>, mut input: mpsc::UnboundedReceiver<Message>) {
        self.apply_config();
        self.prompt_configure_full();
        self.start_watching();
        loop {
            tokio::select! {
                _ = self.stop_input.notified() => break,
                message = input.recv() => match message {
                    Some(message) => self.receive(message).await,
                    None => break,
                },
            }
            if self.shutdown.get() {
                break;
            }
        }
        while self.active.get() > 0 {
            self.idle.notified().await;
        }
        self.stop_watching();
        for daemon in self.daemons.borrow().values() {
            daemon.stop();
        }
        // (The end of the output.)
        self.out.borrow_mut().take();
    }

    /// Handle a message from our parent. Messages addressed to this shell
    /// are handled; those for its processes are delivered to them.
    async fn receive(self: &Rc<Self>, msg: Message) {
        // Every message from our parent must be addressed to ["$proc", ...]
        // — the routing prefix meaning "for a process". Anything else is a
        // protocol violation.
        let Some(to) = address_of(msg.get("to")).filter(|to| to.first().is_some_and(|h| h == "$proc")) else {
            let to = msg.get("to").cloned().unwrap_or(Value::Null);
            return self.emit(make_error(&anyhow!("Downward message must be addressed to [\"$proc\", …] (got to: {to})")));
        };
        // The logical address (the part after "$proc") is either:
        //   ["cq"]                 → this shell itself: handled here;
        //   ["cq", <id>, ...rest]  → one of our subprocesses: forwarded
        //                            down, stripping our own hop so the child
        //                            sees itself at ["$proc", ...rest].
        if let [_, namespace, id, rest @ ..] = to.as_slice() {
            if namespace != "cq" {
                return self.emit(make_error(&anyhow!("Unknown process namespace: {namespace:?}")));
            }
            if self.requests_view.borrow().as_ref() == Some(id) {
                return self.answer_requests_view(&msg);
            }
            // A request about the process itself: at its address, or one of
            // its views (ours, see deliver), or one it left to us (see
            // Delegations). Anything else under it is its own business,
            // delivered as is (to a shell it is, say, which knows what its own
            // cells are about).
            let own = rest.is_empty() || (rest.len() == 1 && PROCESS_VIEWS.contains(&rest[0].as_str()));
            let delegated = !own && self.delegated(id, rest, kind(&msg));
            if kind(&msg) == "rerun" && (own || delegated) {
                let (shell, id) = (self.clone(), id.clone());
                return self.spawn_task(async move { shell.rerun(id).await });
            }
            if !delegated {
                self.deliver(&msg, id, rest);
            }
            return;
        }
        // Addressed to this shell itself. Some requests hold the input up
        // until they are done (`wait`: for --play scripts); the others run
        // as tasks, alongside what comes next.
        match kind(&msg) {
            "wait" | "shutdown" | "stdout_mode" | "nuke" | "daemon_set" | "daemon_enable" | "daemon_disable"
            | "resize" => {
                if let Err(err) = self.clone().handle(msg, None).await {
                    self.emit(make_error(&err));
                }
            }
            _ => {
                let shell = self.clone();
                self.spawn_task(async move { shell.handle(msg, None).await });
            }
        }
    }

    /// Handle a request to the shell itself, by type (from our parent, or
    /// from a process: see emit).
    async fn handle(self: Rc<Self>, msg: Message, process_id: Option<String>) -> Result<()> {
        let str_field = |name: &str| match msg.get(name) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        match kind(&msg) {
            "cd" => self.handle_cd(&str_field("path"), process_id.as_deref())?,
            "set" => self.handle_set(&str_field("name"), &str_field("value"), msg.get("export") == Some(&Value::Bool(true))),
            "nuke" => self.kill_all(),
            "daemon_set" => {
                let args = msg.get("args").and_then(Value::as_array).map_or(vec![], |a| {
                    a.iter().map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_owned)).collect()
                });
                let restart = msg.get("restartMs").and_then(Value::as_u64);
                self.daemon_set(&str_field("name"), &str_field("cmd"), args, restart);
            }
            "daemon_enable" => self.daemon_enable(&str_field("name")),
            "daemon_disable" => self.daemon_disable(&str_field("name")),
            "parse" => self.handle_parse(&msg),
            "command" => self.handle_command(&msg).await?,
            "resize" => self.handle_resize(&msg),
            "wait" => {
                let seconds = msg.get("seconds").and_then(Value::as_f64).unwrap_or(0.0);
                tokio::time::sleep(Duration::from_secs_f64(seconds.max(0.0))).await;
            }
            "shutdown" => self.handle_shutdown(),
            "stdout_mode" => {
                if let Some(id) = from_at(&msg, 2) {
                    let proc = self.processes.borrow().get(id).cloned();
                    if let Some(proc) = proc {
                        proc.set_stdout_mode(msg.get("mode").unwrap_or(&Value::Null));
                    }
                }
            }
            "configure" => self.handle_configure(&msg),
            "library_fetch" => self.handle_library_fetch(&msg).await,
            _ => {}
        }
        Ok(())
    }

    /// Whether process `id` left requests of this `type` about its cell at
    /// `rest` to us (see Delegations), even if it has ended since.
    fn delegated(&self, id: &str, rest: &[String], request: &str) -> bool {
        let Some(run) = self.runs.borrow().get(id).cloned() else { return false };
        let delegations = run.delegations.borrow();
        match delegations.get(&address_key(rest)) {
            Some(Delegate::All) => true,
            Some(Delegate::Types(types)) => types.iter().any(|t| t == request),
            None => false,
        }
    }

    /// Deliver a message to process `id` (at `rest` under it). A `signal` or
    /// `resize` for a direct child (no `rest`) is delivered at the OS level
    /// rather than forwarded, since a leaf process has no shell to interpret
    /// it. A `text` (terminal input) for a direct child likewise goes to its
    /// stdin, not to its control channel.
    fn deliver(self: &Rc<Self>, msg: &Message, id: &str, rest: &[String]) {
        let Some(proc) = self.processes.borrow().get(id).cloned() else { return };
        // A view of the process (its placeholder, terminal or frame): ours,
        // not its child's. Its terminal input and resizes are the process's;
        // its signals mean nothing (the terminal signals the process itself
        // once its last view is closed).
        let view = match rest {
            [view] if PROCESS_VIEWS.contains(&view.as_str()) => Some(view.as_str()),
            _ => None,
        };
        let terminal = rest.is_empty() || matches!(view, Some("?" | "$stdout"));
        match kind(msg) {
            "signal" if view.is_some() => {}
            "signal" if rest.is_empty() => {
                proc.kill(msg.get("code").and_then(Value::as_i64).map(|c| c as i32));
            }
            // Resizing a leaf's PTY (TIOCSWINSZ) is what delivers SIGWINCH.
            "resize" if terminal => self.handle_resize(msg),
            "text" if terminal => proc.write_stdin(msg.get("text").and_then(Value::as_str).unwrap_or_default()),
            _ => {
                let mut to = vec!["$proc".to_owned()];
                to.extend_from_slice(rest);
                proc.write_control(&merged(msg.clone(), json!({ "to": to })));
            }
        }
    }

    /// The terminal asks for the content of a library file we vouched for
    /// (see library.rs): read it again, and send it if it still has that
    /// hash.
    async fn handle_library_fetch(self: &Rc<Self>, msg: &Message) {
        let request_id = msg.get("request_id").map_or(String::new(), |r| r.as_str().map_or_else(|| r.to_string(), str::to_owned));
        let answer = json!({ "type": "library_content", "from": SELF, "to": ["$term"], "request_id": request_id });
        let hash = msg.get("hash").and_then(Value::as_str).unwrap_or_default();
        let fields = match self.libraries.read(hash).await {
            Ok(data) => json!({ "content": BASE64.encode(data), "encoding": "base64" }),
            Err(err) => json!({ "error": err.to_string() }),
        };
        self.emit(merged(answer, fields));
    }

    // The daemons

    /// Tell the daemons a command started: the process of a cell (a builtin,
    /// a program, a pipeline: `commands` holds its stages, each [command,
    /// ...arguments]), as submitted, bound to a key, or rerun. (Not the
    /// commands of a `$(…)`, nor the daemons.)
    fn command_started(&self, process_id: &str, commands: Vec<Vec<String>>, cwd: &std::path::Path) {
        self.notify_daemons(json!({ "type": "command_started", "process_id": process_id, "commands": commands, "cwd": cwd }));
    }

    /// Tell the daemons a command (see command_started) ended, and how.
    fn command_ended(&self, process_id: &str, outcome: &Value) {
        self.notify_daemons(json!({ "type": "command_ended", "process_id": process_id, "outcome": outcome }));
    }

    fn notify_daemons(&self, event: Value) {
        let message = merged(json!({ "to": ["$shell"] }), event);
        for daemon in self.daemons.borrow().values() {
            if let Some(proc) = &*daemon.proc.borrow() {
                proc.write_control(&message);
            }
        }
    }

    // The prompt

    /// The prompt's text and accent, as they are now (see render_prompt).
    fn render_prompt(&self) -> (Vec<Value>, String) {
        let look = render_prompt(&self.prompt_spec.borrow(), &cwd().to_string_lossy(), &|name| self.lookup(name));
        (look.parts, look.color)
    }

    /// After a variable changed: render the prompt again, and update it if
    /// it looks different. (Its text depends on nothing else but the working
    /// directory and the configuration, which configure it anew themselves.)
    fn refresh_prompt(self: &Rc<Self>) {
        if self.prompt_look.borrow().is_none() || self.closing.get() {
            return;
        }
        let (parts, color) = self.render_prompt();
        if self.prompt_color.borrow().as_ref() == Some(&color) && self.prompt_look.borrow().as_ref() == Some(&parts) {
            return;
        }
        *self.prompt_color.borrow_mut() = Some(color.clone());
        *self.prompt_look.borrow_mut() = Some(parts);
        self.emit(prompt_configure(json!({ "input": { "context": self.current_context() }, "color": color })));
    }

    /// Configure the prompt whole: its look, its bindings.
    fn prompt_configure_full(self: &Rc<Self>) {
        let (parts, color) = self.render_prompt();
        *self.prompt_color.borrow_mut() = Some(color.clone());
        *self.prompt_look.borrow_mut() = Some(parts);
        let dir = cwd().file_name().map_or("/".into(), |n| n.to_string_lossy().into_owned());
        let bindings: Map<String, Value> = self.bindings.borrow().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        // (Its ✕ signals this shell: the terminal signals ["$proc"], the
        // group above it, once nothing else under it lives.)
        self.emit(prompt_configure(json!({
            "input": { "context": self.current_context() },
            "color": color,
            // The look of a program's prompt: the coquille logo, a sans-serif label.
            "label": styled_all(&dir, "sans"),
            "icon": logo(),
            "bindings": bindings,
        })));
        // This shell's own tab is its prompt, not a cell: the placeholder the
        // terminal shows for our process in the enclosing shell's stream, if
        // any (locally ["$proc", "?"] — the enclosing shell re-addresses it to
        // the placeholder of the process it spawned us as), goes away on its
        // own once spent. Then mark it spent. A no-op visually at top level,
        // where there is no such placeholder.
        self.emit(json!({ "type": "configure", "from": ["$proc", "?"], "to": ["$term"], "ephemeral": true }));
        self.emit(close_message(&["$proc".into(), "?".into()], true, Some(0)));
    }

    // The configuration

    /// (Re)load the configuration for the working directory and apply it.
    /// Its problems are sent as `error` messages: whatever happens, the shell
    /// keeps running, with what could be loaded.
    fn apply_config(self: &Rc<Self>) {
        // Whatever is loaded now, a pending question about other files is moot.
        self.withdraw_config_request();
        let trust_before = self.trust_request_id();
        for error in self.apply_config_unchecked() {
            self.emit(config_error(error));
        }
        // (What the trust request asks about may have changed with the files.)
        if self.trust_request_id() != trust_before {
            self.requests_changed();
        }
    }

    fn apply_config_unchecked(self: &Rc<Self>) -> Vec<ConfigError> {
        let here = cwd();
        // Start over from the original environment (and no variables), so
        // that stale configuration variables don't accumulate across reloads
        // (a directory's left behind, say); what the user set goes back on
        // top, below.
        let mut env: BTreeMap<String, String> = self.original_env.clone().into_iter().collect();
        env.insert("PWD".into(), here.to_string_lossy().into_owned());
        *self.env.borrow_mut() = env;
        self.vars.borrow_mut().clear();

        let config = load_config(&here, &self.original_env);
        for (name, value) in &config.env {
            if value.export {
                self.env.borrow_mut().insert(name.clone(), value.value.clone());
                self.vars.borrow_mut().remove(name);
            } else {
                self.vars.borrow_mut().insert(name.clone(), value.value.clone());
            }
            self.notify_daemons(json!({ "type": "env_changed", "name": name, "value": value.value }));
        }
        let user_env = self.user_env.borrow().clone();
        for (name, value) in user_env {
            self.apply_export(&name, &value);
        }
        for (name, value) in self.user_vars.borrow().iter() {
            self.vars.borrow_mut().insert(name.clone(), value.clone());
        }

        // Reconcile the daemons: stop those that disappeared or changed,
        // start those that are new; leave the others alone. (The new ones are
        // checked against the control commands loaded with them.)
        *self.control_commands.borrow_mut() = config.control_commands.clone();
        self.daemons.borrow_mut().retain(|name, daemon| {
            let same = config.daemons.get(name).is_some_and(|d| {
                d.cmd == daemon.cmd && d.args == daemon.args && Some(&d.config_dir) == daemon.config_dir.as_ref()
            });
            if !same {
                daemon.stop();
            }
            same
        });
        for (name, spec) in &config.daemons {
            if !self.daemons.borrow().contains_key(name) {
                let daemon = Daemon {
                    cmd: spec.cmd.clone(),
                    args: spec.args.clone(),
                    config_dir: Some(spec.config_dir.clone()),
                    restart_ms: None,
                    enabled: Cell::new(true),
                    proc: RefCell::default(),
                };
                self.daemons.borrow_mut().insert(name.clone(), Rc::new(daemon));
                self.run_daemon(name);
            }
        }

        // The prompt picks the new bindings up from its next configure (see
        // prompt_configure_full, which follows every reload).
        *self.bindings.borrow_mut() = config.bindings;
        *self.prompt_spec.borrow_mut() = config.prompt;
        self.history.borrow_mut().set_limit(config.history_size);
        *self.config_snapshot.borrow_mut() = Some(snapshot(&config.files));
        *self.ignored_version.borrow_mut() = None;
        *self.local_files.borrow_mut() = config.local.into_iter().collect();
        *self.trusted_files.borrow_mut() = config.trusted.into_iter().collect();
        let mut untrusted: Vec<TrustedFile> = vec![];
        for entry in config.untrusted {
            if !untrusted.iter().any(|u| u.file == entry.file) {
                untrusted.push(entry);
            }
        }
        *self.untrusted.borrow_mut() = untrusted;
        config.errors
    }

    /// Poll the configuration files, to offer a reload when they change.
    fn start_watching(self: &Rc<Self>) {
        if self.watch_task.borrow().is_some() {
            return;
        }
        let shell = Rc::downgrade(self);
        *self.watch_task.borrow_mut() = Some(spawn_local(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(shell) = shell.upgrade() else { return };
                shell.check_config();
            }
        }));
    }

    fn stop_watching(&self) {
        if let Some(task) = self.watch_task.borrow_mut().take() {
            task.abort();
        }
    }

    /// Compare the configuration files with what was loaded. Changed:
    /// request (once per version) a reload; back as they were: withdraw the
    /// request. But for files that weren't applied, as not trusted (or
    /// absent): nothing changes until they are, so there is nothing to
    /// reload; what the trust request asks about is what they hold now.
    fn check_config(self: &Rc<Self>) {
        if self.closing.get() || self.shutdown.get() {
            return;
        }
        let Some(loaded) = self.config_snapshot.borrow().clone() else { return };
        let current = snapshot(loaded.files.keys());
        let changed = changes(&loaded, &current);
        let unapplied = |file: &str| self.local_files.borrow().contains(file) && !self.trusted_files.borrow().contains(file);
        if !changed.is_empty() && changed.iter().all(|c| unapplied(&c.file)) {
            {
                let mut untrusted = self.untrusted.borrow_mut();
                for FileChange { file, .. } in &changed {
                    untrusted.retain(|u| &u.file != file);
                    if let Some(Some(hash)) = current.files.get(file) {
                        untrusted.push(TrustedFile { file: file.clone(), hash: hash.clone() });
                    }
                }
            }
            *self.config_snapshot.borrow_mut() = Some(current);
            return self.requests_changed();
        }
        if current.version == loaded.version {
            self.withdraw_config_request();
        } else {
            let asked = self.config_request.borrow().as_ref().map(|(v, _)| v.clone());
            if asked.as_ref() != Some(&current.version) && self.ignored_version.borrow().as_ref() != Some(&current.version) {
                *self.config_request.borrow_mut() = Some((current.version, changed));
                self.requests_changed();
            }
        }
    }

    /// Withdraw the request to reload the configuration, if there is one.
    fn withdraw_config_request(self: &Rc<Self>) {
        if self.config_request.borrow_mut().take().is_some() {
            self.requests_changed();
        }
    }

    // Pending requests

    /// The requests waiting for the user's answer (see requests.rs).
    fn pending_requests(&self) -> Vec<PendingRequest> {
        let mut requests = vec![];
        if let Some((version, changes)) = &*self.config_request.borrow() {
            requests.push(PendingRequest {
                id: format!("config:{version}"),
                summary: "config change is pending".into(),
                title: "The shell configuration changed. Reload it?".into(),
                details: changes.iter().map(|c| format!("{} ({})", tildify(&c.file), c.change)).collect(),
                approve: "Reload".into(),
                ignore: "Ignore".into(),
            });
        }
        let untrusted = self.visible_untrusted();
        if let Some(id) = self.trust_request_id() {
            requests.push(PendingRequest {
                id,
                summary: "config needs your trust".into(),
                title: "This directory's configuration was left out: it isn't trusted. Trust it (it can run commands)?".into(),
                details: untrusted
                    .iter()
                    .map(|u| {
                        let why = if was_trusted(&u.file) { "changed since you trusted it" } else { "never trusted" };
                        format!("{} ({why})", tildify(&u.file))
                    })
                    .collect(),
                approve: "Trust".into(),
                ignore: "Ignore".into(),
            });
        }
        requests
    }

    /// The untrusted files the trust request asks about: those the user
    /// didn't ignore (with what they hold).
    fn visible_untrusted(&self) -> Vec<TrustedFile> {
        let ignored = self.ignored_trust.borrow();
        self.untrusted.borrow().iter().filter(|u| !ignored.contains(&u.key())).cloned().collect()
    }

    /// The trust request's id (None: none): it names what it asks about.
    fn trust_request_id(&self) -> Option<String> {
        let untrusted = self.visible_untrusted();
        if untrusted.is_empty() {
            return None;
        }
        let mut hash = Sha256::new();
        for u in &untrusted {
            hash.update(format!("{}\0", u.key()));
        }
        Some(format!("trust:{}", &hex::encode(hash.finalize())[..16]))
    }

    /// The prompt's context now: the prompt text, then what is pending (if
    /// anything).
    fn current_context(&self) -> Value {
        let look = self.prompt_look.borrow().clone().unwrap_or_default();
        prompt_marker(&look, pending_summary(&self.pending_requests()))
    }

    /// The pending requests changed: say so in the prompt's context, and
    /// show them in the requests view, if it is up (closing it once none is
    /// left).
    fn requests_changed(self: &Rc<Self>) {
        let requests = self.pending_requests();
        if self.prompt_look.borrow().is_some() {
            self.emit(prompt_configure(json!({ "input": { "context": self.current_context() } })));
        }
        let Some(view) = self.requests_view.borrow().clone() else { return };
        if requests.is_empty() {
            return self.close_requests_view();
        }
        self.emit(json!({
            "type": "send",
            "from": ["$proc", "cq", view, "$frame"],
            "to": ["$term"],
            "message": render_requests(&requests),
        }));
    }

    /// The `requests` builtin (Alt+a, or a click on the pending notice in the
    /// prompt's context): show the pending requests in a cell, for the user
    /// to approve or ignore each one from the keyboard (or with its buttons).
    /// The cell takes the focus (it repeats the command's id), and goes when
    /// closed (Escape), or when no request is left.
    fn command_requests(self: &Rc<Self>, msg: &Message) {
        self.close_requests_view();
        let id = self.generate_process_id();
        *self.requests_view.borrow_mut() = Some(id.clone());
        let addr = process_addr(&id);
        let mut configure = json!({
            "type": "configure",
            "from": addr,
            "to": ["$term"],
            "zone": msg.get("zone").filter(|z| z.is_string()).cloned().unwrap_or(Value::Null),
        });
        let obj = configure.as_object_mut().unwrap();
        put_opt(obj, "anchor", anchor_field(msg));
        put_opt(obj, "id", msg.get("id").filter(|v| !v.is_null()).cloned());
        obj.insert("ephemeral".into(), json!(true));
        obj.insert("label".into(), styled_all("requests", "sans"));
        obj.insert("icon".into(), logo());
        put_opt(obj, "color", self.prompt_color.borrow().clone());
        self.emit(configure);
        let mut frame = addr;
        frame.push("$frame".into());
        self.emit(json!({ "type": "configure", "from": frame, "to": ["$term"], "kind": "frame" }));
        self.emit(json!({ "type": "send", "from": frame, "to": ["$term"], "message": { "type": "html", "content": REQUESTS_HTML } }));
        self.emit(json!({ "type": "send", "from": frame, "to": ["$term"], "message": render_requests(&self.pending_requests()) }));
    }

    /// Close the requests view, if it is up (it is ephemeral: it goes).
    fn close_requests_view(self: &Rc<Self>) {
        let Some(view) = self.requests_view.borrow_mut().take() else { return };
        self.emit(close_message(&process_addr(&view), true, Some(0)));
    }

    /// The requests view said something: an answer to a request (`data`:
    /// `{request, answer}`), or that the user is done with it (`data`:
    /// `{dismiss: true}` on Escape, or a `signal`: its cell was closed).
    fn answer_requests_view(self: &Rc<Self>, msg: &Message) {
        match kind(msg) {
            "signal" => self.close_requests_view(),
            "data" => {
                let data = msg.get("data").unwrap_or(&Value::Null);
                if data.get("dismiss") == Some(&Value::Bool(true)) {
                    return self.close_requests_view();
                }
                let answer = match data.get("answer").and_then(Value::as_str) {
                    Some("approve") => Answer::Approve,
                    Some("ignore") => Answer::Ignore,
                    _ => return,
                };
                let request = data.get("request").map_or(String::new(), |r| r.as_str().map_or_else(|| r.to_string(), str::to_owned));
                self.answer_request(&request, answer);
            }
            _ => {}
        }
    }

    /// Answer a pending request (a stale one, no longer pending, is dropped).
    fn answer_request(self: &Rc<Self>, id: &str, answer: Answer) {
        if id.starts_with("trust:") {
            return self.answer_trust_request(id, answer);
        }
        let Some((version, changes)) = self.config_request.borrow().clone() else { return };
        if id != format!("config:{version}") {
            return;
        }
        if answer == Answer::Ignore {
            *self.ignored_version.borrow_mut() = Some(version);
            return self.withdraw_config_request();
        }
        // A reload only happens if the files are still in that version; if
        // they changed since, the next check asks again.
        let files: Vec<String> = self.config_snapshot.borrow().iter().flat_map(|s| s.files.keys().cloned()).collect();
        let current = snapshot(&files);
        if current.version != version {
            return;
        }
        // Reloading accepts the changes: the trusted files changed are
        // trusted with what they hold now (the content the request was about).
        let accepted: Vec<TrustedFile> = changes
            .iter()
            .filter(|c| self.trusted_files.borrow().contains(&c.file))
            .filter_map(|c| {
                let hash = current.files.get(&c.file).cloned().flatten()?;
                Some(TrustedFile { file: c.file.clone(), hash })
            })
            .collect();
        if !accepted.is_empty()
            && let Err(err) = trust(&accepted)
        {
            self.emit(make_error(&anyhow!(err).context("could not record the trusted files")));
        }
        self.apply_config();
        self.prompt_configure_full();
    }

    /// Answer the trust request: trust the files with the very contents it
    /// asked about (changed since, they are asked about again), and load
    /// them; or leave them out, and stop asking about these contents.
    fn answer_trust_request(self: &Rc<Self>, id: &str, answer: Answer) {
        if Some(id) != self.trust_request_id().as_deref() {
            return;
        }
        let untrusted = self.visible_untrusted();
        if answer == Answer::Ignore {
            self.ignored_trust.borrow_mut().extend(untrusted.iter().map(TrustedFile::key));
            return self.requests_changed();
        }
        if let Err(err) = trust(&untrusted) {
            self.emit(make_error(&anyhow!(err).context("could not record the trusted files")));
        }
        self.apply_config();
        self.prompt_configure_full();
    }

    // Builtin requests

    fn handle_cd(self: &Rc<Self>, path: &str, process_id: Option<&str>) -> Result<()> {
        let prev = cwd().to_string_lossy().into_owned();
        let target = if path == "-" { self.old_pwd.borrow().clone().unwrap_or_else(|| prev.clone()) } else { path.to_owned() };
        if let Err(err) = std::env::set_current_dir(&target) {
            // A real shell reports cd failures on the command's stderr —
            // inline, in its cell — not as a protocol `error` (which the
            // terminal surfaces as a problem popup). Without a cell to write
            // to (a request carrying no process id), fall back on the popup.
            let Some(process_id) = process_id else {
                return Err(anyhow::Error::new(err).context(format!("cd: {target}")));
            };
            let reason = match err.raw_os_error() {
                Some(libc::ENOENT) => "no such file or directory".to_owned(),
                Some(libc::ENOTDIR) => "not a directory".to_owned(),
                Some(libc::EACCES) => "permission denied".to_owned(),
                _ => err.to_string(),
            };
            let stdout = json!(["$proc", "cq", process_id, "$stdout"]);
            let look = self.stdout_looks.borrow().get(process_id).cloned().unwrap_or(json!({}));
            self.emit(merged(json!({ "type": "configure", "from": stdout, "to": ["$term"], "kind": "terminal" }), look));
            let text = format!("cd: {reason}: {target}\n");
            self.emit(json!({ "type": "send", "from": stdout, "to": ["$term"], "message": { "type": "text", "stream": "stderr", "text": text } }));
            self.builtin_failure.set(true);
            return Ok(());
        }
        *self.old_pwd.borrow_mut() = Some(prev.clone());
        self.notify_daemons(json!({ "type": "cwd_changed", "cwd": cwd() }));
        self.apply_config();
        self.prompt_configure_full();
        self.export_var("OLDPWD", &prev);
        Ok(())
    }

    fn handle_set(self: &Rc<Self>, name: &str, value: &str, export: bool) {
        if export {
            self.export_var(name, value);
        } else {
            self.user_vars.borrow_mut().insert(name.into(), value.into());
            self.vars.borrow_mut().insert(name.into(), value.into());
        }
        // (The prompt may show it: a daemon keeping $VCS_HEAD, say.)
        self.refresh_prompt();
    }

    /// Export a variable from the shell: now, and after every reload of the
    /// configuration (see user_env).
    fn export_var(&self, name: &str, value: &str) {
        self.user_env.borrow_mut().insert(name.into(), value.into());
        self.user_vars.borrow_mut().shift_remove(name);
        self.apply_export(name, value);
    }

    fn apply_export(&self, name: &str, value: &str) {
        self.env.borrow_mut().insert(name.into(), value.into());
        self.vars.borrow_mut().remove(name);
        self.notify_daemons(json!({ "type": "env_changed", "name": name, "value": value }));
    }

    fn kill_all(&self) {
        for proc in self.processes.borrow().values() {
            proc.kill(None);
        }
    }

    fn daemon_set(self: &Rc<Self>, name: &str, cmd: &str, args: Vec<String>, restart_ms: Option<u64>) {
        let daemon = Daemon {
            cmd: cmd.into(),
            args,
            config_dir: None,
            restart_ms,
            enabled: Cell::new(true),
            proc: RefCell::default(),
        };
        if let Some(old) = self.daemons.borrow_mut().insert(name.into(), Rc::new(daemon)) {
            old.stop();
        }
        self.run_daemon(name);
    }

    fn daemon_enable(self: &Rc<Self>, name: &str) {
        let daemon = self.daemons.borrow().get(name).cloned();
        if let Some(daemon) = daemon
            && !daemon.enabled.get()
        {
            daemon.enabled.set(true);
            self.run_daemon(name);
        }
    }

    fn daemon_disable(&self, name: &str) {
        if let Some(daemon) = self.daemons.borrow().get(name) {
            daemon.stop();
        }
    }

    /// Run daemon `name` (restarting it if it says so) while it is enabled,
    /// as a task: a failure (it can't be started, say) is reported.
    fn run_daemon(self: &Rc<Self>, name: &str) {
        let Some(daemon) = self.daemons.borrow().get(name).cloned() else { return };
        let (shell, name) = (self.clone(), name.to_owned());
        spawn_local(async move {
            if let Err(err) = shell.run_daemon_unchecked(&daemon).await {
                daemon.enabled.set(false);
                daemon.proc.borrow_mut().take();
                shell.emit(config_error(ConfigError { file: None, message: format!("daemon {name:?} failed: {err:#}") }));
            }
        });
    }

    async fn run_daemon_unchecked(self: &Rc<Self>, daemon: &Daemon) -> Result<()> {
        while daemon.enabled.get() {
            let process_id = self.generate_process_id();
            let mut env = self.env.borrow().clone();
            if let Some(dir) = &daemon.config_dir {
                env.insert("THIS_CONFIG_DIR".into(), dir.clone());
            }
            let lookup = |name: &str| env.get(name).cloned();
            // (A daemon may address the shell if it is a control command, as
            // any other process.)
            let path = env.get("PATH").cloned().unwrap_or_default();
            let approval = approve(&expand_env_vars(&daemon.cmd, &lookup), &path, &cwd(), &self.control_commands.borrow());
            let args: Vec<String> = daemon.args.iter().map(|a| expand_env_vars(a, &lookup)).collect();
            let mut options = self.process_options(env, cwd());
            options.privileged = approval.privileged;
            options.refusal = approval.refusal;
            let proc = Process::spawn(&approval.cmd, &args, process_id, options)?;
            *daemon.proc.borrow_mut() = Some(proc.clone());
            let mut events = proc.events();
            while let Some(event) = events.recv().await {
                self.emit(event);
            }
            daemon.proc.borrow_mut().take();
            match daemon.restart_ms {
                Some(ms) if daemon.enabled.get() => tokio::time::sleep(Duration::from_millis(ms)).await,
                _ => break,
            }
        }
        Ok(())
    }

    // Terminal requests

    fn handle_parse(self: &Rc<Self>, msg: &Message) {
        let text = msg.get("text").and_then(Value::as_str).unwrap_or_default();
        // A fresh parse means the user took over the prompt (or it was
        // reset): drop any history-navigation state.
        self.nav.borrow_mut().take();
        // The highlight echo: a prompt configure answering this parse (the
        // terminal drops the answer if a newer parse superseded it). No
        // selection, so the cursor is never moved by an echo. The filigrane
        // travels inside the content — and is left out when there is nothing
        // to suggest (the content is replaced whole, so its absence clears
        // the ghost).
        let mut content = json!({ "parts": shell_highlight(text, &self.path_var()) });
        if let Some(filigrane) = self.history.borrow().filigrane(text) {
            content["filigrane"] = json!(filigrane);
        }
        let request_id = msg.get("request_id").cloned().unwrap_or(Value::Null);
        self.emit(prompt_configure(json!({ "request_id": request_id, "input": { "content": content } })));
    }

    /// Resize of one of our cells, e.g. from the terminal after a user drag:
    ///   to: ["$proc", "cq", <id>], pty: {width, height}
    /// The PTY resize is what raises SIGWINCH in the child.
    fn handle_resize(&self, msg: &Message) {
        let Some(to) = address_of(msg.get("to")) else { return };
        let Some(proc) = to.get(2).and_then(|id| self.processes.borrow().get(id).cloned()) else { return };
        if let Some(pty) = msg.get("pty") {
            let dim = |name| pty.get(name).and_then(Value::as_u64).map(|n| n as u16);
            if let Some(width) = dim("width") {
                proc.resize(width, dim("height").unwrap_or(24));
            }
        }
    }

    fn handle_shutdown(&self) {
        self.stop_watching();
        self.kill_all();
        for daemon in self.daemons.borrow().values() {
            daemon.stop();
        }
        self.shutdown.set(true);
    }

    /// The graceful-close drain (see command_close): while closing, coquille
    /// keeps forwarding for the processes it started; the one whose exit
    /// empties the set ends the input loop, so the shell finishes and
    /// coquille exits (the terminal sees the driver process close).
    fn finish_if_drained(&self) {
        if self.closing.get() && self.processes.borrow().is_empty() {
            self.shutdown.set(true);
            self.stop_input.notify_one();
        }
    }

    /// A process stopped: forget it (and maybe finish the close drain). With
    /// `proc`, only if it is still the one with that id (not its rerun's).
    fn untrack(&self, process_id: &str, proc: Option<&Rc<Process>>) {
        {
            let mut processes = self.processes.borrow_mut();
            if let Some(proc) = proc
                && !processes.get(process_id).is_some_and(|p| Rc::ptr_eq(p, proc))
            {
                return;
            }
            processes.remove(process_id);
        }
        self.finish_if_drained();
    }

    /// A child program (a picker widget like `fuz`, say) asks to update the
    /// prompt in place. The prompt is ours to configure: relay the
    /// instruction to the terminal under our own address. Content given as
    /// text parts is highlighted as typed text would be (its own styles are
    /// dropped); the rest of its `input` goes as given. Only a prompt's
    /// configuration is ours to relay.
    fn handle_configure(self: &Rc<Self>, msg: &Message) {
        if msg.get("kind").and_then(Value::as_str) != Some("prompt") {
            return;
        }
        let mut relayed = msg.clone();
        if let Some(parts) = msg.pointer("/input/content/parts").and_then(Value::as_array)
            && parts.iter().all(Value::is_object)
        {
            let text = parts_text(parts);
            relayed["input"]["content"]["parts"] = json!(shell_highlight(&text, &self.path_var()));
        }
        self.emit(merged(relayed, json!({ "type": "configure", "kind": "prompt", "from": SELF, "to": ["$term"] })));
    }

    // The prompt's commands

    async fn handle_command(self: &Rc<Self>, msg: &Message) -> Result<()> {
        self.env.borrow_mut().insert("CQ_CURRENT_COMMAND".into(), msg.to_string());
        let raw = msg.get("action").unwrap_or(&Value::Null);
        let action = parse_action(raw).map_err(|e| anyhow!("Bad action {raw}: {e}"))?;
        if let Some(builtin) = action.get("builtin").and_then(Value::as_str) {
            return match builtin {
                "submit" => self.command_submit(msg).await,
                "run" => self.submit(SubmitRequest { history: false, ..SubmitRequest::from_message(msg) }).await,
                "previous" => Ok(self.history_step(msg, Direction::Prev)),
                "next" => Ok(self.history_step(msg, Direction::Next)),
                "close" => Ok(self.command_close()),
                "requests" => Ok(self.command_requests(msg)),
                "complete" => Ok(self.command_complete(msg)),
                other => bail!("unknown builtin action {other:?}"),
            };
        }
        // A command line (a key bound to it, a clicked part): run it, as if
        // submitted, but leaving the prompt and the history alone. The
        // prompt's text and selection when the action fired are in
        // $CQ_CURRENT_COMMAND (the command request, as JSON).
        let from = SubmitRequest::from_message(msg);
        self.submit(SubmitRequest {
            text: action.get("command").and_then(Value::as_str).map(str::to_owned),
            history: false,
            echo: true,
            id: from.id,
            zone: from.zone,
            anchor: from.anchor,
            ..Default::default()
        })
        .await
    }

    async fn command_submit(self: &Rc<Self>, msg: &Message) -> Result<()> {
        self.nav.borrow_mut().take();
        // The content is replaced whole: the empty text takes the frozen
        // editability and the ghost suggestion down with it (both absent).
        // The context is refreshed along with it. Not for a submission from
        // elsewhere (an `anchor`: sel, run from a cell, say): what it submits
        // isn't the prompt's text, which is left alone.
        if anchor_field(msg).is_none() {
            let mut input = json!({ "content": { "parts": [], "selection": { "start": 0, "end": 0 } } });
            if self.prompt_look.borrow().is_some() {
                input["context"] = self.current_context();
            }
            self.emit(prompt_configure(json!({ "input": input })));
        }
        self.submit(SubmitRequest::from_message(msg)).await
    }

    /// The terminal sends bare previous/next commands (the virtual chords
    /// fired by ArrowUp on the first line / ArrowDown on the last line)
    /// without any history state, so the shell keeps its own navigation
    /// position (reset by submit or a fresh parse). The prompt text filters
    /// the search on the first step; afterwards the remembered filter keeps
    /// the search stable as the prompt is rewritten, and the text typed
    /// before navigating is kept as the draft: stepping past the newest match
    /// restores it.
    fn history_step(self: &Rc<Self>, msg: &Message, direction: Direction) {
        let text = {
            let mut nav = self.nav.borrow_mut();
            let typed = msg.get("text").and_then(Value::as_str).unwrap_or_default();
            let nav = nav.get_or_insert_with(|| NavState { anchor_id: None, filter: typed.into(), draft: typed.into() });
            match self.history.borrow().navigate(direction, nav.anchor_id.as_deref(), &nav.filter) {
                Some((text, id)) => {
                    nav.anchor_id = Some(id);
                    text
                }
                // Past the newest match: back down to what the user typed.
                None if direction == Direction::Next && nav.anchor_id.is_some() => {
                    nav.anchor_id = None;
                    nav.draft.clone()
                }
                // Nothing (further) in that direction: leave the prompt alone.
                None => return,
            }
        };
        let end = utf16_len(&text);
        self.emit(prompt_configure(json!({ "input": { "content": {
            "parts": shell_highlight(&text, &self.path_var()),
            "selection": { "start": end, "end": end },
        } } })));
    }

    /// Ctrl+D: close the shell gracefully. The prompt goes away (its close
    /// removes it in the terminal; the binding also freezes it as it fires,
    /// so nothing can slip in between), daemons stop — but subprocesses are
    /// left alone: coquille keeps running and forwarding their messages
    /// until the last one finishes (see finish_if_drained), and only then
    /// exits.
    fn command_close(self: &Rc<Self>) {
        // propagate: false — the processes still draining live *under* the
        // prompt in the address tree ($proc.cq.<id>); a plain close would
        // mark them all done along with the prompt.
        self.emit(json!({ "type": "close", "from": SELF, "to": ["$term"], "outcome": { "type": "success" }, "propagate": false }));
        for daemon in self.daemons.borrow().values() {
            daemon.stop();
        }
        self.stop_watching();
        // (The prompt is closed: no context to update.)
        self.config_request.borrow_mut().take();
        self.close_requests_view();
        self.closing.set(true);
        self.finish_if_drained();
    }

    /// Tab completion. A unique match is inserted, several matches complete
    /// up to their longest common prefix, and the result goes back as a
    /// configure (highlighted, cursor after the inserted text). A Tab with
    /// nothing new to insert is a no-op.
    fn command_complete(self: &Rc<Self>, msg: &Message) {
        let text = msg.get("text").and_then(Value::as_str).unwrap_or_default();
        let position = msg
            .pointer("/selection/start")
            .and_then(Value::as_u64)
            .map_or(text.len(), |p| utf16_to_byte(text, p as usize));
        let path = self.path_var();
        let completions = shell_complete(text, position, &path);
        if completions.is_empty() {
            return;
        }
        let (start, prefix) = word_before(text, position);
        let inserted = common_prefix(&completions);
        if inserted.len() <= prefix.len() {
            return; // already complete (or no common extension)
        }
        let new_text = format!("{}{inserted}{}", &text[..start], &text[position..]);
        let cursor = utf16_len(&text[..start]) + utf16_len(&inserted);
        self.emit(prompt_configure(json!({ "input": { "content": {
            "parts": shell_highlight(&new_text, &path),
            "selection": { "start": cursor, "end": cursor },
        } } })));
    }

    // Running commands

    fn process_options(&self, env: BTreeMap<String, String>, cwd: PathBuf) -> ProcessOptions {
        ProcessOptions {
            cols: self.cols,
            rows: self.rows,
            env,
            cwd,
            pipe_stdin: false,
            pipe_stdout: false,
            redirects: vec![],
            libraries: Some(self.libraries.clone()),
            parent_salt: self.original_env.get(LIB_SALT_ENV).cloned(),
            delegations: None,
            privileged: false,
            refusal: "not a control command".into(),
        }
    }

    /// The heart of a submission: history, parsing and running. Reached
    /// through command_submit (the terminal's Enter binding), `cq -c`, the
    /// `run` command and key bindings, and for each parsed command.
    async fn submit(self: &Rc<Self>, req: SubmitRequest) -> Result<()> {
        if let Some(text) = &req.text {
            // An empty (or whitespace-only) submission is a no-op: no
            // history entry, no echo, no process.
            if text.trim().is_empty() {
                return Ok(());
            }
            if req.history {
                let entry = HistoryEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    text: text.clone(),
                    dir: Some(cwd().to_string_lossy().into_owned()),
                };
                self.history.borrow_mut().push(entry);
            }
            // An `@zone` prefix says where it shows. Any name is a valid zone
            // — the terminal decides what to do with it.
            let (zone, text) = match ZONE_PREFIX.captures(text) {
                Some(m) => (Some(m[1].to_owned()), text[m[0].len()..].to_owned()),
                None => (req.zone.clone(), text.clone()),
            };
            if text.trim_start().starts_with('#') {
                return Ok(());
            }
            return Box::pin(self.submit_text(req, text, zone)).await;
        }

        let Some((cmd, args)) = req.command.clone() else { bail!("nothing to run") };
        // The process id reserved by submit_text (and shared with the
        // decoration), if any.
        let process_id = req.process_id.clone().unwrap_or_else(|| self.generate_process_id());
        let addr = process_addr(&process_id);

        // The terminal shows the process (a placeholder, until its output
        // comes: it takes input meanwhile) where `zone` says, decorated with
        // the command.
        let declare = self.declare(&addr, &req);
        if is_builtin(&cmd) {
            self.emit(declare);
            let (message, look) = terminal_decorations(&addr, req.decoration.as_ref());
            if let Some(message) = message {
                self.emit(message);
            }
            self.stdout_looks.borrow_mut().insert(process_id.clone(), look);
            let mut command = vec![cmd.clone()];
            command.extend(args.iter().cloned());
            self.command_started(&process_id, vec![command], &cwd());
            self.builtin_failure.set(false);
            let mut success = true;
            if let Err(err) = self.run_builtin(&cmd, &args, &process_id) {
                self.emit(make_error(&err));
                success = false;
            }
            // An inline-reported failure (cd into nowhere): the message
            // already went to the cell's stderr; only the exit code is left.
            if self.builtin_failure.get() {
                success = false;
            }
            let close = close_message(&addr, success, Some(if success { 0 } else { 1 }));
            self.emit(close.clone());
            self.command_ended(&process_id, &close["outcome"]);
            return Ok(());
        }

        let stage = Stage { cmd, args, redirects: req.redirects.clone(), env: req.env.clone() };
        let run = self.new_run(vec![stage], req.decoration.as_ref());
        let proc = self.spawn_run(&process_id, &run)?;
        self.remember(&process_id, run.clone());
        self.emit(declare);
        let (message, look) = terminal_decorations(&addr, req.decoration.as_ref());
        if let Some(message) = message {
            self.emit(message);
        }
        proc.set_stdout_look(look.clone());
        *run.stdout_look.borrow_mut() = look;
        self.relay_run(proc, run).await;
        Ok(())
    }

    /// The `configure` declaring a process's entry.
    fn declare(&self, addr: &[String], req: &SubmitRequest) -> Message {
        let mut declare = json!({
            "type": "configure",
            "from": addr,
            "to": ["$term"],
            "zone": req.zone.clone().map_or(Value::Null, Value::String),
        });
        let obj = declare.as_object_mut().unwrap();
        put_opt(obj, "anchor", req.anchor.clone());
        if req.focus {
            obj.insert("focus".into(), json!(true));
        }
        obj.insert("background".into(), json!(req.background));
        for (k, v) in req.decoration.iter().flatten() {
            obj.insert(k.clone(), v.clone());
        }
        declare
    }

    fn run_builtin(self: &Rc<Self>, name: &str, args: &[String], process_id: &str) -> Result<()> {
        for event in builtin_events(name, args)? {
            match event {
                // (cd reports its failure inline, in the cell this builtin
                // runs as.)
                BuiltinEvent::Cd { path } => self.handle_cd(&path, Some(process_id))?,
                BuiltinEvent::Set { name, value, export } => self.handle_set(&name, &value, export),
                BuiltinEvent::Nuke => self.kill_all(),
                BuiltinEvent::DaemonSet { name, cmd, args, restart_ms } => self.daemon_set(&name, &cmd, args, restart_ms),
                BuiltinEvent::DaemonEnable { name } => self.daemon_enable(&name),
                BuiltinEvent::DaemonDisable { name } => self.daemon_disable(&name),
            }
        }
        Ok(())
    }

    // Runs (see Run)

    /// A run of `stages`, here and now, as submitted with `decoration`.
    fn new_run(&self, stages: Vec<Stage>, decoration: Option<&Map<String, Value>>) -> Rc<Run> {
        Rc::new(Run {
            stages,
            cwd: cwd(),
            env: self.env.borrow().clone(),
            stdout_look: RefCell::new(json!({})),
            color: decoration.and_then(|d| d.get("color")).and_then(Value::as_str).map(str::to_owned),
            delegations: Rc::default(),
            procs: RefCell::default(),
        })
    }

    /// Remember a run, as process `process_id`'s, as the one used last (the
    /// one used the least long ago is forgotten, past MAX_RUNS).
    fn remember(&self, process_id: &str, run: Rc<Run>) {
        let mut runs = self.runs.borrow_mut();
        runs.shift_remove(process_id);
        runs.insert(process_id.into(), run);
        if runs.len() > MAX_RUNS {
            runs.shift_remove_index(0);
        }
    }

    /// Feed `dst` what `src` outputs, as a pipe would: its stdout to its
    /// stdin, its fd 4 to its fd 3; and its end, as the end of its input. If
    /// `dst` stops reading (`head` has what it wants, say), `src` gets
    /// SIGPIPE on its next write, as with a real pipe.
    fn connect(self: &Rc<Self>, src: Rc<Process>, dst: Rc<Process>) {
        let stop = src.clone();
        dst.on_stdin_gone(move || stop.close_stdout());
        let shell = self.clone();
        spawn_local(async move {
            let mut events = src.events();
            while let Some(event) = events.recv().await {
                // Only the source process's own primary streams feed the
                // pipe; messages forwarded up from its children are not. Its
                // own output is sent from ["$proc", "cq", <id>, "$stdout" |
                // "$frame"] (4 long) and its own close from ["$proc", "cq",
                // <id>] (3 long).
                let view = if from_len(&event) == Some(4) { from_at(&event, 3) } else { None };
                let message = event.get("message");
                let message_kind = message.and_then(|m| m.get("type")).and_then(Value::as_str);
                if kind(&event) == "send" && view == Some("$stdout") && message_kind == Some("text")
                    && message.and_then(|m| m.get("stream")) == Some(&json!("stdout"))
                {
                    dst.write_stdin(message.and_then(|m| m["text"].as_str()).unwrap_or_default());
                } else if kind(&event) == "send" && view == Some("$frame") && message_kind == Some("data") {
                    dst.write_datain(&message.unwrap()["data"]);
                } else if kind(&event) == "close" && from_len(&event) == Some(3) {
                    shell.untrack(&src.process_id, Some(&src));
                    dst.close_stdin();
                }
            }
        });
    }

    /// Start a run's processes, a pipeline's each feeding the next, the last
    /// one as process `process_id`: the one whose cells show the run, to
    /// relay (see relay_run). Nothing is left running if one can't be
    /// started.
    fn spawn_run(self: &Rc<Self>, process_id: &str, run: &Rc<Run>) -> Result<Rc<Process>> {
        let last = run.stages.len() - 1;
        let mut procs: Vec<Rc<Process>> = vec![];
        for (i, stage) in run.stages.iter().enumerate() {
            let id = if i == last { process_id.to_owned() } else { self.generate_process_id() };
            let mut env = run.env.clone();
            env.extend(stage.env.iter().cloned());
            let mut options = self.process_options(env.clone(), run.cwd.clone());
            let mut cmd = stage.cmd.clone();
            // Whether it may address the shell (see approval.rs): checked
            // anew at each run. (Only the last one's messages are heeded.)
            if i == last {
                let path = env.get("PATH").cloned().unwrap_or_default();
                let approval = approve(&stage.cmd, &path, &run.cwd, &self.control_commands.borrow());
                cmd = approval.cmd;
                options.privileged = approval.privileged;
                options.refusal = approval.refusal;
                options.delegations = Some(run.delegations.clone());
            }
            // Non-first processes read stdin from a pipe (the previous one's
            // stdout, not the PTY). Non-last processes write stdout to a
            // pipe, so programs don't see a terminal and behave as they would
            // in a real shell pipeline (e.g. ls outputs one file per line).
            options.pipe_stdin = i > 0;
            options.pipe_stdout = i < last;
            options.redirects = stage.redirects.clone();
            match Process::spawn(&cmd, &stage.args, id.clone(), options) {
                Ok(proc) => {
                    self.processes.borrow_mut().insert(id, proc.clone());
                    procs.push(proc);
                }
                Err(err) => {
                    for proc in &procs {
                        proc.kill(None);
                        self.untrack(&proc.process_id, Some(proc));
                    }
                    return Err(err);
                }
            }
        }
        for pair in procs.windows(2) {
            self.connect(pair[0].clone(), pair[1].clone());
        }
        *run.procs.borrow_mut() = procs.clone();
        let commands = run.stages.iter().map(|s| std::iter::once(s.cmd.clone()).chain(s.args.iter().cloned()).collect()).collect();
        self.command_started(process_id, commands, &run.cwd);
        let (run_ref, ended) = (run.clone(), procs.clone());
        spawn_local(async move {
            for proc in &ended {
                proc.exited().await;
            }
            run_ref.procs.borrow_mut().retain(|p| !ended.iter().any(|e| Rc::ptr_eq(p, e)));
        });
        Ok(procs[last].clone())
    }

    /// Relay what a run's process says, until it ends. Its messages go
    /// as-is: the terminal places them through the `configure` chain. Once
    /// it is being rerun, they are dropped.
    async fn relay_run(self: &Rc<Self>, proc: Rc<Process>, run: Rc<Run>) {
        let name = run.stages.last().map(|s| s.cmd.clone()).unwrap_or_default();
        let mut events = proc.events();
        while let Some(event) = events.recv().await {
            // Only this process's own close (from ["$proc", "cq", <id>], 3
            // long) means it exited; forwarded child closes are relayed on.
            if kind(&event) == "close" && from_len(&event) == Some(3) {
                self.untrack(&proc.process_id, Some(&proc));
                self.command_ended(&proc.process_id, &event["outcome"]);
            }
            if !proc.superseded.get() {
                self.emit(with_program_look(event, &name, run.color.as_deref()));
            }
        }
    }

    /// Run process `process_id` again (a `rerun` from the terminal, about
    /// the process: see receive): its command, as it was first run (see
    /// Run), in its cells, reset — the terminal shows them running again.
    /// Still running, it is ended first (SIGTERM; one that won't end holds
    /// the rerun up, until its cell is killed); what it says meanwhile, its
    /// close included, is dropped. Nothing to do for a process that isn't
    /// remembered (a builtin, say, or one of more than MAX_RUNS ago), one
    /// already being rerun, or while the shell is closing.
    async fn rerun(self: &Rc<Self>, process_id: String) -> Result<()> {
        let Some(run) = self.runs.borrow().get(&process_id).cloned() else { return Ok(()) };
        if self.rerunning.borrow().contains(&process_id) || self.closing.get() || self.shutdown.get() {
            return Ok(());
        }
        self.remember(&process_id, run.clone());
        let addr = process_addr(&process_id);
        self.rerunning.borrow_mut().insert(process_id.clone());
        let started = async {
            let previous = run.procs.borrow().clone();
            for proc in &previous {
                proc.superseded.set(true);
                proc.kill(None);
            }
            for proc in &previous {
                proc.exited().await;
            }
            if self.closing.get() || self.shutdown.get() {
                return Ok(None);
            }
            self.emit(json!({ "type": "reset", "from": addr, "to": ["$term"] }));
            // (A cell closed or killed meanwhile is unresponsive: it runs again.)
            self.emit(json!({ "type": "configure", "from": addr, "to": ["$term"], "status": "running" }));
            match self.spawn_run(&process_id, &run) {
                Ok(proc) => {
                    proc.set_stdout_look(run.stdout_look.borrow().clone());
                    Ok(Some(proc))
                }
                Err(err) => {
                    self.emit(close_message(&addr, false, None));
                    Err(err)
                }
            }
        }
        .await;
        self.rerunning.borrow_mut().remove(&process_id);
        if let Some(proc) = started? {
            self.relay_run(proc, run).await;
        }
        Ok(())
    }

    /// Parse and run a command line.
    async fn submit_text(self: &Rc<Self>, req: SubmitRequest, text: String, zone: Option<String>) -> Result<()> {
        // Reserve a single process id up front and share it between the
        // decoration and the first command's process (running the parsed
        // commands goes through submit again, which would otherwise generate
        // its own).
        let process_id = self.generate_process_id();

        // Parse first: whether the command runs in the background (`&`) is
        // only known from the parse, and the echo must say so, since the
        // terminal acts on it (e.g. not focusing the new cell) as soon as the
        // echo arrives. A parse error is reported after the echo, so the
        // command still shows.
        let program = parse_program(&text);

        // The decoration for the submitted command: the label, highlighting
        // and context that the first command's process entry carries
        // (whatever shows it — its placeholder, its terminal, its GUI — shows
        // it too).
        let color = req.prompt_color.clone().or_else(|| self.prompt_color.borrow().clone());
        let decoration = req.echo.then(|| {
            let mut decoration = program_look(&command_verb(&text), color.as_deref());
            put_opt(&mut decoration, "id", req.id.clone());
            put_opt(&mut decoration, "color", color.clone());
            let mut submission = json!({ "content": { "parts": shell_highlight(&text, &self.path_var()) } });
            if let Some(look) = &*self.prompt_look.borrow() {
                submission["context"] = prompt_context(look);
            }
            decoration.insert("submission".into(), submission);
            decoration
        });

        let opts = SubmitRequest {
            zone,
            anchor: req.anchor.clone(),
            history: false,
            echo: req.echo,
            ..Default::default()
        };
        let program = match program {
            Ok(program) => program,
            Err(err) => {
                // Show the command anyway: an entry that only exists to carry
                // the parse error (its placeholder shows it).
                let addr = process_addr(&process_id);
                let failed = SubmitRequest { decoration: decoration.clone(), focus: req.focus, ..opts };
                let mut declare = self.declare(&addr, &failed);
                declare.as_object_mut().unwrap().remove("background");
                self.emit(declare);
                if let Some(message) = terminal_decorations(&addr, decoration.as_ref()).0 {
                    self.emit(message);
                }
                self.emit(close_message(&addr, false, Some(2)));
                bail!("Parse error: {err}");
            }
        };

        let mut first = true;
        for item in program.complete_commands.iter().flat_map(|c| &c.0) {
            // Only the first command carries the decoration and the reserved
            // id; later `;`-separated commands generate their own.
            let opts = SubmitRequest {
                decoration: if first { decoration.clone() } else { None },
                process_id: first.then(|| process_id.clone()),
                background: matches!(item.1, ast::SeparatorOperator::Async),
                focus: first && req.focus,
                ..opts.clone()
            };
            first = false;
            let pipeline = single_pipeline(&item.0, "")?;
            match pipeline.seq.as_slice() {
                [command] => self.run_command(simple(command)?, opts).await?,
                commands => self.run_pipeline(commands, opts).await?,
            }
        }
        Ok(())
    }

    /// Expand a simple command's words, redirections and assignments.
    async fn expand_simple(self: &Rc<Self>, command: &ast::SimpleCommand) -> Result<Expanded> {
        use ast::CommandPrefixOrSuffixItem as Item;
        let mut expanded = Expanded { words: vec![], redirects: vec![], env: vec![] };
        for item in command.prefix.iter().flat_map(|p| &p.0) {
            match item {
                Item::AssignmentWord(assignment, _) => expanded.env.push(self.expand_assignment(assignment).await?),
                Item::IoRedirect(redirect) => expanded.redirects.extend(self.expand_redirect(redirect).await?),
                Item::Word(word) => expanded.words.extend(self.expand_words(&word.value).await?),
                Item::ProcessSubstitution(..) => return Err(not_implemented("process substitution")),
            }
        }
        // The command word expands like any other: `$(echo echo) hi` runs
        // `echo`, and a command word that expands to several words makes the
        // first the command and the rest arguments.
        if let Some(name) = &command.word_or_name {
            expanded.words.extend(self.expand_words(&name.value).await?);
        }
        for item in command.suffix.iter().flat_map(|s| &s.0) {
            match item {
                Item::Word(word) | Item::AssignmentWord(_, word) => {
                    expanded.words.extend(self.expand_words(&word.value).await?)
                }
                Item::IoRedirect(redirect) => expanded.redirects.extend(self.expand_redirect(redirect).await?),
                Item::ProcessSubstitution(..) => return Err(not_implemented("process substitution")),
            }
        }
        Ok(expanded)
    }

    /// An assignment (`NAME=value`), its value expanded (neither split nor
    /// globbed, as in bash).
    async fn expand_assignment(self: &Rc<Self>, assignment: &ast::Assignment) -> Result<(String, String)> {
        let ast::AssignmentName::VariableName(name) = &assignment.name else {
            return Err(not_implemented("arrays"));
        };
        let ast::AssignmentValue::Scalar(word) = &assignment.value else {
            return Err(not_implemented("arrays"));
        };
        let mut value = self.expand_string(&word.value).await?;
        if assignment.append {
            value = self.lookup(name).unwrap_or_default() + &value;
        }
        Ok((name.clone(), value))
    }

    async fn run_command(self: &Rc<Self>, command: &ast::SimpleCommand, opts: SubmitRequest) -> Result<()> {
        let expanded = self.expand_simple(command).await?;
        if command.word_or_name.is_none() && expanded.words.is_empty() {
            // Assignments alone: shell variables.
            for (name, value) in expanded.env {
                let set = SubmitRequest {
                    command: Some(("set".into(), vec![format!("{name}={value}")])),
                    zone: opts.zone.clone(),
                    anchor: opts.anchor.clone(),
                    ..Default::default()
                };
                Box::pin(self.submit(set)).await?;
            }
            return Ok(());
        }
        let mut words = expanded.words.into_iter();
        // Everything expanded away: no command to run, no cell to show.
        let Some(cmd) = words.next() else { return Ok(()) };
        let req = SubmitRequest {
            command: Some((cmd, words.collect())),
            redirects: expanded.redirects,
            env: expanded.env,
            ..opts
        };
        Box::pin(self.submit(req)).await
    }

    async fn run_pipeline(self: &Rc<Self>, commands: &[ast::Command], opts: SubmitRequest) -> Result<()> {
        // The stages' words expand before any of them starts, as bash expands
        // a whole pipeline up front.
        let mut stages = vec![];
        for command in commands {
            let expanded = self.expand_simple(simple(command)?).await?;
            let mut words = expanded.words.into_iter();
            let Some(cmd) = words.next() else { bail!("An empty expansion cannot be a pipeline stage") };
            if is_builtin(&cmd) {
                return Err(not_implemented("builtins in pipes"));
            }
            stages.push(Stage { cmd, args: words.collect(), redirects: expanded.redirects, env: expanded.env });
        }

        // The cell for the whole pipeline is attributed to the last process,
        // so it gets the reserved process id (shared with the decoration).
        let process_id = opts.process_id.clone().unwrap_or_else(|| self.generate_process_id());
        let run = self.new_run(stages, opts.decoration.as_ref());
        let last = self.spawn_run(&process_id, &run)?;
        self.remember(&process_id, run.clone());

        let addr = process_addr(&process_id);
        self.emit(self.declare(&addr, &opts));
        let (message, look) = terminal_decorations(&addr, opts.decoration.as_ref());
        if let Some(message) = message {
            self.emit(message);
        }
        last.set_stdout_look(look.clone());
        *run.stdout_look.borrow_mut() = look;
        self.relay_run(last, run).await;
        Ok(())
    }

    // Command substitution

    /// Run a substitution's text — which may itself hold substitutions, and
    /// may be a whole script of `;`-separated commands — and return what its
    /// commands wrote to stdout, trailing newlines and NUL bytes dropped, as
    /// bash.
    pub(crate) async fn run_substitution(self: &Rc<Self>, command: &str) -> Result<String> {
        if command.trim().is_empty() {
            return Ok(String::new()); // `$( )`: nothing to run, nothing to show
        }
        let program = parse_program(command).map_err(|e| anyhow!("in $(…): {e}"))?;
        let mut out = String::new();
        for item in program.complete_commands.iter().flat_map(|c| &c.0) {
            let pipeline = single_pipeline(&item.0, " in $(…)")?;
            let stages: Vec<&ast::SimpleCommand> = pipeline
                .seq
                .iter()
                .map(|c| simple(c).map_err(|e| anyhow!("{e} in $(…)")))
                .collect::<Result<_>>()?;
            out += &self.capture(&stages).await?;
        }
        Ok(out.replace('\0', "").trim_end_matches('\n').to_owned())
    }

    /// The stdout of a command or pipeline run for a substitution: its
    /// processes are piped and invisible — their messages are consumed here,
    /// never relayed, and no cell shows them — and their exit status
    /// forgotten, a substitution's failure being not its caller's. Builtins
    /// are not run there (in bash they would run in a subshell and change
    /// nothing here: coquille runs nothing rather than something with the
    /// wrong effect).
    async fn capture(self: &Rc<Self>, commands: &[&ast::SimpleCommand]) -> Result<String> {
        let mut stages = vec![];
        for command in commands {
            let expanded = self.expand_simple(command).await?;
            let mut words = expanded.words.into_iter();
            let Some(cmd) = words.next() else {
                if commands.len() == 1 {
                    // A lone assignment (the subshell's own business, gone
                    // with it), or nothing at all.
                    return Ok(String::new());
                }
                bail!("An empty expansion cannot be a pipeline stage");
            };
            if is_builtin(&cmd) {
                return Err(not_implemented(format!("the builtin {cmd:?} in $(…)")));
            }
            stages.push(Stage { cmd, args: words.collect(), redirects: expanded.redirects, env: expanded.env });
        }
        let mut procs: Vec<Rc<Process>> = vec![];
        for (i, stage) in stages.iter().enumerate() {
            let mut env = self.env.borrow().clone();
            env.extend(stage.env.iter().cloned());
            let mut options = self.process_options(env, cwd());
            options.pipe_stdin = i > 0;
            options.pipe_stdout = true; // the last one's stdout comes to us: piped too
            options.redirects = stage.redirects.clone();
            let id = self.generate_process_id();
            let proc = match Process::spawn(&stage.cmd, &stage.args, id.clone(), options) {
                Ok(proc) => proc,
                Err(err) => {
                    for proc in &procs {
                        proc.kill(None);
                        self.untrack(&proc.process_id, Some(proc));
                    }
                    return Err(err);
                }
            };
            self.processes.borrow_mut().insert(id, proc.clone());
            procs.push(proc);
        }
        let last = procs.last().unwrap().clone();
        for pair in procs.windows(2) {
            self.connect(pair[0].clone(), pair[1].clone());
        }
        let out = capture_stdout(&last).await;
        self.untrack(&last.process_id, Some(&last));
        Ok(out)
    }
}

/// Everything the process writes to stdout, until it closes: its other
/// messages (its views' declaration, its close) are consumed and dropped —
/// a substitution's helpers never show in the terminal.
async fn capture_stdout(proc: &Process) -> String {
    let mut out = String::new();
    let mut events = proc.events();
    while let Some(event) = events.recv().await {
        if kind(&event) == "send" && from_len(&event) == Some(4) && from_at(&event, 3) == Some("$stdout") {
            let message = &event["message"];
            if message["type"] == "text" && message["stream"] == "stdout" {
                out += message["text"].as_str().unwrap_or_default();
            }
        }
    }
    out
}
