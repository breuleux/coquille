//! A child program, with:
//!  - a PTY for stdin/stdout/stderr (or pipes, in pipelines);
//!  - fd 3, data in (JSON lines from the interface);
//!  - fd 4, data out (JSON lines for its GUI, its `$frame`);
//!  - fd 5, its control channel (protocol messages, both ways).
//!
//! Its output comes out of `events()` as protocol messages.
//!
//! Before it execs, the child starts a session of its own and takes its PTY
//! as controlling terminal (setsid + TIOCSCTTY): programs like less or emacs
//! open /dev/tty for keyboard input and display output, which must be this
//! PTY, not the one the shell itself runs in.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, spawn_local};

use crate::approval::OPEN_TO_ALL;
use crate::fdio::{FdStream, Writer, dup_cloexec, pipe, set_cloexec, spawn_writer};
use crate::history::history_file;
use crate::library::{LIB_SALT_ENV, LibraryFiles, forward_library, new_salt, verify_library};
use crate::message::{Message, kind, make_error};
use crate::util::{Utf8Decoder, merged, resolve};

/// A redirection of one of the child's fds (0 to 5).
#[derive(Clone, Debug)]
pub enum Redirect {
    /// `fd` opens `path` (relative to the working directory).
    Open { fd: i32, path: String, mode: OpenMode },
    /// `fd` goes where `from` goes (`fd>&from`).
    Dup { fd: i32, from: i32 },
}

#[derive(Clone, Copy, Debug)]
pub enum OpenMode {
    Read,
    Write,
    Append,
    ReadWrite,
}

/// What requests of a cell a process leaves to the shell: all, or these types.
#[derive(Clone, Debug)]
pub enum Delegate {
    All,
    Types(Vec<String>),
}

/// The requests a process leaves to the shell running it, by the cell they
/// are about (its address under the process's, as a key: see address_key).
/// A process says so with the `delegate` of a cell it configures, which is
/// the shell's alone: it doesn't go on to the terminal. Such requests no
/// longer reach the process: the shell acts on them as on requests about the
/// process itself (see Shell::receive).
pub type Delegations = HashMap<String, Delegate>;

/// The key of an address in Delegations.
pub fn address_key(address: &[String]) -> String {
    serde_json::to_string(address).unwrap_or_default()
}

pub struct ProcessOptions {
    pub cols: u16,
    pub rows: u16,
    /// The environment it runs in (the variables below are set over it).
    pub env: BTreeMap<String, String>,
    /// Its working directory; relative redirections are relative to it.
    pub cwd: PathBuf,
    /// Read stdin from a pipe (a non-first process in a pipeline).
    pub pipe_stdin: bool,
    /// Write stdout to a pipe (a non-last process in a pipeline).
    pub pipe_stdout: bool,
    pub redirects: Vec<Redirect>,
    /// Where the files of the libraries the process declares are recorded,
    /// for this shell to supply them later (see library.rs). Without it,
    /// library declarations are refused.
    pub libraries: Option<Rc<LibraryFiles>>,
    /// The salt this shell got from the one above it, if any (see library.rs).
    pub parent_salt: Option<String>,
    /// Where the requests the process leaves to this shell are recorded (see
    /// Delegations). Without it, they are dropped all the same.
    pub delegations: Option<Rc<RefCell<Delegations>>>,
    /// Whether it may address the shell (["$shell"]) for more than its own
    /// stdout's mode (see approval.rs); if not, why, for the error it gets
    /// if it tries.
    pub privileged: bool,
    pub refusal: String,
}

/// What the process's tasks share: how to say something, and how its views
/// are declared.
struct Shared {
    process_id: String,
    tx: RefCell<Option<mpsc::UnboundedSender<Message>>>,
    /// The views already declared (each is, the first time something is sent
    /// to it: whichever comes first takes the process's placeholder over).
    declared: RefCell<HashSet<&'static str>>,
    stdout_look: RefCell<Value>,
    /// Whether stdout is text for the GUI (`$frame`) rather than the
    /// terminal's (`$stdout`).
    gui: Cell<bool>,
    pipe_stdout: bool,
}

impl Shared {
    fn emit(&self, message: Message) {
        if let Some(tx) = &*self.tx.borrow() {
            let _ = tx.send(message);
        }
    }

    fn address(&self, view: &str) -> Value {
        json!(["$proc", "cq", self.process_id, view])
    }

    /// Send `message` to one of the process's views (`$stdout` or `$frame`),
    /// declaring it first if need be.
    fn send_to(&self, view: &'static str, view_kind: &str, message: Value) {
        if self.declared.borrow_mut().insert(view) {
            let look = if view == "$stdout" { self.stdout_look.borrow().clone() } else { json!({}) };
            self.emit(merged(
                json!({ "type": "configure", "from": self.address(view), "to": ["$term"], "kind": view_kind }),
                look,
            ));
        }
        self.emit(json!({ "type": "send", "from": self.address(view), "to": ["$term"], "message": message }));
    }

    fn emit_stdout(&self, text: String) {
        if text.is_empty() {
            return;
        }
        if self.gui.get() && !self.pipe_stdout {
            let data = json!({ "$schema": "buche:text", "text": text, "stream": "stdout" });
            self.send_to("$frame", "frame", json!({ "type": "data", "data": data }));
        } else {
            self.send_to("$stdout", "terminal", json!({ "type": "text", "stream": "stdout", "text": text }));
        }
    }
}

/// Whether the process still takes its piped stdin, and what to do once it
/// no longer does (see Process::on_stdin_gone).
#[derive(Default)]
struct StdinGone {
    gone: Cell<bool>,
    callback: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl StdinGone {
    fn mark(&self) {
        if !self.gone.replace(true)
            && let Some(f) = self.callback.borrow_mut().take()
        {
            f();
        }
    }
}

pub struct Process {
    pub process_id: String,
    pid: Option<i32>,
    shared: Rc<Shared>,
    /// Set when it is being run again (see Shell::rerun): what it still says
    /// is no longer for the terminal.
    pub superseded: Cell<bool>,
    events: RefCell<Option<mpsc::UnboundedReceiver<Message>>>,
    exited: watch::Receiver<bool>,
    master: OwnedFd,
    pty_writer: Writer,
    stdin: RefCell<Option<Writer>>,
    stdin_gone: Rc<StdinGone>,
    stdout_stop: RefCell<Option<oneshot::Sender<()>>>,
    datain: Writer,
    control: Writer,
}

/// In the child, between fork and exec: put the fds in place (`map[i]`
/// becomes fd i), start a session, and take the PTY as controlling terminal
/// (the first of fds 0-2 that is a tty: fd 0 may be a pipe, in a pipeline).
/// On BSD/macOS, TIOCSCTTY also sets the foreground process group, so that
/// programs reading /dev/tty don't get SIGTTIN. Only async-signal-safe calls.
fn child_setup(map: &[RawFd; 6]) -> io::Result<()> {
    unsafe {
        // (Out of the way first: a source may be one of the fds 0-5.)
        let mut moved = [-1; 6];
        for (i, &fd) in map.iter().enumerate() {
            moved[i] = libc::fcntl(fd, libc::F_DUPFD, 10);
            if moved[i] < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        for (i, &fd) in moved.iter().enumerate() {
            if libc::dup2(fd, i as i32) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        for fd in moved {
            libc::close(fd);
        }
        libc::setsid();
        for fd in 0..3 {
            if libc::isatty(fd) == 1 {
                libc::ioctl(fd, libc::TIOCSCTTY as _, 0);
                break;
            }
        }
    }
    Ok(())
}

fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (a, b) = UnixStream::pair()?;
    Ok((a.into(), b.into()))
}

fn json_line(value: &Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(value).unwrap_or_default();
    line.push(b'\n');
    line
}

/// What the control channel's handler needs (see on_control).
struct Control {
    shared: Rc<Shared>,
    cmd: String,
    libraries: Option<Rc<LibraryFiles>>,
    salt: String,
    parent_salt: Option<String>,
    delegations: Option<Rc<RefCell<Delegations>>>,
    privileged: bool,
    refusal: String,
}

impl Control {
    fn error(&self, message: String) {
        self.shared.emit(make_error(&anyhow::anyhow!(message)));
    }

    /// A message on fd 5, from the process: re-addressed under this one,
    /// checked, and passed on (to the terminal, or to the shell).
    async fn on_control(&self, mut message: Value) {
        let id = &self.shared.process_id;
        // A process's `from` must start with ["$proc"] (strict). This
        // process's address (["cq", id]) is spliced in right after it, so a
        // child `from` of ["$proc", ...rest] becomes ["$proc", "cq", id,
        // ...rest] within this shell's sub-tree.
        let child_from = crate::util::address_of(message.get("from"));
        let Some(child_from) = child_from.filter(|f| f.first().is_some_and(|h| h == "$proc")) else {
            let from = message.get("from").cloned().unwrap_or(Value::Null);
            return self.error(format!("Process {id}: message 'from' must start with \"$proc\" (got {from})"));
        };
        let Some(obj) = message.as_object_mut() else { return };
        let mut from = vec!["$proc".to_owned(), "cq".to_owned(), id.clone()];
        from.extend_from_slice(&child_from[1..]);
        obj.insert("from".into(), json!(from));

        if kind(&message) == "configure"
            && let Some(delegate) = message.as_object_mut().and_then(|o| o.remove("delegate"))
        {
            let key = address_key(&child_from[1..]);
            let types: Option<Vec<String>> = delegate.as_array().and_then(|a| {
                a.iter().map(|t| t.as_str().map(str::to_owned)).collect()
            });
            if let Some(delegations) = &self.delegations {
                let mut delegations = delegations.borrow_mut();
                match (delegate, types) {
                    (Value::Bool(true), _) => drop(delegations.insert(key, Delegate::All)),
                    (_, Some(types)) => drop(delegations.insert(key, Delegate::Types(types))),
                    (Value::Bool(false), _) => drop(delegations.remove(&key)),
                    _ => {}
                }
            }
        }

        if kind(&message) == "library" {
            return self.declare_library(&message, json!(from)).await;
        }

        // Route based on `to`:
        //   ["$shell"]    → handled by this shell (see Shell::emit).
        //   ["$proc", …]  → refused: a process may not address another one.
        //   anything else → bubbled up unchanged (["$term"], …).
        match crate::message::to_head(&message) {
            Some("$proc") => {
                let to = &message["to"];
                return self.error(format!("Process {id} may not address another process (to: {to})"));
            }
            // ["$shell"] is for control commands only (see approval.rs), but
            // for what is about the process itself.
            Some("$shell") if !self.privileged && !OPEN_TO_ALL.contains(&kind(&message)) => {
                let (cmd, what, why) = (&self.cmd, kind(&message), &self.refusal);
                return self.error(format!("Process {id} ({cmd}) may not send {what:?} to the shell: {why}"));
            }
            _ => {}
        }
        // Default the target to the terminal when the child didn't say.
        if message.get("to").is_none() {
            message["to"] = json!(["$term"]);
        }
        self.shared.emit(message);
    }

    /// A library declaration, its proofs checked against the files (see
    /// library.rs), goes on with the files' hashes — or with this shell's
    /// own proofs, under another shell (which gave us a salt).
    async fn declare_library(&self, message: &Value, from: Value) {
        let result = async {
            let libraries = self.libraries.as_ref().ok_or_else(|| anyhow::anyhow!("library declarations are not supported here"))?;
            let (id, files) = verify_library(message, &self.salt).await?;
            forward_library(&id, files, libraries, self.parent_salt.as_deref())
        }
        .await;
        match result {
            Ok(declaration) => self.shared.emit(merged(declaration, json!({ "from": from, "to": ["$term"] }))),
            Err(err) => {
                let error = merged(make_error(&err), json!({ "from": from, "error_type": "library", "traceback": [] }));
                self.shared.emit(error);
            }
        }
    }
}

impl Process {
    /// Start `cmd` with `args`, as process `process_id`. Fails if its
    /// redirections can't be opened; if it can't be started (not found, say),
    /// it says so in its terminal and closes, as a shell's child would.
    pub fn spawn(cmd: &str, args: &[String], process_id: String, opts: ProcessOptions) -> anyhow::Result<Rc<Process>> {
        let ProcessOptions {
            cols,
            rows,
            env,
            cwd,
            pipe_stdin,
            pipe_stdout,
            redirects,
            libraries,
            parent_salt,
            delegations,
            privileged,
            refusal,
        } = opts;

        // A single PTY for stdin/stdout/stderr — this is how real terminals
        // work. Programs like less/more/emacs open /dev/tty for both keyboard
        // input and display output; with a single PTY they all resolve to the
        // same device, so there is no split between multiple masters.
        let winsize = nix::pty::Winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        let pty = nix::pty::openpty(Some(&winsize), None)?;
        set_cloexec(&pty.master)?;
        set_cloexec(&pty.slave)?;

        // The fds the child gets (0 to 5), and those we hold for it until
        // it is started.
        let slave = pty.slave.as_raw_fd();
        let mut map = [slave; 6];
        let mut held: Vec<OwnedFd> = vec![pty.slave];
        let mut stdin_w = None;
        let mut stdout_r = None;
        if pipe_stdin {
            let (r, w) = pipe()?;
            map[0] = r.as_raw_fd();
            held.push(r);
            stdin_w = Some(w);
        }
        let mut stdout_child = -1;
        if pipe_stdout {
            let (r, w) = pipe()?;
            map[1] = w.as_raw_fd();
            stdout_child = map[1];
            held.push(w);
            stdout_r = Some(r);
        }
        let mut parent_ends = Vec::new();
        for fd in 3..6 {
            let (parent, child) = socket_pair()?;
            map[fd] = child.as_raw_fd();
            held.push(child);
            parent_ends.push(parent);
        }
        let [datain_p, dataout_p, control_p]: [OwnedFd; 3] = parent_ends.try_into().unwrap();

        for redirect in &redirects {
            match redirect {
                Redirect::Open { fd, path, mode } => {
                    let fd = check_fd(*fd)?;
                    let mut options = std::fs::OpenOptions::new();
                    match mode {
                        OpenMode::Read => options.read(true),
                        OpenMode::Write => options.write(true).create(true).truncate(true),
                        OpenMode::Append => options.append(true).create(true),
                        OpenMode::ReadWrite => options.read(true).write(true).create(true),
                    };
                    let path = resolve(&cwd, path);
                    let file = options
                        .mode(0o666)
                        .custom_flags(libc::O_CLOEXEC)
                        .open(&path)
                        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                    let file: OwnedFd = file.into();
                    map[fd] = file.as_raw_fd();
                    held.push(file);
                }
                Redirect::Dup { fd, from } => {
                    // n>&m — fd n goes where fd m goes, as set up so far.
                    map[check_fd(*fd)?] = map[check_fd(*from)?];
                }
            }
        }
        // pipe_stdout is only effective if a redirection didn't send fd 1
        // elsewhere.
        let pipe_stdout = pipe_stdout && map[1] == stdout_child;
        if !pipe_stdout {
            stdout_r = None;
        }

        let salt = new_salt();
        let mut command = tokio::process::Command::new(cmd);
        command
            .args(args)
            .env_clear()
            .envs(&env)
            .envs([
                ("TERM", "xterm-256color".to_owned()),
                ("COLORTERM", "truecolor".to_owned()),
                ("BUCHE_CONTROL_FD", "5".to_owned()),
                ("BUCHE_PTY_COLS", cols.to_string()),
                ("BUCHE_PTY_ROWS", rows.to_string()),
                ("BUCHE_HISTORY_FILE", history_file().to_string_lossy().into_owned()),
                (LIB_SALT_ENV, salt.clone()),
            ])
            .current_dir(&cwd);
        unsafe {
            command.pre_exec(move || child_setup(&map));
        }
        let child = command.spawn();
        // The child has them now (or never will).
        drop(held);

        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Rc::new(Shared {
            process_id: process_id.clone(),
            tx: RefCell::new(Some(tx)),
            declared: RefCell::default(),
            stdout_look: RefCell::new(json!({})),
            gui: Cell::new(false),
            pipe_stdout,
        });
        let (exited_tx, exited) = watch::channel(false);
        let stdin_gone = Rc::new(StdinGone::default());

        let pty_reader = FdStream::new(dup_cloexec(pty.master.as_raw_fd())?)?;
        let pty_writer = spawn_writer(FdStream::new(dup_cloexec(pty.master.as_raw_fd())?)?, None);
        let stdin = match stdin_w {
            Some(w) => {
                let gone = stdin_gone.clone();
                // Writing to a pipe the child no longer reads fails (EPIPE):
                // the process feeding it should stop (see on_stdin_gone).
                Some(spawn_writer(FdStream::new(w)?, Some(Box::new(move || gone.mark()))))
            }
            None => None,
        };
        let control_fd = dup_cloexec(control_p.as_raw_fd())?;
        let datain = spawn_writer(FdStream::new(datain_p)?, None);
        let control = spawn_writer(FdStream::new(control_fd)?, None);

        let (stop_tx, stop_rx) = oneshot::channel();
        let (stdout_stop_tx, stdout_stop_rx) = oneshot::channel();

        let pid = child.as_ref().ok().and_then(|c| c.id()).map(|p| p as i32);
        let process = Rc::new(Process {
            process_id,
            pid,
            shared: shared.clone(),
            superseded: Cell::new(false),
            events: RefCell::new(Some(rx)),
            exited,
            master: pty.master,
            pty_writer,
            stdin: RefCell::new(stdin),
            stdin_gone: stdin_gone.clone(),
            stdout_stop: RefCell::new(Some(stdout_stop_tx)),
            datain,
            control,
        });

        let mut child = match child {
            Ok(child) => child,
            Err(err) => {
                // What a shell says of a command it can't run.
                let (text, code) = if err.kind() == io::ErrorKind::NotFound {
                    (format!("command not found: {cmd}\r\n"), 127)
                } else {
                    (format!("{cmd}: {err}\r\n"), 126)
                };
                shared.send_to("$stdout", "terminal", json!({ "type": "text", "stream": "stderr", "text": text }));
                stdin_gone.mark();
                let close = json!({ "type": "close", "from": ["$proc", "cq", shared.process_id], "to": ["$term"], "outcome": { "type": "error", "code": code } });
                shared.emit(close);
                shared.tx.borrow_mut().take();
                let _ = exited_tx.send(true);
                return Ok(process);
            }
        };

        // The terminal: the PTY's output, or, when stdout is piped, the
        // pipe's (the PTY then only carries stderr: drained silently).
        let pty_task = spawn_local(read_pty(pty_reader, (!pipe_stdout).then(|| shared.clone()), stop_rx));
        let stdout_task = stdout_r.map(|r| -> io::Result<JoinHandle<()>> {
            let stream = FdStream::new(r)?;
            Ok(spawn_local(read_stdout_pipe(stream, shared.clone(), stdout_stop_rx)))
        });
        let stdout_task = stdout_task.transpose()?;

        // fd 4: the data channel — JSON values for the process's GUI.
        let data_shared = shared.clone();
        let data_task = spawn_local(json_lines(FdStream::new(dataout_p)?, move |data| {
            data_shared.send_to("$frame", "frame", json!({ "type": "data", "data": data }));
            async {}
        }));

        // fd 5: the control channel. Its messages are handled in order: a
        // library declaration is checked before what follows is passed on,
        // so that the GUI content using it never overtakes it.
        let control = Rc::new(Control {
            shared: shared.clone(),
            cmd: cmd.to_owned(),
            libraries,
            salt,
            parent_salt,
            delegations,
            privileged,
            refusal,
        });
        let control_task = spawn_local(json_lines(FdStream::new(control_p)?, move |message| {
            let control = control.clone();
            async move { control.on_control(message).await }
        }));

        spawn_local(async move {
            let status = child.wait().await;
            stdin_gone.mark();
            // What it said before it ended comes before its close.
            let _ = data_task.await;
            let _ = control_task.await;
            if let Some(task) = stdout_task {
                let _ = task.await;
            }
            let _ = stop_tx.send(());
            let _ = pty_task.await;
            let code = status.ok().and_then(|s| s.code());
            let outcome = json!({ "type": if code == Some(0) { "success" } else { "error" }, "code": code.unwrap_or(0) });
            shared.emit(json!({ "type": "close", "from": ["$proc", "cq", shared.process_id], "to": ["$term"], "outcome": outcome }));
            shared.tx.borrow_mut().take();
            let _ = exited_tx.send(true);
        });

        Ok(process)
    }

    /// The look its terminal (`$stdout`) is declared with (see
    /// look::terminal_decorations).
    pub fn set_stdout_look(&self, look: Value) {
        *self.shared.stdout_look.borrow_mut() = look;
    }

    /// What stdout is: the terminal's ("text"), or text for the GUI ("gui").
    pub fn set_stdout_mode(&self, mode: &Value) {
        self.shared.gui.set(mode == "gui");
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
    }

    /// Write to the PTY (the program's terminal input).
    pub fn write_pty(&self, text: &str) {
        let _ = self.pty_writer.send(text.as_bytes().to_vec());
    }

    /// Write to stdin: its pipe, in a pipeline, else the PTY.
    pub fn write_stdin(&self, text: &str) {
        match &*self.stdin.borrow() {
            Some(stdin) if !self.stdin_gone.gone.get() => drop(stdin.send(text.as_bytes().to_vec())),
            Some(_) => {}
            None => self.write_pty(text),
        }
    }

    /// No more input on its piped stdin: it reads the end of it.
    pub fn close_stdin(&self) {
        self.stdin.borrow_mut().take();
    }

    /// Call `callback` once this process no longer takes its piped stdin (it
    /// closed it, or it exited): in a pipeline, the process feeding it should
    /// then stop, as a real pipe would make it (see close_stdout).
    pub fn on_stdin_gone(&self, callback: impl FnOnce() + 'static) {
        if self.stdin_gone.gone.get() {
            callback();
        } else {
            *self.stdin_gone.callback.borrow_mut() = Some(Box::new(callback));
        }
    }

    /// Stop reading this process's piped stdout: its next write fails, as it
    /// would in a pipe whose reader is gone (SIGPIPE, by default, ends it).
    pub fn close_stdout(&self) {
        if let Some(stop) = self.stdout_stop.borrow_mut().take() {
            let _ = stop.send(());
        }
    }

    /// Send a JSON value on the data channel (fd 3).
    pub fn write_datain(&self, value: &Value) {
        let _ = self.datain.send(json_line(value));
    }

    /// Send a message on the control channel (fd 5).
    pub fn write_control(&self, value: &Value) {
        let _ = self.control.send(json_line(value));
    }

    /// Send it a signal (SIGTERM by default), if it still runs.
    pub fn kill(&self, signal: Option<i32>) {
        if let Some(pid) = self.pid
            && !*self.exited.borrow()
        {
            unsafe { libc::kill(pid, signal.unwrap_or(libc::SIGTERM)) };
        }
    }

    /// Everything the process says, as protocol messages, until it closes
    /// (for one consumer: the first to ask).
    pub fn events(&self) -> mpsc::UnboundedReceiver<Message> {
        self.events.borrow_mut().take().unwrap_or_else(|| mpsc::unbounded_channel().1)
    }

    /// Once it has ended (and said so: its `close` is out).
    pub async fn exited(&self) {
        let mut exited = self.exited.clone();
        let _ = exited.wait_for(|e| *e).await;
    }
}

fn check_fd(fd: i32) -> anyhow::Result<usize> {
    if (0..6).contains(&fd) {
        Ok(fd as usize)
    } else {
        Err(crate::message::not_implemented(format!("redirecting fd {fd}")))
    }
}

/// Read the PTY until told to stop (once the process has ended): then what
/// is left in it, without waiting (kqueue doesn't say when a PTY's slave
/// closes). Its output goes to the terminal, if `shared` is given.
async fn read_pty(mut stream: FdStream, shared: Option<Rc<Shared>>, mut stop: oneshot::Receiver<()>) {
    let mut decoder = Utf8Decoder::default();
    let mut buf = vec![0u8; 16384];
    let emit = |text: String| {
        if let Some(shared) = &shared {
            shared.emit_stdout(text);
        }
    };
    loop {
        tokio::select! {
            _ = &mut stop => {
                while let Ok(n) = stream.read_now(&mut buf) {
                    if n == 0 { break; }
                    emit(decoder.decode(&buf[..n]));
                }
                break;
            }
            result = stream.read(&mut buf) => match result {
                Ok(n) if n > 0 => emit(decoder.decode(&buf[..n])),
                // (Ended — the slave is closed everywhere — or failed: the
                // process ending is what ends this.)
                _ => {
                    let _ = (&mut stop).await;
                    break;
                }
            }
        }
    }
    emit(decoder.finish());
}

/// Read a piped stdout until its end, or until told to stop (the next stage
/// no longer reads).
async fn read_stdout_pipe(mut stream: FdStream, shared: Rc<Shared>, mut stop: oneshot::Receiver<()>) {
    let mut decoder = Utf8Decoder::default();
    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            _ = &mut stop => return,
            result = stream.read(&mut buf) => match result {
                Ok(n) if n > 0 => shared.emit_stdout(decoder.decode(&buf[..n])),
                _ => break,
            }
        }
    }
    shared.emit_stdout(decoder.finish());
}

/// Hand each JSON line of `stream` to `handle`, in order, until its end
/// (lines that aren't JSON are skipped).
async fn json_lines<F, Fut>(stream: FdStream, handle: F)
where
    F: Fn(Value) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                if let Ok(value) = serde_json::from_slice::<Value>(&line) {
                    handle(value).await;
                }
            }
        }
    }
}
