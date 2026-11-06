//! watch: run a command, and whenever the files it uses change, kill it and
//! run it again, its cells reset (under buche: the `$stdout` and `$frame` its
//! output went to start over, blank).
//!
//!   watch python plot.py            # watches plot.py (the arguments that exist)
//!   watch -f src -f data make demo  # watches src and data
//!   watch --restart --cooldown 2 --throttle 5 ./server   # keep it up, gently
//!
//! When it runs again:
//!  - after the watched files change, and have stayed unchanged for
//!    --debounce seconds: right away (it is killed if it still runs);
//!  - with --restart, after it ended on its own (or crashed): --cooldown
//!    seconds later;
//!  - either way, never less than --throttle seconds after it last started.
//!
//! Its cells are reset just before it starts again: until then, they show
//! how its last run ended.
//!
//! The command shares our fds 3, 4 and 5 (buche's channels): to buche, it
//! speaks as us.

use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use notify::{EventKind, RecursiveMode, Watcher};

#[derive(Parser)]
#[command(name = "watch", about = "Run a command, and run it again whenever the files it uses change")]
struct Cli {
    /// Files (or directories) to watch; by default, the command's arguments
    /// that are existing paths
    #[arg(short, long = "files", value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Also run it again after it ends on its own, or crashes
    #[arg(long)]
    restart: bool,

    /// Wait for the files to stay unchanged this many seconds before running
    /// it again
    #[arg(long, value_name = "SECONDS", default_value = "0.05", value_parser = seconds)]
    debounce: Duration,

    /// With --restart: wait this many seconds after it ended to run it again
    #[arg(long, value_name = "SECONDS", default_value = "0", value_parser = seconds)]
    cooldown: Duration,

    /// Never start it less than this many seconds after its previous start
    #[arg(long, value_name = "SECONDS", default_value = "0", value_parser = seconds)]
    throttle: Duration,

    /// The command to run
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    prog: Vec<String>,
}

/// A duration in seconds, as given on the command line (e.g. 0.5).
fn seconds(text: &str) -> Result<Duration, String> {
    let n: f64 = text.parse().map_err(|_| format!("{text:?} is not a number of seconds"))?;
    Duration::try_from_secs_f64(n).map_err(|_| format!("{text:?} is not a number of seconds, 0 or more"))
}

/// buche's control channel, which the command speaks on too.
const CONTROL_FD: RawFd = 5;

/// How often to check whether the command is still running.
const POLL: Duration = Duration::from_millis(50);

/// Start our cells over, blank: the `$stdout` and `$frame` the command's
/// output went to (whichever exist; buche creates none). Not under buche (no
/// control channel), there is nothing to reset.
fn reset() {
    let message = b"{\"type\": \"reset\", \"from\": [\"$proc\"], \"to\": [\"$term\"]}\n";
    unsafe { libc::write(CONTROL_FD, message.as_ptr().cast(), message.len()) };
}

fn run(prog: &[String]) -> Result<Child> {
    Command::new(&prog[0]).args(&prog[1..]).spawn().with_context(|| prog[0].clone())
}

fn main() {
    if let Err(err) = watch(Cli::parse()) {
        eprintln!("watch: {err:#}");
        std::process::exit(1);
    }
}

fn watch(cli: Cli) -> Result<()> {
    let files: Vec<PathBuf> = if cli.files.is_empty() {
        cli.prog.iter().map(PathBuf::from).filter(|p| p.exists()).collect()
    } else {
        cli.files.clone()
    };
    if files.is_empty() {
        bail!("nothing to watch: give files with -f, or name existing files in the command");
    }

    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(tx)?;
    for file in &files {
        watcher.watch(Path::new(file), RecursiveMode::Recursive).with_context(|| file.display().to_string())?;
    }

    let mut child = Some(run(&cli.prog)?);
    let mut last_start = Instant::now();
    // When the files will have been quiet for long enough (after a change).
    let mut quiet_at: Option<Instant> = None;
    // When it is to run again (before throttling), if it is.
    let mut restart_at: Option<Instant> = None;

    loop {
        // Wait for a change, or until the next thing to do (or to check on
        // the command, while it runs).
        let start_at = restart_at.map(|at| at.max(last_start + cli.throttle));
        let next = [quiet_at, start_at, child.as_ref().map(|_| Instant::now() + POLL)].into_iter().flatten().min();
        let event = match next {
            Some(at) => rx.recv_timeout(at.saturating_duration_since(Instant::now())),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Ok(Ok(event)) if !matches!(event.kind, EventKind::Access(_)) => {
                quiet_at = Some(Instant::now() + cli.debounce);
            }
            Ok(Ok(_)) | Err(RecvTimeoutError::Timeout) => {}
            Ok(Err(err)) => eprintln!("watch: {err}"),
            Err(RecvTimeoutError::Disconnected) => bail!("the file watcher stopped"),
        }
        let now = Instant::now();

        // It ended on its own (or crashed).
        if let Some(proc) = &mut child
            && proc.try_wait().ok().flatten().is_some()
        {
            child = None;
            if cli.restart {
                restart_at = Some(now + cli.cooldown);
            }
        }

        // The files changed, and have been quiet since: end it, to run again
        // right away (no cooldown: it was asked for).
        if quiet_at.is_some_and(|at| now >= at) {
            quiet_at = None;
            if let Some(mut proc) = child.take() {
                let _ = proc.kill();
                let _ = proc.wait();
            }
            restart_at = Some(now);
        }

        if let Some(at) = restart_at
            && now >= at.max(last_start + cli.throttle)
        {
            restart_at = None;
            reset();
            last_start = Instant::now();
            // (A command that can't be started now may be after the next
            // change; it isn't retried before, even with --restart.)
            child = run(&cli.prog).map_err(|err| eprintln!("watch: {err:#}")).ok();
        }
    }
}
