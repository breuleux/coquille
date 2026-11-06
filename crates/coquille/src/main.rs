//! coquille (`cq`): a shell for the buche terminal. It speaks buche's driver
//! protocol (JSON lines) on its control channel (fd $BUCHE_CONTROL_FD), or on
//! stdin/stdout.

mod approval;
mod builtins;
mod config;
mod config_watch;
mod expand;
mod fdio;
mod highlight;
mod history;
mod library;
mod look;
mod message;
mod process;
mod prompt;
mod requests;
mod shell;
mod trust;
mod util;

use std::path::PathBuf;

use clap::Parser;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::fdio::{FdStream, dup_cloexec};
use crate::shell::Shell;

#[derive(Parser)]
#[command(name = "cq", version, about = "A shell for the Buche terminal")]
struct Cli {
    /// Run a command and exit
    #[arg(short = 'c', value_name = "COMMAND")]
    command: Option<String>,

    /// Read instructions from a JSONL file instead of running a command
    #[arg(long, value_name = "FILE")]
    play: Option<PathBuf>,

    /// Output to stdout instead of the control file descriptor (fd 5)
    #[arg(long)]
    stdout: bool,
}

/// The size of the terminal the commands get: buche's, or stdout's.
fn terminal_size() -> (u16, u16) {
    let env = |name| std::env::var(name).ok().and_then(|v| v.parse().ok());
    let mut ws = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    let tty = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;
    let cols = env("BUCHE_PTY_COLS").unwrap_or(if tty && ws.ws_col > 0 { ws.ws_col } else { 230 });
    let rows = env("BUCHE_PTY_ROWS").unwrap_or(if tty && ws.ws_row > 0 { ws.ws_row } else { 24 });
    (cols, rows)
}

/// Read JSON lines from `input` into `tx` (lines that aren't JSON are
/// skipped).
async fn read_messages(input: impl AsyncRead + Unpin, tx: mpsc::UnboundedSender<Value>) {
    let mut reader = BufReader::new(input);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                if let Ok(message) = serde_json::from_slice::<Value>(&line)
                    && tx.send(message).is_err()
                {
                    return;
                }
            }
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let control_fd: Option<i32> = std::env::var("BUCHE_CONTROL_FD").ok().and_then(|fd| fd.parse().ok());

    // The control fd is used for output (unless --stdout is given) and for
    // input (unless --play or -c is given).
    let control_output = control_fd.filter(|_| !cli.stdout);
    let control_input = control_fd.filter(|_| cli.play.is_none() && cli.command.is_none());

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Value>();
    let mut output: Box<dyn AsyncWrite + Unpin> = match control_output {
        Some(fd) => Box::new(FdStream::new(dup_cloexec(fd)?)?),
        None => Box::new(tokio::io::stdout()),
    };
    let writer = tokio::task::spawn_local(async move {
        while let Some(message) = out_rx.recv().await {
            let mut line = serde_json::to_vec(&message).unwrap_or_default();
            line.push(b'\n');
            if output.write_all(&line).await.is_err() || output.flush().await.is_err() {
                return;
            }
        }
    });

    let (in_tx, in_rx) = mpsc::unbounded_channel::<Value>();
    if let Some(text) = cli.command {
        // Submit the command the way the terminal would: a `command` message
        // for the shell itself.
        let _ = in_tx.send(json!({ "type": "command", "action": { "builtin": "submit" }, "to": ["$proc", "cq"], "text": text }));
        drop(in_tx); // (Nothing else comes.)
    } else if let Some(play) = cli.play {
        let file = tokio::fs::File::open(&play).await.map_err(|e| anyhow::anyhow!("{}: {e}", play.display()))?;
        tokio::task::spawn_local(read_messages(file, in_tx));
    } else if let Some(fd) = control_input {
        tokio::task::spawn_local(read_messages(FdStream::new(dup_cloexec(fd)?)?, in_tx));
    } else {
        tokio::task::spawn_local(read_messages(tokio::io::stdin(), in_tx));
    }

    let (cols, rows) = terminal_size();
    let shell = Shell::new(out_tx, cols, rows);
    shell.run(in_rx).await;
    let _ = writer.await;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
    let local = tokio::task::LocalSet::new();
    match local.block_on(&runtime, run(cli)) {
        // (Without waiting for what is still running: daemons, a stuck
        // reader...)
        Ok(()) => std::process::exit(0),
        Err(err) => {
            eprintln!("cq: {err:#}");
            std::process::exit(1);
        }
    }
}
