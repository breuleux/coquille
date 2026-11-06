use std::collections::BTreeMap;
use std::env;
use std::ffi::{CString, OsString};
use std::io::Error;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_ulong, c_void};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::RawFd;
use std::process::exit;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

const ESC: u8 = 0x1b;
const STX: u8 = 0x02;
const SOH: u8 = 0x01;
const START_LEN: usize = 4;
const END_SEQ: [u8; 2] = [ESC, SOH];

const DOC: &str = r#"
stdembed: test harness for the +ssh fd-multiplexing protocol.

  stdembed --unwrap/-u COMMAND [ARGS...]   (≡ +ssh)
    Runs COMMAND as a subprocess (the "channel").
    • subprocess stdout  → demux frames → local fds; plain → local stdout
    • local fd3/fd5      → wrap frames  → subprocess stdin
    • local stdin        → subprocess stdin (passthrough)

  stdembed --wrap/-w COMMAND [ARGS...]     (opposite end)
    Runs COMMAND with fd3/fd5 as socketpairs (bidirectional).
    • own stdin          → demux frames → subprocess fds; plain → subprocess stdin
    • subprocess fd3/fd5 → wrap frames  → own stdout
    • subprocess stdout  → own stdout (passthrough)

  stdembed -u stdembed -w COMMAND  ≡  COMMAND
"#;

static LAST_SIG: AtomicI32 = AtomicI32::new(0);
static MASTER_FD: AtomicI32 = AtomicI32::new(-1);
static ENV_ROWS: AtomicI32 = AtomicI32::new(-1);
static ENV_COLS: AtomicI32 = AtomicI32::new(-1);

extern "C" fn record_sig(sig: c_int) {
    LAST_SIG.store(sig, Ordering::SeqCst);
}

extern "C" fn winch_handler(sig: c_int) {
    LAST_SIG.store(sig, Ordering::SeqCst);
    let fd = MASTER_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        let ws = winsize_now();
        unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws as *const libc::winsize) };
    }
}

unsafe fn set_sigaction(sig: c_int, h: extern "C" fn(c_int)) {
    let mut sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
    sa.sa_sigaction = h as libc::sighandler_t;
    sa.sa_flags = 0;
    libc::sigaction(sig, &sa, ptr::null_mut());
}

fn die_errno(what: &str) -> ! {
    let e = Error::last_os_error();
    eprintln!("stdembed: {what}: {e}");
    exit(1)
}

fn py_int(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let (sign, rest) = match t.as_bytes()[0] {
        b'+' => (1i64, &t[1..]),
        b'-' => (-1i64, &t[1..]),
        _ => (1i64, t),
    };
    if rest.is_empty() {
        return None;
    }
    let b = rest.as_bytes();
    let mut val: i64 = 0;
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'0'..=b'9' => {
                val = val.checked_mul(10)?.checked_add((c - b'0') as i64)?;
            }
            b'_' => {
                if i == 0 || i + 1 == b.len() || !b[i - 1].is_ascii_digit() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(sign * val)
}

fn env_int0(name: &str) -> i64 {
    match env::var_os(name) {
        None => 0,
        Some(v) => {
            let s = match String::from_utf8(v.as_bytes().to_vec()) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("ValueError: invalid environment variable {name}");
                    exit(1)
                }
            };
            if s.is_empty() {
                return 0;
            }
            match py_int(&s) {
                Some(n) => n,
                None => {
                    eprintln!("ValueError: invalid literal for int() with base 10: '{s}'");
                    exit(1)
                }
            }
        }
    }
}

fn winsize_of(rows: u16, cols: u16) -> libc::winsize {
    libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

fn winsize_now() -> libc::winsize {
    let rows = ENV_ROWS.load(Ordering::SeqCst);
    let cols = ENV_COLS.load(Ordering::SeqCst);
    if rows > 0 && cols > 0 {
        return winsize_of(rows as u16, cols as u16);
    }
    let mut ws: libc::winsize = unsafe { MaybeUninit::zeroed().assume_init() };
    if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws as *mut libc::winsize) } == 0 {
        ws
    } else {
        winsize_of(24, 80)
    }
}

fn init_env_size_cache() {
    let rows = env_int0("BUCHE_PTY_ROWS");
    let cols = env_int0("BUCHE_PTY_COLS");
    if rows != 0 && cols != 0 {
        if rows < 0 || rows > 65535 || cols < 0 || cols > 65535 {
            eprintln!("struct.error");
            exit(1);
        }
        ENV_ROWS.store(rows as i32, Ordering::SeqCst);
        ENV_COLS.store(cols as i32, Ordering::SeqCst);
    }
}

fn set_winsize(fd: RawFd) {
    let ws = winsize_now();
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws as *const libc::winsize) };
}

fn is_tty(fd: RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

fn want_pty() -> bool {
    is_tty(0)
        || env::var_os("BUCHE_PTY_ROWS").is_some()
        || env::var_os("BUCHE_PTY_COLS").is_some()
}

fn close_fd(fd: RawFd) {
    unsafe { libc::close(fd) };
}

fn fd_read(fd: RawFd, n: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(n);
    loop {
        let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, n) };
        if r < 0 {
            if Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Vec::new();
        }
        unsafe { buf.set_len(r as usize) };
        return buf;
    }
}

fn write_once(fd: RawFd, data: &[u8]) {
    unsafe { libc::write(fd, data.as_ptr() as *const c_void, data.len()) };
}

fn write_loop(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const c_void, data.len()) };
        if n < 0 {
            if Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
        if n == 0 {
            return;
        }
        data = &data[n as usize..];
    }
}

struct LockedWriter {
    fd: RawFd,
    lock: Mutex<()>,
}

impl LockedWriter {
    fn new(fd: RawFd) -> Arc<Self> {
        Arc::new(LockedWriter {
            fd,
            lock: Mutex::new(()),
        })
    }

    fn write(&self, data: &[u8]) {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        write_loop(self.fd, data);
    }
}

fn start_seq(fd: i32) -> Vec<u8> {
    let s = format!("{fd:02}");
    let mut v = Vec::with_capacity(2 + s.len());
    v.push(ESC);
    v.push(STX);
    v.extend_from_slice(s.as_bytes());
    v
}

fn find_byte(hay: &[u8], needle: u8) -> Option<usize> {
    hay.iter().position(|&b| b == needle)
}

fn find_seq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn parse_frame_fd(b: &[u8]) -> Option<i32> {
    if b.iter().any(|&c| c >= 0x80) {
        return None;
    }
    let s = std::str::from_utf8(b).ok()?;
    Some(py_int(s)? as i32)
}

struct StreamParser {
    buf: Vec<u8>,
    frame_fd: Option<i32>,
    frame_buf: Vec<u8>,
}

impl StreamParser {
    fn new() -> Self {
        StreamParser {
            buf: Vec::new(),
            frame_fd: None,
            frame_buf: Vec::new(),
        }
    }

    fn feed<F: FnMut(&[u8]), G: FnMut(i32, &[u8])>(&mut self, data: &[u8], pt: &mut F, sink: &mut G) {
        if self.frame_fd.is_none() {
            self.scan_normal(data, pt, sink);
        } else {
            self.scan_frame(data, pt, sink);
        }
    }

    fn scan_normal<F: FnMut(&[u8]), G: FnMut(i32, &[u8])>(&mut self, data: &[u8], pt: &mut F, sink: &mut G) {
        self.buf.extend_from_slice(data);
        while !self.buf.is_empty() {
            let esc_pos = match find_byte(&self.buf, ESC) {
                None => {
                    let b = std::mem::take(&mut self.buf);
                    pt(&b);
                    return;
                }
                Some(p) => p,
            };
            if esc_pos > 0 {
                let b: Vec<u8> = self.buf.drain(..esc_pos).collect();
                pt(&b);
            }
            if self.buf.len() < START_LEN {
                return;
            }
            if self.buf[1] == STX {
                match parse_frame_fd(&self.buf[2..4]) {
                    Some(fd) => {
                        self.buf.drain(..START_LEN);
                        self.frame_fd = Some(fd);
                        self.frame_buf.clear();
                        let rest = std::mem::take(&mut self.buf);
                        self.scan_frame(&rest, pt, sink);
                        return;
                    }
                    None => {
                        pt(&[ESC]);
                        self.buf.remove(0);
                    }
                }
            } else {
                pt(&[ESC]);
                self.buf.remove(0);
            }
        }
    }

    fn scan_frame<F: FnMut(&[u8]), G: FnMut(i32, &[u8])>(&mut self, data: &[u8], pt: &mut F, sink: &mut G) {
        self.frame_buf.extend_from_slice(data);
        let pos = match find_seq(&self.frame_buf, &END_SEQ) {
            Some(p) => p,
            None => return,
        };
        let fd = self.frame_fd.take().unwrap();
        let payload: Vec<u8> = self.frame_buf.drain(..pos).collect();
        self.frame_buf.drain(..END_SEQ.len());
        let rest = std::mem::take(&mut self.frame_buf);
        sink(fd, &payload);
        if !rest.is_empty() {
            self.scan_normal(&rest, pt, sink);
        }
    }
}

fn make_pipe() -> (RawFd, RawFd) {
    let mut f = [0 as RawFd; 2];
    if unsafe { libc::pipe(f.as_mut_ptr()) } != 0 {
        die_errno("pipe");
    }
    (f[0], f[1])
}

fn make_socketpair() -> (RawFd, RawFd) {
    let mut f = [0 as RawFd; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, f.as_mut_ptr()) } != 0 {
        die_errno("socketpair");
    }
    (f[0], f[1])
}

fn open_pty() -> (RawFd, RawFd) {
    let mut m: c_int = 0;
    let mut s: c_int = 0;
    if unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            ptr::null_mut::<c_char>(),
            ptr::null_mut::<libc::termios>(),
            ptr::null_mut::<libc::winsize>(),
        )
    } != 0
    {
        die_errno("openpty");
    }
    (m, s)
}

fn fork() -> libc::pid_t {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die_errno("fork");
    }
    pid
}

fn wait_child(pid: libc::pid_t, kill_on_int: bool) -> c_int {
    let mut status: c_int = 0;
    let mut forwarded = false;
    loop {
        LAST_SIG.store(0, Ordering::SeqCst);
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r >= 0 {
            return status;
        }
        if Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            if kill_on_int
                && !forwarded
                && LAST_SIG.load(Ordering::SeqCst) == libc::SIGINT
            {
                unsafe { libc::kill(pid, libc::SIGINT) };
                forwarded = true;
            }
            continue;
        }
        return 255 << 8;
    }
}

fn exit_with_status(status: c_int) -> ! {
    if libc::WIFEXITED(status) {
        exit(libc::WEXITSTATUS(status));
    }
    if libc::WIFSIGNALED(status) {
        exit(-libc::WTERMSIG(status));
    }
    exit(status & 0xff);
}

fn grab_raw_stdin() -> Option<libc::termios> {
    if !is_tty(0) {
        return None;
    }
    let mut t: libc::termios = unsafe { MaybeUninit::zeroed().assume_init() };
    if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
        return None;
    }
    let old = t;
    t.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
    t.c_oflag &= !libc::OPOST;
    t.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
    t.c_cc[libc::VMIN as usize] = 1;
    t.c_cc[libc::VTIME as usize] = 0;
    unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &t) };
    Some(old)
}

fn restore_stdin(old: Option<libc::termios>) {
    if let Some(t) = old {
        unsafe { libc::tcsetattr(0, libc::TCSADRAIN, &t) };
    }
}

fn pump_extra_fds(w: &Arc<LockedWriter>, done: &AtomicBool) {
    let mut watches: Vec<RawFd> = Vec::new();
    for fd in [3 as RawFd, 5] {
        let mut st: libc::stat = unsafe { MaybeUninit::zeroed().assume_init() };
        if unsafe { libc::fstat(fd, &mut st) } == 0 {
            watches.push(fd);
        }
    }
    while !watches.is_empty() && !done.load(Ordering::SeqCst) {
        let mut pfds: Vec<libc::pollfd> = watches
            .iter()
            .map(|&fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 500) };
        if r < 0 {
            if Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let mut dead: Vec<RawFd> = Vec::new();
        for p in &pfds {
            if p.revents != 0 {
                let chunk = fd_read(p.fd, 4096);
                if chunk.is_empty() {
                    dead.push(p.fd);
                } else {
                    let mut frame = start_seq(p.fd);
                    frame.extend_from_slice(&chunk);
                    frame.extend_from_slice(&END_SEQ);
                    w.write(&frame);
                }
            }
        }
        watches.retain(|f| !dead.contains(f));
    }
}

fn pump_wrap_fd(fd: RawFd, fdnum: i32, w: &Arc<LockedWriter>) {
    loop {
        let chunk = fd_read(fd, 4096);
        if chunk.is_empty() {
            break;
        }
        let mut frame = start_seq(fdnum);
        frame.extend_from_slice(&chunk);
        frame.extend_from_slice(&END_SEQ);
        w.write(&frame);
    }
}

fn env_vars_copy() -> BTreeMap<OsString, OsString> {
    env::vars_os().collect()
}

fn cstring_of(s: &OsString) -> Option<CString> {
    CString::new(s.as_bytes().to_vec()).ok()
}

fn child_error(msg: &str) -> ! {
    let line = format!("stdembed: child setup error: {msg}\n");
    write_once(2, line.as_bytes());
    unsafe { libc::_exit(127) };
}

fn path_candidates<'a>(prog: &'a OsString, env_map: &BTreeMap<OsString, OsString>) -> Vec<OsString> {
    let bytes = prog.as_bytes();
    if bytes.contains(&b'/') {
        return vec![prog.clone()];
    }
    let default = OsString::from(":/bin:/usr/bin");
    let path = env_map
        .get(&OsString::from("PATH"))
        .cloned()
        .unwrap_or(default);
    path.as_bytes()
        .split(|&c| c == b':')
        .map(|dir| {
            if dir.is_empty() {
                prog.clone()
            } else {
                let mut v = dir.to_vec();
                v.push(b'/');
                v.extend_from_slice(bytes);
                OsString::from_vec(v)
            }
        })
        .collect()
}

fn search_path(prog: &OsString, env_map: &BTreeMap<OsString, OsString>) -> Option<OsString> {
    for cand in path_candidates(prog, env_map) {
        let mut st: libc::stat = unsafe { MaybeUninit::zeroed().assume_init() };
        if let Some(c) = cstring_of(&cand) {
            if unsafe { libc::stat(c.as_ptr(), &mut st) } == 0 {
                return Some(cand);
            }
        }
    }
    None
}

fn exec_child(cmd: &[OsString], env_map: &BTreeMap<OsString, OsString>) -> ! {
    if cmd.is_empty() {
        child_error("list index out of range");
    }
    let mut argv: Vec<CString> = Vec::with_capacity(cmd.len());
    for a in cmd {
        match cstring_of(a) {
            Some(c) => argv.push(c),
            None => child_error("embedded null byte"),
        }
    }
    let mut argv_p: Vec<*const c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(ptr::null());
    let mut envv: Vec<CString> = Vec::new();
    for (k, v) in env_map {
        let mut kv = k.clone();
        kv.push("=");
        kv.push(v);
        match cstring_of(&kv) {
            Some(c) => envv.push(c),
            None => child_error("embedded null byte"),
        }
    }
    let mut env_p: Vec<*const c_char> = envv.iter().map(|c| c.as_ptr()).collect();
    env_p.push(ptr::null());
    for cand in path_candidates(&cmd[0], env_map) {
        if let Some(c) = cstring_of(&cand) {
            unsafe { libc::execve(c.as_ptr(), argv_p.as_ptr(), env_p.as_ptr()) };
        }
    }
    child_error(&format!(
        "[Errno 2] No such file or directory: '{}'",
        cmd[0].to_string_lossy()
    ));
}

fn child_setup_and_exec(
    cmd: &[OsString],
    env_map: &BTreeMap<OsString, OsString>,
    map: &BTreeMap<RawFd, RawFd>,
) -> ! {
    const HI: RawFd = 100;
    let dsts: Vec<RawFd> = map.keys().copied().collect();
    let srcs: Vec<RawFd> = dsts.iter().map(|d| *map.get(d).unwrap()).collect();
    for (i, src) in srcs.iter().enumerate() {
        if unsafe { libc::dup2(*src, HI + i as RawFd) } < 0 {
            child_error(&format!("dup2 {src}: {}", Error::last_os_error()));
        }
    }
    for (i, dst) in dsts.iter().enumerate() {
        if unsafe { libc::dup2(HI + i as RawFd, *dst) } < 0 {
            child_error(&format!("dup2 {dst}: {}", Error::last_os_error()));
        }
    }
    for i in 0..dsts.len() {
        unsafe { libc::close(HI + i as RawFd) };
    }
    let keep = dsts.iter().max().copied().unwrap_or(2).max(2);
    let maxfd: RawFd = {
        let mut lim: libc::rlimit = unsafe { MaybeUninit::zeroed().assume_init() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
            lim.rlim_cur.min(65536) as RawFd
        } else {
            1024
        }
    };
    for fd in (keep + 1)..maxfd {
        unsafe { libc::close(fd) };
    }
    exec_child(cmd, env_map);
}

fn run_unwrap_pipe(cmd: &[OsString]) -> ! {
    if cmd.is_empty() {
        eprintln!("IndexError: list index out of range");
        exit(1);
    }
    let env_map = env_vars_copy();
    if search_path(&cmd[0], &env_map).is_none() {
        eprintln!(
            "FileNotFoundError: [Errno 2] No such file or directory: '{}'",
            cmd[0].to_string_lossy()
        );
        exit(1);
    }
    let (in_r, in_w) = make_pipe();
    let (out_r, out_w) = make_pipe();
    let pid = fork();
    if pid == 0 {
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
        let mut map: BTreeMap<RawFd, RawFd> = BTreeMap::new();
        map.insert(0 as RawFd, in_r);
        map.insert(1 as RawFd, out_w);
        child_setup_and_exec(cmd, &env_map, &map);
    }
    close_fd(in_r);
    close_fd(out_w);

    let w_out = LockedWriter::new(1);
    let w_child = LockedWriter::new(in_w);
    let done = Arc::new(AtomicBool::new(false));

    {
        let (w, done, fd) = (w_out.clone(), done.clone(), out_r);
        thread::spawn(move || {
            let mut parser = StreamParser::new();
            loop {
                let chunk = fd_read(fd, 4096);
                if chunk.is_empty() {
                    break;
                }
                parser.feed(
                    &chunk,
                    &mut |d| w.write(d),
                    &mut |n, d| write_once(n as RawFd, d),
                );
            }
            done.store(true, Ordering::SeqCst);
        });
    }
    {
        let (w, fd) = (w_child.clone(), in_w);
        thread::spawn(move || {
            loop {
                let chunk = fd_read(0, 4096);
                if chunk.is_empty() {
                    break;
                }
                w.write(&chunk);
            }
            close_fd(fd);
        });
    }
    {
        let (w, done) = (w_child, done);
        thread::spawn(move || pump_extra_fds(&w, &done));
    }

    let status = wait_child(pid, false);
    exit_with_status(status)
}

fn run_unwrap_pty(cmd: &[OsString]) -> ! {
    init_env_size_cache();
    let (master, slave) = open_pty();
    set_winsize(master);
    let env_map = env_vars_copy();
    let pid = fork();
    if pid == 0 {
        close_fd(master);
        unsafe { libc::setsid() };
        unsafe { libc::ioctl(slave, libc::TIOCSCTTY as c_ulong, 0) };
        let mut map: BTreeMap<RawFd, RawFd> = BTreeMap::new();
        map.insert(0 as RawFd, slave);
        map.insert(1 as RawFd, slave);
        map.insert(2 as RawFd, slave);
        child_setup_and_exec(cmd, &env_map, &map);
    }
    close_fd(slave);
    MASTER_FD.store(master, Ordering::SeqCst);
    unsafe { set_sigaction(libc::SIGWINCH, winch_handler) };

    let w_out = LockedWriter::new(1);
    let w_master = LockedWriter::new(master);
    let done = Arc::new(AtomicBool::new(false));
    let old = grab_raw_stdin();

    {
        let (w, done, fd) = (w_out.clone(), done.clone(), master);
        thread::spawn(move || {
            let mut parser = StreamParser::new();
            loop {
                let chunk = fd_read(fd, 4096);
                if chunk.is_empty() {
                    break;
                }
                parser.feed(
                    &chunk,
                    &mut |d| w.write(d),
                    &mut |n, d| write_once(n as RawFd, d),
                );
            }
            done.store(true, Ordering::SeqCst);
        });
    }
    {
        let w = w_master.clone();
        thread::spawn(move || {
            loop {
                let chunk = fd_read(0, 4096);
                if chunk.is_empty() {
                    break;
                }
                w.write(&chunk);
            }
        });
    }
    {
        let (w, done) = (w_master, done);
        thread::spawn(move || pump_extra_fds(&w, &done));
    }

    let status = wait_child(pid, true);
    restore_stdin(old);
    close_fd(master);
    exit_with_status(status)
}

fn run_unwrap(cmd: &[OsString]) -> ! {
    if want_pty() {
        run_unwrap_pty(cmd)
    } else {
        run_unwrap_pipe(cmd)
    }
}

fn run_wrap_pipe(
    cmd: &[OsString],
    pipe3_r: RawFd,
    pipe3_w: RawFd,
    pipe4_r: RawFd,
    pipe4_w: RawFd,
    local5: RawFd,
    remote5: RawFd,
    env_map: &BTreeMap<OsString, OsString>,
) -> ! {
    let (cin_r, cin_w) = make_pipe();
    let (cout_r, cout_w) = make_pipe();
    let pid = fork();
    if pid == 0 {
        close_fd(local5);
        let mut map: BTreeMap<RawFd, RawFd> = BTreeMap::new();
        map.insert(0 as RawFd, cin_r);
        map.insert(1 as RawFd, cout_w);
        map.insert(3 as RawFd, pipe3_r);
        map.insert(4 as RawFd, pipe4_w);
        map.insert(5 as RawFd, remote5);
        child_setup_and_exec(cmd, env_map, &map);
    }
    close_fd(cin_r);
    close_fd(cout_w);
    close_fd(pipe3_r);
    close_fd(pipe4_w);
    close_fd(remote5);

    let w_out = LockedWriter::new(1);
    let w_in = LockedWriter::new(cin_w);

    {
        let (w, fd) = (w_out.clone(), cout_r);
        thread::spawn(move || loop {
            let chunk = fd_read(fd, 4096);
            if chunk.is_empty() {
                break;
            }
            w.write(&chunk);
        });
    }
    {
        let (w, p3, p5, cin) = (w_in.clone(), pipe3_w, local5, cin_w);
        thread::spawn(move || {
            let mut parser = StreamParser::new();
            loop {
                let chunk = fd_read(0, 4096);
                if chunk.is_empty() {
                    break;
                }
                parser.feed(
                    &chunk,
                    &mut |d| w.write(d),
                    &mut |n, d| match n {
                        3 => write_loop(p3, d),
                        5 => write_loop(p5, d),
                        _ => {}
                    },
                );
            }
            close_fd(cin);
        });
    }
    {
        let w = w_out.clone();
        thread::spawn(move || pump_wrap_fd(pipe4_r, 4, &w));
    }
    {
        let w = w_out;
        thread::spawn(move || pump_wrap_fd(local5, 5, &w));
    }

    let status = wait_child(pid, false);
    close_fd(pipe3_w);
    close_fd(pipe4_r);
    close_fd(local5);
    exit_with_status(status)
}

fn run_wrap_pty(
    cmd: &[OsString],
    pipe3_r: RawFd,
    pipe3_w: RawFd,
    pipe4_r: RawFd,
    pipe4_w: RawFd,
    local5: RawFd,
    remote5: RawFd,
    env_map: &BTreeMap<OsString, OsString>,
) -> ! {
    init_env_size_cache();
    let (master, slave) = open_pty();
    set_winsize(master);
    let pid = fork();
    if pid == 0 {
        close_fd(master);
        close_fd(local5);
        unsafe { libc::setsid() };
        unsafe { libc::ioctl(slave, libc::TIOCSCTTY as c_ulong, 0) };
        let mut map: BTreeMap<RawFd, RawFd> = BTreeMap::new();
        map.insert(0 as RawFd, slave);
        map.insert(1 as RawFd, slave);
        map.insert(2 as RawFd, slave);
        map.insert(3 as RawFd, pipe3_r);
        map.insert(4 as RawFd, pipe4_w);
        map.insert(5 as RawFd, remote5);
        child_setup_and_exec(cmd, env_map, &map);
    }
    close_fd(slave);
    close_fd(pipe3_r);
    close_fd(pipe4_w);
    close_fd(remote5);
    MASTER_FD.store(master, Ordering::SeqCst);
    unsafe { set_sigaction(libc::SIGWINCH, winch_handler) };

    let w_out = LockedWriter::new(1);
    let w_master = LockedWriter::new(master);
    let old = grab_raw_stdin();

    {
        let (w, fd) = (w_out.clone(), master);
        thread::spawn(move || loop {
            let chunk = fd_read(fd, 4096);
            if chunk.is_empty() {
                break;
            }
            w.write(&chunk);
        });
    }
    {
        let (w, p3, p5) = (w_master.clone(), pipe3_w, local5);
        thread::spawn(move || {
            let mut parser = StreamParser::new();
            loop {
                let chunk = fd_read(0, 4096);
                if chunk.is_empty() {
                    break;
                }
                parser.feed(
                    &chunk,
                    &mut |d| w.write(d),
                    &mut |n, d| match n {
                        3 => write_loop(p3, d),
                        5 => write_loop(p5, d),
                        _ => {}
                    },
                );
            }
        });
    }
    {
        let w = w_out.clone();
        thread::spawn(move || pump_wrap_fd(pipe4_r, 4, &w));
    }
    {
        let w = w_out;
        thread::spawn(move || pump_wrap_fd(local5, 5, &w));
    }

    let status = wait_child(pid, true);
    restore_stdin(old);
    close_fd(master);
    close_fd(pipe3_w);
    close_fd(pipe4_r);
    close_fd(local5);
    exit_with_status(status)
}

fn run_wrap(cmd: &[OsString]) -> ! {
    let (pipe3_r, pipe3_w) = make_pipe();
    let (pipe4_r, pipe4_w) = make_pipe();
    let (local5, remote5) = make_socketpair();
    let mut env_map = env_vars_copy();
    env_map.insert(OsString::from("BUCHE_CONTROL_FD"), OsString::from("5"));
    if want_pty() {
        run_wrap_pty(
            cmd, pipe3_r, pipe3_w, pipe4_r, pipe4_w, local5, remote5, &env_map,
        )
    } else {
        run_wrap_pipe(
            cmd, pipe3_r, pipe3_w, pipe4_r, pipe4_w, local5, remote5, &env_map,
        )
    }
}

fn py_repr(s: &str) -> String {
    let has_sq = s.contains('\'');
    let has_dq = s.contains('"');
    let q = if has_sq && !has_dq { '"' } else { '\'' };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

fn print_size() -> ! {
    let rows = env_int0("BUCHE_PTY_ROWS");
    let cols = env_int0("BUCHE_PTY_COLS");
    if rows != 0 && cols != 0 {
        println!("('buche', {rows}, {cols})");
        exit(0);
    }
    let mut ws: libc::winsize = unsafe { MaybeUninit::zeroed().assume_init() };
    if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws as *mut libc::winsize) } == 0 {
        println!("('winsz', {}, {})", ws.ws_row, ws.ws_col);
    } else {
        println!("b'\\x18\\x00P\\x00\\x00\\x00\\x00\\x00'");
    }
    exit(0);
}

fn main() -> ! {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    unsafe { set_sigaction(libc::SIGINT, record_sig) };
    let mut argv: Vec<OsString> = env::args_os().collect();
    if argv.len() > 1 {
        argv.remove(0);
    }
    if argv.is_empty() {
        eprint!("{DOC}\n");
        exit(1);
    }
    let flag = argv.remove(0);
    if flag == "--help" || flag == "-h" {
        print!("{DOC}\n");
        exit(0)
    } else if flag == "--unwrap" || flag == "-u" {
        run_unwrap(&argv)
    } else if flag == "--wrap" || flag == "-w" {
        run_wrap(&argv)
    } else if flag == "--size" {
        print_size()
    } else {
        eprintln!("stdembed: unknown flag {}", py_repr(&flag.to_string_lossy()));
        exit(1)
    }
}
