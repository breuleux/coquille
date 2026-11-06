//! Asynchronous I/O on raw file descriptors (PTY masters, pipes, socket
//! pairs, the control channel), through the reactor.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

pub fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{F_GETFL, F_SETFL, OFlag, fcntl};
    let flags = OFlag::from_bits_truncate(fcntl(fd, F_GETFL)?);
    fcntl(fd, F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

pub fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{F_SETFD, FdFlag, fcntl};
    fcntl(fd, F_SETFD(FdFlag::FD_CLOEXEC))?;
    Ok(())
}

/// A duplicate of `fd`, closed on exec.
pub fn dup_cloexec(fd: RawFd) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// A pipe, both ends closed on exec.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (r, w) = nix::unistd::pipe()?;
    set_cloexec(&r)?;
    set_cloexec(&w)?;
    Ok((r, w))
}

/// A file descriptor, read and written without blocking. A read that fails
/// with EIO (a PTY master once its slave is closed everywhere) is the end.
pub struct FdStream {
    inner: AsyncFd<OwnedFd>,
}

impl FdStream {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(&fd)?;
        // SAFETY: the AsyncFd owns `fd`, which stays open (and the same)
        // until it is dropped.
        let inner = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
        Ok(Self { inner })
    }

    pub fn raw(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    /// Read what is available now, without waiting (`Ok(0)`: nothing more).
    pub fn read_now(&self, buf: &mut [u8]) -> io::Result<usize> {
        match raw_read(self.raw(), buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || is_eio(&e) => Ok(0),
            r => r,
        }
    }
}

fn is_eio(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EIO)
}

fn raw_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

fn raw_write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

impl AsyncRead for FdStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| raw_read(inner.as_raw_fd(), unfilled)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) if is_eio(&e) => return Poll::Ready(Ok(())),
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for FdStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;
            match guard.try_io(|inner| raw_write(inner.as_raw_fd(), buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Where to queue what to write to a stream: written in order, by a task of
/// its own. Dropping every sender closes the stream once all is written.
pub type Writer = mpsc::UnboundedSender<Vec<u8>>;

/// Start the task writing to `stream`. If a write fails (the reader is
/// gone), `on_error` is called and the rest is dropped.
pub fn spawn_writer<W>(mut stream: W, on_error: Option<Box<dyn FnOnce()>>) -> Writer
where
    W: AsyncWrite + Unpin + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::task::spawn_local(async move {
        let mut on_error = on_error;
        while let Some(data) = rx.recv().await {
            if stream.write_all(&data).await.is_err() {
                if let Some(f) = on_error.take() {
                    f();
                }
                return;
            }
        }
    });
    tx
}
