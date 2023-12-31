use nix::sys::{epoll, signal, signalfd};
use nix::unistd;
use std::error::Error;
use std::io::{self, Write};
use std::net::TcpStream;
use std::os::unix::io::RawFd;
use url::Url;
mod pipe;

const MAX_EVENT: usize = 5;

fn create_signalfd() -> nix::Result<RawFd> {
    let mut mask = signal::SigSet::empty();
    mask.add(signal::SIGINT);
    mask.add(signal::SIGTERM);
    mask.thread_block().unwrap();
    signalfd::signalfd(-1, &mask, signalfd::SfdFlags::SFD_CLOEXEC)
}

fn handle_signals(signal_fd: RawFd) -> bool {
    let mut buf = vec![0u8; std::mem::size_of::<libc::siginfo_t>()];
    unistd::read(signal_fd, &mut buf).expect("Reading from signalfd should not fail.");
    let signo: libc::c_int = unsafe { std::ptr::read(buf.as_ptr() as *const _) };
    match signo {
        libc::SIGINT => {
            eprintln!("Got SIGINT");
            false
        }
        libc::SIGTERM => {
            eprintln!("Got SIGTERM");
            false
        }
        _ => unreachable!(),
    }
}

fn frame_handler(tcp: &mut TcpStream, buf: &mut [u8]) -> bool {
    let n = unistd::read(libc::STDIN_FILENO, buf).unwrap_or(0);
    if n == 0 {
        false
    } else {
        tcp.write_all(&buf[0..n]).is_ok()
    }
}

fn open(url_string: &str) -> io::Result<TcpStream> {
    let uri = Url::parse(url_string).unwrap();
    if uri.scheme() == "tcp" {
        if let (Some(host), Some(port)) = (uri.host_str(), uri.port()) {
            TcpStream::connect((host, port))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Invalid URL"))
        }
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Invalid URL"))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} URL\nURL is 'tcp://hostname:port'", args[0]);
        std::process::exit(1);
    }

    let url_string = &args[1];
    if !pipe::is_pipe(libc::STDIN_FILENO) {
        eprintln!("stdin must be pipe");
        std::process::exit(1);
    }

    let mut tcp = open(url_string).unwrap();

    let epoll_fd = epoll::epoll_create1(epoll::EpollCreateFlags::EPOLL_CLOEXEC)?;
    let mut read_event =
        epoll::EpollEvent::new(epoll::EpollFlags::EPOLLIN, libc::STDIN_FILENO as u64);
    epoll::epoll_ctl(
        epoll_fd,
        epoll::EpollOp::EpollCtlAdd,
        libc::STDIN_FILENO,
        &mut read_event,
    )?;

    let signal_fd = create_signalfd()?;
    let mut signal_event = epoll::EpollEvent::new(epoll::EpollFlags::EPOLLIN, signal_fd as u64);
    epoll::epoll_ctl(
        epoll_fd,
        epoll::EpollOp::EpollCtlAdd,
        signal_fd,
        &mut signal_event,
    )?;

    let timeout = 5000;
    let pipe_max_size = pipe::get_pipe_max_size()?;
    let mut buf = vec![0u8; pipe_max_size];

    loop {
        let mut events = [epoll::EpollEvent::empty(); MAX_EVENT];
        let num_events = epoll::epoll_wait(epoll_fd, &mut events, timeout)?;
        if num_events == 0 {
            eprintln!("Timeout");
            continue;
        }
        for ev in &events[0..num_events] {
            if ev.data() == libc::STDIN_FILENO as u64 {
                if !frame_handler(&mut tcp, &mut buf) {
                    return Ok(());
                }
            } else if ev.data() == signal_fd as u64 {
                if !handle_signals(signal_fd) {
                    return Ok(());
                }
            } else {
                unreachable!();
            }
        }
    }
}
