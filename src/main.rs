extern crate libc;
extern crate nix;
extern crate url;

use nix::sys::{epoll, signal, signalfd};
use nix::unistd;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::RawFd;
use url::Url;

const MAX_EVENT: usize = 5;

struct SignalfdSiginfo {
    signo: libc::c_int,
    // ... (other fields from signalfd_siginfo not included for brevity)
}

fn create_signalfd() -> nix::Result<RawFd> {
    let mut mask = signal::SigSet::empty();
    mask.add(signal::SIGINT);
    mask.add(signal::SIGTERM);
    mask.thread_block().unwrap();
    signalfd::signalfd(-1, &mask, signalfd::SfdFlags::SFD_CLOEXEC)
}

fn handle_signals(signal_fd: RawFd) -> bool {
    let mut buf = vec![0u8; std::mem::size_of::<SignalfdSiginfo>()];
    if unistd::read(signal_fd, &mut buf).is_ok() {
        let info: SignalfdSiginfo = unsafe { std::ptr::read(buf.as_ptr() as *const _) };
        match info.signo {
            libc::SIGINT => {
                println!("Got SIGINT");
                false
            }
            libc::SIGTERM => {
                println!("Got SIGTERM");
                false
            }
            _ => unreachable!(),
        }
    } else {
        true
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

fn is_pipe(fd: RawFd) -> bool {
    match nix::sys::stat::fstat(fd) {
        Ok(stat) => stat.st_mode & libc::S_IFMT == libc::S_IFIFO,
        Err(_) => false,
    }
}

fn get_pipe_max_size() -> Result<usize, Box<dyn std::error::Error>> {
    let mut content = String::new();
    let mut file = File::open("/proc/sys/fs/pipe-max-size")?;
    file.read_to_string(&mut content)?;
    let max_size: usize = content.trim().parse()?;
    Ok(max_size)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} URL\nURL is 'tcp://hostname:port'", args[0]);
        std::process::exit(1);
    }

    let url_string = &args[1];
    if !is_pipe(libc::STDIN_FILENO) {
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
    let pipe_max_size = get_pipe_max_size()?;
    let mut buf = vec![0u8; pipe_max_size];

    loop {
        let mut events = [epoll::EpollEvent::empty(); MAX_EVENT];
        let num_events = epoll::epoll_wait(epoll_fd, &mut events, timeout)?;
        if num_events == 0 {
            println!("Timeout");
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
