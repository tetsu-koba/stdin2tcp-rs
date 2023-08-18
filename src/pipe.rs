use std::fs::File;
use std::io::{self, Read};
use std::os::unix::io::RawFd;

// Check if the given file descriptor is a pipe
pub fn is_pipe(fd: RawFd) -> bool {
    match nix::sys::stat::fstat(fd) {
        Ok(stat) => stat.st_mode & libc::S_IFMT == libc::S_IFIFO,
        Err(_) => false,
    }
}

// Get pipe max buffer size
#[cfg(target_os = "linux")]
pub fn get_pipe_max_size() -> Result<usize, io::Error> {
    // Read the maximum pipe size
    let mut pipe_max_size_file = File::open("/proc/sys/fs/pipe-max-size")?;
    let mut buffer = String::new();
    pipe_max_size_file.read_to_string(&mut buffer)?;
    let max_size_str = buffer.trim_end();
    let max_size: usize = max_size_str.parse().map_err(|err| {
        eprintln!("Failed to parse /proc/sys/fs/pipe-max-size: {:?}", err);
        io::Error::new(io::ErrorKind::InvalidData, "Failed to parse max pipe size")
    })?;
    Ok(max_size)
}

#[cfg(target_os = "macos")]
pub fn get_pipe_max_size() -> Result<usize, io::Error> {
    Ok(64 * 1024)
}
