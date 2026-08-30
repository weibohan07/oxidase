//! Race-bounded opening of file-backed runtime resources.

use std::fs::{self, File, Metadata};
use std::io;
use std::path::Path;

/// Distinguishes filesystem inspection/open failures from the regular-file
/// contract so each resource can retain its own diagnostic codes.
#[derive(Debug)]
pub(crate) enum RegularFileOpenError {
    Inspect(io::Error),
    NotRegular,
    Open(io::Error),
    ChangedType,
}

/// Opens a path only after and before checking its regular-file type.
///
/// On Unix, `O_NONBLOCK` prevents a path swapped to a FIFO between metadata
/// and open from wedging the single preparation worker. The post-open `fstat`
/// then rejects that descriptor. Symlinks remain supported because certificate
/// and Secret rotation commonly uses an atomically replaced symlink.
pub(crate) fn open_regular_file(path: &Path) -> Result<(File, Metadata), RegularFileOpenError> {
    let before = fs::metadata(path).map_err(RegularFileOpenError::Inspect)?;
    if !before.is_file() {
        return Err(RegularFileOpenError::NotRegular);
    }

    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};

        let descriptor = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            RegularFileOpenError::Open(io::Error::from_raw_os_error(error.raw_os_error()))
        })?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = File::open(path).map_err(RegularFileOpenError::Open)?;

    let after = file.metadata().map_err(RegularFileOpenError::Open)?;
    if !after.is_file() {
        return Err(RegularFileOpenError::ChangedType);
    }
    Ok((file, after))
}
