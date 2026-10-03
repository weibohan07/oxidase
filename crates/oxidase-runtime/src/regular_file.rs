//! Race-bounded opening of file-backed runtime resources.

use std::fs::{self, File, Metadata};
use std::io;
use std::path::Path;

/// Opaque prepared provenance for a Secret/private key. It carries no bytes
/// and never renders its paths. Admin bootstrap can retain this identity
/// without retaining a previous data-plane snapshot.
#[derive(Clone)]
pub struct SensitiveFileIdentity {
    declared: std::path::PathBuf,
    canonical: Option<std::path::PathBuf>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl SensitiveFileIdentity {
    pub(crate) fn from_opened(path: &Path, metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        #[cfg(not(unix))]
        let _ = metadata;
        Self {
            declared: path.to_path_buf(),
            canonical: path.canonicalize().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }

    /// Checks both the declared/canonical path and the exact origin FD retained
    /// by reference-mode Asset spooling. No Asset body is collected.
    pub fn overlaps_asset(&self, source: &oxidase_site::AssetSource) -> io::Result<bool> {
        let display = source.display_path();
        if display == self.declared
            || self
                .canonical
                .as_ref()
                .zip(display.canonicalize().ok().as_ref())
                .is_some_and(|(left, right)| left == right)
        {
            return Ok(true);
        }
        let metadata = match source {
            oxidase_site::AssetSource::File(path) => {
                let (_, metadata) = open_regular_file(path)
                    .map_err(|_| io::Error::other("cannot verify public Asset identity"))?;
                metadata
            }
            oxidase_site::AssetSource::Pinned { file, origin, .. } => {
                origin.as_deref().unwrap_or(file).metadata()?
            }
        };
        if !metadata.is_file() {
            return Err(io::Error::other(
                "public Asset origin is not a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Ok(metadata.dev() == self.device && metadata.ino() == self.inode)
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Ok(false)
        }
    }
}

impl std::fmt::Debug for SensitiveFileIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveFileIdentity(<redacted>)")
    }
}

#[cfg(all(test, unix))]
mod identity_tests {
    use super::*;

    #[test]
    fn retained_origin_and_hardlinks_match_without_exposing_paths() {
        let directory = tempfile::tempdir().expect("tempdir");
        let secret_path = directory.path().join("distinctive-admin-token");
        fs::write(&secret_path, b"never-publish").expect("token");
        let (secret, metadata) = open_regular_file(&secret_path).expect("regular token");
        let identity = SensitiveFileIdentity::from_opened(&secret_path, &metadata);
        assert_eq!(format!("{identity:?}"), "SensitiveFileIdentity(<redacted>)");
        let alias = directory.path().join("public.txt");
        fs::hard_link(&secret_path, &alias).expect("alias");
        assert!(
            identity
                .overlaps_asset(&oxidase_site::AssetSource::File(alias))
                .expect("identity check")
        );
        let spool = tempfile::tempfile().expect("private spool");
        let pinned = oxidase_site::AssetSource::pinned_with_origin(
            spool,
            secret,
            directory.path().join("unrelated-display"),
            0,
        );
        fs::remove_file(&secret_path).expect("unlink original path");
        assert!(
            identity
                .overlaps_asset(&pinned)
                .expect("retained origin identity check")
        );
        let unrelated = directory.path().join("other.txt");
        fs::write(&unrelated, b"public").expect("public file");
        assert!(
            !identity
                .overlaps_asset(&oxidase_site::AssetSource::File(unrelated))
                .expect("unrelated check")
        );
    }
}

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
