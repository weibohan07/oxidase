//! Process identity and a common, safe monotonic clock for validation helpers.
//! No path, credential, resource handle or process-owned object is retained.

use std::io::Read as _;
use std::path::Path;

use oxidase_core::ContentHasher;
use serde::{Deserialize, Serialize};

use super::{SoakError, fail};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProcessRole {
    Gateway,
    Controller,
    Dns,
    Upstream,
    Sampler,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutableIdentity {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessIdentity {
    pub role: ProcessRole,
    pub pid: u32,
    pub start_ticks: Option<u64>,
    pub boot_id: Option<String>,
    pub binary_sha256: String,
    pub exe_sha256: Option<String>,
    pub proc_verified: bool,
    pub executable_identity: Option<ExecutableIdentity>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ProcessReference {
    pub role: ProcessRole,
    pub pid: u32,
    pub start_ticks: Option<u64>,
    pub boot_id: Option<String>,
}

impl ProcessIdentity {
    pub(super) fn reference(&self) -> ProcessReference {
        ProcessReference {
            role: self.role,
            pid: self.pid,
            start_ticks: self.start_ticks,
            boot_id: self.boot_id.clone(),
        }
    }
}

/// The same CLOCK_MONOTONIC coordinate is used by all helper processes. An
/// unsupported or out-of-range clock is an error, never timestamp zero.
pub(super) fn monotonic_ns() -> Result<u64, SoakError> {
    #[cfg(unix)]
    {
        let value = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        let seconds = u64::try_from(value.tv_sec).map_err(|_| fail("resource.clock_invalid"))?;
        let nanoseconds = u64::try_from(value.tv_nsec)
            .ok()
            .filter(|value| *value < 1_000_000_000)
            .ok_or_else(|| fail("resource.clock_invalid"))?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(nanoseconds))
            .ok_or_else(|| fail("resource.clock_overflow"))
    }
    #[cfg(not(unix))]
    Err(fail("resource.clock_unsupported"))
}

pub(super) fn hash_binary(path: &Path) -> Result<String, SoakError> {
    let mut file = std::fs::File::open(path).map_err(|_| fail("resource.binary_unreadable"))?;
    if !file
        .metadata()
        .map_err(|_| fail("resource.binary_metadata"))?
        .is_file()
    {
        return Err(fail("resource.binary_not_regular"));
    }
    let mut hasher = ContentHasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| fail("resource.binary_read"))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(|_| fail("resource.binary_size"))?)
            .filter(|bytes| *bytes <= 512 * 1024 * 1024)
            .ok_or_else(|| fail("resource.binary_size"))?;
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finish().to_hex())
}

/// Hash the supplied binary and the actual running /proc executable separately.
/// Linux rejects mismatch/reuse. Other platforms explicitly cannot supply the
/// Linux qualification identity and leave those observations unavailable.
pub(super) fn capture(
    role: ProcessRole,
    pid: u32,
    binary: &Path,
) -> Result<ProcessIdentity, SoakError> {
    if pid == 0 {
        return Err(fail("resource.pid_invalid"));
    }
    let binary_sha256 = hash_binary(binary)?;
    #[cfg(target_os = "linux")]
    {
        let before = read_linux_identity(pid)?;
        let exe_sha256 = hash_binary(&Path::new("/proc").join(pid.to_string()).join("exe"))?;
        let after = read_linux_identity(pid)?;
        if before != after {
            return Err(fail("resource.pid_identity_changed"));
        }
        if exe_sha256 != binary_sha256 {
            return Err(fail("resource.binary_identity_mismatch"));
        }
        Ok(ProcessIdentity {
            role,
            pid,
            start_ticks: Some(before.0),
            boot_id: Some(before.1),
            binary_sha256,
            exe_sha256: Some(exe_sha256),
            proc_verified: true,
            executable_identity: Some(before.2),
        })
    }
    #[cfg(not(target_os = "linux"))]
    Ok(ProcessIdentity {
        role,
        pid,
        start_ticks: None,
        boot_id: None,
        binary_sha256,
        exe_sha256: None,
        proc_verified: false,
        executable_identity: None,
    })
}

/// Cheap repeated identity check. It does not rehash large binaries at every
/// tick, and never silently accepts a replacement executable or recycled PID.
pub(super) fn verify(identity: &ProcessIdentity) -> Result<(), SoakError> {
    if identity.pid == 0
        || !valid_hash(&identity.binary_sha256)
        || identity
            .exe_sha256
            .as_ref()
            .is_some_and(|hash| !valid_hash(hash) || hash != &identity.binary_sha256)
    {
        return Err(fail("resource.binary_identity_invalid"));
    }
    #[cfg(target_os = "linux")]
    {
        if !identity.proc_verified {
            return Err(fail("resource.pid_unverified"));
        }
        let observed = read_linux_identity(identity.pid)?;
        if identity.start_ticks != Some(observed.0)
            || identity.boot_id.as_ref() != Some(&observed.1)
            || identity.executable_identity.as_ref() != Some(&observed.2)
        {
            return Err(fail("resource.pid_identity_changed"));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = identity;
        Err(fail("resource.proc_identity_unsupported"))
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(target_os = "linux")]
fn read_linux_identity(pid: u32) -> Result<(u64, String, ExecutableIdentity), SoakError> {
    use std::os::unix::fs::MetadataExt as _;
    let directory = Path::new("/proc").join(pid.to_string());
    let stat = std::fs::read_to_string(directory.join("stat"))
        .map_err(|_| fail("resource.proc_stat_unreadable"))?;
    let start = parse_start_ticks(&stat, pid).ok_or_else(|| fail("resource.proc_stat_invalid"))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| fail("resource.boot_id_unreadable"))?;
    let boot = boot.trim();
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(fail("resource.boot_id_invalid"));
    }
    let metadata = std::fs::metadata(directory.join("exe"))
        .map_err(|_| fail("resource.proc_exe_unreadable"))?;
    if !metadata.is_file() {
        return Err(fail("resource.proc_exe_not_regular"));
    }
    Ok((
        start,
        boot.to_owned(),
        ExecutableIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        },
    ))
}

#[cfg(any(target_os = "linux", test))]
fn parse_start_ticks(text: &str, expected_pid: u32) -> Option<u64> {
    let (pid, rest) = text.split_once(' ')?;
    if pid.parse::<u32>().ok()? != expected_pid || !rest.starts_with('(') {
        return None;
    }
    // Linux comm can contain whitespace and ')' characters. Fields resume
    // after the final closing delimiter, not after whitespace field number 2.
    let end = rest.rfind(") ")?;
    let fields = rest.get(end + 2..)?.split_whitespace().collect::<Vec<_>>();
    if fields.first()?.len() != 1 {
        return None;
    }
    fields.get(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_comm_with_spaces_parentheses_and_unicode_does_not_shift_start_time() {
        let mut fields = vec!["S".to_owned()];
        fields.extend((1..=19).map(|value| value.to_string()));
        let text = format!("42 (héllo ) worker) {}", fields.join(" "));
        assert_eq!(parse_start_ticks(&text, 42), Some(19));
        assert_eq!(parse_start_ticks(&text, 43), None);
        assert_eq!(parse_start_ticks("42 (bad) S 1", 42), None);
    }

    #[test]
    fn streaming_binary_hash_matches_known_sha256_without_retaining_bytes() {
        let directory = tempfile::tempdir().expect("fixture");
        let binary = directory.path().join("binary");
        std::fs::write(&binary, b"abc").expect("fixture bytes");
        assert_eq!(
            hash_binary(&binary).expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(hash_binary(directory.path()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_running_executable_identity_is_verified_and_reuse_is_rejected() {
        let binary = std::env::current_exe().expect("executable");
        let mut identity =
            capture(ProcessRole::Controller, std::process::id(), &binary).expect("self identity");
        verify(&identity).expect("unchanged process");
        assert_eq!(identity.exe_sha256.as_ref(), Some(&identity.binary_sha256));
        identity.start_ticks = identity.start_ticks.and_then(|ticks| ticks.checked_add(1));
        assert!(verify(&identity).is_err());
    }

    #[test]
    fn monotonic_time_is_not_fabricated_zero() {
        let first = monotonic_ns().expect("supported clock");
        let next = monotonic_ns().expect("supported clock");
        assert!(first > 0);
        assert!(next >= first);
    }

    #[test]
    fn full_binary_hash_is_required_and_never_accepts_short_display_identity() {
        assert!(valid_hash(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
        for bad in [
            "",
            "01234567",
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        ] {
            assert!(!valid_hash(bad));
        }
        let mut identity = capture(
            ProcessRole::Controller,
            std::process::id(),
            &std::env::current_exe().expect("executable"),
        )
        .expect("identity");
        identity.binary_sha256 = "01234567".to_owned();
        assert_eq!(
            verify(&identity)
                .expect_err("short hash is invalid even without Linux proc support")
                .to_string(),
            "resource.binary_identity_invalid"
        );
    }
}
