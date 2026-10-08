//! Private local journal. A server must use its own transactional database.
use crate::error::{Error, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub struct FileJournal {
    directory: PathBuf,
}
/// Fail before storing proofs on platforms without this journal's permission and durability contract.
pub fn require_supported_platform() -> Result<()> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err(Error::config(
            "Native file journals require a local POSIX filesystem. On Windows, use Linux/WSL with state in its Linux filesystem, not /mnt/c or /mnt/d. Keep existing journals for recovery; pending operations remain uncertain.",
        ))
    }
}
impl FileJournal {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }
    pub fn initialize(&self) -> Result<()> {
        require_supported_platform()?;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&self.directory)
            .map_err(|_| Error::config("Cannot initialize operation journal"))?;
        let info = fs::symlink_metadata(&self.directory)
            .map_err(|_| Error::config("Cannot read operation journal"))?;
        if !info.is_dir() || info.file_type().is_symlink() {
            return Err(Error::config("Journal directory must be private (0700)"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if info.permissions().mode() & 0o077 != 0 {
                return Err(Error::config("Journal directory must be private (0700)"));
            }
        }
        Ok(())
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
            || matches!(name, "." | "..")
        {
            return Err(Error::config("Invalid journal entry name"));
        }
        Ok(self.directory.join(format!("{name}.json")))
    }
    pub fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        require_supported_platform()?;
        let path = self.path(name)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = match options.open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(Error::config(
                    "Unreadable journal; recover it before submitting",
                ));
            }
        };
        let info = f
            .metadata()
            .map_err(|_| Error::config("Unreadable journal; recover it before submitting"))?;
        if !info.is_file() {
            return Err(Error::config(
                "Unreadable journal; recover it before submitting",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if info.permissions().mode() & 0o077 != 0 {
                return Err(Error::config("Journal entries must be private (0600)"));
            }
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut f)
            .take(2_097_153)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::config("Unreadable journal; recover it before submitting"))?;
        if bytes.len() > 2_097_152 {
            return Err(Error::config(
                "Unreadable journal; recover it before submitting",
            ));
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Error::config("Unreadable journal; recover it before submitting"))
    }
    pub fn entries<T: DeserializeOwned>(&self) -> Result<Vec<T>> {
        self.initialize()?;
        let mut names = fs::read_dir(&self.directory)
            .map_err(|_| Error::config("Cannot list operation journal"))?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::config("Cannot list operation journal"))?;
        names.sort();
        let mut values = Vec::new();
        for name in names {
            if name.starts_with("request-") && name.ends_with(".json") {
                let stem = &name[..name.len() - 5];
                let value = self.read(stem)?.ok_or_else(|| {
                    Error::config("Unreadable journal; recover it before submitting")
                })?;
                values.push(value);
            }
        }
        Ok(values)
    }
    pub fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        require_supported_platform()?;
        let path = self.path(name)?;
        let temp = self
            .directory
            .join(format!("{name}.json.{}", uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options
                .open(&temp)
                .map_err(|_| Error::config("Cannot persist signed operation journal"))?;
            serde_json::to_writer_pretty(&mut file, value)
                .map_err(|_| Error::config("Cannot serialize operation journal"))?;
            file.write_all(b"\n")
                .and_then(|_| file.sync_all())
                .map_err(|_| Error::config("Cannot persist signed operation journal"))?;
            drop(file);
            fs::rename(&temp, &path)
                .map_err(|_| Error::config("Cannot persist signed operation journal"))?;
            sync_directory(&self.directory)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
    pub fn clear(&self, name: &str) -> Result<()> {
        require_supported_platform()?;
        match fs::remove_file(self.path(name)?) {
            Ok(()) => sync_directory(&self.directory),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::config("Cannot update operation journal")),
        }
    }
    pub fn locked<T>(&self, run: impl FnOnce() -> Result<T>) -> Result<T> {
        self.initialize()?;
        let path = self.directory.join(".lock");
        #[cfg(unix)]
        let mut builder = fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|_|Error::config("Another lifecycle operation is active, or a crashed process needs journal lock recovery"))?;
        let guard = LockGuard(path);
        let result = run();
        drop(guard);
        result
    }
}
struct LockGuard(PathBuf);
impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::config("Cannot persist operation journal directory"))
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    #[cfg(not(unix))]
    #[test]
    fn unsupported_platform_leaves_no_journal_or_lock() {
        let path = std::env::temp_dir().join(format!("allowit-platform-{}", uuid::Uuid::new_v4()));
        let journal = FileJournal::new(&path);
        assert!(
            journal
                .initialize()
                .unwrap_err()
                .message
                .contains("local POSIX filesystem")
        );
        assert!(
            journal
                .write("request-proof", &json!({"proof":"test"}))
                .is_err()
        );
        assert!(journal.read::<Value>("request-proof").is_err());
        assert!(journal.clear("request-proof").is_err());
        assert!(
            journal
                .locked::<()>(|| panic!("must not sign or submit"))
                .is_err()
        );
        assert!(!path.exists());
    }
    #[test]
    fn proof_is_durable_and_locked_before_use() {
        let path =
            std::env::temp_dir().join(format!("allowit-native-journal-{}", uuid::Uuid::new_v4()));
        let j = FileJournal::new(&path);
        j.locked(|| {
            assert!(j.locked(|| Ok(())).is_err());
            j.write(
                "request-proof-0001",
                &json!({"signedBytes":"saved","status":"uncertain"}),
            )?;
            assert_eq!(
                j.read::<Value>("request-proof-0001")?.unwrap()["status"],
                "uncertain"
            );
            Ok(())
        })
        .unwrap();
        assert_eq!(j.entries::<Value>().unwrap().len(), 1);
        assert!(j.read::<Value>("../../escape").is_err());
        j.clear("request-proof-0001").unwrap();
        assert!(j.entries::<Value>().unwrap().is_empty());
        fs::remove_dir(&path).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn refuses_open_directory_and_symlink_entry() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let path =
            std::env::temp_dir().join(format!("allowit-native-journal-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let j = FileJournal::new(&path);
        assert!(j.initialize().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        j.initialize().unwrap();
        symlink("/dev/null", path.join("request-unsafe.json")).unwrap();
        assert!(j.read::<Value>("request-unsafe").is_err());
        fs::remove_file(path.join("request-unsafe.json")).unwrap();
        fs::remove_dir(&path).unwrap();
    }
}
