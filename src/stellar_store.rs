//! Executor-wide private proof storage. The creating process owns the Store lock.
//! Callers choose one directory per executor, chain and native nonce key.
use crate::error::{Error, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::path::Path;

#[cfg(all(
    unix,
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )
))]
mod platform {
    use super::*;
    use sha2::{Digest, Sha256};
    const MAX_BYTES: usize = 2 * 1024 * 1024;
    const MAX_ENTRIES: usize = 1_000;
    use std::{
        ffi::{CStr, CString, OsStr},
        fs::{File, Metadata},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::Component,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    pub(crate) struct Store {
        directory: File,
        // Never unlink this inode: a replacement lock could admit two writers.
        lock: File,
        owner_pid: libc::pid_t,
    }

    impl Drop for Store {
        fn drop(&mut self) {
            // flock follows an open-file description through fork, so close alone
            // can leave the parent's lock held until an unrelated child execs.
            // A child dropping its inherited handle must not unlock a live parent.
            if unsafe { libc::getpid() } != self.owner_pid {
                return;
            }
            loop {
                if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) } == 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
        }
    }

    fn storage_error() -> Error {
        Error::config("Stellar proof storage is unsafe or unreadable; retain the original journal")
    }
    fn file_private(info: &Metadata) -> bool {
        info.is_file()
            && info.uid() == unsafe { libc::geteuid() }
            && info.mode() & 0o7777 == 0o600
            && info.nlink() == 1
    }
    fn directory_private(info: &Metadata) -> bool {
        info.is_dir() && info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o7777 == 0o700
    }
    fn c_name(name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| storage_error())
    }
    fn open_at(
        directory: &File,
        name: &CStr,
        flags: i32,
        // openat is variadic: Darwin's u16 mode_t must be promoted to an int.
        mode: libc::c_uint,
    ) -> std::io::Result<File> {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode,
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            // This successful open created the sole owner of this descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    fn walk_directory(path: &Path) -> Result<File> {
        if path.as_os_str().is_empty() {
            return Err(storage_error());
        }
        let base = if path.is_absolute() { c"/" } else { c"." };
        let fd = unsafe {
            libc::open(
                base.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(storage_error());
        }
        let mut directory = unsafe { File::from_raw_fd(fd) };
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => c_name(name)?,
                // Do not let a path escape through aliases or parent traversal.
                _ => return Err(storage_error()),
            };
            let flags = libc::O_RDONLY | libc::O_DIRECTORY;
            directory = match open_at(&directory, &name, flags, 0) {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let created =
                        unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
                    if created != 0
                        && std::io::Error::last_os_error().kind()
                            != std::io::ErrorKind::AlreadyExists
                    {
                        return Err(storage_error());
                    }
                    if created == 0 {
                        directory.sync_all().map_err(|_| storage_error())?;
                    }
                    open_at(&directory, &name, flags, 0).map_err(|_| storage_error())?
                }
                Err(_) => return Err(storage_error()),
            };
        }
        if !directory_private(&directory.metadata().map_err(|_| storage_error())?) {
            return Err(storage_error());
        }
        Ok(directory)
    }
    fn record_name(request_id: &str) -> Result<CString> {
        if request_id.is_empty() || request_id.len() > 100 {
            return Err(Error::config("Invalid Stellar journal request ID"));
        }
        CString::new(format!(
            "request-{:x}.json",
            Sha256::digest(request_id.as_bytes())
        ))
        .map_err(|_| storage_error())
    }
    fn is_record_name(name: &[u8]) -> bool {
        name.len() == 77
            && name.starts_with(b"request-")
            && name.ends_with(b".json")
            && name[8..72]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    }
    fn private_file(directory: &File, name: &CStr) -> Result<Option<File>> {
        let file = match open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(storage_error()),
        };
        if !file_private(&file.metadata().map_err(|_| storage_error())?) {
            return Err(storage_error());
        }
        Ok(Some(file))
    }
    fn read_value<T: DeserializeOwned>(file: File) -> Result<T> {
        let mut bytes = Vec::new();
        file.take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| storage_error())?;
        if bytes.len() > MAX_BYTES {
            return Err(storage_error());
        }
        // Deliberately discard serde details: records may contain private proofs.
        serde_json::from_slice(&bytes).map_err(|_| storage_error())
    }

    struct LimitedWriter(Vec<u8>);
    impl Write for LimitedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_BYTES - self.0.len() {
                return Err(std::io::Error::other(
                    "Bounded journal serialization failed",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    fn temporary_file(directory: &File) -> Result<(CString, File)> {
        for _ in 0..16 {
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| storage_error())?
                .as_nanos();
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(format!(
                ".tmp-{}-{time:032x}-{sequence:016x}",
                std::process::id()
            ))
            .map_err(|_| storage_error())?;
            match open_at(
                directory,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ) {
                Ok(file) => return Ok((name, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(storage_error()),
            }
        }
        Err(storage_error())
    }

    impl Store {
        pub(crate) fn open(path: &Path) -> Result<Self> {
            let directory = walk_directory(path)?;
            let lock = open_at(
                &directory,
                c".lock",
                libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
                0o600,
            )
            .map_err(|_| storage_error())?;
            if !file_private(&lock.metadata().map_err(|_| storage_error())?) {
                return Err(storage_error());
            }
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(Error::config(
                    "Another Stellar payment or recovery holds the executor journal lock",
                ));
            }
            let store = Self {
                directory,
                lock,
                owner_pid: unsafe { libc::getpid() },
            };
            // From acquisition onward, every error path drops the owner and
            // explicitly releases its lock even if another process inherited it.
            store.directory.sync_all().map_err(|_| storage_error())?;
            store.check_lock()?;
            Ok(store)
        }
        fn check_lock(&self) -> Result<()> {
            if unsafe { libc::getpid() } != self.owner_pid {
                return Err(Error::config(
                    "An inherited Stellar journal handle cannot be used by another process",
                ));
            }
            if !directory_private(&self.directory.metadata().map_err(|_| storage_error())?) {
                return Err(storage_error());
            }
            let lock = private_file(&self.directory, c".lock")?.ok_or_else(storage_error)?;
            let held = self.lock.metadata().map_err(|_| storage_error())?;
            let current = lock.metadata().map_err(|_| storage_error())?;
            if !file_private(&held) || held.dev() != current.dev() || held.ino() != current.ino() {
                return Err(storage_error());
            }
            Ok(())
        }
        pub(crate) fn load<T: DeserializeOwned>(&self, request_id: &str) -> Result<Option<T>> {
            self.check_lock()?;
            private_file(&self.directory, &record_name(request_id)?)?
                .map(read_value)
                .transpose()
        }
        pub(crate) fn save<T: Serialize>(&self, request_id: &str, value: &T) -> Result<()> {
            self.check_lock()?;
            let name = record_name(request_id)?;
            let original = private_file(&self.directory, &name)?
                .map(|file| file.metadata().map(|info| (info.dev(), info.ino())))
                .transpose()
                .map_err(|_| storage_error())?;
            let mut bytes = LimitedWriter(Vec::new());
            serde_json::to_writer(&mut bytes, value).map_err(|_| storage_error())?;
            bytes.write_all(b"\n").map_err(|_| storage_error())?;
            let (temporary, mut file) = temporary_file(&self.directory)?;
            let result = (|| {
                if !file_private(&file.metadata().map_err(|_| storage_error())?) {
                    return Err(storage_error());
                }
                file.write_all(&bytes.0)
                    .and_then(|_| file.sync_all())
                    .map_err(|_| storage_error())?;
                self.check_lock()?;
                let current = private_file(&self.directory, &name)?
                    .map(|file| file.metadata().map(|info| (info.dev(), info.ino())))
                    .transpose()
                    .map_err(|_| storage_error())?;
                if current != original {
                    return Err(storage_error());
                }
                if unsafe {
                    libc::renameat(
                        self.directory.as_raw_fd(),
                        temporary.as_ptr(),
                        self.directory.as_raw_fd(),
                        name.as_ptr(),
                    )
                } != 0
                {
                    return Err(storage_error());
                }
                self.directory.sync_all().map_err(|_| Error::uncertain(
                    "Stellar journal durability is uncertain; retain this request ID and the original proof",
                ))
            })();
            if result.is_err() {
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), temporary.as_ptr(), 0);
                }
            }
            result
        }
        pub(crate) fn entries<T: DeserializeOwned>(&self) -> Result<Vec<T>> {
            self.check_lock()?;
            let mut names = DirectoryStream::open(&self.directory)?.names()?;
            names.sort();
            let mut entries = Vec::new();
            for name in names {
                let file = private_file(&self.directory, &name)?.ok_or_else(storage_error)?;
                if name.to_bytes().starts_with(b".tmp-") {
                    // A crash before rename cannot have reached the broadcaster.
                    continue;
                }
                entries.push(read_value(file)?);
            }
            Ok(entries)
        }
    }
    struct DirectoryStream(*mut libc::DIR);
    impl DirectoryStream {
        fn open(directory: &File) -> Result<Self> {
            // dup() shares a directory offset, so openat(".") gets a fresh one.
            let fresh = open_at(directory, c".", libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .map_err(|_| storage_error())?;
            let fd = unsafe { libc::fcntl(fresh.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                return Err(storage_error());
            }
            let pointer = unsafe { libc::fdopendir(fd) };
            if pointer.is_null() {
                unsafe {
                    libc::close(fd);
                }
                return Err(storage_error());
            }
            Ok(Self(pointer))
        }
        fn names(&mut self) -> Result<Vec<CString>> {
            let mut names = Vec::new();
            loop {
                unsafe {
                    *errno_location() = 0;
                }
                let pointer = unsafe { libc::readdir(self.0) };
                if pointer.is_null() {
                    if unsafe { *errno_location() } != 0 {
                        return Err(storage_error());
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*pointer).d_name.as_ptr()) };
                if matches!(name.to_bytes(), b"." | b".." | b".lock") {
                    continue;
                }
                if names.len() == MAX_ENTRIES {
                    return Err(Error::config(
                        "Stellar journal has too many entries; retain its original proofs",
                    ));
                }
                if !is_record_name(name.to_bytes()) && !name.to_bytes().starts_with(b".tmp-") {
                    return Err(storage_error());
                }
                names.push(name.to_owned());
            }
            Ok(names)
        }
    }
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    #[cfg(target_os = "linux")]
    unsafe fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__errno_location() }
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly"
    ))]
    unsafe fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__error() }
    }
    #[cfg(any(target_os = "android", target_os = "openbsd", target_os = "netbsd"))]
    unsafe fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__errno() }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::{Value, json};
        use std::{
            fs::{self, OpenOptions},
            os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
            path::PathBuf,
        };
        struct TestDirectory(PathBuf);
        impl TestDirectory {
            fn new() -> Self {
                let stamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "allowit-stellar-store-{}-{stamp}-{sequence}",
                    std::process::id()
                ));
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                Self(path)
            }
            fn record(&self, id: &str) -> PathBuf {
                self.0.join(record_name(id).unwrap().to_str().unwrap())
            }
        }
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
        fn private_write(path: &Path, bytes: &[u8]) {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(bytes).unwrap();
        }
        #[test]
        fn durable_roundtrip_update_scan_and_reopen() {
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            assert!(store.load::<Value>("payment-1").unwrap().is_none());
            store
                .save("payment-1", &json!({"hash":"original","status":"signed"}))
                .unwrap();
            store
                .save("payment-1", &json!({"hash":"original","status":"settled"}))
                .unwrap();
            store.save("payment-2", &json!({"hash":"second"})).unwrap();
            assert_eq!(store.entries::<Value>().unwrap().len(), 2);
            assert_eq!(store.entries::<Value>().unwrap().len(), 2); // fresh directory offset
            drop(store);
            let reopened = Store::open(&directory.0).unwrap();
            assert_eq!(
                reopened.load::<Value>("payment-1").unwrap().unwrap()["status"],
                "settled"
            );
            let info = fs::metadata(directory.record("payment-1")).unwrap();
            assert!(file_private(&info));
        }
        #[test]
        fn lifetime_lock_blocks_every_request_and_releases_on_drop() {
            let directory = TestDirectory::new();
            let first = Store::open(&directory.0).unwrap();
            assert!(Store::open(&directory.0).is_err());
            first.save("vault-a", &json!({"proof":1})).unwrap();
            drop(first);
            let second = Store::open(&directory.0).unwrap();
            assert_eq!(second.entries::<Value>().unwrap().len(), 1);
        }
        #[test]
        fn inherited_process_handle_cannot_use_or_unlock_the_live_owner() {
            let directory = TestDirectory::new();
            let owner = Store::open(&directory.0).unwrap();
            // A fork has a separate process ID but shares both open-file
            // descriptions. Model that ownership boundary without a second fork.
            let inherited = Store {
                directory: owner.directory.try_clone().unwrap(),
                lock: owner.lock.try_clone().unwrap(),
                owner_pid: -1,
            };
            assert!(inherited.load::<Value>("payment-1").is_err());
            assert!(inherited.save("payment-1", &json!({"proof":1})).is_err());
            assert!(inherited.entries::<Value>().is_err());
            drop(inherited);
            assert!(
                Store::open(&directory.0).is_err(),
                "An inherited handle must not release its live owner's lock"
            );
            owner.save("payment-1", &json!({"proof":"owner"})).unwrap();
            drop(owner);
            assert!(Store::open(&directory.0).is_ok());
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn parent_drop_releases_lock_while_pre_exec_child_holds_inherited_descriptor() {
            // Keep the long-lived fork in its own test process: otherwise its
            // descriptor table would also retain unrelated tests' journal locks.
            let (_, module) = module_path!().split_once("::").unwrap();
            let test = format!("{module}::inherited_descriptor_scenario_child");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test, "--nocapture"])
                .env("ALLOWIT_STELLAR_LOCK_CHILD_SCENARIO", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn inherited_descriptor_scenario_child() {
            if std::env::var_os("ALLOWIT_STELLAR_LOCK_CHILD_SCENARIO").is_none() {
                return;
            }
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            let mut ready = [-1; 2];
            let mut release = [-1; 2];
            assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
            assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
            assert_ne!(
                unsafe { libc::fcntl(store.lock.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0,
                "The inherited lock is already CLOEXEC; the regression is the pre-exec window"
            );
            // The files own these newly-created descriptors in the parent. The
            // forked child uses raw syscalls and _exit only, never Rust teardown.
            let mut ready_read = unsafe { File::from_raw_fd(ready[0]) };
            let ready_write = unsafe { File::from_raw_fd(ready[1]) };
            let release_read = unsafe { File::from_raw_fd(release[0]) };
            let release_write = unsafe { File::from_raw_fd(release[1]) };
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                unsafe {
                    libc::close(ready[0]);
                    libc::close(release[1]);
                    let ready_byte = [1u8];
                    if libc::write(ready[1], ready_byte.as_ptr().cast(), 1) != 1 {
                        libc::_exit(1);
                    }
                    let mut release_byte = [0u8];
                    loop {
                        let result = libc::read(release[0], release_byte.as_mut_ptr().cast(), 1);
                        if result >= 0 {
                            break;
                        }
                        if *libc::__errno_location() != libc::EINTR {
                            libc::_exit(1);
                        }
                    }
                    libc::_exit(0);
                }
            }
            struct WaitingChild {
                pid: libc::pid_t,
                release: File,
            }
            impl Drop for WaitingChild {
                fn drop(&mut self) {
                    let _ = self.release.write_all(&[1]);
                    loop {
                        let result = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
                        if result >= 0
                            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                        {
                            break;
                        }
                    }
                }
            }
            let child = WaitingChild {
                pid,
                release: release_write,
            };
            drop(ready_write);
            drop(release_read);
            let mut acknowledgement = [0u8];
            ready_read.read_exact(&mut acknowledgement).unwrap();
            assert_eq!(acknowledgement, [1]);
            assert!(
                Store::open(&directory.0).is_err(),
                "A live Store must keep exclusive ownership"
            );
            drop(store);
            let reopened = Store::open(&directory.0).expect(
                "Parent drop must release its lock before the inherited descriptor reaches exec",
            );
            assert!(Store::open(&directory.0).is_err());
            drop(child);
            // Closing the child's old descriptor cannot unlock a newly acquired
            // independent open-file description owned by this live Store.
            assert!(Store::open(&directory.0).is_err());
            drop(reopened);
            assert!(Store::open(&directory.0).is_ok());
        }
        #[test]
        fn hashed_identifiers_do_not_become_paths() {
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            store.save("../../outside", &json!(1)).unwrap();
            assert_eq!(
                store.load::<Value>("../../outside").unwrap(),
                Some(json!(1))
            );
            assert!(directory.record("../../outside").exists());
            assert!(store.load::<Value>("").is_err());
            assert!(store.load::<Value>(&"a".repeat(101)).is_err());
        }
        #[test]
        fn private_directory_and_file_permissions_are_required() {
            let directory = TestDirectory::new();
            fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o750)).unwrap();
            assert!(Store::open(&directory.0).is_err());
            fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
            let store = Store::open(&directory.0).unwrap();
            store.save("payment-1", &json!(1)).unwrap();
            fs::set_permissions(
                directory.record("payment-1"),
                fs::Permissions::from_mode(0o604),
            )
            .unwrap();
            assert!(store.load::<Value>("payment-1").is_err());
            assert!(store.save("payment-1", &json!(2)).is_err());
            assert!(store.entries::<Value>().is_err());
        }
        #[test]
        fn symlinked_directory_components_and_records_are_refused() {
            let directory = TestDirectory::new();
            let target = directory.0.join("real");
            fs::create_dir(&target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
            symlink(&target, directory.0.join("alias")).unwrap();
            assert!(Store::open(&directory.0.join("alias")).is_err());
            assert!(Store::open(&directory.0.join("alias/child")).is_err());
            let store = Store::open(&directory.0).unwrap();
            let outside = directory.0.join("outside");
            private_write(&outside, b"1");
            symlink(&outside, directory.record("payment-1")).unwrap();
            assert!(store.load::<Value>("payment-1").is_err());
            assert!(store.save("payment-1", &json!(2)).is_err());
            assert_eq!(fs::read(outside).unwrap(), b"1");
        }
        #[test]
        fn hard_linked_records_and_lock_are_refused() {
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            store.save("payment-1", &json!(1)).unwrap();
            fs::hard_link(directory.record("payment-1"), directory.0.join("alias")).unwrap();
            assert!(store.load::<Value>("payment-1").is_err());
            assert!(store.save("payment-1", &json!(2)).is_err());
            drop(store);
            fs::hard_link(directory.0.join(".lock"), directory.0.join("lock-alias")).unwrap();
            assert!(Store::open(&directory.0).is_err());
        }
        #[test]
        fn replaced_lock_is_detected_before_storage_use() {
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            fs::remove_file(directory.0.join(".lock")).unwrap();
            private_write(&directory.0.join(".lock"), b"");
            assert!(store.load::<Value>("payment-1").is_err());
            assert!(store.save("payment-1", &json!(1)).is_err());
            assert!(store.entries::<Value>().is_err());
        }
        #[test]
        fn corrupt_and_oversized_proofs_fail_closed_without_echoing_contents() {
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            private_write(&directory.record("payment-1"), b"private-proof-not-json");
            let error = store.load::<Value>("payment-1").unwrap_err();
            assert!(!error.message.contains("private-proof"));
            assert!(store.entries::<Value>().is_err());
            fs::remove_file(directory.record("payment-1")).unwrap();
            private_write(&directory.record("payment-1"), &vec![b' '; MAX_BYTES + 1]);
            assert!(store.load::<Value>("payment-1").is_err());
        }
        #[test]
        fn bounded_serialization_preserves_the_previous_proof() {
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            store
                .save("payment-1", &json!({"hash":"original"}))
                .unwrap();
            assert!(store.save("payment-1", &"x".repeat(MAX_BYTES)).is_err());
            assert_eq!(
                store.load::<Value>("payment-1").unwrap().unwrap()["hash"],
                "original"
            );
        }
        #[test]
        fn entry_scan_is_bounded_and_crashed_temporary_files_are_not_proofs() {
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            private_write(
                &directory.0.join(".tmp-crashed"),
                b"private incomplete data",
            );
            assert!(store.entries::<Value>().unwrap().is_empty());
            fs::remove_file(directory.0.join(".tmp-crashed")).unwrap();
            for index in 0..=MAX_ENTRIES {
                private_write(&directory.record(&format!("request-{index}")), b"1");
            }
            assert!(store.entries::<Value>().is_err());
        }
        #[test]
        fn unexpected_entry_names_cannot_hide_unresolved_proofs() {
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            private_write(&directory.0.join("request-invalid.json"), b"1");
            assert!(store.entries::<Value>().is_err());
        }
    }
}

#[cfg(not(all(
    unix,
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )
)))]
mod platform {
    use super::*;
    pub(crate) struct Store;
    fn unsupported() -> Error {
        Error::unsupported(
            "Stellar proof journals require a supported local POSIX filesystem; on Windows use WSL Linux storage, not /mnt/c or /mnt/d",
        )
    }
    impl Store {
        pub(crate) fn open(_: &Path) -> Result<Self> {
            Err(unsupported())
        }
        pub(crate) fn load<T: DeserializeOwned>(&self, _: &str) -> Result<Option<T>> {
            Err(unsupported())
        }
        pub(crate) fn save<T: Serialize>(&self, _: &str, _: &T) -> Result<()> {
            Err(unsupported())
        }
        pub(crate) fn entries<T: DeserializeOwned>(&self) -> Result<Vec<T>> {
            Err(unsupported())
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn unsupported_platform_creates_no_directory() {
            let directory = std::env::temp_dir().join(format!(
                "allowit-stellar-unsupported-{}",
                std::process::id()
            ));
            assert!(!directory.exists());
            assert!(Store::open(&directory).is_err());
            assert!(!directory.exists());
        }
    }
}
pub(crate) use platform::Store;
