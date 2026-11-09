pub mod migrate;
pub mod registry;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use rust_i18n::t;
use proto::{ACCOUNT_FILE, Account, DeviceId, EncryptedRecord, RECORDS_DIR, RecordId};

const DEVICE_FILE: &str = "device";

const TEMP_SUFFIX: &str = ".tmp";

pub struct VaultStore {
    root: PathBuf,
}

impl VaultStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn default_root() -> Option<PathBuf> {
        let base = if cfg!(windows) {
            std::env::var_os("APPDATA").map(PathBuf::from)
        } else {
            std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .or_else(|| home().map(|home| home.join(".local").join("share")))
        };
        Some(base.or_else(home)?.join("cratty").join("vault"))
    }

    pub fn default_base() -> Option<PathBuf> {
        Self::default_root().and_then(|root| root.parent().map(Path::to_path_buf))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn account_path(&self) -> PathBuf {
        self.root.join(ACCOUNT_FILE)
    }

    fn records_dir(&self) -> PathBuf {
        self.root.join(RECORDS_DIR)
    }

    fn record_path(&self, id: &RecordId) -> PathBuf {
        self.records_dir().join(id.as_str())
    }

    pub fn exists(&self) -> bool {
        self.account_path().is_file()
    }

    pub fn read_account(&self) -> Result<Account> {
        let path = self.account_path();
        let bytes = fs::read(&path).with_context(|| t!("store.read_failed", path = path.display()).into_owned())?;
        Account::decode(&bytes)
            .map_err(|error| anyhow!("{}", t!("store.vault_file_corrupted", path = path.display(), error = error)))
    }

    pub fn write_account(&self, account: &Account) -> Result<()> {
        self.prepare_dirs()?;
        write_atomic(&self.account_path(), &account.encode())
    }

    pub fn read_records(&self) -> Result<(Vec<EncryptedRecord>, Vec<String>)> {
        let dir = self.records_dir();
        if !dir.is_dir() {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut records = Vec::new();
        let mut broken = Vec::new();

        let entries = fs::read_dir(&dir)
            .with_context(|| t!("store.read_dir_failed", path = dir.display()).into_owned())?;
        for entry in entries {
            let entry = entry.with_context(|| t!("store.traverse_failed", path = dir.display()).into_owned())?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();

            if name.ends_with(TEMP_SUFFIX) || !path.is_file() {
                continue;
            }

            match fs::read(&path)
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    EncryptedRecord::decode(&bytes).map_err(|error| error.to_string())
                }) {
                Ok(record) if record.id.as_str() == name => records.push(record),
                Ok(_) => broken.push(t!("store.record_name_mismatch", name = name).into_owned()),
                Err(error) => broken.push(format!("{name}: {error}")),
            }
        }

        records.sort_by(|left, right| left.id.cmp(&right.id));
        broken.sort();
        Ok((records, broken))
    }

    pub fn write_record(&self, record: &EncryptedRecord) -> Result<()> {
        self.prepare_dirs()?;
        write_atomic(&self.record_path(&record.id), &record.encode())
    }

    pub fn device_id(&self) -> Result<DeviceId> {
        let path = self.root.join(DEVICE_FILE);
        if let Ok(text) = fs::read_to_string(&path)
            && let Ok(id) = DeviceId::parse(text.trim())
        {
            return Ok(id);
        }

        let id = DeviceId::generate().map_err(|error| anyhow!("{error}"))?;
        self.prepare_dirs()?;
        write_atomic(&path, id.as_str().as_bytes())?;
        Ok(id)
    }

    fn prepare_dirs(&self) -> Result<()> {
        for dir in [self.root.clone(), self.records_dir()] {
            fs::create_dir_all(&dir).with_context(|| t!("store.create_failed", path = dir.display()).into_owned())?;
            restrict_to_owner(&dir)?;
        }
        Ok(())
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!(
        "{}{TEMP_SUFFIX}",
        path.extension().and_then(|ext| ext.to_str()).unwrap_or("")
    ));

    {
        let mut file =
            fs::File::create(&temp).with_context(|| t!("store.create_failed", path = temp.display()).into_owned())?;
        restrict_to_owner(&temp)?;
        file.write_all(bytes)
            .with_context(|| t!("store.write_failed", path = temp.display()).into_owned())?;
        file.sync_all()
            .with_context(|| t!("store.flush_failed", path = temp.display()).into_owned())?;
    }

    fs::rename(&temp, path)
        .with_context(|| t!("store.replace_failed", path = path.display(), temp = temp.display()).into_owned())
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        fs::metadata(path).with_context(|| t!("store.read_perms_failed", path = path.display()).into_owned())?;
    let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| t!("store.set_perms_failed", path = path.display()).into_owned())
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> Result<()> {
    Ok(())
}

fn home() -> Option<PathBuf> {
    #[allow(deprecated)]
    std::env::home_dir()
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub fn remove_vault(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    if !root.join(ACCOUNT_FILE).is_file() && root.read_dir()?.next().is_some() {
        bail!("{}", t!("store.refuse_delete", path = root.display()));
    }
    fs::remove_dir_all(root).with_context(|| t!("store.remove_failed", path = root.display()).into_owned())
}

/// Moves the vault directory into `target`. An empty `target` is taken over entirely;
/// in a non-empty one a subdirectory with the same name is created. Returns the new path.
/// Across file systems: copy, verify, and only then delete the old one.
pub fn move_vault(from: &Path, target: &Path) -> Result<PathBuf> {
    if !from.join(ACCOUNT_FILE).is_file() {
        bail!("{}", t!("store.not_vault_dir", path = from.display()));
    }
    let empty = target.is_dir() && target.read_dir()?.next().is_none();
    let dest = if empty || !target.exists() {
        target.to_path_buf()
    } else {
        let name = from
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("{}", t!("store.no_dir_name", path = from.display())))?;
        target.join(name)
    };

    let from_real = fs::canonicalize(from)?;
    let dest_parent = dest.parent().unwrap_or(&dest);
    fs::create_dir_all(dest_parent)
        .with_context(|| t!("store.create_failed", path = dest_parent.display()).into_owned())?;
    let dest_real = fs::canonicalize(dest_parent)?.join(dest.file_name().unwrap_or_default());
    if dest_real == from_real {
        bail!("{}", t!("store.already_there", path = dest.display()));
    }
    if dest_real.starts_with(&from_real) {
        bail!("{}", t!("store.move_into_self"));
    }
    if dest.exists() && dest.read_dir()?.next().is_some() {
        bail!("{}", t!("store.not_empty", path = dest.display()));
    }
    if dest.exists() {
        fs::remove_dir(&dest).with_context(|| t!("store.take_over_failed", path = dest.display()).into_owned())?;
    }

    if fs::rename(from, &dest).is_ok() {
        return Ok(dest);
    }

    // Different file system: copy, verify, and only then delete.
    if let Err(error) = copy_dir(from, &dest).and_then(|()| same_tree(from, &dest)) {
        let _ = fs::remove_dir_all(&dest);
        return Err(error.context(t!("store.move_failed", path = dest.display()).into_owned()));
    }
    fs::remove_dir_all(from).with_context(|| {
        t!(
            "store.old_dir_remains",
            dest = dest.display(),
            from = from.display()
        )
        .into_owned()
    })?;
    Ok(dest)
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to).with_context(|| t!("store.create_failed", path = to.display()).into_owned())?;
    restrict_to_owner(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&path, &dest)?;
        } else {
            fs::copy(&path, &dest).with_context(|| t!("store.copy_failed", path = path.display()).into_owned())?;
            restrict_to_owner(&dest)?;
        }
    }
    Ok(())
}

fn same_tree(left: &Path, right: &Path) -> Result<()> {
    for entry in fs::read_dir(left)? {
        let entry = entry?;
        let theirs = right.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            same_tree(&entry.path(), &theirs)?;
        } else if fs::read(entry.path())? != fs::read(&theirs).unwrap_or_default() {
            bail!("{}", t!("store.copy_mismatch", path = theirs.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::{HostRecord, Record, RecordBody};
    use vault::{Argon2idParams, DataKey, SlotSet, WrapSlot};

    fn temp_root(name: &str) -> PathBuf {
        let unique = DeviceId::generate().expect("CSPRNG");
        let path = std::env::temp_dir().join(format!("cratty-test-{name}-{unique}"));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn fake_vault(name: &str) -> PathBuf {
        let root = temp_root(name);
        fs::create_dir_all(root.join(RECORDS_DIR)).expect("directory");
        fs::write(root.join(ACCOUNT_FILE), b"account").expect("account");
        fs::write(root.join(RECORDS_DIR).join("r1"), b"record").expect("write");
        root
    }

    #[test]
    fn migration_into_empty_and_non_empty_directory() {
        let vault = fake_vault("move-src");
        let empty = temp_root("move-empty");
        fs::create_dir_all(&empty).expect("directory");

        let moved = move_vault(&vault, &empty).expect("move into empty");
        assert_eq!(moved, empty);
        assert!(!vault.exists(), "old directory is still there");
        assert_eq!(
            fs::read(moved.join(RECORDS_DIR).join("r1")).expect("write"),
            b"record"
        );

        let busy = temp_root("move-busy");
        fs::create_dir_all(&busy).expect("directory");
        fs::write(busy.join("other"), b"x").expect("file");
        let again = move_vault(&moved, &busy).expect("move into non-empty");
        assert_eq!(again, busy.join(moved.file_name().expect("name")));
        assert!(again.join(ACCOUNT_FILE).is_file());
        assert!(busy.join("other").is_file(), "foreign file was touched");

        let _ = fs::remove_dir_all(&busy);
        let _ = fs::remove_dir_all(&empty);
    }

    #[test]
    fn migration_refuses_in_dangerous_cases() {
        let vault = fake_vault("move-guard");
        assert!(
            move_vault(&vault, &vault.join("inside")).is_err(),
            "into itself"
        );
        assert!(move_vault(&vault, &vault).is_err(), "onto the same place");

        let not_vault = temp_root("move-not-vault");
        fs::create_dir_all(&not_vault).expect("directory");
        assert!(move_vault(&not_vault, &temp_root("move-dest")).is_err());

        assert!(vault.join(ACCOUNT_FILE).is_file(), "vault was damaged");
        let _ = fs::remove_dir_all(&vault);
        let _ = fs::remove_dir_all(&not_vault);
    }

    #[test]
    fn cross_fs_copy_is_verified() {
        let vault = fake_vault("copy-src");
        let dest = temp_root("copy-dest");
        copy_dir(&vault, &dest).expect("copy");
        same_tree(&vault, &dest).expect("verify");
        fs::write(dest.join(RECORDS_DIR).join("r1"), b"other").expect("corrupt");
        assert!(same_tree(&vault, &dest).is_err(), "copy corruption went unnoticed");
        let _ = fs::remove_dir_all(&vault);
        let _ = fs::remove_dir_all(&dest);
    }

    fn account() -> (Account, DataKey) {
        let data_key = DataKey::generate().expect("CSPRNG");
        let params = Argon2idParams::new(1024, 1, 1, [0x61; vault::SALT_LEN]).expect("params");
        let (slot, _) =
            WrapSlot::from_password(&data_key, "password".as_bytes(), params, "master password")
                .expect("wrap");
        let mut slots = SlotSet::new();
        slots.push(slot);
        (
            Account::new(
                proto::VaultId::generate().expect("CSPRNG"),
                slots,
                Vec::new(),
            ),
            data_key,
        )
    }

    fn record(
        data_key: &DataKey,
        account: &Account,
        device: &DeviceId,
        host: &str,
    ) -> EncryptedRecord {
        Record::new(
            RecordId::generate().expect("CSPRNG"),
            device.clone(),
            now_ms(),
            RecordBody::Host(HostRecord::new(host)),
        )
        .seal(
            &data_key.record_key().expect("subkey"),
            &account.vault_id,
            account.key_gen,
        )
        .expect("encrypt")
    }

    #[test]
    fn empty_directory_is_not_an_error() {
        let root = temp_root("empty");
        let store = VaultStore::new(root.clone());
        assert!(!store.exists());
        let (records, broken) = store.read_records().expect("read");
        assert!(records.is_empty() && broken.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn account_and_records_survive_restart() {
        let root = temp_root("roundtrip");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");

        store.write_account(&account).expect("write account");
        let first = record(&data_key, &account, &device, "prod-01.example.com");
        let second = record(&data_key, &account, &device, "prod-02.example.com");
        store.write_record(&first).expect("write");
        store.write_record(&second).expect("write");

        let store = VaultStore::new(root.clone());
        assert!(store.exists());
        assert_eq!(store.read_account().expect("account"), account);

        let (records, broken) = store.read_records().expect("read");
        assert!(broken.is_empty());
        assert_eq!(records.len(), 2);

        let key = data_key.record_key().expect("subkey");
        let mut hosts: Vec<String> = records
            .iter()
            .map(|record| {
                record
                    .open(&key, &account.vault_id)
                    .expect("decrypt")
                    .body
                    .as_host()
                    .expect("host")
                    .host
                    .clone()
            })
            .collect();
        hosts.sort();
        assert_eq!(hosts, ["prod-01.example.com", "prod-02.example.com"]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn device_id_is_the_same_between_runs() {
        let root = temp_root("device");
        let first = VaultStore::new(root.clone())
            .device_id()
            .expect("device_id");
        let second = VaultStore::new(root.clone())
            .device_id()
            .expect("device_id");
        assert_eq!(first, second);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn new_revision_replaces_record_file() {
        let root = temp_root("rev");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");
        store.write_account(&account).expect("write account");

        let key = data_key.record_key().expect("subkey");
        let first = record(&data_key, &account, &device, "example.com");
        store.write_record(&first).expect("write");

        let opened = first.open(&key, &account.vault_id).expect("read");
        let updated = opened.next_rev(
            device,
            now_ms() + 1,
            RecordBody::Host(HostRecord::new("example.org")),
        );
        store
            .write_record(
                &updated
                    .seal(&key, &account.vault_id, account.key_gen)
                    .expect("encrypt"),
            )
            .expect("write");

        let (records, _) = store.read_records().expect("read");
        assert_eq!(
            records.len(),
            1,
            "a revision must replace the file, not add one"
        );
        assert_eq!(records[0].rev, 2);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupted_record_does_not_lose_the_others() {
        let root = temp_root("broken");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");
        store.write_account(&account).expect("write account");
        store
            .write_record(&record(&data_key, &account, &device, "example.com"))
            .expect("write");

        let garbage = RecordId::generate().expect("CSPRNG");
        fs::write(store.record_path(&garbage), "not a record at all".as_bytes())
            .expect("write garbage");

        let (records, broken) = store.read_records().expect("read");
        assert_eq!(records.len(), 1);
        assert_eq!(broken.len(), 1, "a broken file must be reported");
        assert!(broken[0].starts_with(garbage.as_str()));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn file_name_must_match_the_record() {
        let root = temp_root("rename");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");
        store.write_account(&account).expect("write account");

        let record = record(&data_key, &account, &device, "example.com");
        let alien = RecordId::generate().expect("CSPRNG");
        fs::create_dir_all(store.records_dir()).expect("directory");
        fs::write(store.record_path(&alien), record.encode()).expect("write");

        let (records, broken) = store.read_records().expect("read");
        assert!(records.is_empty());
        assert_eq!(broken.len(), 1);
        assert!(broken[0].contains("file name does not match"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn temporary_files_are_ignored() {
        let root = temp_root("temp");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");
        store.write_account(&account).expect("write account");
        store
            .write_record(&record(&data_key, &account, &device, "example.com"))
            .expect("write");

        fs::write(
            store.records_dir().join(format!("leftover{TEMP_SUFFIX}")),
            "fragment".as_bytes(),
        )
        .expect("write");

        let (records, broken) = store.read_records().expect("read");
        assert_eq!(records.len(), 1);
        assert!(broken.is_empty(), "a temp file is not corruption");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupted_account_gives_a_clear_error() {
        let root = temp_root("bad-account");
        let store = VaultStore::new(root.clone());
        let (account, _) = account();
        store.write_account(&account).expect("write");

        let mut bytes = fs::read(store.account_path()).expect("read");
        bytes.truncate(bytes.len() / 2);
        fs::write(store.account_path(), bytes).expect("corrupt");

        let error = store.read_account().expect_err("should fail").to_string();
        assert!(error.contains("corrupted"), "unclear error: {error}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn write_leaves_no_garbage() {
        let root = temp_root("atomic");
        let store = VaultStore::new(root.clone());
        let (account, _) = account();
        store.write_account(&account).expect("write");
        store.write_account(&account).expect("overwrite");

        let leftovers: Vec<_> = fs::read_dir(&root)
            .expect("directory")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(TEMP_SUFFIX))
            .collect();
        assert!(
            leftovers.is_empty(),
            "leftover temp files: {leftovers:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn permissions_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("perms");
        let store = VaultStore::new(root.clone());
        let (account, _) = account();
        store.write_account(&account).expect("write");

        let mode = fs::metadata(store.account_path())
            .expect("permissions")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "account file is open to more than the owner");

        let mode = fs::metadata(&root).expect("permissions").permissions().mode();
        assert_eq!(mode & 0o077, 0, "directory is open to more than the owner");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_vault_does_not_touch_foreign_directory() {
        let root = temp_root("not-a-vault");
        fs::create_dir_all(&root).expect("directory");
        fs::write(root.join("important.txt"), "someone else's data".as_bytes()).expect("file");

        assert!(remove_vault(&root).is_err());
        assert!(root.join("important.txt").exists());

        let _ = fs::remove_dir_all(&root);
    }
}
