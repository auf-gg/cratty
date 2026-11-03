pub mod migrate;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
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
        let bytes = fs::read(&path).with_context(|| format!("не прочитать {}", path.display()))?;
        Account::decode(&bytes)
            .map_err(|error| anyhow!("файл хранилища {} повреждён: {error}", path.display()))
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
            .with_context(|| format!("не прочитать каталог {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("не обойти {}", dir.display()))?;
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
                Ok(_) => broken.push(format!("{name}: имя файла не совпадает с записью")),
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
            fs::create_dir_all(&dir).with_context(|| format!("не создать {}", dir.display()))?;
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
            fs::File::create(&temp).with_context(|| format!("не создать {}", temp.display()))?;
        restrict_to_owner(&temp)?;
        file.write_all(bytes)
            .with_context(|| format!("не записать {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("не сбросить на диск {}", temp.display()))?;
    }

    fs::rename(&temp, path)
        .with_context(|| format!("не заменить {} на {}", path.display(), temp.display()))
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        fs::metadata(path).with_context(|| format!("не прочитать права {}", path.display()))?;
    let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("не выставить права {}", path.display()))
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
        bail!(
            "{} не похож на каталог хранилища — удалять его не буду",
            root.display()
        );
    }
    fs::remove_dir_all(root).with_context(|| format!("не удалить {}", root.display()))
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

    fn account() -> (Account, DataKey) {
        let data_key = DataKey::generate().expect("CSPRNG");
        let params = Argon2idParams::new(1024, 1, 1, [0x61; vault::SALT_LEN]).expect("параметры");
        let (slot, _) =
            WrapSlot::from_password(&data_key, "пароль".as_bytes(), params, "мастер-пароль")
                .expect("обёртка");
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
            &data_key.record_key().expect("подключ"),
            &account.vault_id,
            account.key_gen,
        )
        .expect("шифрование")
    }

    #[test]
    fn pustoy_katalog_eto_ne_oshibka() {
        let root = temp_root("empty");
        let store = VaultStore::new(root.clone());
        assert!(!store.exists());
        let (records, broken) = store.read_records().expect("чтение");
        assert!(records.is_empty() && broken.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn akkaunt_i_zapisi_perezhivayut_perezapusk() {
        let root = temp_root("roundtrip");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");

        store.write_account(&account).expect("запись аккаунта");
        let first = record(&data_key, &account, &device, "prod-01.example.com");
        let second = record(&data_key, &account, &device, "prod-02.example.com");
        store.write_record(&first).expect("запись");
        store.write_record(&second).expect("запись");

        let store = VaultStore::new(root.clone());
        assert!(store.exists());
        assert_eq!(store.read_account().expect("аккаунт"), account);

        let (records, broken) = store.read_records().expect("чтение");
        assert!(broken.is_empty());
        assert_eq!(records.len(), 2);

        let key = data_key.record_key().expect("подключ");
        let mut hosts: Vec<String> = records
            .iter()
            .map(|record| {
                record
                    .open(&key, &account.vault_id)
                    .expect("расшифровка")
                    .body
                    .as_host()
                    .expect("хост")
                    .host
                    .clone()
            })
            .collect();
        hosts.sort();
        assert_eq!(hosts, ["prod-01.example.com", "prod-02.example.com"]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn device_id_odin_i_tot_zhe_mezhdu_zapuskami() {
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
    fn novaya_reviziya_zamenyaet_fayl_zapisi() {
        let root = temp_root("rev");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");
        store.write_account(&account).expect("запись аккаунта");

        let key = data_key.record_key().expect("подключ");
        let first = record(&data_key, &account, &device, "example.com");
        store.write_record(&first).expect("запись");

        let opened = first.open(&key, &account.vault_id).expect("чтение");
        let updated = opened.next_rev(
            device,
            now_ms() + 1,
            RecordBody::Host(HostRecord::new("example.org")),
        );
        store
            .write_record(
                &updated
                    .seal(&key, &account.vault_id, account.key_gen)
                    .expect("шифрование"),
            )
            .expect("запись");

        let (records, _) = store.read_records().expect("чтение");
        assert_eq!(
            records.len(),
            1,
            "ревизия обязана заменить файл, а не добавить"
        );
        assert_eq!(records[0].rev, 2);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bitaya_zapis_ne_teryaet_ostalnye() {
        let root = temp_root("broken");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");
        store.write_account(&account).expect("запись аккаунта");
        store
            .write_record(&record(&data_key, &account, &device, "example.com"))
            .expect("запись");

        let garbage = RecordId::generate().expect("CSPRNG");
        fs::write(store.record_path(&garbage), "не запись вовсе".as_bytes())
            .expect("запись мусора");

        let (records, broken) = store.read_records().expect("чтение");
        assert_eq!(records.len(), 1);
        assert_eq!(broken.len(), 1, "про битый файл обязаны сказать");
        assert!(broken[0].starts_with(garbage.as_str()));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn imya_fayla_obyazano_sovpadat_s_zapisyu() {
        let root = temp_root("rename");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");
        store.write_account(&account).expect("запись аккаунта");

        let record = record(&data_key, &account, &device, "example.com");
        let alien = RecordId::generate().expect("CSPRNG");
        fs::create_dir_all(store.records_dir()).expect("каталог");
        fs::write(store.record_path(&alien), record.encode()).expect("запись");

        let (records, broken) = store.read_records().expect("чтение");
        assert!(records.is_empty());
        assert_eq!(broken.len(), 1);
        assert!(broken[0].contains("имя файла не совпадает"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn vremennye_fayly_ignoriruyutsya() {
        let root = temp_root("temp");
        let store = VaultStore::new(root.clone());
        let (account, data_key) = account();
        let device = store.device_id().expect("device_id");
        store.write_account(&account).expect("запись аккаунта");
        store
            .write_record(&record(&data_key, &account, &device, "example.com"))
            .expect("запись");

        fs::write(
            store.records_dir().join(format!("leftover{TEMP_SUFFIX}")),
            "обрывок".as_bytes(),
        )
        .expect("запись");

        let (records, broken) = store.read_records().expect("чтение");
        assert_eq!(records.len(), 1);
        assert!(broken.is_empty(), "временный файл — не повреждение");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn isporchennyy_akkaunt_daet_ponyatnuyu_oshibku() {
        let root = temp_root("bad-account");
        let store = VaultStore::new(root.clone());
        let (account, _) = account();
        store.write_account(&account).expect("запись");

        let mut bytes = fs::read(store.account_path()).expect("чтение");
        bytes.truncate(bytes.len() / 2);
        fs::write(store.account_path(), bytes).expect("порча");

        let error = store.read_account().expect_err("должно упасть").to_string();
        assert!(error.contains("повреждён"), "невнятная ошибка: {error}");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn zapis_ne_ostavlyaet_musora() {
        let root = temp_root("atomic");
        let store = VaultStore::new(root.clone());
        let (account, _) = account();
        store.write_account(&account).expect("запись");
        store.write_account(&account).expect("перезапись");

        let leftovers: Vec<_> = fs::read_dir(&root)
            .expect("каталог")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(TEMP_SUFFIX))
            .collect();
        assert!(
            leftovers.is_empty(),
            "остались временные файлы: {leftovers:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn prava_tolko_vladeltsu() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("perms");
        let store = VaultStore::new(root.clone());
        let (account, _) = account();
        store.write_account(&account).expect("запись");

        let mode = fs::metadata(store.account_path())
            .expect("права")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "файл аккаунта открыт не только владельцу");

        let mode = fs::metadata(&root).expect("права").permissions().mode();
        assert_eq!(mode & 0o077, 0, "каталог открыт не только владельцу");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_vault_ne_trogaet_chuzhoy_katalog() {
        let root = temp_root("not-a-vault");
        fs::create_dir_all(&root).expect("каталог");
        fs::write(root.join("важное.txt"), "чужие данные".as_bytes()).expect("файл");

        assert!(remove_vault(&root).is_err());
        assert!(root.join("важное.txt").exists());

        let _ = fs::remove_dir_all(&root);
    }
}
