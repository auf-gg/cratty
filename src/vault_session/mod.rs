pub mod autolock;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use proto::{
    Account, DeviceId, HostRecord, KeyRecord, ProxyRecord, Record, RecordBody, RecordId, VaultId,
};
use vault::{
    Argon2idParams, DataKey, Key32, RecordKey, RecoveryCode, SLOT_ID_LEN, SlotKind, SlotSet,
    WrapSlot,
};

use crate::keychain::KeyStash;
use crate::store::{VaultStore, migrate, now_ms};
use autolock::{AutoLock, Verdict};

const PASSWORD_SLOT_LABEL: &str = "мастер-пароль";
const RECOVERY_SLOT_LABEL: &str = "код восстановления";
const OS_KEY_SLOT_LABEL: &str = "ключ этого компьютера";

pub enum VaultState {
    Absent,
    Broken {
        reason: String,
    },
    Locked {
        account: Box<Account>,
        notice: Option<String>,
    },
    Unlocked(Box<Unlocked>),
}

impl VaultState {
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked(_))
    }

    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn broken_reason(&self) -> Option<&str> {
        match self {
            Self::Broken { reason } => Some(reason),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    rev: u64,
    updated_ms: u64,
    device_id: DeviceId,
    device_only: bool,
    body: RecordBody,
}

impl Entry {
    fn from_record(record: &Record) -> Self {
        Self {
            rev: record.rev,
            updated_ms: record.updated_ms,
            device_id: record.device_id.clone(),
            device_only: record.device_only,
            body: record.body.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEntry {
    pub id: RecordId,
    pub host: HostRecord,
    pub updated_ms: u64,
    pub device_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredKey {
    pub id: RecordId,
    pub key: KeyRecord,
    pub updated_ms: u64,
    pub device_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyEntry {
    pub id: RecordId,
    pub proxy: ProxyRecord,
    pub updated_ms: u64,
    pub device_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnippetEntry {
    pub id: RecordId,
    pub snippet: proto::SnippetRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViaItem {
    Proxy(ProxyRecord),
    Host(HostRecord),
}

impl From<ProxyRecord> for ViaItem {
    fn from(proxy: ProxyRecord) -> Self {
        Self::Proxy(proxy)
    }
}

impl ViaItem {
    pub fn title(&self) -> String {
        match self {
            Self::Proxy(proxy) => proxy.title(),
            Self::Host(host) => host.title(),
        }
    }
}

pub(crate) fn resolve_via_in(
    via: &[RecordId],
    find: impl Fn(&RecordId) -> Option<ViaItem>,
) -> std::result::Result<Vec<ViaItem>, String> {
    via.iter()
        .enumerate()
        .map(|(index, id)| {
            let item = find(id).ok_or_else(|| {
                format!(
                    "звена №{} из цепочки нет в хранилище — его удалили или оно ещё \
                     не приехало синхронизацией. Подключение без него не выполняется",
                    index + 1
                )
            })?;
            if let ViaItem::Proxy(proxy) = &item
                && !proxy.is_usable()
            {
                return Err(format!(
                    "прокси «{}» из цепочки не годится к подключению: {}",
                    proxy.title(),
                    if proxy.kind == proto::ProxyKind::Unsupported {
                        "его вид не знаком этой версии приложения"
                    } else {
                        "не указан адрес или порт"
                    }
                ));
            }
            Ok(item)
        })
        .collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub applied: usize,
    pub kept: usize,
    pub stale: usize,
    pub broken: Vec<String>,
}

impl MergeReport {
    pub fn is_empty(&self) -> bool {
        self.applied == 0 && self.broken.is_empty()
    }
}

pub(crate) struct RecordSet {
    record_key: RecordKey,
    vault_id: VaultId,
    key_gen: u32,
    device_id: DeviceId,
    entries: BTreeMap<RecordId, Entry>,
}

impl RecordSet {
    pub(crate) fn open(
        store: &VaultStore,
        record_key: RecordKey,
        vault_id: VaultId,
        key_gen: u32,
        device_id: DeviceId,
    ) -> Result<(Self, Vec<String>)> {
        let (stored, mut broken) = store.read_records()?;

        let mut entries = BTreeMap::new();
        for sealed in stored {
            if sealed.key_gen != key_gen {
                continue;
            }
            match sealed.open(&record_key, &vault_id) {
                Ok(record) => {
                    entries.insert(record.id.clone(), Entry::from_record(&record));
                }
                Err(error) => broken.push(format!("{}: {error}", sealed.id)),
            }
        }

        Ok((
            Self {
                record_key,
                vault_id,
                key_gen,
                device_id,
                entries,
            },
            broken,
        ))
    }

    fn hosts(&self) -> Vec<HostEntry> {
        let mut hosts: Vec<HostEntry> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                entry.body.as_host().map(|host| HostEntry {
                    id: id.clone(),
                    host: host.clone(),
                    updated_ms: entry.updated_ms,
                    device_only: entry.device_only,
                })
            })
            .filter(|entry| entry.host.is_usable())
            .collect();

        hosts.sort_by(|left, right| {
            right
                .updated_ms
                .cmp(&left.updated_ms)
                .then(left.id.cmp(&right.id))
        });
        hosts
    }

    pub(crate) fn proxies(&self) -> Vec<ProxyEntry> {
        let mut proxies: Vec<ProxyEntry> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                entry.body.as_proxy().map(|proxy| ProxyEntry {
                    id: id.clone(),
                    proxy: proxy.clone(),
                    updated_ms: entry.updated_ms,
                    device_only: entry.device_only,
                })
            })
            .collect();
        proxies.sort_by(|left, right| {
            left.proxy
                .title()
                .to_lowercase()
                .cmp(&right.proxy.title().to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        proxies
    }

    pub(crate) fn snippets(&self) -> Vec<SnippetEntry> {
        let mut snippets: Vec<SnippetEntry> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                entry.body.as_snippet().map(|snippet| SnippetEntry {
                    id: id.clone(),
                    snippet: snippet.clone(),
                })
            })
            .collect();
        snippets.sort_by(|left, right| {
            left.snippet
                .title()
                .to_lowercase()
                .cmp(&right.snippet.title().to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        snippets
    }

    pub(crate) fn via_item(&self, id: &RecordId) -> Option<ViaItem> {
        let body = &self.entries.get(id)?.body;
        body.as_proxy().cloned().map(ViaItem::Proxy).or_else(|| {
            body.as_host()
                .filter(|host| host.is_usable())
                .cloned()
                .map(ViaItem::Host)
        })
    }

    pub(crate) fn proxy(&self, id: &RecordId) -> Option<ProxyEntry> {
        let entry = self.entries.get(id)?;
        entry.body.as_proxy().map(|proxy| ProxyEntry {
            id: id.clone(),
            proxy: proxy.clone(),
            updated_ms: entry.updated_ms,
            device_only: entry.device_only,
        })
    }

    fn find_by_target(&self, target: &str) -> Option<HostEntry> {
        let target = target.trim();
        self.hosts()
            .into_iter()
            .find(|entry| entry.host.target() == target)
    }

    fn upsert_host(
        &mut self,
        store: &VaultStore,
        host: HostRecord,
        device_only: bool,
    ) -> Result<RecordId> {
        if !host.is_usable() {
            bail!("у записи нет адреса");
        }
        let existing = self.find_by_target(&host.target()).map(|entry| entry.id);
        self.upsert(store, existing, Some(device_only), RecordBody::Host(host))
    }

    fn upsert(
        &mut self,
        store: &VaultStore,
        existing: Option<RecordId>,
        device_only: Option<bool>,
        body: RecordBody,
    ) -> Result<RecordId> {
        let updated_ms = now_ms();

        let record = match existing {
            Some(id) => {
                let entry = self
                    .entries
                    .get(&id)
                    .ok_or_else(|| anyhow!("запись исчезла из хранилища"))?;
                Record {
                    id,
                    rev: entry.rev.saturating_add(1),
                    device_id: self.device_id.clone(),
                    updated_ms,
                    device_only: device_only.unwrap_or(entry.device_only),
                    body,
                }
            }
            None => Record::new(
                RecordId::generate().map_err(|error| anyhow!("{error}"))?,
                self.device_id.clone(),
                updated_ms,
                body,
            )
            .with_device_only(device_only.unwrap_or(false)),
        };

        self.write(store, record)
    }

    fn remove(&mut self, store: &VaultStore, id: &RecordId) -> Result<()> {
        let entry = self
            .entries
            .get(id)
            .ok_or_else(|| anyhow!("такой записи нет"))?;
        if entry.body.is_tombstone() {
            return Ok(());
        }

        let record = Record {
            id: id.clone(),
            rev: entry.rev.saturating_add(1),
            device_id: self.device_id.clone(),
            updated_ms: now_ms(),
            device_only: entry.device_only,
            body: RecordBody::Tombstone,
        };
        self.write(store, record)?;
        Ok(())
    }

    fn write(&mut self, store: &VaultStore, record: Record) -> Result<RecordId> {
        let sealed = record
            .seal(&self.record_key, &self.vault_id, self.key_gen)
            .map_err(|error| anyhow!("не зашифровать запись: {error}"))?;
        store.write_record(&sealed)?;

        let id = record.id.clone();
        self.entries.insert(id.clone(), Entry::from_record(&record));
        Ok(id)
    }

    fn syncable_ids(&self) -> Vec<RecordId> {
        self.entries
            .iter()
            .filter(|(_, entry)| !entry.device_only)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn records_for_push(&self, store: &VaultStore) -> Result<Vec<proto::EncryptedRecord>> {
        let syncable: std::collections::BTreeSet<RecordId> =
            self.syncable_ids().into_iter().collect();
        let (stored, _broken) = store.read_records()?;
        Ok(stored
            .into_iter()
            .filter(|record| syncable.contains(&record.id))
            .collect())
    }

    fn merge(&mut self, store: &VaultStore, incoming: Vec<proto::EncryptedRecord>) -> MergeReport {
        let mut report = MergeReport::default();

        for sealed in incoming {
            if sealed.key_gen != self.key_gen {
                report.stale += 1;
                continue;
            }

            if let Some(local) = self.entries.get(&sealed.id) {
                let mine = proto::EncryptedRecord {
                    id: sealed.id.clone(),
                    rev: local.rev,
                    key_gen: self.key_gen,
                    device_id: local.device_id.clone(),
                    updated_ms: local.updated_ms,
                    payload: Vec::new(),
                };
                if std::ptr::eq(proto::wins(&mine, &sealed), &mine) {
                    report.kept += 1;
                    continue;
                }
            }

            let record = match sealed.open(&self.record_key, &self.vault_id) {
                Ok(record) => record,
                Err(error) => {
                    report.broken.push(format!("{}: {error}", sealed.id));
                    continue;
                }
            };

            if let Err(error) = store.write_record(&sealed) {
                report.broken.push(format!("{}: {error:#}", sealed.id));
                continue;
            }

            self.entries
                .insert(record.id.clone(), Entry::from_record(&record));
            report.applied += 1;
        }

        report
    }
}

pub struct Unlocked {
    data_key: DataKey,
    records: RecordSet,
    pub broken: Vec<String>,
    pub warnings: Vec<String>,
    _locked_pages: Option<crate::platform::LockedPages>,
    autolock: AutoLock,
}

impl Unlocked {
    pub fn hosts(&self) -> Vec<HostEntry> {
        self.records.hosts()
    }

    pub fn find_by_target(&self, target: &str) -> Option<HostEntry> {
        self.records.find_by_target(target)
    }

    pub fn contains_target(&self, target: &str) -> bool {
        self.find_by_target(target).is_some()
    }

    pub fn upsert_host(&mut self, store: &VaultStore, host: HostRecord) -> Result<RecordId> {
        let device_only = self
            .find_by_target(&host.target())
            .map(|entry| entry.device_only)
            .unwrap_or(false);
        self.upsert_host_with(store, host, device_only)
    }

    pub fn upsert_host_with(
        &mut self,
        store: &VaultStore,
        host: HostRecord,
        device_only: bool,
    ) -> Result<RecordId> {
        self.records.upsert_host(store, host, device_only)
    }

    pub fn syncable_ids(&self) -> Vec<RecordId> {
        self.records.syncable_ids()
    }

    pub fn keys(&self) -> Vec<StoredKey> {
        let mut keys: Vec<StoredKey> = self
            .records
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                entry.body.as_key().map(|key| StoredKey {
                    id: id.clone(),
                    key: key.clone(),
                    updated_ms: entry.updated_ms,
                    device_only: entry.device_only,
                })
            })
            .filter(|entry| entry.key.is_usable())
            .collect();

        keys.sort_by(|left, right| {
            right
                .updated_ms
                .cmp(&left.updated_ms)
                .then(left.id.cmp(&right.id))
        });
        keys
    }

    pub fn find_key_by_public(&self, public: &[u8]) -> Option<StoredKey> {
        self.keys()
            .into_iter()
            .find(|entry| entry.key.public == public)
    }

    pub fn upsert_key(&mut self, store: &VaultStore, key: KeyRecord) -> Result<RecordId> {
        if !key.is_usable() {
            bail!("у ключа нет публичной или приватной части");
        }

        let existing = self.find_key_by_public(&key.public).map(|entry| entry.id);
        self.records
            .upsert(store, existing, None, RecordBody::Key(key))
    }

    pub fn remove_key(&mut self, store: &VaultStore, id: &RecordId) -> Result<()> {
        self.records.remove(store, id)
    }

    pub fn remove_host(&mut self, store: &VaultStore, id: &RecordId) -> Result<()> {
        let users = self.hosts_via(id);
        if !users.is_empty() {
            let names: Vec<String> = users.iter().map(|entry| entry.host.title()).collect();
            bail!(
                "через этот хост подключаются {}. Сначала уберите его из их цепочек",
                names.join(", ")
            );
        }
        self.records.remove(store, id)
    }

    pub fn proxies(&self) -> Vec<ProxyEntry> {
        self.records.proxies()
    }

    pub fn proxy(&self, id: &RecordId) -> Option<ProxyEntry> {
        self.records.proxy(id)
    }

    pub fn via_item(&self, id: &RecordId) -> Option<ViaItem> {
        self.records.via_item(id)
    }

    pub fn snippets(&self) -> Vec<SnippetEntry> {
        self.records.snippets()
    }

    /// Имя хранилища из его зашифрованной записи; `None`, если её ещё нет.
    pub fn vault_name(&self) -> Option<String> {
        let id = RecordId::parse(proto::VAULT_META_ID).ok()?;
        self.records
            .entries
            .get(&id)?
            .body
            .as_vault()
            .map(|meta| meta.name.clone())
            .filter(|name| !name.trim().is_empty())
    }

    /// Записывает имя хранилища; оно уходит на другие устройства с синхронизацией.
    pub fn set_vault_name(&mut self, store: &VaultStore, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            bail!("имя хранилища не может быть пустым");
        }
        if self.vault_name().as_deref() == Some(name) {
            return Ok(());
        }
        let id = RecordId::parse(proto::VAULT_META_ID).map_err(|error| anyhow!("{error}"))?;
        let body = RecordBody::Vault(proto::VaultMeta {
            name: name.to_owned(),
        });
        if self.records.entries.contains_key(&id) {
            self.records.upsert(store, Some(id), Some(false), body)?;
        } else {
            let record = Record::new(id, self.records.device_id.clone(), now_ms(), body);
            self.records.write(store, record)?;
        }
        Ok(())
    }

    pub fn upsert_snippet(
        &mut self,
        store: &VaultStore,
        existing: Option<RecordId>,
        snippet: proto::SnippetRecord,
    ) -> Result<RecordId> {
        if !snippet.is_usable() {
            bail!("у сниппета нет команды");
        }
        if let Some(id) = &existing
            && self
                .records
                .entries
                .get(id)
                .and_then(|entry| entry.body.as_snippet())
                .is_none()
        {
            bail!("сниппет исчез из хранилища — возможно, его удалили на другом устройстве");
        }
        self.records
            .upsert(store, existing, None, RecordBody::Snippet(snippet))
    }

    pub fn remove_snippet(&mut self, store: &VaultStore, id: &RecordId) -> Result<()> {
        self.records.remove(store, id)
    }

    pub fn upsert_proxy(
        &mut self,
        store: &VaultStore,
        existing: Option<RecordId>,
        proxy: ProxyRecord,
    ) -> Result<RecordId> {
        if proxy.host.trim().is_empty() {
            bail!("у прокси нет адреса");
        }
        if proxy.port == 0 {
            bail!("у прокси не указан порт");
        }
        if let Some(id) = &existing
            && self.records.proxy(id).is_none()
        {
            bail!("прокси исчез из хранилища — возможно, его удалили на другом устройстве");
        }
        self.records
            .upsert(store, existing, None, RecordBody::Proxy(proxy))
    }

    pub fn hosts_via(&self, id: &RecordId) -> Vec<HostEntry> {
        self.hosts()
            .into_iter()
            .filter(|entry| entry.host.via.contains(id))
            .collect()
    }

    pub fn remove_proxy(&mut self, store: &VaultStore, id: &RecordId) -> Result<()> {
        let users = self.hosts_via(id);
        if !users.is_empty() {
            let names: Vec<String> = users.iter().map(|entry| entry.host.title()).collect();
            bail!(
                "прокси стоит в цепочке у {}. Сначала уберите его оттуда",
                names.join(", ")
            );
        }
        self.records.remove(store, id)
    }

    pub fn resolve_via(&self, via: &[RecordId]) -> std::result::Result<Vec<ViaItem>, String> {
        resolve_via_in(via, |id| self.via_item(id))
    }

    pub fn vault_id(&self) -> &VaultId {
        &self.records.vault_id
    }

    pub fn records_for_push(&self, store: &VaultStore) -> Result<Vec<proto::EncryptedRecord>> {
        self.records.records_for_push(store)
    }

    pub fn merge(
        &mut self,
        store: &VaultStore,
        incoming: Vec<proto::EncryptedRecord>,
    ) -> MergeReport {
        self.records.merge(store, incoming)
    }

    pub fn autolock(&self) -> &AutoLock {
        &self.autolock
    }

    pub fn autolock_mut(&mut self) -> &mut AutoLock {
        &mut self.autolock
    }
}

pub struct NewVault {
    pub account: Account,
    pub data_key: DataKey,
    pub code: RecoveryCode,
}

pub fn prepare_new_vault(password: &[u8], target: Duration) -> Result<NewVault> {
    let params = vault::calibrate(target, &vault::CalibrationLimits::default())
        .map_err(|error| anyhow!("не подобрать параметры Argon2id: {error}"))?
        .params;
    prepare_new_vault_with_params(password, params)
}

pub fn prepare_new_vault_with_params(password: &[u8], params: Argon2idParams) -> Result<NewVault> {
    let data_key = DataKey::generate().map_err(|error| anyhow!("{error}"))?;

    let (password_slot, _) =
        WrapSlot::from_password(&data_key, password, params, PASSWORD_SLOT_LABEL)
            .map_err(|error| anyhow!("не создать обёртку на пароле: {error}"))?;

    let code = RecoveryCode::generate().map_err(|error| anyhow!("{error}"))?;
    let recovery_slot = WrapSlot::from_recovery_code(&data_key, &code, RECOVERY_SLOT_LABEL)
        .map_err(|error| anyhow!("не создать обёртку на коде восстановления: {error}"))?;

    let mut slots = SlotSet::new();
    slots.push(password_slot);
    slots.push(recovery_slot);

    let account = Account::new(
        VaultId::generate().map_err(|error| anyhow!("{error}"))?,
        slots,
        Vec::new(),
    );

    Ok(NewVault {
        account,
        data_key,
        code,
    })
}

/// Тяжёлая часть смены пароля, для фонового потока: проверяет текущий пароль
/// и заворачивает ключ данных под новый. Результат ставится
/// [`VaultSession::replace_password_slot`].
pub fn prepare_password_change(
    account: &Account,
    current: &[u8],
    new: &[u8],
    target: Duration,
) -> Result<WrapSlot> {
    let data_key =
        derive_from_password(account, current).map_err(|_| anyhow!("текущий пароль неверный"))?;
    let params = vault::calibrate(target, &vault::CalibrationLimits::default())
        .map_err(|error| anyhow!("не подобрать параметры Argon2id: {error}"))?
        .params;
    let (slot, _) = WrapSlot::from_password(&data_key, new, params, PASSWORD_SLOT_LABEL)
        .map_err(|error| anyhow!("не создать обёртку на новом пароле: {error}"))?;
    Ok(slot)
}

pub fn derive_from_password(account: &Account, password: &[u8]) -> Result<DataKey> {
    let slot = account
        .slots
        .iter_kind(SlotKind::Password)
        .next()
        .ok_or_else(|| anyhow!("в хранилище нет обёртки на пароле"))?;
    slot.unlock_with_password(password)
        .map(|(data_key, _auth_hash)| data_key)
        .map_err(|_| anyhow!("неверный пароль"))
}

pub fn derive_from_recovery_code(account: &Account, code: &RecoveryCode) -> Result<DataKey> {
    let slot = account
        .slots
        .iter_kind(SlotKind::RecoveryCode)
        .next()
        .ok_or_else(|| anyhow!("в хранилище нет обёртки на коде восстановления"))?;
    slot.unlock_with_recovery_code(code)
        .map_err(|_| anyhow!("код восстановления не подошёл"))
}

pub fn derive_from_os_key(account: &Account, stash: &dyn KeyStash) -> Result<DataKey> {
    let key = stash
        .get(account.vault_id.as_str())?
        .ok_or_else(|| anyhow!("в хранилище секретов ОС нет ключа от этого хранилища"))?;
    unlock_with_os_key_material(account, &key)
}

fn unlock_with_os_key_material(account: &Account, key: &Key32) -> Result<DataKey> {
    let mut seen = false;
    for slot in account.slots.iter_kind(SlotKind::ExternalKey) {
        seen = true;
        if let Ok(data_key) = slot.unlock_with_external_key(key) {
            return Ok(data_key);
        }
    }
    if seen {
        bail!(
            "ключ из хранилища ОС не подошёл к обёртке — похоже, запись осталась \
             от другого хранилища"
        );
    }
    bail!("в хранилище нет обёртки на ключе операционной системы");
}

fn os_key_slot_id(account: &Account) -> Option<[u8; SLOT_ID_LEN]> {
    account
        .slots
        .iter_kind(SlotKind::ExternalKey)
        .next()
        .map(|slot| *slot.id())
}

pub struct VaultSession {
    store: VaultStore,
    state: VaultState,
    timeout: Duration,
    os_key_slot: Option<[u8; SLOT_ID_LEN]>,
}

impl VaultSession {
    pub fn open(store: VaultStore, timeout: Duration) -> Self {
        let state = if store.exists() {
            match store.read_account() {
                Ok(account) => VaultState::Locked {
                    account: Box::new(account),
                    notice: None,
                },
                Err(error) => VaultState::Broken {
                    reason: format!("{error:#}"),
                },
            }
        } else {
            VaultState::Absent
        };
        let os_key_slot = match &state {
            VaultState::Locked { account, .. } => os_key_slot_id(account),
            _ => None,
        };
        Self {
            store,
            state,
            timeout,
            os_key_slot,
        }
    }

    pub fn store(&self) -> &VaultStore {
        &self.store
    }

    pub fn state(&self) -> &VaultState {
        &self.state
    }

    pub fn unlocked(&self) -> Option<&Unlocked> {
        match &self.state {
            VaultState::Unlocked(unlocked) => Some(unlocked),
            _ => None,
        }
    }

    pub fn unlocked_mut(&mut self) -> Option<&mut Unlocked> {
        match &mut self.state {
            VaultState::Unlocked(unlocked) => Some(unlocked),
            _ => None,
        }
    }

    pub fn account(&self) -> Option<&Account> {
        match &self.state {
            VaultState::Locked { account, .. } => Some(account),
            _ => None,
        }
    }

    pub fn locked_account(&self) -> Result<Account> {
        match &self.state {
            VaultState::Locked { account, .. } => Ok((**account).clone()),
            VaultState::Unlocked(_) => bail!("хранилище уже открыто"),
            VaultState::Broken { reason } => bail!("{reason}"),
            VaultState::Absent => bail!("хранилище ещё не создано"),
        }
    }

    pub fn install(&mut self, prepared: NewVault, import: Vec<HostRecord>) -> Result<RecoveryCode> {
        if self.store.exists() {
            bail!("хранилище уже создано");
        }

        let NewVault {
            account,
            data_key,
            code,
        } = prepared;
        self.store.write_account(&account)?;
        self.os_key_slot = os_key_slot_id(&account);

        let mut unlocked = self.build_unlocked(data_key, &account, Vec::new())?;
        for host in import {
            unlocked.upsert_host(&self.store, host)?;
        }

        self.store
            .read_account()
            .context("хранилище записано, но не перечитывается")?;

        self.state = VaultState::Unlocked(unlocked);
        Ok(code)
    }

    pub fn adopt(&mut self, data_key: DataKey) -> Result<()> {
        let Some(account) = self.locked_account_or_open()? else {
            return Ok(());
        };
        self.finish_unlock(data_key, &account)
    }

    pub fn unlock_with_password(&mut self, password: &[u8]) -> Result<()> {
        let Some(account) = self.locked_account_or_open()? else {
            return Ok(());
        };
        let data_key = derive_from_password(&account, password)?;
        self.finish_unlock(data_key, &account)
    }

    pub fn unlock_with_recovery_code(&mut self, code: &RecoveryCode) -> Result<()> {
        let Some(account) = self.locked_account_or_open()? else {
            return Ok(());
        };
        let data_key = derive_from_recovery_code(&account, code)?;
        self.finish_unlock(data_key, &account)
    }

    pub fn create_for_tests(
        &mut self,
        password: &[u8],
        params: Argon2idParams,
        import: Vec<HostRecord>,
    ) -> Result<RecoveryCode> {
        let prepared = prepare_new_vault_with_params(password, params)?;
        self.install(prepared, import)
    }

    fn locked_account_or_open(&self) -> Result<Option<Account>> {
        match &self.state {
            VaultState::Locked { account, .. } => Ok(Some((**account).clone())),
            VaultState::Unlocked(_) => Ok(None),
            VaultState::Broken { reason } => bail!("{reason}"),
            VaultState::Absent => bail!("хранилище ещё не создано"),
        }
    }

    pub fn change_password(&mut self, new_password: &[u8], params: Argon2idParams) -> Result<()> {
        let Some(unlocked) = self.unlocked() else {
            bail!("хранилище закрыто");
        };

        let (new_slot, _) = WrapSlot::from_password(
            &unlocked.data_key,
            new_password,
            params,
            PASSWORD_SLOT_LABEL,
        )
        .map_err(|error| anyhow!("не создать обёртку на новом пароле: {error}"))?;
        self.replace_password_slot(new_slot)
    }

    pub fn read_account(&self) -> Result<Account> {
        self.store.read_account()
    }

    /// Ставит обёртку на новом пароле вместо прежних. Обёртки на коде
    /// восстановления и на ключе ОС не трогает.
    pub fn replace_password_slot(&mut self, new_slot: WrapSlot) -> Result<()> {
        let mut account = self.store.read_account()?;
        let old: Vec<_> = account
            .slots
            .iter_kind(SlotKind::Password)
            .map(|slot| *slot.id())
            .collect();

        account.slots.push(new_slot);
        for id in old {
            account
                .slots
                .remove(&id)
                .map_err(|error| anyhow!("не убрать старую обёртку: {error}"))?;
        }
        self.store.write_account(&account)
    }

    /// Хранилище перенесли в другой каталог: дальше читаем и пишем там.
    pub fn relocate(&mut self, root: std::path::PathBuf) {
        self.store = VaultStore::new(root);
    }

    pub fn has_os_key(&self) -> bool {
        self.os_key_slot.is_some()
    }

    pub fn enable_os_key(&mut self, stash: &dyn KeyStash) -> Result<()> {
        let Some(unlocked) = self.unlocked() else {
            bail!("хранилище закрыто");
        };

        let key = Key32::generate().map_err(|error| anyhow!("{error}"))?;
        let slot = WrapSlot::from_external_key(&unlocked.data_key, &key, OS_KEY_SLOT_LABEL)
            .map_err(|error| anyhow!("не создать обёртку на ключе ОС: {error}"))?;

        let mut account = self.store.read_account()?;
        let old: Vec<_> = account
            .slots
            .iter_kind(SlotKind::ExternalKey)
            .map(|slot| *slot.id())
            .collect();
        account.slots.push(slot);
        for id in old {
            account
                .slots
                .remove(&id)
                .map_err(|error| anyhow!("не убрать прежнюю обёртку на ключе ОС: {error}"))?;
        }

        stash.put(account.vault_id.as_str(), &key)?;
        if let Err(error) = self.store.write_account(&account) {
            let _ = stash.delete(account.vault_id.as_str());
            return Err(error);
        }

        self.os_key_slot = os_key_slot_id(&account);
        Ok(())
    }

    pub fn disable_os_key(&mut self, stash: &dyn KeyStash) -> Result<()> {
        let mut account = self.store.read_account()?;
        let ids: Vec<_> = account
            .slots
            .iter_kind(SlotKind::ExternalKey)
            .map(|slot| *slot.id())
            .collect();

        for id in ids {
            account
                .slots
                .remove(&id)
                .map_err(|error| anyhow!("не убрать обёртку на ключе ОС: {error}"))?;
        }

        self.store.write_account(&account)?;
        self.os_key_slot = None;

        stash.delete(account.vault_id.as_str()).context(
            "обёртка убрана, хранилище этим ключом больше не открыть, но сама \
             запись осталась в хранилище секретов ОС — её можно удалить вручную",
        )
    }

    pub fn unlock_with_os_key(&mut self, stash: &dyn KeyStash) -> Result<()> {
        let Some(account) = self.locked_account_or_open()? else {
            return Ok(());
        };
        let data_key = derive_from_os_key(&account, stash)?;
        self.finish_unlock(data_key, &account)
    }

    fn finish_unlock(&mut self, data_key: DataKey, account: &Account) -> Result<()> {
        let unlocked = self.build_unlocked(data_key, account, Vec::new())?;
        self.os_key_slot = os_key_slot_id(account);
        self.state = VaultState::Unlocked(unlocked);
        Ok(())
    }

    fn build_unlocked(
        &self,
        data_key: DataKey,
        account: &Account,
        extra_broken: Vec<String>,
    ) -> Result<Box<Unlocked>> {
        let record_key = data_key.record_key().map_err(|error| anyhow!("{error}"))?;
        let (records, mut broken) = RecordSet::open(
            &self.store,
            record_key,
            account.vault_id.clone(),
            account.key_gen,
            self.store.device_id()?,
        )?;
        broken.extend(extra_broken);

        let now = Instant::now();
        let mut unlocked = Box::new(Unlocked {
            data_key,
            records,
            broken,
            warnings: Vec::new(),
            _locked_pages: None,
            autolock: AutoLock::new(self.timeout, now, now_ms(), crate::platform::awake_clock()),
        });

        let mut warnings = Vec::new();
        let locked = crate::platform::LockedPages::lock(unlocked.as_ref(), &mut warnings);
        unlocked._locked_pages = locked;
        unlocked.warnings = warnings;

        Ok(unlocked)
    }

    pub fn lock(&mut self, notice: Option<String>) {
        let account = match &self.state {
            VaultState::Unlocked(_) => self.store.read_account().ok().map(Box::new),
            VaultState::Locked { account, .. } => Some(account.clone()),
            VaultState::Absent | VaultState::Broken { .. } => None,
        };

        self.os_key_slot = account.as_deref().and_then(os_key_slot_id);
        self.state = match account {
            Some(account) => VaultState::Locked { account, notice },
            None if self.store.exists() => VaultState::Broken {
                reason: "файл аккаунта пропал или испортился, пока хранилище было открыто"
                    .to_owned(),
            },
            None => VaultState::Absent,
        };
    }

    pub fn tick(&mut self, now: Instant, wall_ms: u64) -> Option<&'static str> {
        let verdict = match &mut self.state {
            VaultState::Unlocked(unlocked) => {
                unlocked
                    .autolock
                    .check(now, wall_ms, crate::platform::awake_clock())
            }
            _ => Verdict::Keep,
        };

        if verdict.locks() {
            let reason = verdict.reason();
            self.lock(reason.map(str::to_owned));
            reason
        } else {
            None
        }
    }

    pub fn touch(&mut self, now: Instant) {
        if let VaultState::Unlocked(unlocked) = &mut self.state {
            unlocked.autolock.touch(now);
        }
    }

    pub fn rearm(&mut self, now: Instant, wall_ms: u64) {
        if let VaultState::Unlocked(unlocked) = &mut self.state {
            unlocked
                .autolock
                .rearm(now, wall_ms, crate::platform::awake_clock());
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        if let VaultState::Unlocked(unlocked) = &mut self.state {
            unlocked.autolock.set_timeout(timeout);
        }
    }

    pub fn legacy_hosts() -> (Option<std::path::PathBuf>, Vec<HostRecord>) {
        let Some(path) = migrate::legacy_path() else {
            return (None, Vec::new());
        };
        if !path.is_file() {
            return (None, Vec::new());
        }
        let hosts = migrate::read_legacy(&path);
        (Some(path), hosts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(name: &str) -> VaultStore {
        let unique = DeviceId::generate().expect("CSPRNG");
        let path = std::env::temp_dir().join(format!("cratty-session-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&path);
        VaultStore::new(path)
    }

    fn params() -> Argon2idParams {
        Argon2idParams::new(1024, 1, 1, [0x71; vault::SALT_LEN]).expect("параметры")
    }

    fn session(name: &str) -> VaultSession {
        VaultSession::open(temp_store(name), Duration::from_secs(600))
    }

    fn cleanup(session: &VaultSession) {
        let _ = std::fs::remove_dir_all(session.store().root());
    }

    #[test]
    fn pervyy_zapusk_hranilishcha_net() {
        let session = session("absent");
        assert!(session.state().is_absent());
        assert!(session.unlocked().is_none());
        cleanup(&session);
    }

    #[test]
    fn sozdanie_otkryvaet_hranilishche_i_vydaet_kod() {
        let mut session = session("create");
        let code = session
            .create_for_tests("мастер-пароль".as_bytes(), params(), Vec::new())
            .expect("создание");

        assert!(session.state().is_unlocked());
        assert!(session.store().exists());

        use vault::secrecy::ExposeSecret;
        let shown = code.format_for_user();
        let text = std::str::from_utf8(shown.expose_secret()).expect("ASCII");
        assert!(RecoveryCode::parse(text.as_bytes()).is_ok());

        cleanup(&session);
    }

    #[test]
    fn hosty_perezhivayut_zakrytie_i_otkrytie() {
        let mut session = session("hosts");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");

        let store_root = session.store().root().to_path_buf();
        let unlocked = session.unlocked_mut().expect("открыто");
        let mut host = HostRecord::new("prod-01.example.com");
        host.label = "боевой".into();
        host.user = "root".into();
        unlocked
            .upsert_host(&VaultStore::new(store_root.clone()), host.clone())
            .expect("запись");

        session.lock(None);
        assert!(!session.state().is_unlocked());

        session
            .unlock_with_password("пароль".as_bytes())
            .expect("разблокировка");
        let hosts = session.unlocked().expect("открыто").hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, host);

        cleanup(&session);
    }

    #[test]
    fn neverny_parol_ne_otkryvaet_i_ne_teryaet_hranilishche() {
        let mut session = session("wrong-password");
        session
            .create_for_tests("правильный".as_bytes(), params(), Vec::new())
            .expect("создание");
        session.lock(None);

        let error = session
            .unlock_with_password("неправильный".as_bytes())
            .expect_err("должно отказать")
            .to_string();
        assert_eq!(error, "неверный пароль");
        assert!(!session.state().is_unlocked());

        session
            .unlock_with_password("правильный".as_bytes())
            .expect("разблокировка");

        cleanup(&session);
    }

    #[test]
    fn kod_vosstanovleniya_otkryvaet_zabytoe_hranilishche() {
        let mut session = session("recovery");
        let code = session
            .create_for_tests("забытый".as_bytes(), params(), Vec::new())
            .expect("создание");
        session.lock(None);

        session
            .unlock_with_recovery_code(&code)
            .expect("разблокировка кодом");
        assert!(session.state().is_unlocked());

        cleanup(&session);
    }

    #[test]
    fn hranilishche_otkryvaetsya_frazoy_iz_slov_bip39_kak_ona_vvedena() {
        use vault::secrecy::ExposeSecret;

        let mut session = session("mnemonic");
        let code = session
            .create_for_tests("забытый".as_bytes(), params(), Vec::new())
            .expect("создание");
        let words = std::str::from_utf8(code.format_for_user().expose_secret())
            .expect("ASCII")
            .to_uppercase()
            .replace(' ', "  ");
        assert_eq!(words.split_whitespace().count(), 24);
        session.lock(None);

        let typed = RecoveryCode::parse(words.as_bytes()).expect("разбор");
        session
            .unlock_with_recovery_code(&typed)
            .expect("разблокировка фразой");
        assert!(session.state().is_unlocked());

        cleanup(&session);
    }

    #[test]
    fn povtornoe_sohranenie_hosta_ne_plodit_zapisi() {
        let mut session = session("upsert");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let mut host = HostRecord::new("example.com");
        host.user = "root".into();
        let first = unlocked.upsert_host(&store, host.clone()).expect("запись");

        host.label = "переименован".into();
        let second = unlocked.upsert_host(&store, host.clone()).expect("правка");

        assert_eq!(first, second, "тот же адрес — та же запись");
        let hosts = unlocked.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host.label, "переименован");

        cleanup(&session);
    }

    #[test]
    fn udalenie_stavit_nadgrobie_i_perezhivaet_perezapusk() {
        let mut session = session("remove");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let id = unlocked
            .upsert_host(&store, HostRecord::new("example.com"))
            .expect("запись");
        unlocked.remove_host(&store, &id).expect("удаление");
        assert!(unlocked.hosts().is_empty());

        session.lock(None);
        session
            .unlock_with_password("пароль".as_bytes())
            .expect("разблокировка");
        assert!(
            session.unlocked().expect("открыто").hosts().is_empty(),
            "удалённый хост воскрес после перезапуска"
        );

        cleanup(&session);
    }

    #[test]
    fn smena_parolya_ne_trogaet_zapisi() {
        let mut session = session("change-password");
        session
            .create_for_tests("старый".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());
        session
            .unlocked_mut()
            .expect("открыто")
            .upsert_host(&store, HostRecord::new("example.com"))
            .expect("запись");

        let new_params =
            Argon2idParams::new(1024, 1, 1, [0x72; vault::SALT_LEN]).expect("параметры");
        session
            .change_password("новый".as_bytes(), new_params)
            .expect("смена пароля");

        session.lock(None);
        assert!(session.unlock_with_password("старый".as_bytes()).is_err());
        session
            .unlock_with_password("новый".as_bytes())
            .expect("новый пароль");
        assert_eq!(session.unlocked().expect("открыто").hosts().len(), 1);

        cleanup(&session);
    }

    #[test]
    fn smena_parolya_v_dva_shaga_proveryaet_tekushchiy() {
        let mut session = session("change-password-prepared");
        session
            .create_for_tests("старый".as_bytes(), params(), Vec::new())
            .expect("создание");
        let account = session.read_account().expect("аккаунт");
        let fast = Duration::from_millis(1);

        assert!(
            prepare_password_change(&account, "чужой".as_bytes(), "новый".as_bytes(), fast)
                .is_err(),
            "сменили пароль, не зная текущего"
        );

        let slot = prepare_password_change(&account, "старый".as_bytes(), "новый".as_bytes(), fast)
            .expect("подготовка");
        session.replace_password_slot(slot).expect("замена");

        session.lock(None);
        assert!(session.unlock_with_password("старый".as_bytes()).is_err());
        session
            .unlock_with_password("новый".as_bytes())
            .expect("новый пароль");

        cleanup(&session);
    }

    #[test]
    fn import_iz_starogo_spiska_popadaet_v_hranilishche() {
        let mut session = session("import");
        let mut first = HostRecord::new("prod.example.com");
        first.label = "боевой".into();
        let second = HostRecord::new("dev.example.com");

        session
            .create_for_tests("пароль".as_bytes(), params(), vec![first, second])
            .expect("создание");

        let hosts = session.unlocked().expect("открыто").hosts();
        assert_eq!(hosts.len(), 2);

        cleanup(&session);
    }

    #[test]
    fn avtolok_zakryvaet_i_klyuchi_uhodyat() {
        let mut session = session("autolock");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");

        let now = Instant::now();
        assert!(session.tick(now, now_ms()).is_none());

        let later = now + Duration::from_secs(3600);
        let reason = session
            .tick(later, now_ms() + 3_600_000)
            .expect("закрылось");
        assert!(reason.contains("хранилище закрыто"));
        assert!(!session.state().is_unlocked());
        assert!(session.unlocked().is_none());

        cleanup(&session);
    }

    #[test]
    fn zakrytie_ne_teryaet_zapisi() {
        let mut session = session("lock-keeps");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());
        session
            .unlocked_mut()
            .expect("открыто")
            .upsert_host(&store, HostRecord::new("example.com"))
            .expect("запись");

        session.lock(Some("проверка".into()));
        match session.state() {
            VaultState::Locked { notice, .. } => {
                assert_eq!(notice.as_deref(), Some("проверка"))
            }
            _ => panic!("хранилище должно быть закрыто"),
        }

        session
            .unlock_with_password("пароль".as_bytes())
            .expect("разблокировка");
        assert_eq!(session.unlocked().expect("открыто").hosts().len(), 1);

        cleanup(&session);
    }

    #[test]
    fn parol_perezhivaet_zakrytie_i_otkrytie() {
        let mut session = session("password");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let mut host = HostRecord::new("prod.example.com");
        host.set_password(proto::Secret::new(b"hunter2".to_vec()));
        session
            .unlocked_mut()
            .expect("открыто")
            .upsert_host(&store, host)
            .expect("запись");

        session.lock(None);
        session
            .unlock_with_password("пароль".as_bytes())
            .expect("разблокировка");

        let hosts = session.unlocked().expect("открыто").hosts();
        assert_eq!(
            hosts[0].host.password().expect("пароль").expose(),
            b"hunter2"
        );

        cleanup(&session);
    }

    #[test]
    fn pravka_zapisi_ne_teryaet_parol() {
        let mut session = session("keep-password");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let mut host = HostRecord::new("example.com");
        host.set_password(proto::Secret::new(b"hunter2".to_vec()));
        unlocked.upsert_host(&store, host.clone()).expect("запись");

        host.label = "переименован".into();
        unlocked.upsert_host(&store, host).expect("правка");

        let hosts = unlocked.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host.label, "переименован");
        assert!(hosts[0].host.has_password(), "пароль потерялся при правке");

        cleanup(&session);
    }

    #[test]
    fn parol_mozhno_zabyt() {
        let mut session = session("forget-password");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let mut host = HostRecord::new("example.com");
        host.set_password(proto::Secret::new(b"hunter2".to_vec()));
        unlocked.upsert_host(&store, host.clone()).expect("запись");

        host.forget_password();
        unlocked.upsert_host(&store, host).expect("правка");
        assert!(!unlocked.hosts()[0].host.has_password());

        cleanup(&session);
    }

    #[test]
    fn privyazka_k_ustroystvu_upravlyaet_sinhronizaciey() {
        let mut session = session("device-only");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let free = unlocked
            .upsert_host(&store, HostRecord::new("shared.example.com"))
            .expect("запись");
        let bound = unlocked
            .upsert_host_with(&store, HostRecord::new("local.example.com"), true)
            .expect("запись");

        let syncable = unlocked.syncable_ids();
        assert!(syncable.contains(&free));
        assert!(
            !syncable.contains(&bound),
            "привязанная к устройству запись не должна уходить в синхронизацию"
        );

        session.lock(None);
        session
            .unlock_with_password("пароль".as_bytes())
            .expect("разблокировка");

        let unlocked = session.unlocked().expect("открыто");
        assert_eq!(unlocked.syncable_ids(), vec![free]);
        let local = unlocked
            .find_by_target("local.example.com")
            .expect("запись на месте");
        assert!(local.device_only, "привязка потерялась после перезапуска");

        cleanup(&session);
    }

    #[test]
    fn imya_hranilishcha_hranitsya_i_uhodit_v_sinhronizaciyu() {
        let mut session = session("vault-name");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        assert_eq!(unlocked.vault_name(), None);
        assert!(unlocked.set_vault_name(&store, "   ").is_err());
        unlocked.set_vault_name(&store, "Работа").expect("имя");
        unlocked
            .set_vault_name(&store, " Работа 2 ")
            .expect("переименование");
        assert_eq!(unlocked.vault_name().as_deref(), Some("Работа 2"));

        let meta = RecordId::parse(proto::VAULT_META_ID).expect("id");
        assert!(
            unlocked.syncable_ids().contains(&meta),
            "имя должно уходить на другие устройства"
        );
        assert!(
            unlocked.hosts().is_empty() && unlocked.snippets().is_empty(),
            "запись имени не должна попадать в списки"
        );

        session.lock(None);
        session
            .unlock_with_password("пароль".as_bytes())
            .expect("разблокировка");
        assert_eq!(
            session.unlocked().expect("открыто").vault_name().as_deref(),
            Some("Работа 2")
        );

        cleanup(&session);
    }

    #[test]
    fn pravka_ne_snimaet_privyazku_k_ustroystvu() {
        let mut session = session("device-only-edit");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let mut host = HostRecord::new("local.example.com");
        let id = unlocked
            .upsert_host_with(&store, host.clone(), true)
            .expect("запись");

        host.label = "переименован".into();
        unlocked.upsert_host(&store, host).expect("правка");

        assert!(
            !unlocked.syncable_ids().contains(&id),
            "переименование отправило запись на сервер"
        );

        cleanup(&session);
    }

    #[test]
    fn parolya_net_v_fayle_zapisi() {
        let mut session = session("password-on-disk");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let mut host = HostRecord::new("example.com");
        host.set_password(proto::Secret::new(b"hunter2".to_vec()));
        session
            .unlocked_mut()
            .expect("открыто")
            .upsert_host(&store, host)
            .expect("запись");

        let dir = session.store().root().join(proto::RECORDS_DIR);
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("каталог записей") {
            let bytes = std::fs::read(entry.expect("файл").path()).expect("чтение");
            assert!(
                !bytes.windows(7).any(|window| window == b"hunter2"),
                "пароль нашёлся в файле записи"
            );
            checked += 1;
        }
        assert!(checked > 0, "записи не нашлись — тест ничего не проверил");

        cleanup(&session);
    }

    #[test]
    fn povtornoe_sozdanie_otvergaetsya() {
        let mut session = session("recreate");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        assert!(
            session
                .create_for_tests("другой".as_bytes(), params(), Vec::new())
                .is_err()
        );
        cleanup(&session);
    }

    use crate::keychain::MemoryStash;

    fn session_with_os_key(name: &str) -> (VaultSession, MemoryStash) {
        let mut session = session(name);
        session
            .create_for_tests("мастер-пароль".as_bytes(), params(), Vec::new())
            .expect("создание");

        let store = VaultStore::new(session.store().root().to_path_buf());
        let mut host = HostRecord::new("prod-01.example.com");
        host.user = "root".into();
        session
            .unlocked_mut()
            .expect("открыто")
            .upsert_host(&store, host)
            .expect("запись");

        let stash = MemoryStash::new();
        session.enable_os_key(&stash).expect("включение ключа ОС");
        assert!(session.has_os_key());

        (session, stash)
    }

    #[test]
    fn klyuch_os_otkryvaet_hranilishche_bez_parolya() {
        let (mut session, stash) = session_with_os_key("os-key-unlock");
        session.lock(None);
        assert!(!session.state().is_unlocked());
        assert!(session.has_os_key(), "обёртка переживает закрытие");

        session.unlock_with_os_key(&stash).expect("разблокировка");
        let hosts = session.unlocked().expect("открыто").hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host.host, "prod-01.example.com");

        cleanup(&session);
    }

    #[test]
    fn otklyuchenie_ubiraet_i_obertku_i_zapis() {
        let (mut session, stash) = session_with_os_key("os-key-disable");
        let vault_id = session
            .store()
            .read_account()
            .expect("аккаунт")
            .vault_id
            .as_str()
            .to_owned();

        session.disable_os_key(&stash).expect("отключение");
        assert!(!session.has_os_key());
        assert!(stash.get(&vault_id).expect("чтение").is_none());
        assert_eq!(
            session
                .store()
                .read_account()
                .expect("аккаунт")
                .slots
                .iter_kind(SlotKind::ExternalKey)
                .count(),
            0
        );

        session.lock(None);
        assert!(session.unlock_with_os_key(&stash).is_err());
        session
            .unlock_with_password("мастер-пароль".as_bytes())
            .expect("разблокировка паролем");

        cleanup(&session);
    }

    #[test]
    fn propavshiy_klyuch_os_ne_lomaet_parol() {
        let (mut session, stash) = session_with_os_key("os-key-wiped");
        session.lock(None);
        stash.wipe();

        let error = session
            .unlock_with_os_key(&stash)
            .expect_err("открылось без ключа");
        assert!(format!("{error:#}").contains("нет ключа"));

        session
            .unlock_with_password("мастер-пароль".as_bytes())
            .expect("разблокировка паролем");

        cleanup(&session);
    }

    #[test]
    fn chuzhoy_klyuch_os_ne_otkryvaet_hranilishche() {
        let (mut session, stash) = session_with_os_key("os-key-alien");
        let vault_id = session
            .store()
            .read_account()
            .expect("аккаунт")
            .vault_id
            .as_str()
            .to_owned();
        session.lock(None);

        stash.corrupt(&vault_id);
        assert!(session.unlock_with_os_key(&stash).is_err());
        assert!(!session.state().is_unlocked());

        session
            .unlock_with_password("мастер-пароль".as_bytes())
            .expect("разблокировка паролем");

        cleanup(&session);
    }

    #[test]
    fn povtornoe_vklyuchenie_zamenyaet_obertku() {
        let (mut session, stash) = session_with_os_key("os-key-again");
        let account = session.store().read_account().expect("аккаунт");
        let vault_id = account.vault_id.as_str().to_owned();
        let old_key = stash.get(&vault_id).expect("чтение").expect("ключ есть");

        session.enable_os_key(&stash).expect("повторное включение");

        let account = session.store().read_account().expect("аккаунт");
        assert_eq!(
            account.slots.iter_kind(SlotKind::ExternalKey).count(),
            1,
            "обёрток на ключе ОС должно остаться ровно одна"
        );
        let new_key = stash.get(&vault_id).expect("чтение").expect("ключ есть");
        assert_ne!(old_key, new_key);
        assert!(unlock_with_os_key_material(&account, &old_key).is_err());
        unlock_with_os_key_material(&account, &new_key).expect("новый ключ подходит");

        cleanup(&session);
    }

    #[test]
    fn vklyuchenie_na_zakrytom_hranilishche_otkazyvaet() {
        let mut session = session("os-key-locked");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        session.lock(None);

        let stash = MemoryStash::new();
        assert!(session.enable_os_key(&stash).is_err());
        assert!(!session.has_os_key());

        cleanup(&session);
    }

    #[test]
    fn fayl_akkaunta_ne_soderzhit_klyucha_os() {
        let (session, stash) = session_with_os_key("os-key-bytes");
        let account = session.store().read_account().expect("аккаунт");
        let key = stash
            .get(account.vault_id.as_str())
            .expect("чтение")
            .expect("ключ есть");

        let bytes =
            std::fs::read(session.store().root().join(proto::ACCOUNT_FILE)).expect("файл аккаунта");
        let needle = key.as_bytes();
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "ключ ОС нашёлся в файле аккаунта"
        );

        cleanup(&session);
    }

    fn office_proxy() -> ProxyRecord {
        let mut proxy = ProxyRecord::new(proto::ProxyKind::Socks5, "proxy.office", 1080);
        proxy.label = "офис".into();
        proxy.user = "dan".into();
        proxy.set_password(proto::Secret::new(b"hunter2".to_vec()));
        proxy
    }

    #[test]
    fn cepochka_proksi_perezhivaet_zakrytie() {
        let mut session = session("proxy-chain");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let first = unlocked
            .upsert_proxy(&store, None, office_proxy())
            .expect("прокси");
        let second = unlocked
            .upsert_proxy(
                &store,
                None,
                ProxyRecord::new(proto::ProxyKind::Socks5, "tor", 9050),
            )
            .expect("прокси");

        let mut host = HostRecord::new("example.com");
        host.via = vec![first.clone(), second.clone()];
        unlocked.upsert_host(&store, host).expect("хост");

        session.lock(None);
        session
            .unlock_with_password("пароль".as_bytes())
            .expect("открытие");
        let unlocked = session.unlocked().expect("открыто");

        let host = unlocked.find_by_target("example.com").expect("хост");
        let chain = unlocked.resolve_via(&host.host.via).expect("цепочка");
        let proxies: Vec<&ProxyRecord> = chain
            .iter()
            .map(|item| match item {
                ViaItem::Proxy(proxy) => proxy,
                ViaItem::Host(_) => panic!("ждали прокси"),
            })
            .collect();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].host, "proxy.office");
        assert_eq!(
            proxies[0].password().map(proto::Secret::expose),
            Some(&b"hunter2"[..])
        );
        assert_eq!(proxies[1].host, "tor");

        cleanup(&session);
    }

    #[test]
    fn sokhranyonnyy_khost_zveno_cepochki() {
        let mut session = session("jump-host");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let unlocked = session.unlocked_mut().expect("открыто");

        let mut bastion = HostRecord::new("bastion.example.com");
        bastion.user = "jump".into();
        bastion.set_password(proto::Secret::new(b"bastion-pw".to_vec()));
        let bastion_id = unlocked.upsert_host(&store, bastion).expect("хост");

        let mut inner = HostRecord::new("db.internal");
        inner.via = vec![bastion_id.clone()];
        unlocked.upsert_host(&store, inner).expect("хост");

        let inner = unlocked.find_by_target("db.internal").expect("хост");
        match unlocked
            .resolve_via(&inner.host.via)
            .expect("цепочка")
            .as_slice()
        {
            [ViaItem::Host(host)] => {
                assert_eq!(host.target(), "jump@bastion.example.com");
                assert_eq!(
                    host.password().map(proto::Secret::expose),
                    Some(&b"bastion-pw"[..])
                );
            }
            other => panic!("ждали один хост, пришло {other:?}"),
        }

        let error = unlocked
            .remove_host(&store, &bastion_id)
            .expect_err("используется");
        assert!(error.to_string().contains("db.internal"), "{error}");

        cleanup(&session);
    }

    #[test]
    fn snippet_perezhivaet_zakrytie_i_udalyaetsya() {
        let mut session = session("snippets");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let unlocked = session.unlocked_mut().expect("открыто");
        let snippet = proto::SnippetRecord {
            label: "Поднять всё".into(),
            command: "cd /opt/stacks && ./all_up.sh".into(),
            run: true,
        };
        let id = unlocked
            .upsert_snippet(&store, None, snippet.clone())
            .expect("сниппет");
        assert!(
            unlocked
                .upsert_snippet(&store, None, proto::SnippetRecord::default())
                .is_err()
        );

        session.lock(None);
        session
            .unlock_with_password("пароль".as_bytes())
            .expect("открытие");
        let unlocked = session.unlocked_mut().expect("открыто");
        assert_eq!(
            unlocked
                .snippets()
                .into_iter()
                .map(|entry| entry.snippet)
                .collect::<Vec<_>>(),
            vec![snippet]
        );

        unlocked.remove_snippet(&store, &id).expect("удаление");
        assert!(unlocked.snippets().is_empty());

        cleanup(&session);
    }

    #[test]
    fn propavshiy_proksi_ne_vypadaet_iz_cepochki_molcha() {
        let mut session = session("proxy-missing");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let unlocked = session.unlocked().expect("открыто");

        let ghost = RecordId::generate().expect("CSPRNG");
        let error = unlocked
            .resolve_via(&[ghost])
            .expect_err("обязана не собраться");
        assert!(error.contains("нет в хранилище"), "{error}");

        cleanup(&session);
    }

    #[test]
    fn ispolzuemyy_proksi_ne_udalyaetsya() {
        let mut session = session("proxy-in-use");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let id = unlocked
            .upsert_proxy(&store, None, office_proxy())
            .expect("прокси");
        let mut host = HostRecord::new("example.com");
        host.label = "прод".into();
        host.via = vec![id.clone()];
        unlocked.upsert_host(&store, host.clone()).expect("хост");

        let error = unlocked
            .remove_proxy(&store, &id)
            .expect_err("обязан отказать");
        assert!(format!("{error}").contains("прод"), "{error}");
        assert!(unlocked.proxy(&id).is_some());

        host.via.clear();
        unlocked
            .upsert_host(&store, host)
            .expect("хост без цепочки");
        unlocked.remove_proxy(&store, &id).expect("теперь можно");
        assert!(unlocked.proxy(&id).is_none());

        cleanup(&session);
    }

    #[test]
    fn pravka_proksi_ne_zavodit_vtoruyu_zapis() {
        let mut session = session("proxy-edit");
        session
            .create_for_tests("пароль".as_bytes(), params(), Vec::new())
            .expect("создание");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("открыто");
        let id = unlocked
            .upsert_proxy(&store, None, office_proxy())
            .expect("прокси");
        let mut changed = office_proxy();
        changed.port = 1081;
        let again = unlocked
            .upsert_proxy(&store, Some(id.clone()), changed)
            .expect("правка");

        assert_eq!(again, id);
        assert_eq!(unlocked.proxies().len(), 1);
        assert_eq!(unlocked.proxies()[0].proxy.port, 1081);

        cleanup(&session);
    }
}
