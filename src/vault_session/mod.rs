pub mod autolock;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rust_i18n::t;
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

fn password_slot_label() -> String {
    t!("vault.slot_password").into_owned()
}
fn recovery_slot_label() -> String {
    t!("vault.slot_recovery").into_owned()
}
fn os_key_slot_label() -> String {
    t!("vault.slot_os_key").into_owned()
}

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

/// Host group as it is shown: name and icon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostGroup {
    pub name: String,
    /// Empty — the default icon.
    pub icon: String,
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
                t!("vault.chain_link_missing", index = index + 1).into_owned()
            })?;
            if let ViaItem::Proxy(proxy) = &item
                && !proxy.is_usable()
            {
                let title = proxy.title();
                return Err(if proxy.kind == proto::ProxyKind::Unsupported {
                    t!("vault.chain_proxy_unknown_kind", title = title).into_owned()
                } else {
                    t!("vault.chain_proxy_no_address", title = title).into_owned()
                });
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

        // Manually placed ones first, in position, then the rest — newer on top.
        hosts.sort_by(|left, right| {
            let (a, b) = (left.host.order, right.host.order);
            (a == 0)
                .cmp(&(b == 0))
                .then(a.cmp(&b))
                .then(right.updated_ms.cmp(&left.updated_ms))
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
            bail!("{}", t!("vault.entry_no_address"));
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
                    .ok_or_else(|| anyhow!("{}", t!("vault.entry_disappeared")))?;
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
            .ok_or_else(|| anyhow!("{}", t!("vault.entry_not_found")))?;
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
            .map_err(|error| anyhow!("{}", t!("vault.encrypt_failed", error = error)))?;
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
            bail!("{}", t!("vault.key_no_parts"));
        }

        let existing = self.find_key_by_public(&key.public).map(|entry| entry.id);
        self.records
            .upsert(store, existing, None, RecordBody::Key(key))
    }

    /// Keys copied from disk (with the original file), including encrypted ones,
    /// that are not in the agent's list.
    pub fn key_backups(&self) -> Vec<StoredKey> {
        self.records
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
            .filter(|entry| entry.key.key_file().is_some_and(|file| !file.is_empty()))
            .collect()
    }

    /// Saves a copy of a key file. The entry is looked up by its original path; if the file
    /// has not changed, nothing is written and `None` is returned.
    pub fn backup_key_file(
        &mut self,
        store: &VaultStore,
        key: KeyRecord,
    ) -> Result<Option<RecordId>> {
        let Some(file) = key.key_file().filter(|file| !file.is_empty()) else {
            bail!("{}", t!("vault.key_file_empty"));
        };
        let existing = self
            .key_backups()
            .into_iter()
            .find(|entry| entry.key.source == key.source);
        if let Some(entry) = &existing
            && entry.key.key_file().map(|old| old.expose()) == Some(file.expose())
        {
            return Ok(None);
        }
        let existing = existing.map(|entry| entry.id).or_else(|| {
            (!key.public.is_empty())
                .then(|| self.find_key_by_public(&key.public).map(|entry| entry.id))
                .flatten()
        });
        self.records
            .upsert(store, existing, None, RecordBody::Key(key))
            .map(Some)
    }

    pub fn remove_key(&mut self, store: &VaultStore, id: &RecordId) -> Result<()> {
        self.records.remove(store, id)
    }

    pub fn remove_host(&mut self, store: &VaultStore, id: &RecordId) -> Result<()> {
        let users = self.hosts_via(id);
        if !users.is_empty() {
            let names: Vec<String> = users.iter().map(|entry| entry.host.title()).collect();
            bail!("{}", t!("vault.host_has_dependents", names = names.join(", ")));
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

    /// A downloaded icon by key (`selfhst:github`) and the revision of its entry:
    /// the UI uses the revision to know the image needs rebuilding.
    pub fn icon(&self, key: &str) -> Option<(u64, &proto::IconRecord)> {
        self.records.entries.values().find_map(|entry| {
            entry
                .body
                .as_icon()
                .filter(|icon| icon.key() == key)
                .map(|icon| (entry.rev, icon))
        })
    }

    /// Puts the icon into the vault (replacing the previous one with the same key) so it
    /// is visible offline and reaches other devices.
    pub fn store_icon(&mut self, store: &VaultStore, icon: proto::IconRecord) -> Result<()> {
        if !icon.is_complete() {
            bail!("{}", t!("vault.icon_no_image"));
        }
        let key = icon.key();
        let existing = self.records.entries.iter().find_map(|(id, entry)| {
            entry
                .body
                .as_icon()
                .filter(|stored| stored.key() == key)
                .map(|stored| (id.clone(), *stored == icon))
        });
        match existing {
            Some((_, true)) => Ok(()),
            Some((id, false)) => self
                .records
                .upsert(store, Some(id), None, RecordBody::Icon(icon))
                .map(|_| ()),
            None => self
                .records
                .upsert(store, None, Some(false), RecordBody::Icon(icon))
                .map(|_| ()),
        }
    }

    /// Whether at least one host or group references the icon.
    pub fn icon_in_use(&self, key: &str) -> bool {
        self.records
            .entries
            .values()
            .any(|entry| match &entry.body {
                RecordBody::Host(host) => host.icon == key,
                RecordBody::Group(group) => group.icon == key,
                _ => false,
            })
    }

    /// Removes a downloaded icon if nothing references it any more:
    /// only icons in use are kept in the vault.
    pub fn release_icon(&mut self, store: &VaultStore, key: &str) -> Result<()> {
        if key.is_empty() || self.icon_in_use(key) {
            return Ok(());
        }
        let ids: Vec<RecordId> = self
            .records
            .entries
            .iter()
            .filter(|(_, entry)| entry.body.as_icon().is_some_and(|icon| icon.key() == key))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.records.remove(store, &id)?;
        }
        Ok(())
    }

    /// Group appearance entries: id and contents.
    fn group_records(&self) -> Vec<(RecordId, proto::GroupRecord)> {
        self.records
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                entry
                    .body
                    .as_group()
                    .map(|group| (id.clone(), group.clone()))
            })
            .collect()
    }

    /// Groups that contain hosts, alphabetically. The name is spelled as in the appearance
    /// entry, or, without one, as on the group's first host.
    pub fn groups(&self) -> Vec<HostGroup> {
        let records = self.group_records();
        let mut groups: BTreeMap<String, HostGroup> = BTreeMap::new();
        for entry in self.hosts() {
            let name = entry.host.group.trim();
            if name.is_empty() {
                continue;
            }
            groups
                .entry(proto::GroupRecord::key(name))
                .or_insert_with(|| {
                    let record = records.iter().find(|(_, group)| group.is_named(name));
                    HostGroup {
                        name: record
                            .map(|(_, group)| group.name.trim().to_owned())
                            .filter(|name| !name.is_empty())
                            .unwrap_or_else(|| name.to_owned()),
                        icon: record
                            .map(|(_, group)| group.icon.clone())
                            .unwrap_or_default(),
                    }
                });
        }
        groups.into_values().collect()
    }

    /// Group name for saving a host: if what was typed matches an existing
    /// group case-insensitively, the existing spelling is used.
    pub fn group_name(&self, typed: &str) -> String {
        let typed = typed.trim();
        if typed.is_empty() {
            return String::new();
        }
        self.groups()
            .into_iter()
            .find(|group| proto::GroupRecord::key(&group.name) == proto::GroupRecord::key(typed))
            .map(|group| group.name)
            .unwrap_or_else(|| typed.to_owned())
    }

    /// Moves a host into group `group`; an empty name takes it out of the group.
    ///
    /// Without `anchor` the host goes to the end of the group (its own group — nothing
    /// changes). With `anchor` it takes that host's place: below it if
    /// dragged top to bottom within the group, otherwise above. Positions of the whole group
    /// are renumbered in the process.
    pub fn move_host(
        &mut self,
        store: &VaultStore,
        target: &str,
        group: &str,
        anchor: Option<&str>,
    ) -> Result<()> {
        let entry = self
            .find_by_target(target)
            .ok_or_else(|| anyhow!("{}", t!("vault.host_not_found", target = target)))?;
        let group = group.trim();
        let key = proto::GroupRecord::key(group);
        let same_group = proto::GroupRecord::key(&entry.host.group) == key;

        let Some(anchor) = anchor.filter(|anchor| *anchor != target) else {
            if same_group {
                return Ok(());
            }
            let mut host = entry.host;
            host.group = group.to_owned();
            host.order = 0;
            return self
                .records
                .upsert(store, Some(entry.id), None, RecordBody::Host(host))
                .map(drop);
        };

        let mut members: Vec<HostEntry> = self
            .hosts()
            .into_iter()
            .filter(|member| proto::GroupRecord::key(&member.host.group) == key)
            .collect();
        let to = members
            .iter()
            .position(|member| member.host.target() == anchor)
            .ok_or_else(|| anyhow!("{}", t!("vault.host_not_in_group", anchor = anchor, group = group)))?;
        // Top to bottom: after the host is removed the anchor shifts up by one, and
        // `to` points to the spot right below it. From below or from another group `to` is
        // the spot above the anchor.
        if let Some(from) = members.iter().position(|member| member.id == entry.id) {
            members.remove(from);
        }
        let moved_id = entry.id.clone();
        let mut moved = entry;
        moved.host.group = group.to_owned();
        members.insert(to, moved);

        for (index, member) in members.into_iter().enumerate() {
            let order = index as u64 + 1;
            let regrouped = member.id == moved_id && !same_group;
            if member.host.order == order && !regrouped {
                continue;
            }
            let mut host = member.host;
            host.order = order;
            self.records
                .upsert(store, Some(member.id), None, RecordBody::Host(host))?;
        }
        Ok(())
    }

    /// Renames group `old` and sets its icon. If the new name is already taken
    /// by another group, the groups merge.
    pub fn edit_group(
        &mut self,
        store: &VaultStore,
        old: &str,
        name: &str,
        icon: &str,
    ) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            bail!("{}", t!("vault.group_name_required"));
        }
        if old.trim().is_empty() {
            bail!("{}", t!("vault.group_ungrouped_rename"));
        }
        let keys = [proto::GroupRecord::key(old), proto::GroupRecord::key(name)];

        // Hosts of both groups — the renamed one and the one it merged with —
        // get the same spelling.
        for entry in self.hosts() {
            if !keys.contains(&proto::GroupRecord::key(&entry.host.group))
                || entry.host.group == name
            {
                continue;
            }
            let mut host = entry.host;
            host.group = name.to_owned();
            self.records
                .upsert(store, Some(entry.id), None, RecordBody::Host(host))?;
        }

        let body = RecordBody::Group(proto::GroupRecord {
            name: name.to_owned(),
            icon: icon.to_owned(),
        });
        let mut records = self
            .group_records()
            .into_iter()
            .filter(|(_, group)| group.is_named(old) || group.is_named(name))
            .map(|(id, _)| id);
        self.records
            .upsert(store, records.next(), Some(false), body)?;
        for duplicate in records {
            self.records.remove(store, &duplicate)?;
        }
        Ok(())
    }

    /// Vault name from its encrypted entry; `None` if there is none yet.
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

    /// Writes the vault name; it goes to other devices with sync.
    pub fn set_vault_name(&mut self, store: &VaultStore, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            bail!("{}", t!("vault.name_empty"));
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
            bail!("{}", t!("vault.snippet_no_command"));
        }
        if let Some(id) = &existing
            && self
                .records
                .entries
                .get(id)
                .and_then(|entry| entry.body.as_snippet())
                .is_none()
        {
            bail!("{}", t!("vault.snippet_gone"));
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
            bail!("{}", t!("vault.proxy_no_address"));
        }
        if proxy.port == 0 {
            bail!("{}", t!("vault.proxy_no_port"));
        }
        if let Some(id) = &existing
            && self.records.proxy(id).is_none()
        {
            bail!("{}", t!("vault.proxy_gone"));
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
            bail!("{}", t!("vault.proxy_in_chain", names = names.join(", ")));
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
        .map_err(|error| anyhow!("{}", t!("vault.argon_params_failed", error = error)))?
        .params;
    prepare_new_vault_with_params(password, params)
}

pub fn prepare_new_vault_with_params(password: &[u8], params: Argon2idParams) -> Result<NewVault> {
    let data_key = DataKey::generate().map_err(|error| anyhow!("{error}"))?;

    let (password_slot, _) =
        WrapSlot::from_password(&data_key, password, params, &password_slot_label())
            .map_err(|error| anyhow!("{}", t!("vault.password_wrap_failed", error = error)))?;

    let code = RecoveryCode::generate().map_err(|error| anyhow!("{error}"))?;
    let recovery_slot = WrapSlot::from_recovery_code(&data_key, &code, &recovery_slot_label())
        .map_err(|error| anyhow!("{}", t!("vault.recovery_wrap_failed", error = error)))?;

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

/// The heavy part of a password change, for a background thread: verifies the current password
/// and wraps the data key under the new one. The result is put
/// [`VaultSession::replace_password_slot`].
pub fn prepare_password_change(
    account: &Account,
    current: &[u8],
    new: &[u8],
    target: Duration,
) -> Result<WrapSlot> {
    let data_key =
        derive_from_password(account, current).map_err(|_| anyhow!("{}", t!("vault.current_password_wrong")))?;
    let params = vault::calibrate(target, &vault::CalibrationLimits::default())
        .map_err(|error| anyhow!("{}", t!("vault.argon_params_failed", error = error)))?
        .params;
    let (slot, _) = WrapSlot::from_password(&data_key, new, params, &password_slot_label())
        .map_err(|error| anyhow!("{}", t!("vault.new_password_wrap_failed", error = error)))?;
    Ok(slot)
}

pub fn derive_from_password(account: &Account, password: &[u8]) -> Result<DataKey> {
    let slot = account
        .slots
        .iter_kind(SlotKind::Password)
        .next()
        .ok_or_else(|| anyhow!("{}", t!("vault.no_password_wrap")))?;
    slot.unlock_with_password(password)
        .map(|(data_key, _auth_hash)| data_key)
        .map_err(|_| anyhow!("{}", t!("vault.wrong_password")))
}

pub fn derive_from_recovery_code(account: &Account, code: &RecoveryCode) -> Result<DataKey> {
    let slot = account
        .slots
        .iter_kind(SlotKind::RecoveryCode)
        .next()
        .ok_or_else(|| anyhow!("{}", t!("vault.no_recovery_wrap")))?;
    slot.unlock_with_recovery_code(code)
        .map_err(|_| anyhow!("{}", t!("vault.recovery_code_mismatch")))
}

pub fn derive_from_os_key(account: &Account, stash: &dyn KeyStash) -> Result<DataKey> {
    let key = stash
        .get(account.vault_id.as_str())?
        .ok_or_else(|| anyhow!("{}", t!("vault.no_os_key")))?;
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
        bail!("{}", t!("vault.os_key_mismatch"));
    }
    bail!("{}", t!("vault.no_os_wrap"));
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
            VaultState::Unlocked(_) => bail!("{}", t!("vault.already_unlocked")),
            VaultState::Broken { reason } => bail!("{reason}"),
            VaultState::Absent => bail!("{}", t!("vault.not_created")),
        }
    }

    pub fn install(&mut self, prepared: NewVault, import: Vec<HostRecord>) -> Result<RecoveryCode> {
        if self.store.exists() {
            bail!("{}", t!("vault.already_created"));
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
            .context(t!("vault.written_unreadable").into_owned())?;

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
            VaultState::Absent => bail!("{}", t!("vault.not_created")),
        }
    }

    pub fn change_password(&mut self, new_password: &[u8], params: Argon2idParams) -> Result<()> {
        let Some(unlocked) = self.unlocked() else {
            bail!("{}", t!("vault.locked"));
        };

        let (new_slot, _) = WrapSlot::from_password(
            &unlocked.data_key,
            new_password,
            params,
            &password_slot_label(),
        )
        .map_err(|error| anyhow!("{}", t!("vault.new_password_wrap_failed", error = error)))?;
        self.replace_password_slot(new_slot)
    }

    pub fn read_account(&self) -> Result<Account> {
        self.store.read_account()
    }

    /// Puts the new password wrap in place of the previous ones. Wraps on the recovery code
    /// and the OS key are left untouched.
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
                .map_err(|error| anyhow!("{}", t!("vault.remove_old_wrap_failed", error = error)))?;
        }
        self.store.write_account(&account)
    }

    /// The vault was moved to another directory: read and write there from now on.
    pub fn relocate(&mut self, root: std::path::PathBuf) {
        self.store = VaultStore::new(root);
    }

    pub fn has_os_key(&self) -> bool {
        self.os_key_slot.is_some()
    }

    pub fn enable_os_key(&mut self, stash: &dyn KeyStash) -> Result<()> {
        let Some(unlocked) = self.unlocked() else {
            bail!("{}", t!("vault.locked"));
        };

        let key = Key32::generate().map_err(|error| anyhow!("{error}"))?;
        let slot = WrapSlot::from_external_key(&unlocked.data_key, &key, &os_key_slot_label())
            .map_err(|error| anyhow!("{}", t!("vault.os_wrap_failed", error = error)))?;

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
                .map_err(|error| anyhow!("{}", t!("vault.remove_prev_os_wrap_failed", error = error)))?;
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
                .map_err(|error| anyhow!("{}", t!("vault.remove_os_wrap_failed", error = error)))?;
        }

        self.store.write_account(&account)?;
        self.os_key_slot = None;

        stash.delete(account.vault_id.as_str()).context(t!("vault.os_wrap_removed_entry_remains").into_owned())
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
                reason: t!("vault.account_vanished").into_owned(),
            },
            None => VaultState::Absent,
        };
    }

    pub fn tick(&mut self, now: Instant, wall_ms: u64) -> Option<String> {
        let verdict = match &mut self.state {
            VaultState::Unlocked(unlocked) => {
                unlocked
                    .autolock
                    .check(now, wall_ms, crate::platform::awake_clock())
            }
            _ => Verdict::Keep,
        };

        if verdict.locks() {
            let reason = verdict.reason().map(std::borrow::Cow::into_owned);
            self.lock(reason.clone());
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
        Argon2idParams::new(1024, 1, 1, [0x71; vault::SALT_LEN]).expect("params")
    }

    fn session(name: &str) -> VaultSession {
        VaultSession::open(temp_store(name), Duration::from_secs(600))
    }

    fn cleanup(session: &VaultSession) {
        let _ = std::fs::remove_dir_all(session.store().root());
    }

    #[test]
    fn first_run_has_no_vault() {
        let session = session("absent");
        assert!(session.state().is_absent());
        assert!(session.unlocked().is_none());
        cleanup(&session);
    }

    #[test]
    fn creation_opens_vault_and_issues_code() {
        let mut session = session("create");
        let code = session
            .create_for_tests("master password".as_bytes(), params(), Vec::new())
            .expect("create");

        assert!(session.state().is_unlocked());
        assert!(session.store().exists());

        use vault::secrecy::ExposeSecret;
        let shown = code.format_for_user();
        let text = std::str::from_utf8(shown.expose_secret()).expect("ASCII");
        assert!(RecoveryCode::parse(text.as_bytes()).is_ok());

        cleanup(&session);
    }

    #[test]
    fn hosts_survive_locking_and_unlocking() {
        let mut session = session("hosts");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");

        let store_root = session.store().root().to_path_buf();
        let unlocked = session.unlocked_mut().expect("unlocked");
        let mut host = HostRecord::new("prod-01.example.com");
        host.label = "production".into();
        host.user = "root".into();
        unlocked
            .upsert_host(&VaultStore::new(store_root.clone()), host.clone())
            .expect("write");

        session.lock(None);
        assert!(!session.state().is_unlocked());

        session
            .unlock_with_password("password".as_bytes())
            .expect("unlock");
        let hosts = session.unlocked().expect("unlocked").hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, host);

        cleanup(&session);
    }

    #[test]
    fn wrong_password_does_not_open_and_does_not_lose_the_vault() {
        let mut session = session("wrong-password");
        session
            .create_for_tests("correct".as_bytes(), params(), Vec::new())
            .expect("create");
        session.lock(None);

        let error = session
            .unlock_with_password("incorrect".as_bytes())
            .expect_err("should refuse")
            .to_string();
        assert_eq!(error, "wrong password");
        assert!(!session.state().is_unlocked());

        session
            .unlock_with_password("correct".as_bytes())
            .expect("unlock");

        cleanup(&session);
    }

    #[test]
    fn recovery_code_opens_forgotten_vault() {
        let mut session = session("recovery");
        let code = session
            .create_for_tests("forgotten".as_bytes(), params(), Vec::new())
            .expect("create");
        session.lock(None);

        session
            .unlock_with_recovery_code(&code)
            .expect("unlock with code");
        assert!(session.state().is_unlocked());

        cleanup(&session);
    }

    #[test]
    fn vault_opens_with_bip39_phrase_as_entered() {
        use vault::secrecy::ExposeSecret;

        let mut session = session("mnemonic");
        let code = session
            .create_for_tests("forgotten".as_bytes(), params(), Vec::new())
            .expect("create");
        let words = std::str::from_utf8(code.format_for_user().expose_secret())
            .expect("ASCII")
            .to_uppercase()
            .replace(' ', "  ");
        assert_eq!(words.split_whitespace().count(), 24);
        session.lock(None);

        let typed = RecoveryCode::parse(words.as_bytes()).expect("parse");
        session
            .unlock_with_recovery_code(&typed)
            .expect("unlock with phrase");
        assert!(session.state().is_unlocked());

        cleanup(&session);
    }

    #[test]
    fn saving_host_again_does_not_multiply_records() {
        let mut session = session("upsert");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let mut host = HostRecord::new("example.com");
        host.user = "root".into();
        let first = unlocked.upsert_host(&store, host.clone()).expect("write");

        host.label = "renamed".into();
        let second = unlocked.upsert_host(&store, host.clone()).expect("edit");

        assert_eq!(first, second, "same address — same entry");
        let hosts = unlocked.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host.label, "renamed");

        cleanup(&session);
    }

    #[test]
    fn deletion_leaves_tombstone_and_survives_restart() {
        let mut session = session("remove");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let id = unlocked
            .upsert_host(&store, HostRecord::new("example.com"))
            .expect("write");
        unlocked.remove_host(&store, &id).expect("remove");
        assert!(unlocked.hosts().is_empty());

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("unlock");
        assert!(
            session.unlocked().expect("unlocked").hosts().is_empty(),
            "a deleted host came back after restart"
        );

        cleanup(&session);
    }

    #[test]
    fn password_change_does_not_touch_records() {
        let mut session = session("change-password");
        session
            .create_for_tests("old".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        session
            .unlocked_mut()
            .expect("unlocked")
            .upsert_host(&store, HostRecord::new("example.com"))
            .expect("write");

        let new_params =
            Argon2idParams::new(1024, 1, 1, [0x72; vault::SALT_LEN]).expect("params");
        session
            .change_password("new".as_bytes(), new_params)
            .expect("change password");

        session.lock(None);
        assert!(session.unlock_with_password("old".as_bytes()).is_err());
        session
            .unlock_with_password("new".as_bytes())
            .expect("new password");
        assert_eq!(session.unlocked().expect("unlocked").hosts().len(), 1);

        cleanup(&session);
    }

    #[test]
    fn two_step_password_change_checks_current_one() {
        let mut session = session("change-password-prepared");
        session
            .create_for_tests("old".as_bytes(), params(), Vec::new())
            .expect("create");
        let account = session.read_account().expect("account");
        let fast = Duration::from_millis(1);

        assert!(
            prepare_password_change(&account, "foreign".as_bytes(), "new".as_bytes(), fast)
                .is_err(),
            "changed the password without knowing the current one"
        );

        let slot = prepare_password_change(&account, "old".as_bytes(), "new".as_bytes(), fast)
            .expect("prepare");
        session.replace_password_slot(slot).expect("replace");

        session.lock(None);
        assert!(session.unlock_with_password("old".as_bytes()).is_err());
        session
            .unlock_with_password("new".as_bytes())
            .expect("new password");

        cleanup(&session);
    }

    #[test]
    fn import_from_old_list_lands_in_vault() {
        let mut session = session("import");
        let mut first = HostRecord::new("prod.example.com");
        first.label = "production".into();
        let second = HostRecord::new("dev.example.com");

        session
            .create_for_tests("password".as_bytes(), params(), vec![first, second])
            .expect("create");

        let hosts = session.unlocked().expect("unlocked").hosts();
        assert_eq!(hosts.len(), 2);

        cleanup(&session);
    }

    #[test]
    fn autolock_locks_and_keys_go_away() {
        let mut session = session("autolock");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");

        let now = Instant::now();
        assert!(session.tick(now, now_ms()).is_none());

        let later = now + Duration::from_secs(3600);
        let reason = session
            .tick(later, now_ms() + 3_600_000)
            .expect("locked");
        assert!(reason.contains("vault locked"));
        assert!(!session.state().is_unlocked());
        assert!(session.unlocked().is_none());

        cleanup(&session);
    }

    #[test]
    fn locking_does_not_lose_records() {
        let mut session = session("lock-keeps");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        session
            .unlocked_mut()
            .expect("unlocked")
            .upsert_host(&store, HostRecord::new("example.com"))
            .expect("write");

        session.lock(Some("check".into()));
        match session.state() {
            VaultState::Locked { notice, .. } => {
                assert_eq!(notice.as_deref(), Some("check"))
            }
            _ => panic!("the vault must be locked"),
        }

        session
            .unlock_with_password("password".as_bytes())
            .expect("unlock");
        assert_eq!(session.unlocked().expect("unlocked").hosts().len(), 1);

        cleanup(&session);
    }

    #[test]
    fn password_survives_locking_and_unlocking() {
        let mut session = session("password");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let mut host = HostRecord::new("prod.example.com");
        host.set_password(proto::Secret::new(b"hunter2".to_vec()));
        session
            .unlocked_mut()
            .expect("unlocked")
            .upsert_host(&store, host)
            .expect("write");

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("unlock");

        let hosts = session.unlocked().expect("unlocked").hosts();
        assert_eq!(
            hosts[0].host.password().expect("password").expose(),
            b"hunter2"
        );

        cleanup(&session);
    }

    #[test]
    fn record_edit_does_not_lose_password() {
        let mut session = session("keep-password");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let mut host = HostRecord::new("example.com");
        host.set_password(proto::Secret::new(b"hunter2".to_vec()));
        unlocked.upsert_host(&store, host.clone()).expect("write");

        host.label = "renamed".into();
        unlocked.upsert_host(&store, host).expect("edit");

        let hosts = unlocked.hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host.label, "renamed");
        assert!(hosts[0].host.has_password(), "the password was lost on edit");

        cleanup(&session);
    }

    #[test]
    fn password_can_be_forgotten() {
        let mut session = session("forget-password");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let mut host = HostRecord::new("example.com");
        host.set_password(proto::Secret::new(b"hunter2".to_vec()));
        unlocked.upsert_host(&store, host.clone()).expect("write");

        host.forget_password();
        unlocked.upsert_host(&store, host).expect("edit");
        assert!(!unlocked.hosts()[0].host.has_password());

        cleanup(&session);
    }

    #[test]
    fn device_binding_controls_sync() {
        let mut session = session("device-only");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let free = unlocked
            .upsert_host(&store, HostRecord::new("shared.example.com"))
            .expect("write");
        let bound = unlocked
            .upsert_host_with(&store, HostRecord::new("local.example.com"), true)
            .expect("write");

        let syncable = unlocked.syncable_ids();
        assert!(syncable.contains(&free));
        assert!(
            !syncable.contains(&bound),
            "a device-bound entry must not go into sync"
        );

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("unlock");

        let unlocked = session.unlocked().expect("unlocked");
        assert_eq!(unlocked.syncable_ids(), vec![free]);
        let local = unlocked
            .find_by_target("local.example.com")
            .expect("record in place");
        assert!(local.device_only, "the binding was lost after restart");

        cleanup(&session);
    }

    #[test]
    fn key_file_copy_is_not_duplicated_and_survives_restart() {
        let mut session = session("key-backup");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let backup = |bytes: &[u8]| {
            KeyRecord::from_file(
                "~/.ssh/id_test".into(),
                proto::Secret::new(bytes.to_vec()),
                Vec::new(),
                None,
            )
        };

        let unlocked = session.unlocked_mut().expect("unlocked");
        let first = unlocked
            .backup_key_file(&store, backup(b"KEY-1"))
            .expect("copy")
            .expect("written");
        assert_eq!(
            unlocked
                .backup_key_file(&store, backup(b"KEY-1"))
                .expect("repeat"),
            None,
            "an unchanged file was rewritten"
        );
        let second = unlocked
            .backup_key_file(&store, backup(b"KEY-2"))
            .expect("update")
            .expect("written");
        assert_eq!(first, second, "a changed file created a second entry");
        assert!(
            unlocked.keys().is_empty(),
            "an encrypted copy is not for the agent"
        );

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("unlock");
        let backups = session.unlocked().expect("unlocked").key_backups();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].key.key_file().expect("file").expose(), b"KEY-2");
        assert_eq!(backups[0].key.source, "~/.ssh/id_test");

        cleanup(&session);
    }

    #[test]
    fn vault_name_is_stored_and_goes_to_sync() {
        let mut session = session("vault-name");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        assert_eq!(unlocked.vault_name(), None);
        assert!(unlocked.set_vault_name(&store, "   ").is_err());
        unlocked.set_vault_name(&store, "Work").expect("name");
        unlocked
            .set_vault_name(&store, " Work 2 ")
            .expect("rename");
        assert_eq!(unlocked.vault_name().as_deref(), Some("Work 2"));

        let meta = RecordId::parse(proto::VAULT_META_ID).expect("id");
        assert!(
            unlocked.syncable_ids().contains(&meta),
            "the name must go to other devices"
        );
        assert!(
            unlocked.hosts().is_empty() && unlocked.snippets().is_empty(),
            "the name entry must not appear in the lists"
        );

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("unlock");
        assert_eq!(
            session.unlocked().expect("unlocked").vault_name().as_deref(),
            Some("Work 2")
        );

        cleanup(&session);
    }

    #[test]
    fn edit_does_not_remove_device_binding() {
        let mut session = session("device-only-edit");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let mut host = HostRecord::new("local.example.com");
        let id = unlocked
            .upsert_host_with(&store, host.clone(), true)
            .expect("write");

        host.label = "renamed".into();
        unlocked.upsert_host(&store, host).expect("edit");

        assert!(
            !unlocked.syncable_ids().contains(&id),
            "renaming sent the entry to the server"
        );

        cleanup(&session);
    }

    #[test]
    fn password_is_absent_from_record_file() {
        let mut session = session("password-on-disk");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let mut host = HostRecord::new("example.com");
        host.set_password(proto::Secret::new(b"hunter2".to_vec()));
        session
            .unlocked_mut()
            .expect("unlocked")
            .upsert_host(&store, host)
            .expect("write");

        let dir = session.store().root().join(proto::RECORDS_DIR);
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("records directory") {
            let bytes = std::fs::read(entry.expect("file").path()).expect("read");
            assert!(
                !bytes.windows(7).any(|window| window == b"hunter2"),
                "the password was found in the record file"
            );
            checked += 1;
        }
        assert!(checked > 0, "no records found — the test checked nothing");

        cleanup(&session);
    }

    #[test]
    fn repeated_creation_is_rejected() {
        let mut session = session("recreate");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        assert!(
            session
                .create_for_tests("other".as_bytes(), params(), Vec::new())
                .is_err()
        );
        cleanup(&session);
    }

    use crate::keychain::MemoryStash;

    fn session_with_os_key(name: &str) -> (VaultSession, MemoryStash) {
        let mut session = session(name);
        session
            .create_for_tests("master password".as_bytes(), params(), Vec::new())
            .expect("create");

        let store = VaultStore::new(session.store().root().to_path_buf());
        let mut host = HostRecord::new("prod-01.example.com");
        host.user = "root".into();
        session
            .unlocked_mut()
            .expect("unlocked")
            .upsert_host(&store, host)
            .expect("write");

        let stash = MemoryStash::new();
        session.enable_os_key(&stash).expect("enable OS key");
        assert!(session.has_os_key());

        (session, stash)
    }

    #[test]
    fn os_key_opens_vault_without_password() {
        let (mut session, stash) = session_with_os_key("os-key-unlock");
        session.lock(None);
        assert!(!session.state().is_unlocked());
        assert!(session.has_os_key(), "the wrap survives locking");

        session.unlock_with_os_key(&stash).expect("unlock");
        let hosts = session.unlocked().expect("unlocked").hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host.host, "prod-01.example.com");

        cleanup(&session);
    }

    #[test]
    fn disabling_removes_both_wrapper_and_record() {
        let (mut session, stash) = session_with_os_key("os-key-disable");
        let vault_id = session
            .store()
            .read_account()
            .expect("account")
            .vault_id
            .as_str()
            .to_owned();

        session.disable_os_key(&stash).expect("disable");
        assert!(!session.has_os_key());
        assert!(stash.get(&vault_id).expect("read").is_none());
        assert_eq!(
            session
                .store()
                .read_account()
                .expect("account")
                .slots
                .iter_kind(SlotKind::ExternalKey)
                .count(),
            0
        );

        session.lock(None);
        assert!(session.unlock_with_os_key(&stash).is_err());
        session
            .unlock_with_password("master password".as_bytes())
            .expect("unlock with password");

        cleanup(&session);
    }

    #[test]
    fn missing_os_key_does_not_break_password() {
        let (mut session, stash) = session_with_os_key("os-key-wiped");
        session.lock(None);
        stash.wipe();

        let error = session
            .unlock_with_os_key(&stash)
            .expect_err("opened without key");
        assert!(format!("{error:#}").contains("has no key"));

        session
            .unlock_with_password("master password".as_bytes())
            .expect("unlock with password");

        cleanup(&session);
    }

    #[test]
    fn foreign_os_key_does_not_open_vault() {
        let (mut session, stash) = session_with_os_key("os-key-alien");
        let vault_id = session
            .store()
            .read_account()
            .expect("account")
            .vault_id
            .as_str()
            .to_owned();
        session.lock(None);

        stash.corrupt(&vault_id);
        assert!(session.unlock_with_os_key(&stash).is_err());
        assert!(!session.state().is_unlocked());

        session
            .unlock_with_password("master password".as_bytes())
            .expect("unlock with password");

        cleanup(&session);
    }

    #[test]
    fn enabling_again_replaces_wrapper() {
        let (mut session, stash) = session_with_os_key("os-key-again");
        let account = session.store().read_account().expect("account");
        let vault_id = account.vault_id.as_str().to_owned();
        let old_key = stash.get(&vault_id).expect("read").expect("key present");

        session.enable_os_key(&stash).expect("repeated enable");

        let account = session.store().read_account().expect("account");
        assert_eq!(
            account.slots.iter_kind(SlotKind::ExternalKey).count(),
            1,
            "exactly one OS key wrap must remain"
        );
        let new_key = stash.get(&vault_id).expect("read").expect("key present");
        assert_ne!(old_key, new_key);
        assert!(unlock_with_os_key_material(&account, &old_key).is_err());
        unlock_with_os_key_material(&account, &new_key).expect("new key fits");

        cleanup(&session);
    }

    #[test]
    fn enabling_on_locked_vault_is_refused() {
        let mut session = session("os-key-locked");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        session.lock(None);

        let stash = MemoryStash::new();
        assert!(session.enable_os_key(&stash).is_err());
        assert!(!session.has_os_key());

        cleanup(&session);
    }

    #[test]
    fn account_file_does_not_contain_os_key() {
        let (session, stash) = session_with_os_key("os-key-bytes");
        let account = session.store().read_account().expect("account");
        let key = stash
            .get(account.vault_id.as_str())
            .expect("read")
            .expect("key present");

        let bytes =
            std::fs::read(session.store().root().join(proto::ACCOUNT_FILE)).expect("account file");
        let needle = key.as_bytes();
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "the OS key was found in the account file"
        );

        cleanup(&session);
    }

    fn office_proxy() -> ProxyRecord {
        let mut proxy = ProxyRecord::new(proto::ProxyKind::Socks5, "proxy.office", 1080);
        proxy.label = "office".into();
        proxy.user = "dan".into();
        proxy.set_password(proto::Secret::new(b"hunter2".to_vec()));
        proxy
    }

    #[test]
    fn proxy_chain_survives_locking() {
        let mut session = session("proxy-chain");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let first = unlocked
            .upsert_proxy(&store, None, office_proxy())
            .expect("proxy");
        let second = unlocked
            .upsert_proxy(
                &store,
                None,
                ProxyRecord::new(proto::ProxyKind::Socks5, "tor", 9050),
            )
            .expect("proxy");

        let mut host = HostRecord::new("example.com");
        host.via = vec![first.clone(), second.clone()];
        unlocked.upsert_host(&store, host).expect("host");

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("open");
        let unlocked = session.unlocked().expect("unlocked");

        let host = unlocked.find_by_target("example.com").expect("host");
        let chain = unlocked.resolve_via(&host.host.via).expect("chain");
        let proxies: Vec<&ProxyRecord> = chain
            .iter()
            .map(|item| match item {
                ViaItem::Proxy(proxy) => proxy,
                ViaItem::Host(_) => panic!("expected a proxy"),
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
    fn saved_host_is_a_chain_hop() {
        let mut session = session("jump-host");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let unlocked = session.unlocked_mut().expect("unlocked");

        let mut bastion = HostRecord::new("bastion.example.com");
        bastion.user = "jump".into();
        bastion.set_password(proto::Secret::new(b"bastion-pw".to_vec()));
        let bastion_id = unlocked.upsert_host(&store, bastion).expect("host");

        let mut inner = HostRecord::new("db.internal");
        inner.via = vec![bastion_id.clone()];
        unlocked.upsert_host(&store, inner).expect("host");

        let inner = unlocked.find_by_target("db.internal").expect("host");
        match unlocked
            .resolve_via(&inner.host.via)
            .expect("chain")
            .as_slice()
        {
            [ViaItem::Host(host)] => {
                assert_eq!(host.target(), "jump@bastion.example.com");
                assert_eq!(
                    host.password().map(proto::Secret::expose),
                    Some(&b"bastion-pw"[..])
                );
            }
            other => panic!("expected one host, got {other:?}"),
        }

        let error = unlocked
            .remove_host(&store, &bastion_id)
            .expect_err("in use");
        assert!(error.to_string().contains("db.internal"), "{error}");

        cleanup(&session);
    }

    #[test]
    fn icon_is_stored_and_replaced() {
        let mut session = session("icons");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let unlocked = session.unlocked_mut().expect("unlocked");

        let mut icon = proto::IconRecord {
            source: "selfhst".into(),
            name: "github".into(),
            format: "svg".into(),
            colored: false,
            color: b"<svg/>".to_vec(),
            light: Vec::new(),
            dark: Vec::new(),
        };
        assert!(
            unlocked
                .store_icon(&store, proto::IconRecord::default())
                .is_err()
        );
        unlocked.store_icon(&store, icon.clone()).expect("icon");
        let (first_rev, _) = unlocked.icon("selfhst:github").expect("present");
        unlocked.store_icon(&store, icon.clone()).expect("same");
        assert_eq!(unlocked.icon("selfhst:github").expect("present").0, first_rev);

        icon.light = b"<svg light/>".to_vec();
        unlocked.store_icon(&store, icon.clone()).expect("replace");

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("open");
        let unlocked = session.unlocked_mut().expect("unlocked");
        let (rev, stored) = unlocked.icon("selfhst:github").expect("present");
        assert!(rev > first_rev);
        assert_eq!(stored, &icon);
        assert!(unlocked.icon("selfhst:gitlab").is_none());

        // The icon stays while a host references it and goes away with it.
        let mut host = HostRecord::new("git.example");
        host.icon = "selfhst:github".into();
        unlocked.upsert_host(&store, host.clone()).expect("host");
        unlocked
            .release_icon(&store, "selfhst:github")
            .expect("in use");
        assert!(unlocked.icon("selfhst:github").is_some());
        host.icon.clear();
        unlocked.upsert_host(&store, host).expect("without icon");
        unlocked
            .release_icon(&store, "selfhst:github")
            .expect("release");
        assert!(unlocked.icon("selfhst:github").is_none());

        cleanup(&session);
    }

    #[test]
    fn groups_are_renamed_and_merged() {
        let mut session = session("groups");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let unlocked = session.unlocked_mut().expect("unlocked");

        let host = |address: &str, group: &str| {
            let mut host = HostRecord::new(address);
            host.group = group.into();
            host
        };
        unlocked
            .upsert_host(&store, host("a.example", "Prod"))
            .expect("a");
        unlocked
            .upsert_host(&store, host("b.example", "prod"))
            .expect("b");
        unlocked
            .upsert_host(&store, host("c.example", "Stage"))
            .expect("c");
        unlocked
            .upsert_host(&store, host("d.example", ""))
            .expect("d");

        let names = |unlocked: &Unlocked| -> Vec<String> {
            unlocked
                .groups()
                .into_iter()
                .map(|group| group.name)
                .collect()
        };
        assert_eq!(names(unlocked).len(), 2, "Prod and prod are one group");
        assert_eq!(unlocked.group_name("  STAGE "), "Stage");
        assert_eq!(unlocked.group_name("New"), "New");
        assert_eq!(unlocked.group_name("  "), "");

        unlocked
            .edit_group(&store, "prod", "Production", "database")
            .expect("rename");
        assert!(unlocked.edit_group(&store, "Stage", " ", "").is_err());
        assert_eq!(
            unlocked.groups(),
            vec![
                HostGroup {
                    name: "Production".into(),
                    icon: "database".into(),
                },
                HostGroup {
                    name: "Stage".into(),
                    icon: String::new(),
                },
            ]
        );

        // Renaming to a taken name merges the groups.
        unlocked
            .edit_group(&store, "Stage", "production", "rocket")
            .expect("merge");

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("open");
        let unlocked = session.unlocked_mut().expect("unlocked");
        assert_eq!(
            unlocked.groups(),
            vec![HostGroup {
                name: "production".into(),
                icon: "rocket".into(),
            }]
        );
        let grouped = unlocked
            .hosts()
            .into_iter()
            .filter(|entry| entry.host.group == "production")
            .count();
        assert_eq!(grouped, 3);

        cleanup(&session);
    }

    #[test]
    fn host_moves_into_and_out_of_group() {
        let mut session = session("move-host");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let unlocked = session.unlocked_mut().expect("unlocked");

        let mut host = HostRecord::new("a.example");
        host.group = "Prod".into();
        unlocked.upsert_host_with(&store, host, true).expect("a");
        let group_of = |unlocked: &Unlocked| unlocked.find_by_target("a.example").expect("present");

        unlocked
            .move_host(&store, "a.example", " Stage ", None)
            .expect("to another group");
        let entry = group_of(unlocked);
        assert_eq!(entry.host.group, "Stage");
        assert!(entry.device_only, "the device binding is preserved");

        unlocked
            .move_host(&store, "a.example", "", None)
            .expect("out of group");
        assert_eq!(group_of(unlocked).host.group, "");
        assert!(unlocked.groups().is_empty());
        assert!(
            unlocked
                .move_host(&store, "missing.example", "Prod", None)
                .is_err()
        );

        cleanup(&session);
    }

    #[test]
    fn hosts_are_reordered_within_group() {
        let mut session = session("reorder-hosts");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let unlocked = session.unlocked_mut().expect("unlocked");

        for address in ["d.example", "c.example", "b.example", "a.example"] {
            let mut host = HostRecord::new(address);
            host.group = "Prod".into();
            unlocked.upsert_host(&store, host).expect("host");
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let mut other = HostRecord::new("x.example");
        other.group = "Stage".into();
        unlocked.upsert_host(&store, other).expect("x");

        let order = |unlocked: &Unlocked, group: &str| -> Vec<String> {
            unlocked
                .hosts()
                .into_iter()
                .filter(|entry| entry.host.group == group)
                .map(|entry| entry.host.host)
                .collect()
        };
        // No positions yet — newer on top.
        assert_eq!(
            order(unlocked, "Prod"),
            ["a.example", "b.example", "c.example", "d.example"]
        );

        // Top to bottom — below the anchor.
        unlocked
            .move_host(&store, "a.example", "Prod", Some("c.example"))
            .expect("down");
        assert_eq!(
            order(unlocked, "Prod"),
            ["b.example", "c.example", "a.example", "d.example"]
        );

        // Bottom to top — above the anchor.
        unlocked
            .move_host(&store, "d.example", "Prod", Some("b.example"))
            .expect("up");
        assert_eq!(
            order(unlocked, "Prod"),
            ["d.example", "b.example", "c.example", "a.example"]
        );

        // From another group — above the anchor.
        unlocked
            .move_host(&store, "x.example", "Prod", Some("c.example"))
            .expect("from another group");
        assert_eq!(
            order(unlocked, "Prod"),
            [
                "d.example",
                "b.example",
                "x.example",
                "c.example",
                "a.example"
            ]
        );

        // The order survives a restart.
        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("open");
        let unlocked = session.unlocked_mut().expect("unlocked");
        assert_eq!(
            order(unlocked, "Prod"),
            [
                "d.example",
                "b.example",
                "x.example",
                "c.example",
                "a.example"
            ]
        );

        cleanup(&session);
    }

    #[test]
    fn snippet_survives_locking_and_can_be_deleted() {
        let mut session = session("snippets");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());
        let unlocked = session.unlocked_mut().expect("unlocked");
        let snippet = proto::SnippetRecord {
            label: "Bring everything up".into(),
            command: "cd /opt/stacks && ./all_up.sh".into(),
            run: true,
        };
        let id = unlocked
            .upsert_snippet(&store, None, snippet.clone())
            .expect("snippet");
        assert!(
            unlocked
                .upsert_snippet(&store, None, proto::SnippetRecord::default())
                .is_err()
        );

        session.lock(None);
        session
            .unlock_with_password("password".as_bytes())
            .expect("open");
        let unlocked = session.unlocked_mut().expect("unlocked");
        assert_eq!(
            unlocked
                .snippets()
                .into_iter()
                .map(|entry| entry.snippet)
                .collect::<Vec<_>>(),
            vec![snippet]
        );

        unlocked.remove_snippet(&store, &id).expect("remove");
        assert!(unlocked.snippets().is_empty());

        cleanup(&session);
    }

    #[test]
    fn missing_proxy_is_not_silently_dropped_from_chain() {
        let mut session = session("proxy-missing");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let unlocked = session.unlocked().expect("unlocked");

        let ghost = RecordId::generate().expect("CSPRNG");
        let error = unlocked
            .resolve_via(&[ghost])
            .expect_err("must fail to build");
        assert!(error.contains("not in the vault"), "{error}");

        cleanup(&session);
    }

    #[test]
    fn proxy_in_use_cannot_be_deleted() {
        let mut session = session("proxy-in-use");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let id = unlocked
            .upsert_proxy(&store, None, office_proxy())
            .expect("proxy");
        let mut host = HostRecord::new("example.com");
        host.label = "prod".into();
        host.via = vec![id.clone()];
        unlocked.upsert_host(&store, host.clone()).expect("host");

        let error = unlocked
            .remove_proxy(&store, &id)
            .expect_err("must refuse");
        assert!(format!("{error}").contains("prod"), "{error}");
        assert!(unlocked.proxy(&id).is_some());

        host.via.clear();
        unlocked
            .upsert_host(&store, host)
            .expect("host without chain");
        unlocked.remove_proxy(&store, &id).expect("now allowed");
        assert!(unlocked.proxy(&id).is_none());

        cleanup(&session);
    }

    #[test]
    fn proxy_edit_does_not_create_second_record() {
        let mut session = session("proxy-edit");
        session
            .create_for_tests("password".as_bytes(), params(), Vec::new())
            .expect("create");
        let store = VaultStore::new(session.store().root().to_path_buf());

        let unlocked = session.unlocked_mut().expect("unlocked");
        let id = unlocked
            .upsert_proxy(&store, None, office_proxy())
            .expect("proxy");
        let mut changed = office_proxy();
        changed.port = 1081;
        let again = unlocked
            .upsert_proxy(&store, Some(id.clone()), changed)
            .expect("edit");

        assert_eq!(again, id);
        assert_eq!(unlocked.proxies().len(), 1);
        assert_eq!(unlocked.proxies()[0].proxy.port, 1081);

        cleanup(&session);
    }
}
