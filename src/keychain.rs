use anyhow::{Result, anyhow, bail};
use vault::Key32;
use zeroize::Zeroize;

const SERVICE: &str = "cratty";

fn entry_name(vault_id: &str) -> String {
    format!("vault-key:{vault_id}")
}

pub trait KeyStash: Send + Sync {
    fn put(&self, vault_id: &str, key: &Key32) -> Result<()>;
    fn get(&self, vault_id: &str) -> Result<Option<Key32>>;
    fn delete(&self, vault_id: &str) -> Result<()>;
}

pub struct OsKeychain;

impl OsKeychain {
    fn entry(vault_id: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, &entry_name(vault_id))
            .map_err(|error| anyhow!("хранилище секретов ОС недоступно: {error}"))
    }
}

impl KeyStash for OsKeychain {
    fn put(&self, vault_id: &str, key: &Key32) -> Result<()> {
        Self::entry(vault_id)?
            .set_secret(key.as_bytes())
            .map_err(|error| anyhow!("не записать ключ в хранилище ОС: {error}"))
    }

    fn get(&self, vault_id: &str) -> Result<Option<Key32>> {
        match Self::entry(vault_id)?.get_secret() {
            Ok(mut bytes) => {
                let key = Key32::from_slice(&bytes);
                bytes.zeroize();
                Ok(Some(key.map_err(|_| {
                    anyhow!("в хранилище ОС лежит запись не на 32 байта")
                })?))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => bail!("не прочитать ключ из хранилища ОС: {error}"),
        }
    }

    fn delete(&self, vault_id: &str) -> Result<()> {
        match Self::entry(vault_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => bail!("не убрать ключ из хранилища ОС: {error}"),
        }
    }
}

#[cfg(test)]
pub struct MemoryStash {
    entries: std::sync::Mutex<std::collections::HashMap<String, Key32>>,
}

#[cfg(test)]
impl Default for MemoryStash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl MemoryStash {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn wipe(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    pub fn corrupt(&self, vault_id: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                entry_name(vault_id),
                Key32::from_bytes([0x00; vault::KEY_LEN]),
            );
        }
    }
}

#[cfg(test)]
impl KeyStash for MemoryStash {
    fn put(&self, vault_id: &str, key: &Key32) -> Result<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("хранилище-заглушка отравлено паникой"))?;
        entries.insert(entry_name(vault_id), key.clone());
        Ok(())
    }

    fn get(&self, vault_id: &str) -> Result<Option<Key32>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("хранилище-заглушка отравлено паникой"))?;
        Ok(entries.get(&entry_name(vault_id)).cloned())
    }

    fn delete(&self, vault_id: &str) -> Result<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("хранилище-заглушка отравлено паникой"))?;
        entries.remove(&entry_name(vault_id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imena_zapisey_ne_peresekayutsya() {
        assert_ne!(entry_name("a"), entry_name("b"));
        assert!(entry_name("vault-1").contains("vault-1"));
    }

    #[test]
    fn zaglushka_vedet_sebya_kak_hranilishche() {
        let stash = MemoryStash::new();
        let key = Key32::generate().expect("CSPRNG");

        assert!(stash.get("v1").expect("чтение").is_none());
        stash.put("v1", &key).expect("запись");
        assert_eq!(stash.get("v1").expect("чтение").as_ref(), Some(&key));
        assert!(stash.get("v2").expect("чтение").is_none());

        stash.delete("v1").expect("удаление");
        assert!(stash.get("v1").expect("чтение").is_none());
        stash.delete("v1").expect("повторное удаление");
    }

    #[test]
    #[ignore = "трогает настоящее хранилище секретов ОС"]
    fn keychain_operacionnoy_sistemy_hranit_i_otdaet_klyuch() {
        let stash = OsKeychain;
        let vault_id = format!("test-{}", std::process::id());
        let key = Key32::generate().expect("CSPRNG");

        stash.put(&vault_id, &key).expect("запись");
        assert_eq!(stash.get(&vault_id).expect("чтение").as_ref(), Some(&key));
        stash.delete(&vault_id).expect("удаление");
        assert!(stash.get(&vault_id).expect("чтение").is_none());
    }
}
