use rust_i18n::t;
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
            .map_err(|error| anyhow!("{}", t!("keychain.unavailable", error = error)))
    }
}

impl KeyStash for OsKeychain {
    fn put(&self, vault_id: &str, key: &Key32) -> Result<()> {
        Self::entry(vault_id)?
            .set_secret(key.as_bytes())
            .map_err(|error| anyhow!("{}", t!("keychain.write_failed", error = error)))
    }

    fn get(&self, vault_id: &str) -> Result<Option<Key32>> {
        match Self::entry(vault_id)?.get_secret() {
            Ok(mut bytes) => {
                let key = Key32::from_slice(&bytes);
                bytes.zeroize();
                Ok(Some(key.map_err(|_| {
                    anyhow!("{}", t!("keychain.bad_length"))
                })?))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => bail!("{}", t!("keychain.read_failed", error = error)),
        }
    }

    fn delete(&self, vault_id: &str) -> Result<()> {
        match Self::entry(vault_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => bail!("{}", t!("keychain.remove_failed", error = error)),
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
            .map_err(|_| anyhow!("stub store poisoned by a panic"))?;
        entries.insert(entry_name(vault_id), key.clone());
        Ok(())
    }

    fn get(&self, vault_id: &str) -> Result<Option<Key32>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("stub store poisoned by a panic"))?;
        Ok(entries.get(&entry_name(vault_id)).cloned())
    }

    fn delete(&self, vault_id: &str) -> Result<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("stub store poisoned by a panic"))?;
        entries.remove(&entry_name(vault_id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names_do_not_overlap() {
        assert_ne!(entry_name("a"), entry_name("b"));
        assert!(entry_name("vault-1").contains("vault-1"));
    }

    #[test]
    fn stub_behaves_like_a_store() {
        let stash = MemoryStash::new();
        let key = Key32::generate().expect("CSPRNG");

        assert!(stash.get("v1").expect("read").is_none());
        stash.put("v1", &key).expect("write");
        assert_eq!(stash.get("v1").expect("read").as_ref(), Some(&key));
        assert!(stash.get("v2").expect("read").is_none());

        stash.delete("v1").expect("delete");
        assert!(stash.get("v1").expect("read").is_none());
        stash.delete("v1").expect("repeated delete");
    }

    #[test]
    #[ignore = "touches the real OS secret store"]
    fn os_keychain_stores_and_returns_key() {
        let stash = OsKeychain;
        let vault_id = format!("test-{}", std::process::id());
        let key = Key32::generate().expect("CSPRNG");

        stash.put(&vault_id, &key).expect("write");
        assert_eq!(stash.get(&vault_id).expect("read").as_ref(), Some(&key));
        stash.delete(&vault_id).expect("delete");
        assert!(stash.get(&vault_id).expect("read").is_none());
    }
}
