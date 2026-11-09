use crate::aad::Aad;
use crate::aead;
use crate::datakey::DataKey;
use crate::error::{Error, Result};
use crate::kdf::{Argon2idParams, AuthHash, MasterSecrets, derive_master_secrets};
use crate::recovery::{RECOVERY_SALT_LEN, RecoveryCode};
use crate::rng;
use crate::secret::Key32;
use zeroize::Zeroize;

pub const SLOT_VERSION: u8 = 1;
pub const SLOT_ID_LEN: usize = 16;
const MAX_LABEL_LEN: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Password = 1,
    ExternalKey = 2,
    RecoveryCode = 3,
}

impl SlotKind {
    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Password),
            2 => Ok(Self::ExternalKey),
            3 => Ok(Self::RecoveryCode),
            _ => Err(Error::Format("unknown slot type")),
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Password => "master password",
            Self::ExternalKey => "operating system key",
            Self::RecoveryCode => "recovery code",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SlotKdf {
    None,
    Argon2id(Argon2idParams),
    Hkdf { salt: [u8; RECOVERY_SALT_LEN] },
}

impl SlotKdf {
    fn tag(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Argon2id(_) => 1,
            Self::Hkdf { .. } => 2,
        }
    }

    fn body(&self) -> Vec<u8> {
        match self {
            Self::None => Vec::new(),
            Self::Argon2id(params) => params.encode(),
            Self::Hkdf { salt } => salt.to_vec(),
        }
    }

    fn decode(tag: u8, body: &[u8]) -> Result<Self> {
        match tag {
            0 if body.is_empty() => Ok(Self::None),
            1 => Ok(Self::Argon2id(Argon2idParams::decode(body)?)),
            2 => {
                let salt: [u8; RECOVERY_SALT_LEN] = body
                    .try_into()
                    .map_err(|_| Error::Format("HKDF salt length"))?;
                Ok(Self::Hkdf { salt })
            }
            _ => Err(Error::Format("unknown slot key derivation")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapSlot {
    kind: SlotKind,
    id: [u8; SLOT_ID_LEN],
    label: String,
    kdf: SlotKdf,
    sealed: Vec<u8>,
}

impl WrapSlot {
    pub fn kind(&self) -> SlotKind {
        self.kind
    }

    pub fn id(&self) -> &[u8; SLOT_ID_LEN] {
        &self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn argon2_params(&self) -> Option<&Argon2idParams> {
        match &self.kdf {
            SlotKdf::Argon2id(params) => Some(params),
            _ => None,
        }
    }

    pub fn from_password(
        data_key: &DataKey,
        password: &[u8],
        params: Argon2idParams,
        label: &str,
    ) -> Result<(Self, AuthHash)> {
        let secrets = derive_master_secrets(password, &params)?;
        let slot = Self::seal(
            SlotKind::Password,
            SlotKdf::Argon2id(params),
            label,
            secrets.kek(),
            data_key,
        )?;
        Ok((slot, secrets.auth_hash().clone()))
    }

    pub fn from_external_key(data_key: &DataKey, key: &Key32, label: &str) -> Result<Self> {
        Self::seal(SlotKind::ExternalKey, SlotKdf::None, label, key, data_key)
    }

    pub fn from_recovery_code(
        data_key: &DataKey,
        code: &RecoveryCode,
        label: &str,
    ) -> Result<Self> {
        let salt: [u8; RECOVERY_SALT_LEN] = rng::array()?;
        let wrap_key = code.wrap_key(&salt)?;
        Self::seal(
            SlotKind::RecoveryCode,
            SlotKdf::Hkdf { salt },
            label,
            &wrap_key,
            data_key,
        )
    }

    pub fn unlock_with_password(&self, password: &[u8]) -> Result<(DataKey, AuthHash)> {
        let params = match &self.kdf {
            SlotKdf::Argon2id(params) => params,
            _ => return Err(Error::Format("slot is not opened by a password")),
        };
        let secrets: MasterSecrets = derive_master_secrets(password, params)?;
        let data_key = self.unseal(secrets.kek())?;
        Ok((data_key, secrets.auth_hash().clone()))
    }

    pub fn unlock_with_external_key(&self, key: &Key32) -> Result<DataKey> {
        if self.kind != SlotKind::ExternalKey {
            return Err(Error::Format("slot is not opened by an external key"));
        }
        self.unseal(key)
    }

    pub fn unlock_with_recovery_code(&self, code: &RecoveryCode) -> Result<DataKey> {
        let salt = match &self.kdf {
            SlotKdf::Hkdf { salt } => salt,
            _ => return Err(Error::Format("slot is not opened by a recovery code")),
        };
        let wrap_key = code.wrap_key(salt)?;
        self.unseal(&wrap_key)
    }

    fn seal(
        kind: SlotKind,
        kdf: SlotKdf,
        label: &str,
        wrap_key: &Key32,
        data_key: &DataKey,
    ) -> Result<Self> {
        if label.len() > MAX_LABEL_LEN {
            return Err(Error::Format("slot label is longer than 255 bytes"));
        }
        let id: [u8; SLOT_ID_LEN] = rng::array()?;
        let aad = slot_aad(kind, &id, label, &kdf);
        let sealed = aead::seal(wrap_key, &aad, data_key.as_key().as_bytes())?;
        Ok(Self {
            kind,
            id,
            label: label.to_owned(),
            kdf,
            sealed,
        })
    }

    fn unseal(&self, wrap_key: &Key32) -> Result<DataKey> {
        let aad = slot_aad(self.kind, &self.id, &self.label, &self.kdf);
        let mut plaintext = aead::open_to_vec(wrap_key, &aad, &self.sealed)?;
        let key = Key32::from_slice(&plaintext);
        plaintext.zeroize();
        Ok(DataKey::from_key(key.map_err(|_| Error::Decrypt)?))
    }

    pub fn encode(&self) -> Vec<u8> {
        let body = self.kdf.body();
        let mut out = Vec::with_capacity(64 + self.label.len() + body.len() + self.sealed.len());
        out.push(SLOT_VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.id);
        out.push(self.label.len() as u8);
        out.extend_from_slice(self.label.as_bytes());
        out.push(self.kdf.tag());
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
        out.extend_from_slice(&(self.sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.u8()? != SLOT_VERSION {
            return Err(Error::Format("slot version is not supported"));
        }
        let kind = SlotKind::from_byte(reader.u8()?)?;
        let id: [u8; SLOT_ID_LEN] = reader
            .take(SLOT_ID_LEN)?
            .try_into()
            .map_err(|_| Error::Format("slot identifier"))?;
        let label_len = usize::from(reader.u8()?);
        let label = core::str::from_utf8(reader.take(label_len)?)
            .map_err(|_| Error::Format("slot label is not UTF-8"))?
            .to_owned();
        let kdf_tag = reader.u8()?;
        let kdf_len = usize::from(reader.u8()?);
        let kdf = SlotKdf::decode(kdf_tag, reader.take(kdf_len)?)?;
        let sealed_len = usize_from_u32(reader.u32()?)?;
        let sealed = reader.take(sealed_len)?.to_vec();
        reader.finish()?;

        let consistent = matches!(
            (kind, &kdf),
            (SlotKind::Password, SlotKdf::Argon2id(_))
                | (SlotKind::ExternalKey, SlotKdf::None)
                | (SlotKind::RecoveryCode, SlotKdf::Hkdf { .. })
        );
        if !consistent {
            return Err(Error::Format("slot type does not match the key derivation"));
        }

        Ok(Self {
            kind,
            id,
            label,
            kdf,
            sealed,
        })
    }
}

fn slot_aad(kind: SlotKind, id: &[u8; SLOT_ID_LEN], label: &str, kdf: &SlotKdf) -> Vec<u8> {
    let mut aad = Aad::new("slot");
    aad.u8(SLOT_VERSION)
        .u8(kind as u8)
        .bytes(id)
        .bytes(label.as_bytes())
        .u8(kdf.tag())
        .bytes(&kdf.body());
    aad.finish()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlotSet {
    slots: Vec<WrapSlot>,
}

pub const SLOT_SET_VERSION: u8 = 1;

impl SlotSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, slot: WrapSlot) {
        self.slots.push(slot);
    }

    pub fn iter(&self) -> impl Iterator<Item = &WrapSlot> {
        self.slots.iter()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn find(&self, id: &[u8; SLOT_ID_LEN]) -> Option<&WrapSlot> {
        self.slots.iter().find(|slot| &slot.id == id)
    }

    pub fn iter_kind(&self, kind: SlotKind) -> impl Iterator<Item = &WrapSlot> {
        self.slots.iter().filter(move |slot| slot.kind == kind)
    }

    pub fn remove(&mut self, id: &[u8; SLOT_ID_LEN]) -> Result<WrapSlot> {
        let position = self
            .slots
            .iter()
            .position(|slot| &slot.id == id)
            .ok_or(Error::Format("no slot with this identifier"))?;
        if self.slots.len() == 1 {
            return Err(Error::Format(
                "this is the last Data Key wrapper; the vault cannot be opened without it",
            ));
        }
        Ok(self.slots.remove(position))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SLOT_SET_VERSION);
        out.extend_from_slice(&(self.slots.len() as u32).to_le_bytes());
        for slot in &self.slots {
            let encoded = slot.encode();
            out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            out.extend_from_slice(&encoded);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.u8()? != SLOT_SET_VERSION {
            return Err(Error::Format("slot list version is not supported"));
        }
        let count = usize_from_u32(reader.u32()?)?;
        let mut slots = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let len = usize_from_u32(reader.u32()?)?;
            slots.push(WrapSlot::decode(reader.take(len)?)?);
        }
        reader.finish()?;
        Ok(Self { slots })
    }
}

fn usize_from_u32(value: u32) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::Format("length does not fit in usize"))
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(Error::Format("length overflow"))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::Format("data truncated"))?;
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4-byte slice"),
        ))
    }

    fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Format("extra bytes left in the blob"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::SALT_LEN;
    use crate::secret::KEY_LEN;

    fn params() -> Argon2idParams {
        Argon2idParams::for_tests([0x77; SALT_LEN])
    }

    fn password_slot() -> (DataKey, WrapSlot) {
        let data_key = DataKey::generate().expect("CSPRNG");
        let (slot, _) = WrapSlot::from_password(
            &data_key,
            "master password".as_bytes(),
            params(),
            "primary password",
        )
        .expect("wrap");
        (data_key, slot)
    }

    #[test]
    fn password_wrapper_opens() {
        let (data_key, slot) = password_slot();
        let (opened, _) = slot
            .unlock_with_password("master password".as_bytes())
            .expect("unlock");
        assert_eq!(opened.as_key(), data_key.as_key());
        assert_eq!(slot.kind(), SlotKind::Password);
        assert_eq!(slot.label(), "primary password");
    }

    #[test]
    fn auth_hash_is_same_on_creation_and_unlock() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let (slot, created) =
            WrapSlot::from_password(&data_key, "password".as_bytes(), params(), "label")
                .expect("wrap");
        let (_, unlocked) = slot
            .unlock_with_password("password".as_bytes())
            .expect("unlock");
        assert_eq!(created, unlocked);
    }

    #[test]
    fn wrong_password_does_not_open() {
        let (_, slot) = password_slot();
        assert_eq!(
            slot.unlock_with_password("master password ".as_bytes())
                .unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn external_key_and_foreign_external_key() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let key = Key32::generate().expect("CSPRNG");
        let slot =
            WrapSlot::from_external_key(&data_key, &key, "MacBook, Touch ID").expect("wrap");

        let opened = slot.unlock_with_external_key(&key).expect("unlock");
        assert_eq!(opened.as_key(), data_key.as_key());

        let alien = Key32::generate().expect("CSPRNG");
        assert_eq!(
            slot.unlock_with_external_key(&alien).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn recovery_code_and_foreign_code() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let code = RecoveryCode::generate().expect("CSPRNG");
        let slot =
            WrapSlot::from_recovery_code(&data_key, &code, "recovery code").expect("wrap");

        let opened = slot
            .unlock_with_recovery_code(&code)
            .expect("unlock");
        assert_eq!(opened.as_key(), data_key.as_key());

        let alien = RecoveryCode::generate().expect("CSPRNG");
        assert_eq!(
            slot.unlock_with_recovery_code(&alien).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn three_wrappers_of_one_data_key() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let external = Key32::generate().expect("CSPRNG");
        let code = RecoveryCode::generate().expect("CSPRNG");

        let (password, _) =
            WrapSlot::from_password(&data_key, "password".as_bytes(), params(), "password")
                .expect("wrap");
        let keychain =
            WrapSlot::from_external_key(&data_key, &external, "keychain").expect("wrap");
        let recovery = WrapSlot::from_recovery_code(&data_key, &code, "code").expect("wrap");

        assert_eq!(
            password
                .unlock_with_password("password".as_bytes())
                .expect("password")
                .0
                .as_key(),
            data_key.as_key()
        );
        assert_eq!(
            keychain
                .unlock_with_external_key(&external)
                .expect("key")
                .as_key(),
            data_key.as_key()
        );
        assert_eq!(
            recovery
                .unlock_with_recovery_code(&code)
                .expect("code")
                .as_key(),
            data_key.as_key()
        );
    }

    #[test]
    fn slot_does_not_open_with_foreign_method() {
        let (_, slot) = password_slot();
        let key = Key32::generate().expect("CSPRNG");
        assert!(slot.unlock_with_external_key(&key).is_err());

        let code = RecoveryCode::generate().expect("CSPRNG");
        assert!(slot.unlock_with_recovery_code(&code).is_err());
    }

    #[test]
    fn slot_survives_serialization() {
        let (_, slot) = password_slot();
        let restored = WrapSlot::decode(&slot.encode()).expect("parse");
        assert_eq!(slot, restored);
        assert_eq!(
            restored
                .unlock_with_password("master password".as_bytes())
                .expect("unlock")
                .0
                .as_key(),
            slot.unlock_with_password("master password".as_bytes())
                .expect("unlock")
                .0
                .as_key()
        );
    }

    #[test]
    fn swapped_label_does_not_open() {
        let (_, slot) = password_slot();
        let mut tampered = slot.clone();
        tampered.label = "foreign label".to_owned();
        assert_eq!(
            tampered
                .unlock_with_password("master password".as_bytes())
                .unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn swapped_id_does_not_open() {
        let (_, slot) = password_slot();
        let mut tampered = slot.clone();
        tampered.id[0] ^= 0xFF;
        assert_eq!(
            tampered
                .unlock_with_password("master password".as_bytes())
                .unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn weakened_parameters_do_not_open_slot() {
        let (_, slot) = password_slot();
        let mut tampered = slot.clone();
        tampered.kdf = SlotKdf::Argon2id(
            Argon2idParams::new(8, 1, 1, [0x77; SALT_LEN]).expect("weak parameters"),
        );
        assert_eq!(
            tampered
                .unlock_with_password("master password".as_bytes())
                .unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn modified_wrapper_byte_does_not_open() {
        let (_, slot) = password_slot();
        for i in 0..slot.sealed.len() {
            let mut tampered = slot.clone();
            tampered.sealed[i] ^= 0x01;
            assert_eq!(
                tampered
                    .unlock_with_password("master password".as_bytes())
                    .unwrap_err(),
                Error::Decrypt,
                "wrap byte {i} was modified but the slot still opened"
            );
        }
    }

    #[test]
    fn corrupted_bytes_do_not_parse() {
        let (_, slot) = password_slot();
        let encoded = slot.encode();

        assert!(WrapSlot::decode(&[]).is_err());
        assert!(WrapSlot::decode(&encoded[..encoded.len() - 1]).is_err());

        let mut extra = encoded.clone();
        extra.push(0);
        assert!(WrapSlot::decode(&extra).is_err());

        let mut bad_version = encoded.clone();
        bad_version[0] = 99;
        assert!(WrapSlot::decode(&bad_version).is_err());

        let mut bad_kind = encoded.clone();
        bad_kind[1] = 99;
        assert!(WrapSlot::decode(&bad_kind).is_err());

        let external = WrapSlot::from_external_key(
            &DataKey::generate().expect("CSPRNG"),
            &Key32::generate().expect("CSPRNG"),
            "keychain",
        )
        .expect("wrap");
        let mut mismatched = external.encode();
        mismatched[1] = SlotKind::Password as u8;
        assert!(WrapSlot::decode(&mismatched).is_err());
    }

    #[test]
    fn slot_ids_differ() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let a =
            WrapSlot::from_external_key(&data_key, &Key32::generate().expect("CSPRNG"), "first")
                .expect("wrap");
        let b =
            WrapSlot::from_external_key(&data_key, &Key32::generate().expect("CSPRNG"), "second")
                .expect("wrap");
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn slot_list_survives_serialization() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let mut set = SlotSet::new();
        let (password, _) =
            WrapSlot::from_password(&data_key, "password".as_bytes(), params(), "password")
                .expect("wrap");
        set.push(password);
        set.push(
            WrapSlot::from_external_key(&data_key, &Key32::generate().expect("CSPRNG"), "keychain")
                .expect("wrap"),
        );

        let restored = SlotSet::decode(&set.encode()).expect("parse");
        assert_eq!(set, restored);
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.iter_kind(SlotKind::ExternalKey).count(), 1);
    }

    #[test]
    fn removing_keychain_wrapper_does_not_break_password() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let mut set = SlotSet::new();
        let (password, _) =
            WrapSlot::from_password(&data_key, "password".as_bytes(), params(), "password")
                .expect("wrap");
        set.push(password);
        let keychain =
            WrapSlot::from_external_key(&data_key, &Key32::generate().expect("CSPRNG"), "keychain")
                .expect("wrap");
        let keychain_id = *keychain.id();
        set.push(keychain);

        set.remove(&keychain_id).expect("removal");
        assert_eq!(set.len(), 1);
        assert!(set.find(&keychain_id).is_none());
        assert!(
            set.iter()
                .next()
                .expect("password remains")
                .unlock_with_password("password".as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn last_wrapper_cannot_be_removed() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let mut set = SlotSet::new();
        let slot =
            WrapSlot::from_external_key(&data_key, &Key32::generate().expect("CSPRNG"), "single")
                .expect("wrap");
        let id = *slot.id();
        set.push(slot);
        assert!(set.remove(&id).is_err());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn long_label_is_rejected() {
        let data_key = DataKey::generate().expect("CSPRNG");
        let long = "x".repeat(300);
        assert!(
            WrapSlot::from_external_key(&data_key, &Key32::generate().expect("CSPRNG"), &long)
                .is_err()
        );
    }

    #[test]
    fn wrapper_does_not_contain_data_key_in_plaintext() {
        let (data_key, slot) = password_slot();
        let encoded = slot.encode();
        let needle = data_key.as_key().as_bytes();
        assert!(
            !encoded.windows(KEY_LEN).any(|window| window == needle),
            "Data Key found in the serialized wrap"
        );
    }
}
