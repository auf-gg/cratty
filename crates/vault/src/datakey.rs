use crate::aad::DOMAIN;
use crate::error::{Error, Result};
use crate::secret::{KEY_LEN, Key32};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Records,
    Identity,
    SshKeys,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Records => b"records",
            Self::Identity => b"identity",
            Self::SshKeys => b"ssh-keys",
        }
    }

    fn info(self) -> Vec<u8> {
        let mut info = Vec::with_capacity(DOMAIN.len() + 1 + self.label().len());
        info.extend_from_slice(DOMAIN);
        info.push(b' ');
        info.extend_from_slice(self.label());
        info
    }
}

#[derive(Clone, Debug)]
pub struct DataKey(Key32);

impl DataKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(Key32::generate()?))
    }

    pub fn from_key(key: Key32) -> Self {
        Self(key)
    }

    pub(crate) fn as_key(&self) -> &Key32 {
        &self.0
    }

    fn subkey(&self, purpose: Purpose) -> Result<Key32> {
        expand(&self.0, purpose)
    }

    pub fn record_key(&self) -> Result<RecordKey> {
        Ok(RecordKey(self.subkey(Purpose::Records)?))
    }

    pub fn identity_key(&self) -> Result<IdentityKey> {
        Ok(IdentityKey(self.subkey(Purpose::Identity)?))
    }

    pub fn ssh_keys_key(&self) -> Result<SshKeysKey> {
        Ok(SshKeysKey(self.subkey(Purpose::SshKeys)?))
    }
}

pub(crate) fn expand(root: &Key32, purpose: Purpose) -> Result<Key32> {
    let hkdf = Hkdf::<Sha256>::from_prk(root.as_bytes())
        .map_err(|_| Error::Kdf("root key is not usable as a PRK"))?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&purpose.info(), out.as_mut())
        .map_err(|_| Error::Kdf("HKDF rejected the output length"))?;
    Ok(Key32::from_bytes(*out))
}

macro_rules! purpose_key {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug)]
        pub struct $name(Key32);

        impl $name {
            #[allow(dead_code)]
            pub(crate) fn as_key(&self) -> &Key32 {
                &self.0
            }
        }
    };
}

purpose_key!(RecordKey, "Record encryption key.");
purpose_key!(IdentityKey, "Key for wrapping the member's key pairs.");
purpose_key!(SshKeysKey, "Key for wrapping private SSH keys.");

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn hkdf_sha256_rfc5869_known_vector() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(
            prk.as_slice(),
            hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );

        let mut okm = [0u8; 42];
        hkdf.expand(&info, &mut okm).expect("expand");
        assert_eq!(
            okm,
            hex!(
                "3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"
            )
        );
    }

    fn fixed() -> DataKey {
        DataKey::from_key(Key32::from_bytes([0x42; KEY_LEN]))
    }

    #[test]
    fn subkeys_known_vector() {
        let dk = fixed();
        assert_eq!(
            dk.record_key().expect("subkey").as_key().as_bytes(),
            &hex!("570eef53b1acbada981f420cfff12901a7dd65fc6a4598355ceb5664e48e2f30")
        );
        assert_eq!(
            dk.identity_key().expect("subkey").as_key().as_bytes(),
            &hex!("cfdf689c7f6ea832d43bd1424587a91c70c1519a45b01508cf7aa76a6525da7d")
        );
        assert_eq!(
            dk.ssh_keys_key().expect("subkey").as_key().as_bytes(),
            &hex!("e5515c2ad706d7b1135a839131b4fcc132b5653e747421f3c4217f78395ec934")
        );
    }

    #[test]
    fn purposes_do_not_overlap() {
        let dk = fixed();
        let r = dk.record_key().expect("subkey");
        let i = dk.identity_key().expect("subkey");
        let s = dk.ssh_keys_key().expect("subkey");

        assert_ne!(r.as_key(), i.as_key());
        assert_ne!(r.as_key(), s.as_key());
        assert_ne!(i.as_key(), s.as_key());
        assert_ne!(r.as_key(), dk.as_key());
    }

    #[test]
    fn subkeys_are_deterministic() {
        let a = fixed().record_key().expect("subkey");
        let b = fixed().record_key().expect("subkey");
        assert_eq!(a.as_key(), b.as_key());
    }

    #[test]
    fn different_data_key_gives_different_subkeys() {
        let a = fixed().record_key().expect("subkey");
        let other = DataKey::from_key(Key32::from_bytes([0x43; KEY_LEN]));
        let b = other.record_key().expect("subkey");
        assert_ne!(a.as_key(), b.as_key());
    }

    #[test]
    fn generate_does_not_repeat() {
        let a = DataKey::generate().expect("CSPRNG");
        let b = DataKey::generate().expect("CSPRNG");
        assert_ne!(a.as_key(), b.as_key());
    }

    #[test]
    fn debug_does_not_print_keys() {
        let dk = fixed();
        assert!(format!("{dk:?}").contains("<hidden>"));
        assert!(format!("{:?}", dk.record_key().expect("subkey")).contains("<hidden>"));
    }
}
