use crate::error::{Error, Result};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; KEY_LEN]);

impl Key32 {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        crate::rng::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Format("ключ не 32 байта"))?;
        Ok(Self(arr))
    }
}

impl core::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key32(<скрыт>)")
    }
}

impl ConstantTimeEq for Key32 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Key32 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_ne_pechataet_kluch() {
        let key = Key32::from_bytes([0xAB; KEY_LEN]);
        let text = format!("{key:?}");
        assert_eq!(text, "Key32(<скрыт>)");
        assert!(!text.contains("171") && !text.to_lowercase().contains("ab"));
    }

    #[test]
    fn ravenstvo_za_postoyannoe_vremya() {
        let a = Key32::from_bytes([1; KEY_LEN]);
        let b = Key32::from_bytes([1; KEY_LEN]);
        let mut other = [1u8; KEY_LEN];
        other[31] = 2;
        let c = Key32::from_bytes(other);

        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    #[test]
    fn from_slice_trebuet_tochnoy_dliny() {
        assert!(Key32::from_slice(&[0u8; 31]).is_err());
        assert!(Key32::from_slice(&[0u8; 33]).is_err());
        assert!(Key32::from_slice(&[0u8; 32]).is_ok());
    }

    #[test]
    fn generate_ne_daet_odinakovyh_klyuchey() {
        let a = Key32::generate().expect("CSPRNG ОС недоступен");
        let b = Key32::generate().expect("CSPRNG ОС недоступен");
        assert_ne!(a, b);
        assert_ne!(a.as_bytes(), &[0u8; KEY_LEN]);
    }
}
