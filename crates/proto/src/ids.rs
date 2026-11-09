use crate::error::{Error, Result};

const ID_BYTES: usize = 16;

macro_rules! id_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn generate() -> Result<Self> {
                let mut bytes = [0u8; ID_BYTES];
                getrandom::fill(&mut bytes).map_err(|_| Error::Rng)?;
                Ok(Self(to_hex(&bytes)))
            }

            pub fn parse(text: &str) -> Result<Self> {
                if text.len() != ID_BYTES * 2 {
                    return Err(Error::Format(concat!(
                        "length of identifier ",
                        stringify!($name)
                    )));
                }
                if !text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                    return Err(Error::Format(concat!(
                        "identifier ",
                        stringify!($name),
                        " is not lowercase hex"
                    )));
                }
                Ok(Self(text.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(
    VaultId,
    "Vault identifier. Part of the AAD of every record."
);
id_type!(
    RecordId,
    "Record identifier. Also the file name and part of the AAD."
);
id_type!(
    DeviceId,
    "Device identifier. Tie-breaker when merging in M13."
);

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0F)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_do_not_repeat() {
        let a = RecordId::generate().expect("CSPRNG");
        let b = RecordId::generate().expect("CSPRNG");
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), ID_BYTES * 2);
    }

    #[test]
    fn parsing_accepts_own_ids() {
        let id = VaultId::generate().expect("CSPRNG");
        assert_eq!(VaultId::parse(id.as_str()).expect("parse"), id);
    }

    #[test]
    fn parsing_rejects_everything_else() {
        for bad in [
            "",
            "../../etc/passwd",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcd/f",
            "0123456789abcdef0123456789abcd f",
        ] {
            assert!(
                RecordId::parse(bad).is_err(),
                "identifier {bad:?} passed parsing"
            );
        }
    }

    #[test]
    fn hex_has_no_uppercase() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }
}
