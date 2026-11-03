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
                        "длина идентификатора ",
                        stringify!($name)
                    )));
                }
                if !text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                    return Err(Error::Format(concat!(
                        "идентификатор ",
                        stringify!($name),
                        " не строчный hex"
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
    "Идентификатор хранилища. Входит в AAD каждой записи."
);
id_type!(
    RecordId,
    "Идентификатор записи. Он же имя файла и часть AAD."
);
id_type!(
    DeviceId,
    "Идентификатор устройства. Тайбрейкер при слиянии в M13."
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
    fn identifikatory_ne_povtoryayutsya() {
        let a = RecordId::generate().expect("CSPRNG");
        let b = RecordId::generate().expect("CSPRNG");
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), ID_BYTES * 2);
    }

    #[test]
    fn razbor_prinimaet_svoi_identifikatory() {
        let id = VaultId::generate().expect("CSPRNG");
        assert_eq!(VaultId::parse(id.as_str()).expect("разбор"), id);
    }

    #[test]
    fn razbor_otvergaet_vsyo_ostalnoe() {
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
                "идентификатор {bad:?} прошёл разбор"
            );
        }
    }

    #[test]
    fn hex_bez_verhnego_registra() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }
}
