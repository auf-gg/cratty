use crate::aad::DOMAIN;
use crate::base32;
use crate::error::{Error, Result};
use crate::rng;
use crate::secret::{KEY_LEN, Key32};
use hkdf::Hkdf;
use secrecy::SecretSlice;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const RECOVERY_CODE_BITS: usize = 160;

pub const RECOVERY_CODE_BYTES: usize = RECOVERY_CODE_BITS / 8;

pub const RECOVERY_CODE_SYMBOLS: usize = RECOVERY_CODE_BITS / 5;

const CHECK_ALPHABET: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

pub const RECOVERY_SALT_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode([u8; RECOVERY_CODE_BYTES]);

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCode(<скрыт>)")
    }
}

impl RecoveryCode {
    pub fn generate() -> Result<Self> {
        Ok(Self(rng::array()?))
    }

    pub fn parse(input: &[u8]) -> Result<Self> {
        let mut symbols = Vec::with_capacity(RECOVERY_CODE_SYMBOLS + 1);
        for &byte in input {
            match byte {
                b'-' | b' ' | b'\t' | b'\r' | b'\n' => continue,
                other => symbols.push(other.to_ascii_uppercase()),
            }
        }

        if symbols.len() != RECOVERY_CODE_SYMBOLS + 1 {
            return Err(Error::RecoveryCode("не то число символов"));
        }

        let mut bytes = Zeroizing::new([0u8; RECOVERY_CODE_BYTES]);
        let mut bit = 0usize;
        for &symbol in &symbols[..RECOVERY_CODE_SYMBOLS] {
            let value = base32::decode_symbol(symbol)
                .ok_or(Error::RecoveryCode("символ вне алфавита Crockford base32"))?;
            for offset in 0..5 {
                if value & (1 << (4 - offset)) != 0 {
                    let position = bit + offset;
                    bytes[position / 8] |= 1 << (7 - position % 8);
                }
            }
            bit += 5;
        }

        let given = decode_check_symbol(symbols[RECOVERY_CODE_SYMBOLS])
            .ok_or(Error::RecoveryCode("контрольный символ вне алфавита"))?;
        let expected = check_value(&bytes);
        if !bool::from(given.ct_eq(&expected)) {
            return Err(Error::RecoveryCode("контрольный символ не сошёлся"));
        }

        Ok(Self(*bytes))
    }

    pub fn format_for_user(&self) -> SecretSlice<u8> {
        let mut out = Vec::with_capacity(RECOVERY_CODE_SYMBOLS + 8 + 1);
        base32::encode_into(&self.0, RECOVERY_CODE_SYMBOLS, 4, &mut out);
        out.push(b'-');
        out.push(CHECK_ALPHABET[usize::from(check_value(&self.0))]);

        crate::aead::into_secret(out)
    }

    pub fn wrap_key(&self, salt: &[u8; RECOVERY_SALT_LEN]) -> Result<Key32> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut info = Vec::with_capacity(DOMAIN.len() + 1 + 13);
        info.extend_from_slice(DOMAIN);
        info.push(b' ');
        info.extend_from_slice(b"recovery-wrap");

        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(&info, out.as_mut())
            .map_err(|_| Error::Kdf("HKDF отказал на длине вывода"))?;
        Ok(Key32::from_bytes(*out))
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; RECOVERY_CODE_BYTES]) -> Self {
        Self(bytes)
    }
}

fn check_value(bytes: &[u8; RECOVERY_CODE_BYTES]) -> u8 {
    let mut remainder = 0u32;
    for &byte in bytes {
        remainder = (remainder * 256 + u32::from(byte)) % 37;
    }
    remainder as u8
}

fn decode_check_symbol(symbol: u8) -> Option<u8> {
    match symbol {
        b'I' | b'L' => Some(1),
        b'O' => Some(0),
        other => CHECK_ALPHABET
            .iter()
            .position(|&c| c == other)
            .map(|index| index as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn shown(code: &RecoveryCode) -> String {
        String::from_utf8(code.format_for_user().expose_secret().to_vec()).expect("вывод — ASCII")
    }

    #[test]
    fn crockford_izvestnye_vektory() {
        let cases: [([u8; RECOVERY_CODE_BYTES], &str); 4] = [
            (
                [0x00; RECOVERY_CODE_BYTES],
                "0000-0000-0000-0000-0000-0000-0000-0000-0",
            ),
            (
                [0xFF; RECOVERY_CODE_BYTES],
                "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-8",
            ),
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
                ],
                "000G-40R4-0M30-E209-185G-R38E-1W81-24GK-R",
            ),
            (
                [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
                ],
                "04HM-ASW9-NF6Y-Y093-8NKR-KAYD-XW0J-6HB7-N",
            ),
        ];

        for (bytes, expected) in cases {
            let code = RecoveryCode::from_bytes(bytes);
            assert_eq!(shown(&code), expected);
            let parsed = RecoveryCode::parse(expected.as_bytes()).expect("разбор");
            assert_eq!(parsed.0, bytes);
        }
    }

    #[test]
    fn roundtrip_sgenerirovannogo_koda() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        let shown = shown(&code);
        assert_eq!(shown.len(), RECOVERY_CODE_SYMBOLS + 8 + 1);
        let parsed = RecoveryCode::parse(shown.as_bytes()).expect("разбор");
        assert_eq!(parsed.0, code.0);
    }

    #[test]
    fn razbor_proshchaet_registr_defisy_i_pohozhie_simvoly() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        let canonical = shown(&code);

        let lowercase = canonical.to_lowercase();
        assert_eq!(
            RecoveryCode::parse(lowercase.as_bytes()).expect("разбор").0,
            code.0
        );

        let no_dashes: String = canonical.chars().filter(|c| *c != '-').collect();
        assert_eq!(
            RecoveryCode::parse(no_dashes.as_bytes()).expect("разбор").0,
            code.0
        );

        let spaced = canonical.replace('-', "  ");
        assert_eq!(
            RecoveryCode::parse(spaced.as_bytes()).expect("разбор").0,
            code.0
        );

        let handwritten = canonical.replace('1', "I").replace('0', "O");
        assert_eq!(
            RecoveryCode::parse(handwritten.as_bytes())
                .expect("разбор")
                .0,
            code.0
        );
    }

    #[test]
    fn lyubaya_odinochnaya_opechatka_lovitsya() {
        let code = RecoveryCode::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ]);
        let canonical: Vec<u8> = shown(&code).bytes().filter(|byte| *byte != b'-').collect();

        for position in 0..RECOVERY_CODE_SYMBOLS {
            for &replacement in base32::ALPHABET.iter() {
                if replacement == canonical[position] {
                    continue;
                }
                let mut typo = canonical.clone();
                typo[position] = replacement;
                assert!(
                    RecoveryCode::parse(&typo).is_err(),
                    "замена символа {position} на {} прошла проверку",
                    replacement as char
                );
            }
        }
    }

    #[test]
    fn ne_ta_dlina_otvergaetsya() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        let canonical = shown(&code);
        assert!(RecoveryCode::parse(&canonical.as_bytes()[..canonical.len() - 1]).is_err());
        assert!(RecoveryCode::parse(format!("{canonical}0").as_bytes()).is_err());
        assert!(RecoveryCode::parse(b"").is_err());
    }

    #[test]
    fn simvol_u_v_dannyh_otvergaetsya() {
        let code = RecoveryCode::from_bytes([0x00; RECOVERY_CODE_BYTES]);
        let mut canonical: Vec<u8> = shown(&code).bytes().filter(|b| *b != b'-').collect();
        canonical[0] = b'U';
        assert_eq!(
            RecoveryCode::parse(&canonical).unwrap_err(),
            Error::RecoveryCode("символ вне алфавита Crockford base32")
        );
    }

    #[test]
    fn vyvod_klyucha_izvestnyy_vektor() {
        let code = RecoveryCode::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        ]);
        let key = code.wrap_key(&[0x11; RECOVERY_SALT_LEN]).expect("вывод");
        assert_eq!(
            key.as_bytes(),
            &hex_literal::hex!("8931c034712959f218240a19722d7d296318569fff3020daa89a4c98822fdb57")
        );
    }

    #[test]
    fn vyvod_klyucha_determinirovan_i_zavisit_ot_soli() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        let salt = [0x11; RECOVERY_SALT_LEN];
        let other_salt = [0x12; RECOVERY_SALT_LEN];

        assert_eq!(
            code.wrap_key(&salt).expect("вывод"),
            code.wrap_key(&salt).expect("вывод")
        );
        assert_ne!(
            code.wrap_key(&salt).expect("вывод"),
            code.wrap_key(&other_salt).expect("вывод")
        );

        let another = RecoveryCode::generate().expect("CSPRNG");
        assert_ne!(
            code.wrap_key(&salt).expect("вывод"),
            another.wrap_key(&salt).expect("вывод")
        );
    }

    #[test]
    fn kody_ne_povtoryayutsya() {
        let a = RecoveryCode::generate().expect("CSPRNG");
        let b = RecoveryCode::generate().expect("CSPRNG");
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn debug_ne_pechataet_kod() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        assert_eq!(format!("{code:?}"), "RecoveryCode(<скрыт>)");
    }
}
