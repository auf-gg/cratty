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

/// Энтропия новой фразы восстановления: 24 слова BIP39.
pub const RECOVERY_ENTROPY_BYTES: usize = 32;

const MAX_ENTROPY_BYTES: usize = RECOVERY_ENTROPY_BYTES;

/// Секрет восстановления: 16 или 32 байта (12 или 24 слова BIP39) либо
/// 20 байт прежнего формата. Ключ обёртки всегда — HKDF от этих байт.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode {
    bytes: [u8; MAX_ENTROPY_BYTES],
    len: usize,
}

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCode(<скрыт>)")
    }
}

impl RecoveryCode {
    fn from_slice(entropy: &[u8]) -> Self {
        let mut bytes = [0u8; MAX_ENTROPY_BYTES];
        bytes[..entropy.len()].copy_from_slice(entropy);
        Self {
            bytes,
            len: entropy.len(),
        }
    }

    fn entropy(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn generate() -> Result<Self> {
        let mut entropy = Zeroizing::new(rng::array::<RECOVERY_ENTROPY_BYTES>()?);
        Ok(Self::from_slice(entropy.as_mut()))
    }

    /// Принимает 12 или 24 слова BIP39 (английский словарь) либо код прежнего
    /// формата из 37 символов.
    pub fn parse(input: &[u8]) -> Result<Self> {
        let words = input
            .split(|byte| matches!(byte, b'-' | b' ' | b'\t' | b'\r' | b'\n'))
            .filter(|word| !word.is_empty())
            .count();

        if matches!(words, 12 | 24) {
            return Self::parse_mnemonic(input);
        }

        let stripped = input
            .iter()
            .filter(|byte| !matches!(byte, b'-' | b' ' | b'\t' | b'\r' | b'\n'))
            .count();
        if stripped == RECOVERY_CODE_SYMBOLS + 1 {
            return Self::parse_legacy(input);
        }
        Err(Error::RecoveryCode("не то число слов"))
    }

    fn parse_mnemonic(input: &[u8]) -> Result<Self> {
        let text = core::str::from_utf8(input)
            .map_err(|_| Error::RecoveryCode("слова вне словаря BIP39"))?;
        let mut normalized = Zeroizing::new(String::with_capacity(text.len()));
        for word in text
            .split(|c: char| c == '-' || c.is_whitespace())
            .filter(|word| !word.is_empty())
        {
            if !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push_str(&word.to_lowercase());
        }

        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized)
            .map_err(|error| match error {
                bip39::Error::BadWordCount(_) => Error::RecoveryCode("не то число слов"),
                bip39::Error::UnknownWord(_) => Error::RecoveryCode("слова вне словаря BIP39"),
                _ => Error::RecoveryCode("контрольная сумма не сошлась"),
            })?;
        let (entropy, len) = mnemonic.to_entropy_array();
        let entropy = Zeroizing::new(entropy);
        Ok(Self::from_slice(&entropy[..len]))
    }

    fn parse_legacy(input: &[u8]) -> Result<Self> {
        let mut symbols = Vec::with_capacity(RECOVERY_CODE_SYMBOLS + 1);
        for &byte in input {
            match byte {
                b'-' | b' ' | b'\t' | b'\r' | b'\n' => continue,
                other => symbols.push(other.to_ascii_uppercase()),
            }
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

        Ok(Self::from_slice(bytes.as_ref()))
    }

    /// Слова BIP39 через пробел. Код прежнего формата (20 байт) показывается
    /// в прежнем виде: в слова он не укладывается.
    pub fn format_for_user(&self) -> SecretSlice<u8> {
        if self.len == RECOVERY_CODE_BYTES {
            return self.format_legacy();
        }
        let words = bip39::Mnemonic::from_entropy_in(bip39::Language::English, self.entropy())
            .map(|mnemonic| Zeroizing::new(mnemonic.to_string()))
            .unwrap_or_default();
        crate::aead::into_secret(words.as_bytes().to_vec())
    }

    fn format_legacy(&self) -> SecretSlice<u8> {
        let mut raw = Zeroizing::new([0u8; RECOVERY_CODE_BYTES]);
        raw.copy_from_slice(self.entropy());
        let mut out = Vec::with_capacity(RECOVERY_CODE_SYMBOLS + 8 + 1);
        base32::encode_into(raw.as_ref(), RECOVERY_CODE_SYMBOLS, 4, &mut out);
        out.push(b'-');
        out.push(CHECK_ALPHABET[usize::from(check_value(&raw))]);

        crate::aead::into_secret(out)
    }

    pub fn wrap_key(&self, salt: &[u8; RECOVERY_SALT_LEN]) -> Result<Key32> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), self.entropy());
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
    pub(crate) fn from_bytes<const N: usize>(bytes: [u8; N]) -> Self {
        assert!(matches!(N, 16 | 20 | 32));
        Self::from_slice(&bytes)
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
            assert_eq!(parsed.entropy(), bytes.as_slice());
        }
    }

    #[test]
    fn roundtrip_sgenerirovannogo_koda() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        let shown = shown(&code);
        assert_eq!(shown.split(' ').count(), 24);
        let parsed = RecoveryCode::parse(shown.as_bytes()).expect("разбор");
        assert_eq!(parsed.entropy(), code.entropy());
    }

    #[test]
    fn razbor_proshchaet_registr_defisy_i_pohozhie_simvoly() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        let canonical = shown(&code);

        let lowercase = canonical.to_lowercase();
        assert_eq!(
            RecoveryCode::parse(lowercase.as_bytes())
                .expect("разбор")
                .entropy(),
            code.entropy()
        );

        let no_dashes: String = canonical.chars().filter(|c| *c != '-').collect();
        assert_eq!(
            RecoveryCode::parse(no_dashes.as_bytes())
                .expect("разбор")
                .entropy(),
            code.entropy()
        );

        let spaced = canonical.replace('-', "  ");
        assert_eq!(
            RecoveryCode::parse(spaced.as_bytes())
                .expect("разбор")
                .entropy(),
            code.entropy()
        );

        let handwritten = canonical.replace('1', "I").replace('0', "O");
        assert_eq!(
            RecoveryCode::parse(handwritten.as_bytes())
                .expect("разбор")
                .entropy(),
            code.entropy()
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
        assert_ne!(a.entropy(), b.entropy());
    }

    #[test]
    fn debug_ne_pechataet_kod() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        assert_eq!(format!("{code:?}"), "RecoveryCode(<скрыт>)");
    }

    const WORDS_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const WORDS_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const WORDS_12_7F: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    #[test]
    fn bip39_izvestnye_vektory_12_i_24_slov() {
        let cases: [(&[u8], &str); 3] = [
            (&[0x00; 16], WORDS_12),
            (&[0x7f; 16], WORDS_12_7F),
            (&[0x00; 32], WORDS_24),
        ];
        for (entropy, words) in cases {
            let parsed = RecoveryCode::parse(words.as_bytes()).expect("разбор");
            assert_eq!(parsed.entropy(), entropy);
            assert_eq!(shown(&parsed), words);
        }
    }

    #[test]
    fn novaya_fraza_iz_24_slov_perezhivaet_roundtrip() {
        let code = RecoveryCode::generate().expect("CSPRNG");
        let text = shown(&code);
        assert_eq!(text.split(' ').count(), 24);
        assert!(!text.contains('-'));
        let parsed = RecoveryCode::parse(text.as_bytes()).expect("разбор");
        assert_eq!(parsed.entropy(), code.entropy());
        let salt = [0x22; RECOVERY_SALT_LEN];
        assert_eq!(
            parsed.wrap_key(&salt).expect("вывод"),
            code.wrap_key(&salt).expect("вывод")
        );
    }

    #[test]
    fn fraza_proshchaet_registr_defisy_i_perenosy() {
        let messy = WORDS_12.to_uppercase().replace(' ', " \n-  ");
        let parsed = RecoveryCode::parse(messy.as_bytes()).expect("разбор");
        assert_eq!(parsed.entropy(), &[0x00; 16]);
    }

    #[test]
    fn slova_v_drugom_poryadke_otvergayutsya() {
        let swapped = WORDS_12_7F.split(' ').rev().collect::<Vec<_>>().join(" ");
        assert_eq!(
            RecoveryCode::parse(swapped.as_bytes()).unwrap_err(),
            Error::RecoveryCode("контрольная сумма не сошлась")
        );
    }

    #[test]
    fn slovo_vne_slovarya_otvergaetsya() {
        let text = WORDS_12.replace("about", "cratty");
        assert_eq!(
            RecoveryCode::parse(text.as_bytes()).unwrap_err(),
            Error::RecoveryCode("слова вне словаря BIP39")
        );
    }

    #[test]
    fn podmenennoe_poslednee_slovo_otvergaetsya() {
        let text = WORDS_12.replace("about", "abandon");
        assert_eq!(
            RecoveryCode::parse(text.as_bytes()).unwrap_err(),
            Error::RecoveryCode("контрольная сумма не сошлась")
        );
    }

    #[test]
    fn nevernoe_chislo_slov_otvergaetsya() {
        let eleven = WORDS_12.rsplit_once(' ').expect("слова").0;
        assert_eq!(
            RecoveryCode::parse(eleven.as_bytes()).unwrap_err(),
            Error::RecoveryCode("не то число слов")
        );
    }

    #[test]
    fn staryy_kod_prinimaetsya_po_prezhnemu_i_pokazyvaetsya_po_prezhnemu() {
        let legacy = "04HM-ASW9-NF6Y-Y093-8NKR-KAYD-XW0J-6HB7-N";
        let parsed = RecoveryCode::parse(legacy.as_bytes()).expect("разбор");
        assert_eq!(parsed.entropy().len(), RECOVERY_CODE_BYTES);
        assert_eq!(shown(&parsed), legacy);
        let compact: String = legacy.chars().filter(|c| *c != '-').collect();
        assert_eq!(
            RecoveryCode::parse(compact.as_bytes())
                .expect("разбор")
                .entropy(),
            parsed.entropy()
        );
    }
}
