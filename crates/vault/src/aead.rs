use crate::error::{Error, Result};
use crate::rng;
use crate::secret::Key32;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::array::Array;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use secrecy::SecretSlice;
use zeroize::Zeroize;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = rng::array()?;
    seal_with_nonce(key, &nonce, aad, plaintext)
}

fn seal_with_nonce(
    key: &Key32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&Array(*key.as_bytes()));
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(&Array(*nonce), payload)
        .map_err(|_| Error::Decrypt)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(key: &Key32, aad: &[u8], sealed: &[u8]) -> Result<SecretSlice<u8>> {
    let plaintext = open_to_vec(key, aad, sealed)?;
    Ok(into_secret(plaintext))
}

pub(crate) fn open_to_vec(key: &Key32, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, body) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Decrypt)?;

    let cipher = XChaCha20Poly1305::new(&Array(*key.as_bytes()));
    let payload = Payload { msg: body, aad };
    cipher
        .decrypt(&Array(nonce), payload)
        .map_err(|_| Error::Decrypt)
}

pub(crate) fn into_secret(mut plaintext: Vec<u8>) -> SecretSlice<u8> {
    let secret = SecretSlice::new(plaintext.as_slice().into());
    plaintext.zeroize();
    secret
}

#[cfg(test)]
pub(crate) fn key_material_aad(context: &str, version: u8) -> Vec<u8> {
    let mut aad = crate::aad::Aad::new(context);
    aad.u8(version);
    aad.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use secrecy::ExposeSecret;

    #[test]
    fn xchacha20poly1305_izvestnyy_vektor() {
        let key = Key32::from_bytes(hex!(
            "808182838485868788898a8b8c8d8e8f 909192939495969798999a9b9c9d9e9f"
        ));
        let nonce = hex!("404142434445464748494a4b 4c4d4e4f5051525354555657");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
            If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct = hex!(
            "bd6d179d3e83d43b9576579493c0e939"
            "572a1700252bfaccbed2902c21396cbb"
            "731c7f1b0b4aa6440bf3a82f4eda7e39"
            "ae64c6708c54c216cb96b72e1213b452"
            "2f8c9ba40db5d945b11b69b982c1bb9e"
            "3f3fac2bc369488f76b2383565d3fff9"
            "21f9664c97637da9768812f615c68b13"
            "b52e"
        );
        let expected_tag = hex!("c0875924c1c7987947deafd8780acf49");

        let sealed = seal_with_nonce(&key, &nonce, &aad, plaintext).expect("шифрование");

        assert_eq!(
            &sealed[..NONCE_LEN],
            &nonce,
            "nonce кладётся в начало блоба"
        );
        let body = &sealed[NONCE_LEN..];
        assert_eq!(&body[..body.len() - TAG_LEN], &expected_ct[..]);
        assert_eq!(&body[body.len() - TAG_LEN..], &expected_tag[..]);

        let opened = open(&key, &aad, &sealed).expect("расшифровка");
        assert_eq!(opened.expose_secret(), plaintext.as_slice());
    }

    fn fixture() -> (Key32, Vec<u8>, Vec<u8>) {
        let key = Key32::from_bytes([7u8; 32]);
        let aad = key_material_aad("test", 1);
        let sealed = seal(&key, &aad, "секрет".as_bytes()).expect("шифрование");
        (key, aad, sealed)
    }

    #[test]
    fn roundtrip() {
        let (key, aad, sealed) = fixture();
        let opened = open(&key, &aad, &sealed).expect("расшифровка");
        assert_eq!(opened.expose_secret(), "секрет".as_bytes());
        assert_eq!(sealed.len(), NONCE_LEN + "секрет".len() + TAG_LEN);
    }

    #[test]
    fn chuzhoy_kluch_ne_otkryvaet() {
        let (_, aad, sealed) = fixture();
        let alien = Key32::from_bytes([8u8; 32]);
        assert_eq!(open(&alien, &aad, &sealed).unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn izmenennyy_bayt_shifroteksta_ne_otkryvaet() {
        let (key, aad, sealed) = fixture();
        for i in 0..sealed.len() {
            let mut damaged = sealed.clone();
            damaged[i] ^= 0x01;
            assert_eq!(
                open(&key, &aad, &damaged).unwrap_err(),
                Error::Decrypt,
                "байт {i} изменён, а блоб всё равно открылся"
            );
        }
    }

    #[test]
    fn izmenennyy_aad_ne_otkryvaet() {
        let (key, _, sealed) = fixture();
        let other = key_material_aad("test", 2);
        assert_eq!(open(&key, &other, &sealed).unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn obrezannyy_blob_ne_otkryvaet() {
        let (key, aad, sealed) = fixture();
        for cut in 0..sealed.len() {
            assert_eq!(
                open(&key, &aad, &sealed[..cut]).unwrap_err(),
                Error::Decrypt,
                "блоб обрезан до {cut} байт и открылся"
            );
        }
    }

    #[test]
    fn nonce_ne_povtoryaetsya() {
        let key = Key32::from_bytes([7u8; 32]);
        let aad = key_material_aad("test", 1);
        let a = seal(&key, &aad, "одно и то же".as_bytes()).expect("шифрование");
        let b = seal(&key, &aad, "одно и то же".as_bytes()).expect("шифрование");
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a[NONCE_LEN..], b[NONCE_LEN..]);
    }
}
