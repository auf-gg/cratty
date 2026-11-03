use anyhow::{Context, Result, anyhow, bail};
use russh::keys::signature::{Signer, Verifier};
use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::{self, HashAlg, Signature};
use russh::keys::{PrivateKey, PublicKey};

pub fn public_blob(key: &PublicKey) -> Result<Vec<u8>> {
    let mut blob = Vec::new();
    key.key_data()
        .encode(&mut blob)
        .map_err(|error| anyhow!("не собрать публичный ключ: {error}"))?;
    Ok(blob)
}

pub fn parse_public(blob: &[u8]) -> Result<PublicKey> {
    russh::keys::key::parse_public_key(blob)
        .map_err(|error| anyhow!("публичный ключ не разбирается: {error}"))
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub fn decode_private(text: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    russh::keys::decode_secret_key(text, passphrase)
        .map_err(|error| anyhow!("ключ не читается: {error}"))
}

pub fn is_encrypted(text: &str) -> Result<bool> {
    match russh::keys::decode_secret_key(text, None) {
        Ok(_) => Ok(false),
        Err(russh::keys::Error::KeyIsEncrypted) => Ok(true),
        Err(error) => Err(anyhow!("ключ не читается: {error}")),
    }
}

pub fn to_openssh(key: &PrivateKey) -> Result<Vec<u8>> {
    let text = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|error| anyhow!("ключ не сериализуется: {error}"))?;
    Ok(text.as_bytes().to_vec())
}

pub fn sign(key: &PrivateKey, data: &[u8], hash: Option<HashAlg>) -> Result<Vec<u8>> {
    let signature: Signature = match key.key_data() {
        KeypairData::Rsa(keypair) => {
            let hash = hash.unwrap_or(HashAlg::Sha512);
            Signer::try_sign(&(keypair, Some(hash)), data)
                .map_err(|error| anyhow!("не подписать ключом RSA: {error}"))?
        }
        keypair => {
            Signer::try_sign(keypair, data).map_err(|error| anyhow!("не подписать: {error}"))?
        }
    };

    let mut out = Vec::new();
    signature
        .encode(&mut out)
        .map_err(|error| anyhow!("подпись не сериализуется: {error}"))?;
    Ok(out)
}

pub fn verify_session_bind(
    host_key: &[u8],
    session_id: &[u8],
    signature: &[u8],
) -> Result<PublicKey> {
    let key = parse_public(host_key).context("ключ сервера в привязке")?;
    let signature = Signature::try_from(signature)
        .map_err(|error| anyhow!("подпись в привязке не разбирается: {error}"))?;
    if Verifier::verify(key.key_data(), session_id, &signature).is_err() {
        bail!("подпись сервера в привязке не сходится");
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> PrivateKey {
        PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            ssh_key::Algorithm::Ed25519,
        )
        .expect("генерация ключа")
    }

    #[test]
    fn publichnyy_blob_razbiraetsya_obratno() {
        let key = key();
        let blob = public_blob(key.public_key()).expect("блоб");
        let parsed = parse_public(&blob).expect("разбор");
        assert_eq!(parsed.key_data(), key.public_key().key_data());
        assert!(fingerprint(&parsed).starts_with("SHA256:"));
    }

    #[test]
    fn podpis_proveryaetsya_publichnoy_chastyu() {
        let key = key();
        let signature = sign(&key, "данные под подписью".as_bytes(), None).expect("подпись");

        let decoded = Signature::try_from(&signature[..]).expect("разбор подписи");
        Verifier::verify(
            key.public_key().key_data(),
            "данные под подписью".as_bytes(),
            &decoded,
        )
        .expect("подпись не сошлась");

        assert!(
            Verifier::verify(
                key.public_key().key_data(),
                "другие данные".as_bytes(),
                &decoded
            )
            .is_err()
        );
    }

    #[test]
    fn klyuch_perezhivaet_hranilishche() {
        let key = key();
        let stored = to_openssh(&key).expect("сериализация");
        let text = String::from_utf8(stored).expect("текст OpenSSH");
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(!is_encrypted(&text).expect("проверка"));

        let restored = decode_private(&text, None).expect("разбор");
        assert_eq!(
            restored.public_key().key_data(),
            key.public_key().key_data()
        );
    }

    #[test]
    fn zashifrovannyy_klyuch_otlichaetsya_ot_bitogo() {
        let key = key();
        let encrypted = key
            .encrypt(&mut russh::keys::key::safe_rng(), "пароль")
            .expect("шифрование")
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("сериализация");

        assert!(is_encrypted(&encrypted).expect("проверка"));
        assert!(decode_private(&encrypted, None).is_err());
        decode_private(&encrypted, Some("пароль")).expect("разбор с паролем");
        assert!(decode_private(&encrypted, Some("не тот")).is_err());

        assert!(is_encrypted("-----BEGIN OPENSSH PRIVATE KEY-----\nмусор\n").is_err());
    }

    #[test]
    fn privyazka_s_chuzhoy_podpisyu_ne_prinimaetsya() {
        let host = key();
        let session_id = "идентификатор сессии".as_bytes();
        let signature = sign(&host, session_id, None).expect("подпись");
        let host_blob = public_blob(host.public_key()).expect("блоб");

        verify_session_bind(&host_blob, session_id, &signature).expect("привязка");

        let other = sign(&host, "другая сессия".as_bytes(), None).expect("подпись");
        assert!(verify_session_bind(&host_blob, session_id, &other).is_err());

        let alien = key();
        let alien_signature = sign(&alien, session_id, None).expect("подпись");
        assert!(verify_session_bind(&host_blob, session_id, &alien_signature).is_err());
    }
}
