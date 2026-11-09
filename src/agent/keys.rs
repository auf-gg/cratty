use rust_i18n::t;
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
        .map_err(|error| anyhow!(t!("agent.build_public_failed", error = error)))?;
    Ok(blob)
}

pub fn parse_public(blob: &[u8]) -> Result<PublicKey> {
    russh::keys::key::parse_public_key(blob)
        .map_err(|error| anyhow!(t!("agent.parse_public_failed", error = error)))
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub fn decode_private(text: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    russh::keys::decode_secret_key(text, passphrase)
        .map_err(|error| anyhow!(t!("agent.read_key_failed", error = error)))
}

pub fn is_encrypted(text: &str) -> Result<bool> {
    match russh::keys::decode_secret_key(text, None) {
        Ok(_) => Ok(false),
        Err(russh::keys::Error::KeyIsEncrypted) => Ok(true),
        Err(error) => Err(anyhow!(t!("agent.read_key_failed", error = error))),
    }
}

pub fn to_openssh(key: &PrivateKey) -> Result<Vec<u8>> {
    let text = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|error| anyhow!(t!("agent.serialize_key_failed", error = error)))?;
    Ok(text.as_bytes().to_vec())
}

pub fn sign(key: &PrivateKey, data: &[u8], hash: Option<HashAlg>) -> Result<Vec<u8>> {
    let signature: Signature = match key.key_data() {
        KeypairData::Rsa(keypair) => {
            let hash = hash.unwrap_or(HashAlg::Sha512);
            Signer::try_sign(&(keypair, Some(hash)), data)
                .map_err(|error| anyhow!(t!("agent.sign_rsa_failed", error = error)))?
        }
        keypair => {
            Signer::try_sign(keypair, data).map_err(|error| anyhow!(t!("agent.sign_failed", error = error)))?
        }
    };

    let mut out = Vec::new();
    signature
        .encode(&mut out)
        .map_err(|error| anyhow!(t!("agent.serialize_signature_failed", error = error)))?;
    Ok(out)
}

pub fn verify_session_bind(
    host_key: &[u8],
    session_id: &[u8],
    signature: &[u8],
) -> Result<PublicKey> {
    let key = parse_public(host_key).context(t!("agent.bind_server_key"))?;
    let signature = Signature::try_from(signature)
        .map_err(|error| anyhow!(t!("agent.bind_parse_signature_failed", error = error)))?;
    if Verifier::verify(key.key_data(), session_id, &signature).is_err() {
        bail!(t!("agent.bind_signature_mismatch"));
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
        .expect("generate key")
    }

    #[test]
    fn public_blob_parses_back() {
        let key = key();
        let blob = public_blob(key.public_key()).expect("blob");
        let parsed = parse_public(&blob).expect("parse");
        assert_eq!(parsed.key_data(), key.public_key().key_data());
        assert!(fingerprint(&parsed).starts_with("SHA256:"));
    }

    #[test]
    fn signature_is_verified_with_public_part() {
        let key = key();
        let signature = sign(&key, "data under signature".as_bytes(), None).expect("signature");

        let decoded = Signature::try_from(&signature[..]).expect("parse signature");
        Verifier::verify(
            key.public_key().key_data(),
            "data under signature".as_bytes(),
            &decoded,
        )
        .expect("signature did not verify");

        assert!(
            Verifier::verify(
                key.public_key().key_data(),
                "other data".as_bytes(),
                &decoded
            )
            .is_err()
        );
    }

    #[test]
    fn key_survives_storage() {
        let key = key();
        let stored = to_openssh(&key).expect("serialize");
        let text = String::from_utf8(stored).expect("OpenSSH text");
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(!is_encrypted(&text).expect("check"));

        let restored = decode_private(&text, None).expect("parse");
        assert_eq!(
            restored.public_key().key_data(),
            key.public_key().key_data()
        );
    }

    #[test]
    fn encrypted_key_is_distinguished_from_corrupted() {
        let key = key();
        let encrypted = key
            .encrypt(&mut russh::keys::key::safe_rng(), "password")
            .expect("encrypt")
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("serialize");

        assert!(is_encrypted(&encrypted).expect("check"));
        assert!(decode_private(&encrypted, None).is_err());
        decode_private(&encrypted, Some("password")).expect("parse with password");
        assert!(decode_private(&encrypted, Some("wrong")).is_err());

        assert!(is_encrypted("-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n").is_err());
    }

    #[test]
    fn binding_with_foreign_signature_is_not_accepted() {
        let host = key();
        let session_id = "session identifier".as_bytes();
        let signature = sign(&host, session_id, None).expect("signature");
        let host_blob = public_blob(host.public_key()).expect("blob");

        verify_session_bind(&host_blob, session_id, &signature).expect("binding");

        let other = sign(&host, "another session".as_bytes(), None).expect("signature");
        assert!(verify_session_bind(&host_blob, session_id, &other).is_err());

        let alien = key();
        let alien_signature = sign(&alien, session_id, None).expect("signature");
        assert!(verify_session_bind(&host_blob, session_id, &alien_signature).is_err());
    }
}
