#![forbid(unsafe_code)]

mod error;
pub mod msg;
mod request;
mod response;
mod wire;

pub use error::{Error, Result};
pub use request::{
    RSA_SHA2_256, RSA_SHA2_512, Request, RsaHash, SESSION_BIND, SessionBind, SignFlags,
    parse_session_bind,
};
pub use response::{
    Identity, extension_failure, failure, identities_answer, sign_response, success,
};

pub const MAX_FRAME_LEN: usize = 256 * 1024;

pub fn frame_len(header: [u8; 4]) -> Result<usize> {
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(Error::Empty);
    }
    if len > MAX_FRAME_LEN {
        return Err(Error::TooLong { len });
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlina_kadra_ogranichena() {
        assert_eq!(frame_len([0, 0, 0, 5]), Ok(5));
        assert_eq!(frame_len([0, 0, 0, 0]), Err(Error::Empty));
        assert!(matches!(
            frame_len([0xFF, 0xFF, 0xFF, 0xFF]),
            Err(Error::TooLong { .. })
        ));
        assert_eq!(frame_len([0, 4, 0, 0]), Ok(MAX_FRAME_LEN));
    }

    #[test]
    fn spisok_klyuchey_tuda_i_obratno() {
        let identities = vec![
            Identity::new(b"\x00\x00\x00\x0bssh-ed25519".to_vec(), "рабочий"),
            Identity::new(b"blob-2".to_vec(), ""),
        ];
        let frame = identities_answer(&identities);

        let header: [u8; 4] = frame[..4].try_into().expect("заголовок");
        let len = frame_len(header).expect("длина");
        assert_eq!(len, frame.len() - 4);

        let body = &frame[4..4 + len];
        assert_eq!(body[0], msg::IDENTITIES_ANSWER);
    }

    #[test]
    fn zapros_podpisi_tuda_i_obratno() {
        let mut frame = vec![msg::SIGN_REQUEST];
        for field in [b"key-blob".as_slice(), b"to-be-signed".as_slice()] {
            frame.extend_from_slice(&(field.len() as u32).to_be_bytes());
            frame.extend_from_slice(field);
        }
        frame.extend_from_slice(&RSA_SHA2_256.to_be_bytes());

        match Request::parse(&frame).expect("разбор") {
            Request::Sign {
                key_blob,
                data,
                flags,
            } => {
                assert_eq!(key_blob, b"key-blob");
                assert_eq!(data, b"to-be-signed");
                assert_eq!(flags.rsa_hash(), Some(RsaHash::Sha256));
                assert_eq!(flags.unknown(), 0);
            }
            other => panic!("ожидалась подпись, пришло {other:?}"),
        }
    }
}
