use crate::error::{Error, Result};
use crate::msg;
use crate::wire::Reader;

pub const SESSION_BIND: &str = "session-bind@openssh.com";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignFlags(u32);

pub const RSA_SHA2_256: u32 = 2;
pub const RSA_SHA2_512: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaHash {
    Sha256,
    Sha512,
}

impl SignFlags {
    pub fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn unknown(self) -> u32 {
        self.0 & !(RSA_SHA2_256 | RSA_SHA2_512)
    }

    pub fn rsa_hash(self) -> Option<RsaHash> {
        if self.0 & RSA_SHA2_512 != 0 {
            Some(RsaHash::Sha512)
        } else if self.0 & RSA_SHA2_256 != 0 {
            Some(RsaHash::Sha256)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionBind<'a> {
    pub host_key: &'a [u8],
    pub session_id: &'a [u8],
    pub signature: &'a [u8],
    pub is_forwarding: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Identities,
    Sign {
        key_blob: &'a [u8],
        data: &'a [u8],
        flags: SignFlags,
    },
    Extension {
        name: &'a str,
        body: &'a [u8],
    },
    Unsupported {
        kind: u8,
    },
}

impl<'a> Request<'a> {
    pub fn parse(frame: &'a [u8]) -> Result<Self> {
        let (kind, rest) = frame.split_first().ok_or(Error::Empty)?;
        let mut reader = Reader::new(rest);

        match *kind {
            msg::REQUEST_IDENTITIES => {
                reader.finish()?;
                Ok(Self::Identities)
            }
            msg::SIGN_REQUEST => {
                let key_blob = reader.string()?;
                let data = reader.string()?;
                let flags = SignFlags::from_bits(reader.u32()?);
                reader.finish()?;
                Ok(Self::Sign {
                    key_blob,
                    data,
                    flags,
                })
            }
            msg::EXTENSION => {
                let name = reader.utf8()?;
                let body = reader.take(reader.remaining())?;
                Ok(Self::Extension { name, body })
            }
            kind => Ok(Self::Unsupported { kind }),
        }
    }
}

pub fn parse_session_bind(body: &[u8]) -> Result<SessionBind<'_>> {
    let mut reader = Reader::new(body);
    let host_key = reader.string()?;
    let session_id = reader.string()?;
    let signature = reader.string()?;
    let is_forwarding = reader.bool()?;
    reader.finish()?;
    Ok(SessionBind {
        host_key,
        session_id,
        signature,
        is_forwarding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_keys_request() {
        assert_eq!(
            Request::parse(&[msg::REQUEST_IDENTITIES]),
            Ok(Request::Identities)
        );
        assert!(Request::parse(&[msg::REQUEST_IDENTITIES, 0]).is_err());
        assert_eq!(Request::parse(&[]), Err(Error::Empty));
    }

    #[test]
    fn sign_request_parses_field_by_field() {
        let mut frame = vec![msg::SIGN_REQUEST];
        frame.extend_from_slice(&[0, 0, 0, 3]);
        frame.extend_from_slice(b"key");
        frame.extend_from_slice(&[0, 0, 0, 4]);
        frame.extend_from_slice(b"data");
        frame.extend_from_slice(&RSA_SHA2_512.to_be_bytes());

        let request = Request::parse(&frame).expect("parse");
        assert_eq!(
            request,
            Request::Sign {
                key_blob: b"key",
                data: b"data",
                flags: SignFlags::from_bits(RSA_SHA2_512),
            }
        );
    }

    #[test]
    fn flags_select_hash_for_rsa() {
        assert_eq!(SignFlags::from_bits(0).rsa_hash(), None);
        assert_eq!(
            SignFlags::from_bits(RSA_SHA2_256).rsa_hash(),
            Some(RsaHash::Sha256)
        );
        assert_eq!(
            SignFlags::from_bits(RSA_SHA2_512).rsa_hash(),
            Some(RsaHash::Sha512)
        );
        assert_eq!(
            SignFlags::from_bits(RSA_SHA2_256 | RSA_SHA2_512).rsa_hash(),
            Some(RsaHash::Sha512)
        );
    }

    #[test]
    fn unknown_flags_are_visible() {
        assert_eq!(SignFlags::from_bits(RSA_SHA2_256).unknown(), 0);
        assert_eq!(SignFlags::from_bits(0x100).unknown(), 0x100);
    }

    #[test]
    fn add_key_is_unsupported_but_recognized() {
        let request = Request::parse(&[msg::ADD_IDENTITY, 1, 2, 3]).expect("parse");
        assert_eq!(
            request,
            Request::Unsupported {
                kind: msg::ADD_IDENTITY
            }
        );
        assert!(msg::describe(msg::ADD_IDENTITY).contains("vault"));
    }

    #[test]
    fn session_bind_parses() {
        let mut body = Vec::new();
        for field in [
            b"hostkey".as_slice(),
            b"session".as_slice(),
            b"sig".as_slice(),
        ] {
            body.extend_from_slice(&(field.len() as u32).to_be_bytes());
            body.extend_from_slice(field);
        }
        body.push(0);

        let mut frame = vec![msg::EXTENSION];
        frame.extend_from_slice(&(SESSION_BIND.len() as u32).to_be_bytes());
        frame.extend_from_slice(SESSION_BIND.as_bytes());
        frame.extend_from_slice(&body);

        let Request::Extension { name, body } = Request::parse(&frame).expect("parse")
        else {
            panic!("expected an extension");
        };
        assert_eq!(name, SESSION_BIND);

        let bind = parse_session_bind(body).expect("bind parse");
        assert_eq!(bind.host_key, b"hostkey");
        assert_eq!(bind.session_id, b"session");
        assert_eq!(bind.signature, b"sig");
        assert!(!bind.is_forwarding);
    }

    #[test]
    fn truncated_session_bind_does_not_parse() {
        assert!(parse_session_bind(&[0, 0, 0, 9, 1, 2]).is_err());
        assert!(
            parse_session_bind(&[0, 0, 0, 1, b'a', 0, 0, 0, 1, b'b', 0, 0, 0, 1, b'c']).is_err()
        );
    }

    #[test]
    fn arbitrary_bytes_do_not_crash_parsing() {
        let mut seed = 0x1234_5678u32;
        for _ in 0..5000 {
            let mut frame = Vec::new();
            let len = (seed % 40) as usize;
            for _ in 0..len {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                frame.push((seed >> 16) as u8);
            }
            let _ = Request::parse(&frame);
            let _ = parse_session_bind(&frame);
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        }
    }
}
