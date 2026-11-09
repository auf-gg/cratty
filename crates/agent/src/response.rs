use crate::msg;
use crate::wire::Writer;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: String,
}

impl Identity {
    pub fn new(blob: Vec<u8>, comment: impl Into<String>) -> Self {
        Self {
            blob,
            comment: comment.into(),
        }
    }
}

pub fn identities_answer(identities: &[Identity]) -> Vec<u8> {
    let mut writer = Writer::message(msg::IDENTITIES_ANSWER);
    writer.u32(u32::try_from(identities.len()).unwrap_or(u32::MAX));
    for identity in identities {
        writer
            .string(&identity.blob)
            .string(identity.comment.as_bytes());
    }
    writer.finish()
}

pub fn sign_response(signature: &[u8]) -> Vec<u8> {
    let mut writer = Writer::message(msg::SIGN_RESPONSE);
    writer.string(signature);
    writer.finish()
}

pub fn failure() -> Vec<u8> {
    Writer::message(msg::FAILURE).finish()
}

pub fn success() -> Vec<u8> {
    Writer::message(msg::SUCCESS).finish()
}

pub fn extension_failure() -> Vec<u8> {
    Writer::message(msg::EXTENSION_FAILURE).finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_known_vector() {
        assert_eq!(identities_answer(&[]), vec![0, 0, 0, 5, 12, 0, 0, 0, 0]);
    }

    #[test]
    fn single_key_list_known_vector() {
        let identity = Identity::new(b"blob".to_vec(), "dan@laptop");
        assert_eq!(
            identities_answer(&[identity]),
            [
                &[0, 0, 0, 27][..],
                &[12][..],
                &[0, 0, 0, 1][..],
                &[0, 0, 0, 4][..],
                b"blob",
                &[0, 0, 0, 10][..],
                b"dan@laptop",
            ]
            .concat()
        );
    }

    #[test]
    fn failure_known_vectors() {
        assert_eq!(failure(), vec![0, 0, 0, 1, 5]);
        assert_eq!(success(), vec![0, 0, 0, 1, 6]);
        assert_eq!(extension_failure(), vec![0, 0, 0, 1, 28]);
    }

    #[test]
    fn signature_is_wrapped_in_a_string() {
        assert_eq!(
            sign_response(b"sig"),
            vec![0, 0, 0, 8, 14, 0, 0, 0, 3, b's', b'i', b'g']
        );
    }

    #[test]
    fn header_length_matches_body() {
        for frame in [
            failure(),
            identities_answer(&[Identity::new(vec![7; 300], "x".repeat(100))]),
            sign_response(&[9; 1000]),
        ] {
            let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
            assert_eq!(declared, frame.len() - 4);
        }
    }
}
