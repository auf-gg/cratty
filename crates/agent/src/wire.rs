use crate::error::{Error, Result};

pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(len).ok_or(Error::Truncated)?;
        let slice = self.bytes.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = usize_from_u32(self.u32()?)?;
        self.take(len)
    }

    pub fn utf8(&mut self) -> Result<&'a str> {
        core::str::from_utf8(self.string()?).map_err(|_| Error::NotUtf8)
    }

    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    pub fn finish(&self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::Trailing)
        }
    }
}

pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub fn message(kind: u8) -> Self {
        let mut bytes = vec![0, 0, 0, 0];
        bytes.push(kind);
        Self { bytes }
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn string(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(value);
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        let len = u32::try_from(self.bytes.len() - 4).unwrap_or(u32::MAX);
        self.bytes[..4].copy_from_slice(&len.to_be_bytes());
        self.bytes
    }
}

pub fn usize_from_u32(value: u32) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_reads_and_writes_symmetrically() {
        let mut writer = Writer::message(42);
        writer.string(b"ssh-ed25519").u32(7);
        let frame = writer.finish();

        assert_eq!(
            &frame[..4],
            &[0, 0, 0, 20],
            "frame length excluding the length field itself"
        );
        assert_eq!(frame[4], 42);

        let mut reader = Reader::new(&frame[5..]);
        assert_eq!(reader.string().expect("string"), b"ssh-ed25519");
        assert_eq!(reader.u32().expect("number"), 7);
        reader.finish().expect("no trailing bytes");
    }

    #[test]
    fn truncated_input_errors_instead_of_panicking() {
        let mut reader = Reader::new(&[0, 0, 0, 8, 1, 2]);
        assert!(matches!(reader.string(), Err(Error::Truncated)));

        let mut reader = Reader::new(&[0, 0]);
        assert!(matches!(reader.u32(), Err(Error::Truncated)));

        let mut reader = Reader::new(&[]);
        assert!(matches!(reader.u8(), Err(Error::Truncated)));
    }

    #[test]
    fn huge_length_does_not_allocate_memory() {
        let mut reader = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3]);
        assert!(reader.string().is_err());
    }

    #[test]
    fn trailing_bytes_after_message_are_detected() {
        let mut reader = Reader::new(&[0, 0, 0, 1, b'x', b'?']);
        assert_eq!(reader.string().expect("string"), b"x");
        assert!(matches!(reader.finish(), Err(Error::Trailing)));
    }

    #[test]
    fn non_utf8_name_is_rejected() {
        let mut reader = Reader::new(&[0, 0, 0, 2, 0xFF, 0xFE]);
        assert!(matches!(reader.utf8(), Err(Error::NotUtf8)));
    }
}
