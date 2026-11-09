use crate::error::{Error, Result};

#[derive(Default)]
pub struct Writer(Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).expect("field longer than 4 GiB is unreachable");
        self.0.extend_from_slice(&len.to_le_bytes());
        self.0.extend_from_slice(value);
        self
    }

    pub fn str(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes())
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(Error::Format("length overflow"))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::Format("data truncated"))?;
        self.position = end;
        Ok(slice)
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4-byte slice"),
        ))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8-byte slice"),
        ))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| Error::Format("length not in usize"))?;
        self.take(len)
    }

    pub fn str(&mut self) -> Result<&'a str> {
        core::str::from_utf8(self.bytes()?).map_err(|_| Error::Format("field is not UTF-8"))
    }

    pub fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Format("extra bytes left in the file"))
        }
    }
}

pub fn take_magic<'a>(bytes: &'a [u8], magic: &[u8]) -> Result<Reader<'a>> {
    let mut reader = Reader::new(bytes);
    if reader.take(magic.len())? != magic {
        return Err(Error::Format("not a file of this application"));
    }
    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read_match() {
        let mut writer = Writer::new();
        writer.u32(1234).u64(99).str("hello").bytes(&[1, 2, 3]);
        let encoded = writer.finish();

        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.u32().expect("u32"), 1234);
        assert_eq!(reader.u64().expect("u64"), 99);
        assert_eq!(reader.str().expect("str"), "hello");
        assert_eq!(reader.bytes().expect("bytes"), &[1, 2, 3]);
        reader.finish().expect("bytes ran out");
    }

    #[test]
    fn truncation_at_any_position_errors() {
        let mut writer = Writer::new();
        writer.u32(1).str("host").u64(5);
        let encoded = writer.finish();

        for cut in 0..encoded.len() {
            let mut reader = Reader::new(&encoded[..cut]);
            let parsed = (|| {
                reader.u32()?;
                reader.str()?;
                reader.u64()?;
                reader.finish()
            })();
            assert!(parsed.is_err(), "truncation to {cut} bytes passed parsing");
        }
    }

    #[test]
    fn extra_trailing_bytes_are_rejected() {
        let mut writer = Writer::new();
        writer.u32(1);
        let mut encoded = writer.finish();
        encoded.push(0);

        let mut reader = Reader::new(&encoded);
        reader.u32().expect("u32");
        assert!(reader.finish().is_err());
    }

    #[test]
    fn non_utf8_is_rejected() {
        let mut writer = Writer::new();
        writer.bytes(&[0xFF, 0xFE]);
        let encoded = writer.finish();
        assert!(Reader::new(&encoded).str().is_err());
    }

    #[test]
    fn lying_length_does_not_crash() {
        let mut encoded = u32::MAX.to_le_bytes().to_vec();
        encoded.push(1);
        assert!(Reader::new(&encoded).bytes().is_err());
    }

    #[test]
    fn magic_is_checked() {
        let magic = b"RSREC\x01";
        let mut bytes = magic.to_vec();
        bytes.push(42);
        assert!(take_magic(&bytes, magic).is_ok());
        assert!(take_magic(&bytes, b"OTHER\x01").is_err());
        assert!(take_magic(&[], magic).is_err());
    }
}
