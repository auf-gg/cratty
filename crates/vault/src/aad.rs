pub const DOMAIN: &[u8] = b"cratty/vault/v1";

pub struct Aad(Vec<u8>);

impl Aad {
    pub fn new(context: &str) -> Self {
        let mut aad = Self(Vec::with_capacity(64));
        aad.bytes(DOMAIN);
        aad.bytes(context.as_bytes());
        aad
    }

    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).expect("поле AAD длиннее 4 ГиБ недостижимо");
        self.0.extend_from_slice(&len.to_le_bytes());
        self.0.extend_from_slice(value);
        self
    }

    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn finish(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn izvestnyy_vektor_kodirovaniya() {
        let mut aad = Aad::new("record");
        aad.bytes(b"v1").u64(7).u32(1);

        let mut expected = Vec::new();
        expected.extend_from_slice(&15u32.to_le_bytes());
        expected.extend_from_slice(b"cratty/vault/v1");
        expected.extend_from_slice(&6u32.to_le_bytes());
        expected.extend_from_slice(b"record");
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(b"v1");
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());

        assert_eq!(aad.finish(), expected);
        assert_eq!(aad.finish().len(), 4 + 15 + 4 + 6 + 4 + 2 + 8 + 4);
    }

    #[test]
    fn granicy_poley_ne_skleivayutsya() {
        let mut a = Aad::new("record");
        a.bytes(b"ab").bytes(b"c");
        let mut b = Aad::new("record");
        b.bytes(b"a").bytes(b"bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn kontekst_razdelyaet_operacii() {
        let a = Aad::new("record");
        let b = Aad::new("slot");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn domen_prisutstvuet_vsegda() {
        let aad = Aad::new("record").finish();
        assert!(aad.windows(DOMAIN.len()).any(|w| w == DOMAIN));
    }
}
