pub(crate) const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub(crate) fn encode_into(bytes: &[u8], symbols: usize, group: usize, out: &mut Vec<u8>) {
    let mut bit = 0usize;
    for index in 0..symbols {
        if index > 0 && index % group == 0 {
            out.push(b'-');
        }
        let mut value = 0u8;
        for offset in 0..5 {
            let position = bit + offset;
            let taken = bytes
                .get(position / 8)
                .is_some_and(|byte| byte & (1 << (7 - position % 8)) != 0);
            value = (value << 1) | u8::from(taken);
        }
        out.push(ALPHABET[usize::from(value)]);
        bit += 5;
    }
}

pub(crate) fn decode_symbol(symbol: u8) -> Option<u8> {
    match symbol {
        b'I' | b'L' => Some(1),
        b'O' => Some(0),
        other => ALPHABET
            .iter()
            .position(|&c| c == other)
            .map(|index| index as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn izvestnye_vektory() {
        let cases: [(&[u8], usize, usize, &str); 4] = [
            (&[0x00, 0x00], 3, 4, "000"),
            (&[0xFF, 0xFF], 3, 4, "ZZZ"),
            (&[0x01, 0x02], 3, 4, "041"),
            (&[0xFF; 5], 8, 4, "ZZZZ-ZZZZ"),
        ];

        for (bytes, symbols, group, expected) in cases {
            let mut out = Vec::new();
            encode_into(bytes, symbols, group, &mut out);
            assert_eq!(String::from_utf8(out).expect("ASCII"), expected);
        }
    }

    #[test]
    fn kodirovanie_i_razbor_shodyatsya() {
        let mut out = Vec::new();
        encode_into(&[0xAB, 0xCD, 0xEF, 0x12, 0x34], 8, 4, &mut out);

        let symbols: Vec<u8> = out.iter().copied().filter(|&byte| byte != b'-').collect();
        assert_eq!(symbols.len(), 8);
        for symbol in symbols {
            assert!(
                decode_symbol(symbol).is_some(),
                "символ {symbol} не разобрался"
            );
        }
    }

    #[test]
    fn pohozhie_znaki_svodyatsya_vmeste() {
        assert_eq!(decode_symbol(b'I'), decode_symbol(b'1'));
        assert_eq!(decode_symbol(b'L'), decode_symbol(b'1'));
        assert_eq!(decode_symbol(b'O'), decode_symbol(b'0'));
        assert_eq!(decode_symbol(b'U'), None, "U в алфавит не входит");
        assert_eq!(decode_symbol(b'-'), None);
    }
}
