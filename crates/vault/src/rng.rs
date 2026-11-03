use crate::error::{Error, Result};

pub fn fill(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|_| Error::Rng)
}

pub fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zapolnyaet_ves_bufer() {
        let a: [u8; 64] = array().expect("CSPRNG ОС недоступен");
        let b: [u8; 64] = array().expect("CSPRNG ОС недоступен");
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 64]);
    }
}
