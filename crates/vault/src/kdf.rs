use crate::error::{Error, Result};
use crate::rng;
use crate::secret::{KEY_LEN, Key32};
use argon2::{Algorithm, Argon2, Params, Version};
use std::time::{Duration, Instant};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 32;

pub const MASTER_OUTPUT_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Argon2idParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    salt: [u8; SALT_LEN],
}

impl Argon2idParams {
    pub const BASELINE_M_COST_KIB: u32 = 19 * 1024;
    pub const BASELINE_T_COST: u32 = 2;

    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32, salt: [u8; SALT_LEN]) -> Result<Self> {
        Params::new(m_cost_kib, t_cost, p_cost, Some(MASTER_OUTPUT_LEN))
            .map_err(|_| Error::Params("значение вне диапазона Argon2id"))?;
        Ok(Self {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        })
    }

    pub fn with_random_salt(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        Self::new(m_cost_kib, t_cost, p_cost, rng::array()?)
    }

    pub fn baseline() -> Result<Self> {
        Self::with_random_salt(Self::BASELINE_M_COST_KIB, Self::BASELINE_T_COST, 1)
    }

    pub fn m_cost_kib(&self) -> u32 {
        self.m_cost_kib
    }

    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }

    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub fn meets_baseline(&self) -> bool {
        self.m_cost_kib >= Self::BASELINE_M_COST_KIB && self.t_cost >= Self::BASELINE_T_COST
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + 1 + SALT_LEN);
        out.extend_from_slice(&self.m_cost_kib.to_le_bytes());
        out.extend_from_slice(&self.t_cost.to_le_bytes());
        out.extend_from_slice(&self.p_cost.to_le_bytes());
        out.push(SALT_LEN as u8);
        out.extend_from_slice(&self.salt);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 12 + 1 + SALT_LEN {
            return Err(Error::Format("длина параметров Argon2id"));
        }
        let m = u32::from_le_bytes(bytes[0..4].try_into().expect("срез 4 байта"));
        let t = u32::from_le_bytes(bytes[4..8].try_into().expect("срез 4 байта"));
        let p = u32::from_le_bytes(bytes[8..12].try_into().expect("срез 4 байта"));
        if usize::from(bytes[12]) != SALT_LEN {
            return Err(Error::Format("длина соли"));
        }
        let salt: [u8; SALT_LEN] = bytes[13..].try_into().expect("срез длины SALT_LEN");
        Self::new(m, t, p, salt)
    }

    #[cfg(test)]
    pub(crate) fn for_tests(salt: [u8; SALT_LEN]) -> Self {
        Self::new(1024, 1, 1, salt).expect("тестовые параметры валидны")
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthHash([u8; KEY_LEN]);

impl AuthHash {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for AuthHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthHash(<скрыт>)")
    }
}

impl ConstantTimeEq for AuthHash {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for AuthHash {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AuthHash {}

#[derive(Clone, Debug)]
pub struct MasterSecrets {
    kek: Key32,
    auth_hash: AuthHash,
}

impl MasterSecrets {
    pub fn kek(&self) -> &Key32 {
        &self.kek
    }

    pub fn auth_hash(&self) -> &AuthHash {
        &self.auth_hash
    }
}

pub fn derive_master_secrets(password: &[u8], params: &Argon2idParams) -> Result<MasterSecrets> {
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(MASTER_OUTPUT_LEN),
    )
    .map_err(|_| Error::Params("значение вне диапазона Argon2id"))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; MASTER_OUTPUT_LEN];
    argon
        .hash_password_into(password, &params.salt, &mut out)
        .map_err(|_| Error::Kdf("Argon2id не выдал вывод (не хватило памяти?)"))?;

    let kek = Key32::from_bytes(out[..KEY_LEN].try_into().expect("срез 32 байта"));
    let auth_hash = AuthHash(out[KEY_LEN..].try_into().expect("срез 32 байта"));
    out.zeroize();

    Ok(MasterSecrets { kek, auth_hash })
}

#[derive(Clone, Debug)]
pub struct CalibrationLimits {
    pub max_m_cost_kib: u32,
    pub max_t_cost: u32,
    pub p_cost: u32,
}

impl Default for CalibrationLimits {
    fn default() -> Self {
        Self {
            max_m_cost_kib: 512 * 1024,
            max_t_cost: 12,
            p_cost: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Calibrated {
    pub params: Argon2idParams,
    pub measured: Duration,
}

pub fn calibrate(target: Duration, limits: &CalibrationLimits) -> Result<Calibrated> {
    let floor_m = Argon2idParams::BASELINE_M_COST_KIB;
    let floor_t = Argon2idParams::BASELINE_T_COST;
    let max_m = limits.max_m_cost_kib.max(floor_m);
    let max_t = limits.max_t_cost.max(floor_t);

    let mut best_m = floor_m;
    let mut best_t = floor_t;
    let mut measured = probe(floor_m, floor_t, limits.p_cost)?;

    if measured < target {
        for _ in 0..2 {
            let scaled = scale(best_m, target, measured);
            let candidate = round_to_mib(scaled).clamp(floor_m, max_m);
            if candidate <= best_m {
                break;
            }
            let taken = probe(candidate, best_t, limits.p_cost)?;
            if taken > target {
                break;
            }
            best_m = candidate;
            measured = taken;
            if best_m == max_m {
                break;
            }
        }
    }

    if measured < target && best_m == max_m {
        let candidate = scale(best_t, target, measured).clamp(floor_t, max_t);
        if candidate > best_t {
            let taken = probe(best_m, candidate, limits.p_cost)?;
            if taken <= target {
                best_t = candidate;
                measured = taken;
            }
        }
    }

    Ok(Calibrated {
        params: Argon2idParams::with_random_salt(best_m, best_t, limits.p_cost)?,
        measured,
    })
}

fn probe(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Duration> {
    let params = Argon2idParams::new(m_cost_kib, t_cost, p_cost, [0x2a; SALT_LEN])?;
    let started = Instant::now();
    let secrets = derive_master_secrets(b"argon2id calibration probe", &params)?;
    let elapsed = started.elapsed();
    drop(secrets);
    Ok(elapsed)
}

fn scale(value: u32, target: Duration, measured: Duration) -> u32 {
    let measured_ns = measured.as_nanos().max(1) as f64;
    let factor = target.as_nanos() as f64 / measured_ns;
    let scaled = f64::from(value) * factor;
    if scaled >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        scaled as u32
    }
}

fn round_to_mib(kib: u32) -> u32 {
    kib - (kib % 1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{AssociatedData, ParamsBuilder};
    use hex_literal::hex;

    #[test]
    fn argon2id_rfc9106_izvestnyy_vektor() {
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[0x04; 12]).expect("AD"))
            .build()
            .expect("параметры вектора");
        let argon =
            Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
                .expect("секрет");

        let mut out = [0u8; 32];
        argon
            .hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
            .expect("хеширование");

        assert_eq!(
            out,
            hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    #[test]
    fn vyvod_iz_parolya_izvestnyy_vektor() {
        let params = Argon2idParams::new(1024, 3, 1, [0x11; SALT_LEN]).expect("параметры");
        let secrets =
            derive_master_secrets(b"correct horse battery staple", &params).expect("вывод ключа");

        assert_eq!(
            secrets.kek().as_bytes(),
            &hex!("c081a08aa49fb29da0bfefcd48994404244f808434fa46142ffbd42200c61983")
        );
        assert_eq!(
            secrets.auth_hash().as_bytes(),
            &hex!("194523cacf7b8c7788f1a0fdb7ad7e382c193db683d8b64bce8dcac88031595c")
        );
    }

    #[test]
    fn kek_i_auth_hash_ne_sovpadayut() {
        let params = Argon2idParams::for_tests([0x22; SALT_LEN]);
        let secrets = derive_master_secrets("пароль".as_bytes(), &params).expect("вывод ключа");
        assert_ne!(secrets.kek().as_bytes(), secrets.auth_hash().as_bytes());
        assert_ne!(secrets.kek().as_bytes(), &[0u8; KEY_LEN]);
        assert_ne!(secrets.auth_hash().as_bytes(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn drugoy_parol_drugoy_klyuch() {
        let params = Argon2idParams::for_tests([0x22; SALT_LEN]);
        let a = derive_master_secrets("пароль".as_bytes(), &params).expect("вывод");
        let b = derive_master_secrets("паролю".as_bytes(), &params).expect("вывод");
        assert_ne!(a.kek(), b.kek());
        assert_ne!(a.auth_hash(), b.auth_hash());
    }

    #[test]
    fn drugaya_sol_drugoy_klyuch() {
        let a = derive_master_secrets(
            "пароль".as_bytes(),
            &Argon2idParams::for_tests([0x22; SALT_LEN]),
        )
        .expect("вывод");
        let b = derive_master_secrets(
            "пароль".as_bytes(),
            &Argon2idParams::for_tests([0x23; SALT_LEN]),
        )
        .expect("вывод");
        assert_ne!(a.kek(), b.kek());
    }

    #[test]
    fn dlina_vyvoda_vhodit_v_hesh() {
        let params = Argon2idParams::for_tests([0x33; SALT_LEN]);
        let ours = derive_master_secrets("пароль".as_bytes(), &params).expect("вывод");

        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                params.m_cost_kib(),
                params.t_cost(),
                params.p_cost(),
                Some(32),
            )
            .expect("параметры"),
        );
        let mut short = [0u8; 32];
        argon
            .hash_password_into("пароль".as_bytes(), params.salt(), &mut short)
            .expect("хеширование");

        assert_ne!(
            ours.kek().as_bytes(),
            &short,
            "если это когда-нибудь совпадёт, комментарий в заголовке модуля можно убрать"
        );
    }

    #[test]
    fn parametry_perezhivayut_serializaciyu() {
        let params = Argon2idParams::new(19 * 1024, 3, 1, [0x44; SALT_LEN]).expect("параметры");
        let restored = Argon2idParams::decode(&params.encode()).expect("разбор");
        assert_eq!(params, restored);
    }

    #[test]
    fn isporchennye_parametry_ne_razbirayutsya() {
        let params = Argon2idParams::new(19 * 1024, 3, 1, [0x44; SALT_LEN]).expect("параметры");
        let encoded = params.encode();
        assert!(Argon2idParams::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(Argon2idParams::decode(&[]).is_err());

        let mut bad_salt_len = encoded.clone();
        bad_salt_len[12] = 16;
        assert!(Argon2idParams::decode(&bad_salt_len).is_err());

        let mut zero_memory = encoded.clone();
        zero_memory[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(Argon2idParams::decode(&zero_memory).is_err());
    }

    #[test]
    fn baseline_znaet_pro_slabye_parametry() {
        assert!(
            Argon2idParams::baseline()
                .expect("базовые")
                .meets_baseline()
        );
        assert!(!Argon2idParams::for_tests([0; SALT_LEN]).meets_baseline());
    }

    #[test]
    fn sol_sluchaynaya_u_kazhdyh_parametrov() {
        let a = Argon2idParams::baseline().expect("базовые");
        let b = Argon2idParams::baseline().expect("базовые");
        assert_ne!(a.salt(), b.salt());
    }

    #[test]
    fn kalibrovka_ne_opuskaetsya_nizhe_baseline() {
        let calibrated =
            calibrate(Duration::from_nanos(1), &CalibrationLimits::default()).expect("калибровка");
        assert!(calibrated.params.meets_baseline());
        assert_eq!(
            calibrated.params.m_cost_kib(),
            Argon2idParams::BASELINE_M_COST_KIB
        );
    }

    #[test]
    fn kalibrovka_uvazhaet_potolok_pamyati() {
        let limits = CalibrationLimits {
            max_m_cost_kib: 24 * 1024,
            max_t_cost: 3,
            p_cost: 1,
        };
        let calibrated = calibrate(Duration::from_secs(30), &limits).expect("калибровка");
        assert!(calibrated.params.m_cost_kib() <= limits.max_m_cost_kib);
        assert!(calibrated.params.t_cost() <= limits.max_t_cost);
        assert!(calibrated.params.meets_baseline());
    }

    #[test]
    fn auth_hash_ne_pechataetsya() {
        let params = Argon2idParams::for_tests([0x55; SALT_LEN]);
        let secrets = derive_master_secrets("пароль".as_bytes(), &params).expect("вывод");
        assert_eq!(format!("{:?}", secrets.auth_hash()), "AuthHash(<скрыт>)");
        assert!(format!("{secrets:?}").contains("<скрыт>"));
    }
}
