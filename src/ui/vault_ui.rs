use gpui::SharedString;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage {
    Create,
    Recovery { code: SharedString, confirmed: bool },
    Unlock,
    UnlockWithCode,
}

impl Stage {
    pub fn blocks_hosts(&self) -> bool {
        true
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::Create => "Создать хранилище",
            Self::Recovery { .. } => "Запишите код восстановления",
            Self::Unlock => "Хранилище заблокировано",
            Self::UnlockWithCode => "Вход по коду восстановления",
        }
    }

    pub fn subtitle(&self) -> &'static str {
        match self {
            Self::Create => "",
            Self::Recovery { .. } => "",
            Self::Unlock => {
                "Введите мастер-пароль для доступа к сохранённым хостам и ключам. Подключение по адресу доступно без разблокировки."
            }
            Self::UnlockWithCode => "",
        }
    }
}

pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordVerdict {
    Ok,
    TooShort,
    Mismatch,
}

impl PasswordVerdict {
    pub fn message(self) -> Option<&'static str> {
        match self {
            Self::Ok => None,
            Self::TooShort => Some("Пароль должен содержать не менее восьми символов."),
            Self::Mismatch => Some("Пароли не совпадают."),
        }
    }

    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

pub fn check_new_password(password: &str, repeat: &str) -> PasswordVerdict {
    if password.chars().count() < MIN_PASSWORD_LEN {
        PasswordVerdict::TooShort
    } else if password != repeat {
        PasswordVerdict::Mismatch
    } else {
        PasswordVerdict::Ok
    }
}

pub fn create_explainer(import_count: usize) -> String {
    let mut text = String::from(
        "Хосты и ключи шифруются мастер-паролем. Пароль не хранится и не может быть восстановлен; при его утрате доступ возможен только по коду восстановления.",
    );
    if import_count > 0 {
        text.push_str(&format!(
            " Из файла hosts.json будет импортировано записей: {import_count}; после импорта файл будет удалён."
        ));
    }
    text
}

pub const RECOVERY_EXPLAINER: &str = "Сохраните код в надёжном месте отдельно от компьютера. Это единственный способ разблокировать хранилище без мастер-пароля; код показывается однократно.";

pub const MIGRATION_WARNING: &str = "Файл hosts.json удалён, однако его копии могли сохраниться в резервных копиях и снимках диска.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn korotkiy_parol_otvergaetsya() {
        assert_eq!(
            check_new_password("1234567", "1234567"),
            PasswordVerdict::TooShort
        );
        assert!(check_new_password("12345678", "12345678").is_ok());
    }

    #[test]
    fn dlina_schitaetsya_v_znakah() {
        assert_eq!(
            check_new_password("паролик", "паролик"),
            PasswordVerdict::TooShort,
            "семь букв — мало"
        );
        assert!(check_new_password("паролище", "паролище").is_ok());
    }

    #[test]
    fn nesovpadenie_lovitsya() {
        assert_eq!(
            check_new_password("правильный", "неправильный"),
            PasswordVerdict::Mismatch
        );
        assert!(
            PasswordVerdict::Mismatch.message().is_some(),
            "человеку надо сказать, что именно не так"
        );
        assert!(PasswordVerdict::Ok.message().is_none());
    }

    #[test]
    fn snachala_dlina_potom_sovpadenie() {
        assert_eq!(check_new_password("123", "456"), PasswordVerdict::TooShort);
    }

    #[test]
    fn poyasnenie_upominaet_perenos_tolko_kogda_est_chto_perenosit() {
        let without = create_explainer(0);
        assert!(!without.contains("hosts.json"));

        let with = create_explainer(3);
        assert!(with.contains("3"));
        assert!(with.contains("удалён"));
    }

    #[test]
    fn teksty_govoryat_o_neobratimosti_pryamo() {
        assert!(create_explainer(0).contains("не может быть восстановлен"));
        assert!(RECOVERY_EXPLAINER.contains("однократно"));
        assert!(MIGRATION_WARNING.contains("резервных копиях"));
    }

    #[test]
    fn u_kazhdoy_stadii_est_zagolovok() {
        for stage in [
            Stage::Create,
            Stage::Recovery {
                code: SharedString::from("код"),
                confirmed: false,
            },
            Stage::Unlock,
            Stage::UnlockWithCode,
        ] {
            assert!(!stage.title().is_empty());
            assert!(stage.blocks_hosts());
        }
    }

    #[test]
    fn ekrany_koda_nazyvayutsya_po_raznomu() {
        let shown = Stage::Recovery {
            code: SharedString::from("код"),
            confirmed: false,
        };
        assert_ne!(shown.title(), Stage::UnlockWithCode.title());
    }

    #[test]
    fn zakrytoe_hranilishche_obyasnyaet_chto_delat() {
        let subtitle = Stage::Unlock.subtitle();
        assert!(subtitle.contains("мастер-пароль"));
        assert!(
            subtitle.contains("Подключение по адресу"),
            "замок закрывает список, а не терминал — это надо сказать"
        );
    }
}
