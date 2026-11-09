use gpui_kit::SharedString;
use rust_i18n::t;

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

    pub fn title(&self) -> String {
        match self {
            Self::Create => t!("vault_ui.stage_create_title").to_string(),
            Self::Recovery { .. } => t!("vault_ui.stage_recovery_title").to_string(),
            Self::Unlock => t!("vault_ui.stage_unlock_title").to_string(),
            Self::UnlockWithCode => t!("vault_ui.stage_unlock_code_title").to_string(),
        }
    }

    pub fn subtitle(&self) -> String {
        match self {
            Self::Create => String::new(),
            Self::Recovery { .. } => String::new(),
            Self::Unlock => t!("vault_ui.unlock_subtitle").to_string(),
            Self::UnlockWithCode => String::new(),
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
    pub fn message(self) -> Option<String> {
        match self {
            Self::Ok => None,
            Self::TooShort => Some(t!("vault_ui.password_too_short").to_string()),
            Self::Mismatch => Some(t!("vault_ui.password_mismatch").to_string()),
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
    if import_count > 0 {
        t!("vault_ui.create_explainer_import", count = import_count).to_string()
    } else {
        t!("vault_ui.create_explainer").to_string()
    }
}

pub fn recovery_explainer() -> String {
    t!("vault_ui.recovery_explainer").to_string()
}

pub fn migration_warning() -> String {
    t!("vault_ui.migration_warning").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_password_is_rejected() {
        assert_eq!(
            check_new_password("1234567", "1234567"),
            PasswordVerdict::TooShort
        );
        assert!(check_new_password("12345678", "12345678").is_ok());
    }

    #[test]
    fn length_is_counted_in_characters() {
        assert_eq!(
            check_new_password("passwor", "passwor"),
            PasswordVerdict::TooShort,
            "seven characters is too few"
        );
        assert!(check_new_password("password", "password").is_ok());
    }

    #[test]
    fn mismatch_is_caught() {
        assert_eq!(
            check_new_password("correct-pw", "incorrect-pw"),
            PasswordVerdict::Mismatch
        );
        assert!(
            PasswordVerdict::Mismatch.message().is_some(),
            "the user must be told what exactly is wrong"
        );
        assert!(PasswordVerdict::Ok.message().is_none());
    }

    #[test]
    fn length_first_then_match() {
        assert_eq!(check_new_password("123", "456"), PasswordVerdict::TooShort);
    }

    #[test]
    fn hint_mentions_migration_only_when_there_is_something_to_migrate() {
        let without = create_explainer(0);
        assert!(!without.contains("hosts.json"));

        let with = create_explainer(3);
        assert!(with.contains("3"));
        assert!(with.contains("deleted"));
    }

    #[test]
    fn texts_state_irreversibility_plainly() {
        assert!(create_explainer(0).contains("cannot be recovered"));
        assert!(recovery_explainer().contains("only once"));
        assert!(migration_warning().contains("backups"));
    }

    #[test]
    fn every_stage_has_a_title() {
        for stage in [
            Stage::Create,
            Stage::Recovery {
                code: SharedString::from("code"),
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
    fn code_screens_are_named_differently() {
        let shown = Stage::Recovery {
            code: SharedString::from("code"),
            confirmed: false,
        };
        assert_ne!(shown.title(), Stage::UnlockWithCode.title());
    }

    #[test]
    fn locked_vault_explains_what_to_do() {
        let subtitle = Stage::Unlock.subtitle();
        assert!(subtitle.contains("master password"));
        assert!(
            subtitle.contains("Connecting by address"),
            "the lock covers the list, not the terminal — this must be said"
        );
    }
}
