use serde::{Deserialize, Serialize};

/// Оформление группы хостов. Хост попадает в группу по имени (поле
/// `HostRecord::group`), эта запись лишь добавляет к имени иконку. Группа без
/// записи — обычная группа со значком по умолчанию.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRecord {
    #[serde(default)]
    pub name: String,
    /// Имя значка из набора приложения; пусто — значок по умолчанию.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub icon: String,
}

impl GroupRecord {
    /// Ключ, по которому сравниваются имена групп: «Prod» и « prod » — одна группа.
    pub fn key(name: &str) -> String {
        name.trim().to_lowercase()
    }

    pub fn is_named(&self, name: &str) -> bool {
        Self::key(&self.name) == Self::key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imena_grupp_sravnivayutsya_bez_registra_i_probelov() {
        let group = GroupRecord {
            name: "Prod".into(),
            icon: String::new(),
        };
        assert!(group.is_named(" prod "));
        assert!(!group.is_named("stage"));
    }

    #[test]
    fn v_tele_zapisi_razbiraetsya_obratno() {
        let body = crate::RecordBody::Group(GroupRecord {
            name: "Базы".into(),
            icon: "database".into(),
        });
        let json = serde_json::to_string(&body).expect("сериализация");
        assert_eq!(
            serde_json::from_str::<crate::RecordBody>(&json).expect("разбор"),
            body
        );
    }
}
