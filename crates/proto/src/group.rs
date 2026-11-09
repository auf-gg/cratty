use serde::{Deserialize, Serialize};

/// Host group presentation. A host belongs to a group by name (the field
/// `HostRecord::group`); this record only adds an icon to the name. A group without
/// a record is a regular group with the default icon.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRecord {
    #[serde(default)]
    pub name: String,
    /// Icon name from the app's set; empty — the default icon.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub icon: String,
}

impl GroupRecord {
    /// Key by which group names are compared: "Prod" and " prod " are the same group.
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
    fn group_names_compare_ignoring_case_and_whitespace() {
        let group = GroupRecord {
            name: "Prod".into(),
            icon: String::new(),
        };
        assert!(group.is_named(" prod "));
        assert!(!group.is_named("stage"));
    }

    #[test]
    fn record_body_parses_back() {
        let body = crate::RecordBody::Group(GroupRecord {
            name: "Databases".into(),
            icon: "database".into(),
        });
        let json = serde_json::to_string(&body).expect("serialization");
        assert_eq!(
            serde_json::from_str::<crate::RecordBody>(&json).expect("parse"),
            body
        );
    }
}
