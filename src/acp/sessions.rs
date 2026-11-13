//! Which agent session each server's conversation continues. It is all Cratty keeps of
//! a conversation: the conversation itself stays with the agent, in Cratty's folder for
//! agents, and comes back from the agent when the session is loaded.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::AgentKind;

const FILE: &str = "sessions.json";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Book {
    version: u32,
    /// By server address, such as `root@prod-01:2222`.
    servers: BTreeMap<String, Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    agent: String,
    session: String,
}

/// Read once, then kept in memory and written through.
static BOOK: Mutex<Option<Book>> = Mutex::new(None);

/// The agent and session the server's conversation continues, if any.
pub fn get(server: &str) -> Option<(AgentKind, String)> {
    with_book(|book, _| {
        let entry = book.servers.get(server)?;
        Some((AgentKind::from_id(&entry.agent)?, entry.session.clone()))
    })
}

pub fn remember(server: &str, kind: AgentKind, session: &str) {
    with_book(|book, path| {
        let entry = Entry {
            agent: kind.id().into(),
            session: session.into(),
        };
        if book.servers.get(server) != Some(&entry) {
            book.servers.insert(server.into(), entry);
            save(book, path);
        }
    })
}

pub fn forget(server: &str) {
    with_book(|book, path| {
        if book.servers.remove(server).is_some() {
            save(book, path);
        }
    })
}

fn with_book<R>(work: impl FnOnce(&mut Book, Option<&Path>) -> R) -> R {
    let path = super::agents::agents_dir().ok().map(|dir| dir.join(FILE));
    let mut guard = BOOK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let book = guard.get_or_insert_with(|| path.as_deref().map(load).unwrap_or_default());
    work(book, path.as_deref())
}

fn load(path: &Path) -> Book {
    std::fs::read(path)
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

/// Written whole and renamed into place, so a crash leaves the old file.
fn save(book: &mut Book, path: Option<&Path>) {
    let Some(path) = path else {
        return;
    };
    book.version = 1;
    let Ok(data) = serde_json::to_vec_pretty(book) else {
        return;
    };
    let temporary: PathBuf = path.with_extension("json.tmp");
    if std::fs::write(&temporary, data).is_ok() {
        let _ = std::fs::rename(&temporary, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn book_round_trips_and_skips_unknown_agents() {
        let mut book = Book::default();
        book.servers.insert(
            "root@prod".into(),
            Entry {
                agent: "claude".into(),
                session: "s1".into(),
            },
        );
        let text = serde_json::to_string(&book).unwrap();
        let back: Book = serde_json::from_str(&text).unwrap();
        assert_eq!(back, book);
        assert_eq!(AgentKind::from_id("claude"), Some(AgentKind::Claude));
        assert_eq!(AgentKind::from_id("gpt"), None);
    }

    #[test]
    fn broken_file_reads_as_empty() {
        let dir = std::env::temp_dir().join(format!("cratty-sessions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(FILE);
        std::fs::write(&file, "{not json").unwrap();
        assert_eq!(load(&file), Book::default());

        let mut book = Book::default();
        book.servers.insert(
            "db".into(),
            Entry {
                agent: "opencode".into(),
                session: "ses_1".into(),
            },
        );
        save(&mut book, Some(&file));
        assert_eq!(load(&file).servers["db"].session, "ses_1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
