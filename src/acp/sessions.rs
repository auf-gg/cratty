//! The chats of each server and the agent the user picked. It is all Cratty keeps of a
//! conversation: the conversation itself stays with the agent, in Cratty's folder for
//! agents, and comes back from the agent when its session is loaded.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::AgentKind;

const FILE: &str = "sessions.json";
const VERSION: u32 = 2;
/// The longest chat title, taken from the chat's first message.
const TITLE_CHARS: usize = 60;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Book {
    #[serde(default)]
    version: u32,
    /// The agent picked last, for every server.
    #[serde(default)]
    agent: Option<String>,
    /// By server address, such as `root@prod-01:2222`.
    #[serde(default)]
    servers: BTreeMap<String, Vec<Saved>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Saved {
    agent: String,
    session: String,
    title: String,
    /// Seconds since the epoch of the last answer.
    updated: u64,
}

/// A saved chat of a server with one agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chat {
    pub session: String,
    pub title: String,
}

/// Read once, then kept in memory and written through.
static BOOK: Mutex<Option<Book>> = Mutex::new(None);

/// The agent the user picked last, if any.
pub fn chosen_agent() -> Option<AgentKind> {
    with_book(|book, _| book.agent.as_deref().and_then(AgentKind::from_id))
}

pub fn choose_agent(kind: AgentKind) {
    with_book(|book, path| {
        if book.agent.as_deref() != Some(kind.id()) {
            book.agent = Some(kind.id().into());
            save(book, path);
        }
    })
}

/// The server's chats with the agent, the latest first.
pub fn chats(server: &str, kind: AgentKind) -> Vec<Chat> {
    with_book(|book, _| chats_in(book, server, kind))
}

/// Records that the chat answered: a new chat gets its title, a known one moves first.
pub fn touch(server: &str, kind: AgentKind, session: &str, first_message: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    with_book(|book, path| {
        let chats = book.servers.entry(server.into()).or_default();
        match chats.iter_mut().find(|chat| chat.session == session) {
            Some(chat) => chat.updated = now.max(chat.updated),
            None => chats.push(Saved {
                agent: kind.id().into(),
                session: session.into(),
                title: title_of(first_message),
                updated: now,
            }),
        }
        save(book, path);
    })
}

pub fn forget(server: &str, session: &str) {
    with_book(|book, path| {
        let Some(chats) = book.servers.get_mut(server) else {
            return;
        };
        let before = chats.len();
        chats.retain(|chat| chat.session != session);
        if chats.is_empty() {
            book.servers.remove(server);
        }
        if book.servers.get(server).map_or(0, Vec::len) != before {
            save(book, path);
        }
    })
}

fn chats_in(book: &Book, server: &str, kind: AgentKind) -> Vec<Chat> {
    let mut saved: Vec<&Saved> = book
        .servers
        .get(server)
        .map(|chats| {
            chats
                .iter()
                .filter(|chat| chat.agent == kind.id())
                .collect()
        })
        .unwrap_or_default();
    saved.sort_by_key(|chat| std::cmp::Reverse(chat.updated));
    saved
        .into_iter()
        .map(|chat| Chat {
            session: chat.session.clone(),
            title: chat.title.clone(),
        })
        .collect()
}

/// The first line of the first message, shortened.
fn title_of(message: &str) -> String {
    let line = message
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .trim();
    let mut title: String = line.chars().take(TITLE_CHARS).collect();
    if line.chars().count() > TITLE_CHARS {
        title.push('…');
    }
    title
}

fn with_book<R>(work: impl FnOnce(&mut Book, Option<&Path>) -> R) -> R {
    let path = super::agents::agents_dir().ok().map(|dir| dir.join(FILE));
    let mut guard = BOOK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let book = guard.get_or_insert_with(|| path.as_deref().map(load).unwrap_or_default());
    work(book, path.as_deref())
}

/// The first version: one session per server.
#[derive(Deserialize)]
struct BookV1 {
    servers: BTreeMap<String, SavedV1>,
}

#[derive(Deserialize)]
struct SavedV1 {
    agent: String,
    session: String,
}

/// An unreadable file reads as empty; the first version is carried over, its sessions
/// as untitled chats.
fn load(path: &Path) -> Book {
    let Ok(data) = std::fs::read(path) else {
        return Book::default();
    };
    if let Ok(book) = serde_json::from_slice::<Book>(&data)
        && book.version == VERSION
    {
        return book;
    }
    let Ok(old) = serde_json::from_slice::<BookV1>(&data) else {
        return Book::default();
    };
    let servers = old
        .servers
        .into_iter()
        .map(|(server, saved)| {
            let chat = Saved {
                agent: saved.agent,
                session: saved.session,
                title: String::new(),
                updated: 0,
            };
            (server, vec![chat])
        })
        .collect();
    Book {
        version: VERSION,
        agent: None,
        servers,
    }
}

/// Written whole and renamed into place, so a crash leaves the old file.
fn save(book: &mut Book, path: Option<&Path>) {
    let Some(path) = path else {
        return;
    };
    book.version = VERSION;
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

    fn saved(agent: &str, session: &str, updated: u64) -> Saved {
        Saved {
            agent: agent.into(),
            session: session.into(),
            title: format!("chat {session}"),
            updated,
        }
    }

    #[test]
    fn chats_are_per_agent_and_latest_first() {
        let mut book = Book::default();
        book.servers.insert(
            "root@prod".into(),
            vec![
                saved("claude", "a", 10),
                saved("opencode", "b", 30),
                saved("claude", "c", 20),
            ],
        );
        let claude: Vec<String> = chats_in(&book, "root@prod", AgentKind::Claude)
            .into_iter()
            .map(|chat| chat.session)
            .collect();
        assert_eq!(claude, ["c", "a"]);
        assert_eq!(chats_in(&book, "root@prod", AgentKind::OpenCode).len(), 1);
        assert!(chats_in(&book, "db", AgentKind::Claude).is_empty());
    }

    #[test]
    fn title_is_the_first_line_shortened() {
        assert_eq!(
            title_of("\n  Why is the disk full?\nmore"),
            "Why is the disk full?"
        );
        let long = "x".repeat(100);
        assert_eq!(title_of(&long).chars().count(), TITLE_CHARS + 1);
        assert!(title_of(&long).ends_with('…'));
    }

    #[test]
    fn file_round_trips_and_the_first_version_carries_over() {
        let dir = std::env::temp_dir().join(format!("cratty-sessions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(FILE);

        std::fs::write(
            &file,
            r#"{"version":1,"servers":{"db":{"agent":"claude","session":"s"}}}"#,
        )
        .unwrap();
        let carried = load(&file);
        assert_eq!(carried.version, VERSION);
        assert_eq!(
            chats_in(&carried, "db", AgentKind::Claude),
            vec![Chat {
                session: "s".into(),
                title: String::new(),
            }]
        );
        std::fs::write(&file, "{not json").unwrap();
        assert_eq!(load(&file), Book::default());

        let mut book = Book {
            agent: Some("opencode".into()),
            ..Book::default()
        };
        book.servers
            .insert("db".into(), vec![saved("opencode", "ses_1", 5)]);
        save(&mut book, Some(&file));
        let back = load(&file);
        assert_eq!(back.agent.as_deref(), Some("opencode"));
        assert_eq!(back.servers["db"][0].session, "ses_1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
