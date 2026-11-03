#![forbid(unsafe_code)]

pub mod folder;

use anyhow::Result;
use async_trait::async_trait;
use futures::stream::BoxStream;
use proto::EncryptedRecord;

pub use folder::FolderBackend;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cursor(pub u64);

impl Cursor {
    pub const BEGINNING: Self = Self(0);

    pub fn is_beginning(self) -> bool {
        self.0 == 0
    }
}

#[async_trait]
pub trait VaultBackend: Send + Sync {
    async fn pull(&self, since: Cursor) -> Result<Pulled>;

    async fn push(&self, records: Vec<EncryptedRecord>) -> Result<Cursor>;

    fn watch(&self) -> BoxStream<'static, ()>;
}

#[derive(Debug, Default)]
pub struct Pulled {
    pub records: Vec<EncryptedRecord>,
    pub cursor: Cursor,
    pub broken: Vec<String>,
}
