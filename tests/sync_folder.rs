use std::path::PathBuf;

use cratty::store::VaultStore;
use cratty::vault_session::VaultSession;
use proto::{HostRecord, RecordId, VaultId};
use sync::{Cursor, FolderBackend, VaultBackend};
use vault::Argon2idParams;

const PASSWORD: &[u8] = "master-password".as_bytes();

fn params() -> Argon2idParams {
    Argon2idParams::new(1024, 1, 1, [0x42; vault::SALT_LEN]).expect("params")
}

fn temp_dir(name: &str) -> PathBuf {
    let unique = proto::DeviceId::generate().expect("CSPRNG");
    let path = std::env::temp_dir().join(format!("cratty-sync-{name}-{unique}"));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn first_device(name: &str) -> (VaultSession, PathBuf) {
    let root = temp_dir(name);
    let mut session = VaultSession::open(
        VaultStore::new(root.clone()),
        std::time::Duration::from_secs(600),
    );
    session
        .create_for_tests(PASSWORD, params(), Vec::new())
        .expect("creating the vault");
    (session, root)
}

fn second_device(name: &str, first_root: &std::path::Path) -> (VaultSession, PathBuf) {
    let root = temp_dir(name);
    std::fs::create_dir_all(&root).expect("second device directory");
    std::fs::copy(
        first_root.join(proto::ACCOUNT_FILE),
        root.join(proto::ACCOUNT_FILE),
    )
    .expect("account transfer");

    let mut session = VaultSession::open(
        VaultStore::new(root.clone()),
        std::time::Duration::from_secs(600),
    );
    session
        .unlock_with_password(PASSWORD)
        .expect("unlocking on the second device");
    (session, root)
}

fn vault_id(session: &VaultSession) -> VaultId {
    session
        .store()
        .read_account()
        .expect("account")
        .vault_id
        .clone()
}

async fn sync(
    session: &mut VaultSession,
    folder: &FolderBackend,
) -> cratty::vault_session::MergeReport {
    let store = VaultStore::new(session.store().root().to_path_buf());
    let mine = session
        .unlocked()
        .expect("opened")
        .records_for_push(&store)
        .expect("own records");
    folder.push(mine).await.expect("push");

    let pulled = folder.pull(Cursor::BEGINNING).await.expect("pull");
    assert!(
        pulled.broken.is_empty(),
        "junk in the folder: {:?}",
        pulled.broken
    );
    session
        .unlocked_mut()
        .expect("opened")
        .merge(&store, pulled.records)
}

fn add_host(session: &mut VaultSession, host: &str, label: &str) -> RecordId {
    let store = VaultStore::new(session.store().root().to_path_buf());
    let mut record = HostRecord::new(host);
    record.label = label.to_owned();
    record.user = "root".into();
    session
        .unlocked_mut()
        .expect("opened")
        .upsert_host(&store, record)
        .expect("host record")
}

fn hosts(session: &VaultSession) -> Vec<String> {
    session
        .unlocked()
        .expect("opened")
        .hosts()
        .into_iter()
        .map(|entry| entry.host.host)
        .collect()
}

fn cleanup(paths: &[&PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_dir_all(path);
    }
}

#[tokio::test]
async fn record_reaches_second_device() {
    let (mut first, first_root) = first_device("dev-a");
    let (mut second, second_root) = second_device("dev-b", &first_root);
    let shared = temp_dir("folder");

    let folder_a = FolderBackend::open(&shared, &vault_id(&first)).expect("folder");
    let folder_b = FolderBackend::open(&shared, &vault_id(&second)).expect("folder");

    add_host(&mut first, "prod-01.example.com", "production");
    sync(&mut first, &folder_a).await;

    let report = sync(&mut second, &folder_b).await;
    assert_eq!(report.applied, 1);
    assert!(report.broken.is_empty());
    assert_eq!(hosts(&second), vec!["prod-01.example.com".to_owned()]);

    cleanup(&[&first_root, &second_root, &shared]);
}

#[tokio::test]
async fn deletion_propagates_and_record_does_not_resurrect() {
    let (mut first, first_root) = first_device("del-a");
    let (mut second, second_root) = second_device("del-b", &first_root);
    let shared = temp_dir("del-folder");

    let folder_a = FolderBackend::open(&shared, &vault_id(&first)).expect("folder");
    let folder_b = FolderBackend::open(&shared, &vault_id(&second)).expect("folder");

    let id = add_host(&mut first, "old.example.com", "old");
    sync(&mut first, &folder_a).await;
    sync(&mut second, &folder_b).await;
    assert_eq!(hosts(&second).len(), 1);

    let store = VaultStore::new(first.store().root().to_path_buf());
    first
        .unlocked_mut()
        .expect("opened")
        .remove_host(&store, &id)
        .expect("deletion");
    sync(&mut first, &folder_a).await;

    let report = sync(&mut second, &folder_b).await;
    assert_eq!(report.applied, 1, "the tombstone should have arrived");
    assert!(hosts(&second).is_empty());

    sync(&mut second, &folder_b).await;
    sync(&mut first, &folder_a).await;
    assert!(hosts(&first).is_empty(), "record came back to life");
    assert!(hosts(&second).is_empty());

    cleanup(&[&first_root, &second_root, &shared]);
}

#[tokio::test]
async fn concurrent_edit_converges_to_one_winner() {
    let (mut first, first_root) = first_device("race-a");
    let (mut second, second_root) = second_device("race-b", &first_root);
    let shared = temp_dir("race-folder");

    let folder_a = FolderBackend::open(&shared, &vault_id(&first)).expect("folder");
    let folder_b = FolderBackend::open(&shared, &vault_id(&second)).expect("folder");

    add_host(&mut first, "shared.example.com", "first name");
    sync(&mut first, &folder_a).await;
    sync(&mut second, &folder_b).await;

    add_host(&mut first, "shared.example.com", "name from the first");
    add_host(&mut second, "shared.example.com", "name from the second");

    sync(&mut first, &folder_a).await;
    sync(&mut second, &folder_b).await;
    sync(&mut first, &folder_a).await;
    sync(&mut second, &folder_b).await;

    let label = |session: &VaultSession| {
        session
            .unlocked()
            .expect("opened")
            .hosts()
            .first()
            .expect("record")
            .host
            .label
            .clone()
    };

    assert_eq!(
        label(&first),
        label(&second),
        "devices picked different winners"
    );

    cleanup(&[&first_root, &second_root, &shared]);
}

#[tokio::test]
async fn device_bound_record_does_not_leave_for_the_folder() {
    let (mut first, first_root) = first_device("local-a");
    let (mut second, second_root) = second_device("local-b", &first_root);
    let shared = temp_dir("local-folder");

    let folder_a = FolderBackend::open(&shared, &vault_id(&first)).expect("folder");
    let folder_b = FolderBackend::open(&shared, &vault_id(&second)).expect("folder");

    let store = VaultStore::new(first.store().root().to_path_buf());
    let mut record = HostRecord::new("only-here.example.com");
    record.label = "this machine only".into();
    first
        .unlocked_mut()
        .expect("opened")
        .upsert_host_with(&store, record, true)
        .expect("record");

    sync(&mut first, &folder_a).await;
    let report = sync(&mut second, &folder_b).await;

    assert_eq!(report.applied, 0);
    assert!(hosts(&second).is_empty(), "device-local record was synced away");

    cleanup(&[&first_root, &second_root, &shared]);
}

#[tokio::test]
async fn foreign_records_are_not_accepted_but_noticed() {
    let (mut mine, mine_root) = first_device("alien-mine");
    let (mut alien, alien_root) = first_device("alien-other");
    let shared = temp_dir("alien-folder");

    let folder = FolderBackend::open(&shared, &vault_id(&mine)).expect("folder");

    add_host(&mut alien, "alien.example.com", "foreign");
    let alien_store = VaultStore::new(alien.store().root().to_path_buf());
    let alien_records = alien
        .unlocked()
        .expect("opened")
        .records_for_push(&alien_store)
        .expect("foreign records");
    let dir = shared.join(proto::RECORDS_DIR);
    std::fs::create_dir_all(&dir).expect("directory");
    for record in &alien_records {
        std::fs::write(dir.join(record.id.as_str()), record.encode()).expect("foreign record");
    }

    let report = sync(&mut mine, &folder).await;
    assert_eq!(report.applied, 0);
    assert_eq!(report.broken.len(), alien_records.len());
    assert!(hosts(&mine).is_empty());

    cleanup(&[&mine_root, &alien_root, &shared]);
}
