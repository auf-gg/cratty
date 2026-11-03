use std::path::PathBuf;

use cratty::store::VaultStore;
use cratty::vault_session::VaultSession;
use proto::{HostRecord, RecordId, VaultId};
use sync::{Cursor, FolderBackend, VaultBackend};
use vault::Argon2idParams;

const PASSWORD: &[u8] = "мастер-пароль".as_bytes();

fn params() -> Argon2idParams {
    Argon2idParams::new(1024, 1, 1, [0x42; vault::SALT_LEN]).expect("параметры")
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
        .expect("создание хранилища");
    (session, root)
}

fn second_device(name: &str, first_root: &std::path::Path) -> (VaultSession, PathBuf) {
    let root = temp_dir(name);
    std::fs::create_dir_all(&root).expect("каталог второго устройства");
    std::fs::copy(
        first_root.join(proto::ACCOUNT_FILE),
        root.join(proto::ACCOUNT_FILE),
    )
    .expect("перенос аккаунта");

    let mut session = VaultSession::open(
        VaultStore::new(root.clone()),
        std::time::Duration::from_secs(600),
    );
    session
        .unlock_with_password(PASSWORD)
        .expect("разблокировка на втором устройстве");
    (session, root)
}

fn vault_id(session: &VaultSession) -> VaultId {
    session
        .store()
        .read_account()
        .expect("аккаунт")
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
        .expect("открыто")
        .records_for_push(&store)
        .expect("свои записи");
    folder.push(mine).await.expect("push");

    let pulled = folder.pull(Cursor::BEGINNING).await.expect("pull");
    assert!(
        pulled.broken.is_empty(),
        "в папке мусор: {:?}",
        pulled.broken
    );
    session
        .unlocked_mut()
        .expect("открыто")
        .merge(&store, pulled.records)
}

fn add_host(session: &mut VaultSession, host: &str, label: &str) -> RecordId {
    let store = VaultStore::new(session.store().root().to_path_buf());
    let mut record = HostRecord::new(host);
    record.label = label.to_owned();
    record.user = "root".into();
    session
        .unlocked_mut()
        .expect("открыто")
        .upsert_host(&store, record)
        .expect("запись хоста")
}

fn hosts(session: &VaultSession) -> Vec<String> {
    session
        .unlocked()
        .expect("открыто")
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
async fn zapis_doezzhaet_do_vtorogo_ustroystva() {
    let (mut first, first_root) = first_device("dev-a");
    let (mut second, second_root) = second_device("dev-b", &first_root);
    let shared = temp_dir("folder");

    let folder_a = FolderBackend::open(&shared, &vault_id(&first)).expect("папка");
    let folder_b = FolderBackend::open(&shared, &vault_id(&second)).expect("папка");

    add_host(&mut first, "prod-01.example.com", "боевой");
    sync(&mut first, &folder_a).await;

    let report = sync(&mut second, &folder_b).await;
    assert_eq!(report.applied, 1);
    assert!(report.broken.is_empty());
    assert_eq!(hosts(&second), vec!["prod-01.example.com".to_owned()]);

    cleanup(&[&first_root, &second_root, &shared]);
}

#[tokio::test]
async fn udalenie_doezzhaet_i_zapis_ne_voskresaet() {
    let (mut first, first_root) = first_device("del-a");
    let (mut second, second_root) = second_device("del-b", &first_root);
    let shared = temp_dir("del-folder");

    let folder_a = FolderBackend::open(&shared, &vault_id(&first)).expect("папка");
    let folder_b = FolderBackend::open(&shared, &vault_id(&second)).expect("папка");

    let id = add_host(&mut first, "old.example.com", "старый");
    sync(&mut first, &folder_a).await;
    sync(&mut second, &folder_b).await;
    assert_eq!(hosts(&second).len(), 1);

    let store = VaultStore::new(first.store().root().to_path_buf());
    first
        .unlocked_mut()
        .expect("открыто")
        .remove_host(&store, &id)
        .expect("удаление");
    sync(&mut first, &folder_a).await;

    let report = sync(&mut second, &folder_b).await;
    assert_eq!(report.applied, 1, "надгробие должно было приехать");
    assert!(hosts(&second).is_empty());

    sync(&mut second, &folder_b).await;
    sync(&mut first, &folder_a).await;
    assert!(hosts(&first).is_empty(), "запись воскресла");
    assert!(hosts(&second).is_empty());

    cleanup(&[&first_root, &second_root, &shared]);
}

#[tokio::test]
async fn odnovremennaya_pravka_shoditsya_k_odnomu_pobeditelyu() {
    let (mut first, first_root) = first_device("race-a");
    let (mut second, second_root) = second_device("race-b", &first_root);
    let shared = temp_dir("race-folder");

    let folder_a = FolderBackend::open(&shared, &vault_id(&first)).expect("папка");
    let folder_b = FolderBackend::open(&shared, &vault_id(&second)).expect("папка");

    add_host(&mut first, "shared.example.com", "первое имя");
    sync(&mut first, &folder_a).await;
    sync(&mut second, &folder_b).await;

    add_host(&mut first, "shared.example.com", "имя с первого");
    add_host(&mut second, "shared.example.com", "имя со второго");

    sync(&mut first, &folder_a).await;
    sync(&mut second, &folder_b).await;
    sync(&mut first, &folder_a).await;
    sync(&mut second, &folder_b).await;

    let label = |session: &VaultSession| {
        session
            .unlocked()
            .expect("открыто")
            .hosts()
            .first()
            .expect("запись")
            .host
            .label
            .clone()
    };

    assert_eq!(
        label(&first),
        label(&second),
        "устройства выбрали разных победителей"
    );

    cleanup(&[&first_root, &second_root, &shared]);
}

#[tokio::test]
async fn ustroystvennaya_zapis_ne_uezzhaet_v_papku() {
    let (mut first, first_root) = first_device("local-a");
    let (mut second, second_root) = second_device("local-b", &first_root);
    let shared = temp_dir("local-folder");

    let folder_a = FolderBackend::open(&shared, &vault_id(&first)).expect("папка");
    let folder_b = FolderBackend::open(&shared, &vault_id(&second)).expect("папка");

    let store = VaultStore::new(first.store().root().to_path_buf());
    let mut record = HostRecord::new("only-here.example.com");
    record.label = "только эта машина".into();
    first
        .unlocked_mut()
        .expect("открыто")
        .upsert_host_with(&store, record, true)
        .expect("запись");

    sync(&mut first, &folder_a).await;
    let report = sync(&mut second, &folder_b).await;

    assert_eq!(report.applied, 0);
    assert!(hosts(&second).is_empty(), "устройственная запись уехала");

    cleanup(&[&first_root, &second_root, &shared]);
}

#[tokio::test]
async fn chuzhie_zapisi_ne_prinimayutsya_a_zamechayutsya() {
    let (mut mine, mine_root) = first_device("alien-mine");
    let (mut alien, alien_root) = first_device("alien-other");
    let shared = temp_dir("alien-folder");

    let folder = FolderBackend::open(&shared, &vault_id(&mine)).expect("папка");

    add_host(&mut alien, "alien.example.com", "чужой");
    let alien_store = VaultStore::new(alien.store().root().to_path_buf());
    let alien_records = alien
        .unlocked()
        .expect("открыто")
        .records_for_push(&alien_store)
        .expect("чужие записи");
    let dir = shared.join(proto::RECORDS_DIR);
    std::fs::create_dir_all(&dir).expect("каталог");
    for record in &alien_records {
        std::fs::write(dir.join(record.id.as_str()), record.encode()).expect("чужая запись");
    }

    let report = sync(&mut mine, &folder).await;
    assert_eq!(report.applied, 0);
    assert_eq!(report.broken.len(), alien_records.len());
    assert!(hosts(&mine).is_empty());

    cleanup(&[&mine_root, &alien_root, &shared]);
}
