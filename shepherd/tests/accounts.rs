/// Account management tests — direct function calls, no HTTP.
/// Covers load/save/CRUD for shepherd.accounts.json.
use shepherd::accounts;
use shepherd::types::{Account, Role};
use tempfile::TempDir;

fn tmp() -> TempDir {
    TempDir::new().unwrap()
}

fn make_account(id: &str, name: &str, role: Role) -> Account {
    Account {
        id: id.to_string(),
        name: name.to_string(),
        display_name: format!("{name} Display"),
        role,
        active: true,
        identities: vec![format!("vigil://credo/test/{name}")],
        notes: String::new(),
        created_at: None,
    }
}

/// `load_accounts` returns an empty vec when the file does not exist.
#[test]
fn load_accounts_empty_when_no_file() {
    let dir = tmp();
    let path = dir.path().join("accounts.json");
    let accounts = accounts::load_accounts(&path).unwrap();
    assert!(accounts.is_empty(), "missing file must return empty vec");
}

/// `save_accounts` then `load_accounts` round-trips the data faithfully.
#[test]
fn save_and_load_round_trips() {
    let dir = tmp();
    let path = dir.path().join("accounts.json");

    let a1 = make_account("a1", "alice", Role::Admin);
    let a2 = make_account("a2", "bob", Role::Readonly);
    accounts::save_accounts(&path, &[a1.clone(), a2.clone()]).unwrap();

    let loaded = accounts::load_accounts(&path).unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].id, "a1");
    assert_eq!(loaded[1].id, "a2");
}

/// `find_by_identity_uri` finds an active account by URI; returns None for unknown URI.
#[test]
fn find_by_identity_uri() {
    let accts = vec![
        make_account("a1", "alice", Role::Admin),
        make_account("a2", "bob", Role::Readonly),
    ];

    let found = accounts::find_by_identity_uri(&accts, "vigil://credo/test/alice");
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, "a1");

    let not_found = accounts::find_by_identity_uri(&accts, "vigil://credo/test/unknown");
    assert!(not_found.is_none());
}

/// `find_by_id` locates an account by its ID.
#[test]
fn find_by_id() {
    let accts = vec![make_account("x1", "xray", Role::Admin)];
    assert!(accounts::find_by_id(&accts, "x1").is_some());
    assert!(accounts::find_by_id(&accts, "nope").is_none());
}

/// `create_account` appends the account to the vec.
#[test]
fn create_account_appends() {
    let mut accts: Vec<Account> = vec![];
    accounts::create_account(&mut accts, make_account("new1", "newuser", Role::Admin));
    assert_eq!(accts.len(), 1);
    assert_eq!(accts[0].id, "new1");
}

/// `update_account` mutates the matching account; returns false for unknown IDs.
#[test]
fn update_account_mutates() {
    let mut accts = vec![make_account("u1", "user1", Role::Readonly)];

    let updated = accounts::update_account(&mut accts, "u1", |a| a.active = false);
    assert!(updated, "update must return true for known ID");
    assert!(!accts[0].active, "account must be deactivated");

    let not_found = accounts::update_account(&mut accts, "unknown", |a| a.active = true);
    assert!(!not_found, "update must return false for unknown ID");
}

/// `delete_account` removes the account; returns false for unknown IDs.
#[test]
fn delete_account_removes() {
    let mut accts = vec![
        make_account("d1", "del1", Role::Admin),
        make_account("d2", "del2", Role::Admin),
    ];

    let removed = accounts::delete_account(&mut accts, "d1");
    assert!(removed, "delete must return true for known ID");
    assert_eq!(accts.len(), 1);
    assert_eq!(accts[0].id, "d2");

    let not_found = accounts::delete_account(&mut accts, "d1");
    assert!(
        !not_found,
        "delete must return false for already-removed ID"
    );
}
