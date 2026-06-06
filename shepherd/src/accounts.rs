use anyhow::{Context, Result};
use std::path::Path;

use crate::types::{Account, AccountsFile};

pub fn load_accounts(path: &Path) -> Result<Vec<Account>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let value = credo_lib::config::load_json_config(path)
        .with_context(|| format!("Loading accounts config: {}", path.display()))?;
    let file: AccountsFile = serde_json::from_value(value)
        .with_context(|| format!("Parsing accounts: {}", path.display()))?;
    Ok(file.accounts)
}

pub fn save_accounts(path: &Path, accounts: &[Account]) -> Result<()> {
    let file = AccountsFile { accounts: accounts.to_vec() };
    let content = serde_json::to_string_pretty(&file)
        .context("Serializing accounts")?;
    std::fs::write(path, content)
        .with_context(|| format!("Writing accounts: {}", path.display()))
}

pub fn find_by_identity_uri<'a>(accounts: &'a [Account], uri: &str) -> Option<&'a Account> {
    accounts.iter().find(|a| a.active && a.identities.iter().any(|id| id == uri))
}

pub fn find_by_id<'a>(accounts: &'a [Account], id: &str) -> Option<&'a Account> {
    accounts.iter().find(|a| a.id == id)
}

pub fn create_account(accounts: &mut Vec<Account>, account: Account) {
    accounts.push(account);
}

pub fn update_account(accounts: &mut Vec<Account>, id: &str, mut updater: impl FnMut(&mut Account)) -> bool {
    if let Some(a) = accounts.iter_mut().find(|a| a.id == id) {
        updater(a);
        true
    } else {
        false
    }
}

pub fn delete_account(accounts: &mut Vec<Account>, id: &str) -> bool {
    let before = accounts.len();
    accounts.retain(|a| a.id != id);
    accounts.len() < before
}
