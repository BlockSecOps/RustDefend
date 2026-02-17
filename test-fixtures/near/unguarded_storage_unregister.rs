// Test fixture for NEAR-011: unguarded-storage-unregister
// storage_unregister without checking non-zero token balances

fn storage_unregister(account_id: AccountId) -> bool {
    let account_id = env::predecessor_account_id();
    self.accounts.remove(&account_id);
    env::storage_remove(&account_id.as_bytes());
    true
}

fn storage_unregister_v2(account_id: AccountId) -> bool {
    let account = env::predecessor_account_id();
    self.token_balances.remove(&account);
    self.storage_deposits.remove(&account);
    true
}
