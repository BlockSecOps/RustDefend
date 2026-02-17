// Test fixture for SOL-001: missing-signer-check
// Functions accepting AccountInfo without verifying is_signer

use solana_program::account_info::AccountInfo;
use solana_program::pubkey::Pubkey;

fn withdraw_from_vault(
    program_id: &Pubkey,
    authority: AccountInfo,
    recipient: AccountInfo,
    amount: u64,
) {
    let mut data = recipient.try_borrow_mut_data().unwrap();
    data[0..8].copy_from_slice(&amount.to_le_bytes());
}

fn update_admin(
    program_id: &Pubkey,
    admin: AccountInfo,
    new_admin: AccountInfo,
) {
    let mut data = new_admin.try_borrow_mut_data().unwrap();
    data[0] = 1;
}
