/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * Type Confusion Vulnerability
 *
 * This program fails to validate account data types,
 * allowing attackers to pass wrong account types with crafted data.
 */

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

// Two different account types with similar structure
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub rewards: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct AdminAccount {
    pub owner: Pubkey,
    pub balance: u64,      // Same layout as UserAccount!
    pub admin_level: u64,  // But means something different!
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data[0];

    match instruction {
        0 => withdraw_user(program_id, accounts, &instruction_data[1..]),
        1 => admin_action(program_id, accounts, &instruction_data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub fn withdraw_user(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Withdraw User (No Type Check)");

    let accounts_iter = &mut accounts.iter();
    let user_account_info = next_account_info(accounts_iter)?;
    let owner_account = next_account_info(accounts_iter)?;

    if user_account_info.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if !owner_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY: No discriminator or type check
    // Program assumes this is UserAccount, but could be AdminAccount!
    let mut user_data = UserAccount::try_from_slice(&user_account_info.data.borrow())?;

    if user_data.owner != *owner_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    // VULNERABILITY: If attacker passes AdminAccount, they can withdraw more than intended
    // Because AdminAccount.admin_level maps to UserAccount.rewards
    if user_data.balance + user_data.rewards < amount {
        return Err(ProgramError::InsufficientFunds);
    }

    msg!("Withdrawing {} (balance: {}, rewards: {})", amount, user_data.balance, user_data.rewards);

    user_data.balance = user_data.balance.saturating_sub(amount);
    user_data.serialize(&mut &mut user_account_info.data.borrow_mut()[..])?;

    Ok(())
}

pub fn admin_action(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin_account_info = next_account_info(accounts_iter)?;
    let admin_signer = next_account_info(accounts_iter)?;

    if admin_account_info.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if !admin_signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY: No type discriminator
    let admin_data = AdminAccount::try_from_slice(&admin_account_info.data.borrow())?;

    if admin_data.owner != *admin_signer.key {
        return Err(ProgramError::InvalidAccountData);
    }

    // Check admin level
    if admin_data.admin_level < 5 {
        return Err(ProgramError::InvalidAccountData);
    }

    msg!("Admin action executed");

    Ok(())
}

/*
 * SECURE VERSION WITH DISCRIMINATOR:
 *
 * use std::mem::size_of;
 *
 * const USER_ACCOUNT_DISCRIMINATOR: u64 = 0x1111111111111111;
 * const ADMIN_ACCOUNT_DISCRIMINATOR: u64 = 0x2222222222222222;
 *
 * #[derive(BorshSerialize, BorshDeserialize, Debug)]
 * pub struct UserAccountSecure {
 *     pub discriminator: u64,  // ADD DISCRIMINATOR
 *     pub owner: Pubkey,
 *     pub balance: u64,
 *     pub rewards: u64,
 * }
 *
 * #[derive(BorshSerialize, BorshDeserialize, Debug)]
 * pub struct AdminAccountSecure {
 *     pub discriminator: u64,  // ADD DISCRIMINATOR
 *     pub owner: Pubkey,
 *     pub balance: u64,
 *     pub admin_level: u64,
 * }
 *
 * pub fn withdraw_user_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let user_account_info = next_account_info(accounts_iter)?;
 *     let owner_account = next_account_info(accounts_iter)?;
 *
 *     if user_account_info.owner != program_id {
 *         return Err(ProgramError::IncorrectProgramId);
 *     }
 *
 *     if !owner_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     let mut user_data = UserAccountSecure::try_from_slice(&user_account_info.data.borrow())?;
 *
 *     // CHECK: Verify discriminator matches UserAccount type
 *     if user_data.discriminator != USER_ACCOUNT_DISCRIMINATOR {
 *         msg!("Invalid account type - expected UserAccount");
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     if user_data.owner != *owner_account.key {
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
 *
 *     if user_data.balance + user_data.rewards < amount {
 *         return Err(ProgramError::InsufficientFunds);
 *     }
 *
 *     user_data.balance = user_data.balance.saturating_sub(amount);
 *     user_data.serialize(&mut &mut user_account_info.data.borrow_mut()[..])?;
 *
 *     Ok(())
 * }
 *
 * // Anchor framework provides automatic discriminators with #[account] macro
 */

/*
 * EXPLOIT SCENARIO:
 *
 * 1. Attacker creates AdminAccount with:
 *    - owner: ATTACKER
 *    - balance: 100 SOL
 *    - admin_level: 1000 (high value)
 *
 * 2. Attacker calls withdraw_user with AdminAccount
 * 3. Program deserializes as UserAccount:
 *    - owner: ATTACKER ✓
 *    - balance: 100 SOL
 *    - rewards: 1000 SOL (actually admin_level field!)
 *
 * 4. Attacker requests withdrawal of 1100 SOL
 * 5. Check passes: balance (100) + rewards (1000) >= 1100 ✓
 * 6. Attacker withdraws more than they should
 *
 * 7. Similar attacks possible in reverse:
 *    - Pass UserAccount where AdminAccount expected
 *    - UserAccount.rewards interpreted as admin_level
 *    - Bypass admin level checks
 */

/*
 * REAL-WORLD EXAMPLES:
 *
 * - Several Solana programs vulnerable to type confusion
 * - Anchor framework added automatic discriminators to prevent this
 * - Still possible in raw Solana programs without proper checks
 */
