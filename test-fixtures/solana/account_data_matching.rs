/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * Account Data Matching Vulnerability
 *
 * This program fails to verify that multiple accounts passed in a transaction
 * have the expected relationships, allowing account substitution attacks.
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

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct UserProfile {
    pub owner: Pubkey,
    pub escrow_account: Pubkey,
    pub total_deposits: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct EscrowAccount {
    pub beneficiary: Pubkey,
    pub amount: u64,
    pub release_time: i64,
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Account Data Matching");

    let accounts_iter = &mut accounts.iter();
    let user_profile_account = next_account_info(accounts_iter)?;
    let escrow_account = next_account_info(accounts_iter)?;
    let beneficiary_account = next_account_info(accounts_iter)?;
    let signer_account = next_account_info(accounts_iter)?;

    if user_profile_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if escrow_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if !signer_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let user_profile = UserProfile::try_from_slice(&user_profile_account.data.borrow())?;
    let mut escrow_data = EscrowAccount::try_from_slice(&escrow_account.data.borrow())?;

    // CHECK 1: Verify signer owns the profile
    if user_profile.owner != *signer_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABILITY 1: Doesn't verify escrow_account matches user_profile.escrow_account
    // Attacker can pass ANY escrow account owned by the program
    // Should have: if user_profile.escrow_account != *escrow_account.key { return Err(...); }

    // CHECK 2: Verify release time has passed
    let current_time = 1000000_i64;  // Placeholder
    if current_time < escrow_data.release_time {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABILITY 2: Doesn't verify beneficiary_account matches escrow_data.beneficiary
    // Attacker can redirect funds to any account
    // Should have: if escrow_data.beneficiary != *beneficiary_account.key { return Err(...); }

    let amount = escrow_data.amount;
    escrow_data.amount = 0;
    escrow_data.serialize(&mut &mut escrow_account.data.borrow_mut()[..])?;

    msg!("Releasing {} lamports", amount);

    **escrow_account.try_borrow_mut_lamports()? -= amount;
    **beneficiary_account.try_borrow_mut_lamports()? += amount;

    Ok(())
}

/*
 * SECURE VERSION:
 *
 * pub fn process_instruction_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let user_profile_account = next_account_info(accounts_iter)?;
 *     let escrow_account = next_account_info(accounts_iter)?;
 *     let beneficiary_account = next_account_info(accounts_iter)?;
 *     let signer_account = next_account_info(accounts_iter)?;
 *
 *     if user_profile_account.owner != program_id {
 *         return Err(ProgramError::IncorrectProgramId);
 *     }
 *
 *     if escrow_account.owner != program_id {
 *         return Err(ProgramError::IncorrectProgramId);
 *     }
 *
 *     if !signer_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     let user_profile = UserProfile::try_from_slice(&user_profile_account.data.borrow())?;
 *     let mut escrow_data = EscrowAccount::try_from_slice(&escrow_account.data.borrow())?;
 *
 *     // CHECK: Verify signer owns the profile
 *     if user_profile.owner != *signer_account.key {
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     // CHECK: Verify escrow account matches profile's escrow
 *     if user_profile.escrow_account != *escrow_account.key {
 *         msg!("Escrow account mismatch");
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     // CHECK: Verify release time
 *     let current_time = 1000000_i64;
 *     if current_time < escrow_data.release_time {
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     // CHECK: Verify beneficiary matches
 *     if escrow_data.beneficiary != *beneficiary_account.key {
 *         msg!("Beneficiary account mismatch");
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     let amount = escrow_data.amount;
 *     escrow_data.amount = 0;
 *     escrow_data.serialize(&mut &mut escrow_account.data.borrow_mut()[..])?;
 *
 *     **escrow_account.try_borrow_mut_lamports()? -= amount;
 *     **beneficiary_account.try_borrow_mut_lamports()? += amount;
 *
 *     Ok(())
 * }
 */

/*
 * EXPLOIT SCENARIO:
 *
 * Setup:
 * - User has profile with escrow_account = EscrowA
 * - EscrowA has 100 SOL, beneficiary = UserWallet, release_time = future
 * - Victim has escrow_account = EscrowB
 * - EscrowB has 1000 SOL, beneficiary = VictimWallet, release_time = past
 *
 * Attack:
 * 1. Attacker creates transaction with:
 *    - user_profile_account: User's profile (points to EscrowA)
 *    - escrow_account: Victim's EscrowB (not EscrowA!)
 *    - beneficiary_account: Attacker's wallet (not VictimWallet!)
 *    - signer_account: Attacker (signed)
 *
 * 2. Program checks:
 *    - user_profile.owner == signer ✓ (attacker owns profile)
 *    - escrow_account.owner == program_id ✓
 *    - But DOESN'T check: user_profile.escrow_account == escrow_account ✗
 *    - But DOESN'T check: escrow_data.beneficiary == beneficiary_account ✗
 *
 * 3. Release time check passes (EscrowB is ready)
 * 4. Funds from EscrowB sent to Attacker instead of Victim
 * 5. Attacker stole 1000 SOL by account substitution
 */

/*
 * ANOTHER VULNERABILITY: Token Account Confusion
 */

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct TokenVault {
    pub authority: Pubkey,
    pub token_account: Pubkey,
}

pub fn vulnerable_token_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault_account = next_account_info(accounts_iter)?;
    let token_account = next_account_info(accounts_iter)?;  // SPL Token account
    let authority = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let vault_data = TokenVault::try_from_slice(&vault_account.data.borrow())?;

    if vault_data.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABILITY: Doesn't verify token_account matches vault_data.token_account
    // Attacker can pass different token account and steal tokens
    // Should have: if vault_data.token_account != *token_account.key { return Err(...); }

    // Transfer tokens (pseudocode)
    msg!("Would transfer tokens from {} to authority", token_account.key);

    Ok(())
}

/*
 * KEY TAKEAWAYS:
 *
 * 1. Always verify relationships between accounts
 * 2. Don't assume accounts passed by caller are the correct ones
 * 3. Check that addresses in account data match actual accounts passed
 * 4. Use PDAs to enforce account relationships when possible
 * 5. Anchor's #[account] macro helps prevent these issues
 */
