/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * PDA (Program Derived Address) Validation Issues
 *
 * This program fails to properly validate PDA accounts,
 * allowing attackers to pass invalid PDAs or bypass authorization.
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
pub struct UserData {
    pub owner: Pubkey,
    pub balance: u64,
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: PDA Validation Issues");

    let accounts_iter = &mut accounts.iter();
    let user_account = next_account_info(accounts_iter)?;
    let pda_account = next_account_info(accounts_iter)?;
    let recipient_account = next_account_info(accounts_iter)?;

    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY 1: No verification that pda_account is actually derived correctly
    // Should verify: let (expected_pda, bump) = Pubkey::find_program_address(&[seeds], program_id);
    // Then check: if expected_pda != *pda_account.key { return Err(...); }

    // VULNERABILITY 2: No check that PDA is owned by this program
    if pda_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut user_data = UserData::try_from_slice(&pda_account.data.borrow())?;

    // VULNERABILITY 3: Only checks owner field, but PDA wasn't validated
    // Attacker can create a PDA with different seeds that passes this check
    if user_data.owner != *user_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    if user_data.balance < amount {
        return Err(ProgramError::InsufficientFunds);
    }

    msg!("Withdrawing {} from PDA", amount);

    user_data.balance -= amount;
    user_data.serialize(&mut &mut pda_account.data.borrow_mut()[..])?;

    **pda_account.try_borrow_mut_lamports()? -= amount;
    **recipient_account.try_borrow_mut_lamports()? += amount;

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
 *     let user_account = next_account_info(accounts_iter)?;
 *     let pda_account = next_account_info(accounts_iter)?;
 *     let recipient_account = next_account_info(accounts_iter)?;
 *
 *     if !user_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     // CHECK: Derive expected PDA
 *     let (expected_pda, bump) = Pubkey::find_program_address(
 *         &[b"user_data", user_account.key.as_ref()],
 *         program_id
 *     );
 *
 *     // CHECK: Verify PDA matches expected address
 *     if expected_pda != *pda_account.key {
 *         msg!("Invalid PDA provided");
 *         return Err(ProgramError::InvalidSeeds);
 *     }
 *
 *     // CHECK: Verify PDA is owned by this program
 *     if pda_account.owner != program_id {
 *         return Err(ProgramError::IncorrectProgramId);
 *     }
 *
 *     let mut user_data = UserData::try_from_slice(&pda_account.data.borrow())?;
 *
 *     // Now this check is meaningful since PDA was validated
 *     if user_data.owner != *user_account.key {
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
 *
 *     if user_data.balance < amount {
 *         return Err(ProgramError::InsufficientFunds);
 *     }
 *
 *     user_data.balance -= amount;
 *     user_data.serialize(&mut &mut pda_account.data.borrow_mut()[..])?;
 *
 *     **pda_account.try_borrow_mut_lamports()? -= amount;
 *     **recipient_account.try_borrow_mut_lamports()? += amount;
 *
 *     Ok(())
 * }
 */

/*
 * EXPLOIT SCENARIO:
 *
 * 1. Legitimate user has PDA at: PDA = hash(b"user_data" + user_pubkey)
 * 2. Attacker finds different seeds that produce a valid PDA for this program:
 *    - Attacker PDA = hash(b"malicious_seeds" + attacker_pubkey)
 * 3. Attacker initializes their PDA with:
 *    - owner: USER's pubkey (not attacker!)
 *    - balance: 1,000,000 SOL (funded by attacker)
 * 4. Attacker creates transaction signed by USER (through phishing, etc.)
 * 5. Transaction calls vulnerable program with:
 *    - user_account: USER (signed)
 *    - pda_account: ATTACKER's PDA (with user as owner)
 *    - recipient_account: ATTACKER
 * 6. Program doesn't verify PDA derivation, only checks:
 *    - pda_account.owner == program_id ✓
 *    - user_data.owner == user_account.key ✓
 * 7. Attacker withdraws their own SOL but makes it look like user's withdrawal
 * 8. More complex attacks possible with PDA authorization bypass
 */

/*
 * ANOTHER VULNERABILITY: Missing Bump Seed Validation
 */

pub fn vulnerable_with_bump(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let pda_account = next_account_info(accounts_iter)?;

    let bump = instruction_data[0];

    // VULNERABILITY: Accepts user-provided bump seed without validation
    // Should use find_program_address to get canonical bump
    let seeds = &[b"vault", &[bump]];

    // Attacker can provide non-canonical bump and potentially bypass checks
    let pda = Pubkey::create_program_address(seeds, program_id)?;

    if pda != *pda_account.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Rest of logic...
    Ok(())
}
