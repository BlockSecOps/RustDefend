/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * Missing Owner Check Vulnerability
 *
 * This program fails to verify that accounts are owned by the expected program,
 * allowing attackers to pass malicious account data.
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
pub struct VaultData {
    pub authority: Pubkey,
    pub balance: u64,
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Missing Owner Check");

    let accounts_iter = &mut accounts.iter();
    let vault_account = next_account_info(accounts_iter)?;
    let authority_account = next_account_info(accounts_iter)?;
    let recipient_account = next_account_info(accounts_iter)?;

    // VULNERABILITY: No check that vault_account is owned by this program
    // Attacker can pass an account they control with fake data
    // Should have: if vault_account.owner != program_id { return Err(ProgramError::IncorrectProgramId); }

    let mut vault_data = VaultData::try_from_slice(&vault_account.data.borrow())?;

    // VULNERABILITY: This check can be bypassed by providing fake account data
    if vault_data.authority != *authority_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    // VULNERABILITY: No signer check either!
    // Should have: if !authority_account.is_signer { return Err(...); }

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    msg!("Withdrawing {} lamports", amount);

    // Attacker's fake account will pass all checks
    vault_data.balance -= amount;
    vault_data.serialize(&mut &mut vault_account.data.borrow_mut()[..])?;

    **vault_account.try_borrow_mut_lamports()? -= amount;
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
 *     let vault_account = next_account_info(accounts_iter)?;
 *     let authority_account = next_account_info(accounts_iter)?;
 *     let recipient_account = next_account_info(accounts_iter)?;
 *
 *     // CHECK: Verify vault_account is owned by this program
 *     if vault_account.owner != program_id {
 *         return Err(ProgramError::IncorrectProgramId);
 *     }
 *
 *     // CHECK: Verify authority is signer
 *     if !authority_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     let mut vault_data = VaultData::try_from_slice(&vault_account.data.borrow())?;
 *
 *     // Now this check is meaningful
 *     if vault_data.authority != *authority_account.key {
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
 *
 *     vault_data.balance -= amount;
 *     vault_data.serialize(&mut &mut vault_account.data.borrow_mut()[..])?;
 *
 *     **vault_account.try_borrow_mut_lamports()? -= amount;
 *     **recipient_account.try_borrow_mut_lamports()? += amount;
 *
 *     Ok(())
 * }
 */

/*
 * EXPLOIT SCENARIO:
 *
 * 1. Attacker creates their own account with crafted data
 * 2. In the fake account data, attacker sets:
 *    - authority: ATTACKER's pubkey
 *    - balance: 1,000,000 (fake!)
 * 3. Attacker funds the fake account with actual SOL
 * 4. Attacker calls vulnerable program with:
 *    - vault_account: ATTACKER's fake account
 *    - authority_account: ATTACKER (they can sign)
 *    - recipient_account: ATTACKER
 * 5. Program doesn't verify vault_account is owned by program
 * 6. Attacker withdraws real SOL from the fake account
 */
