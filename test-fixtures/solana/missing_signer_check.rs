/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * Missing Signer Check Vulnerability
 *
 * This program fails to verify that required accounts are signers,
 * allowing unauthorized users to modify data or steal funds.
 */

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Missing Signer Check");

    let accounts_iter = &mut accounts.iter();
    let user_account = next_account_info(accounts_iter)?;
    let destination_account = next_account_info(accounts_iter)?;

    // VULNERABILITY: No check that user_account is a signer
    // Anyone can pass any account as user_account and drain it
    // Should have: if !user_account.is_signer { return Err(ProgramError::MissingRequiredSignature); }

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    msg!("Transferring {} lamports", amount);

    // VULNERABILITY: This transfer will succeed even if user_account didn't sign
    **user_account.try_borrow_mut_lamports()? -= amount;
    **destination_account.try_borrow_mut_lamports()? += amount;

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
 *     let destination_account = next_account_info(accounts_iter)?;
 *
 *     // CHECK: Verify user_account is a signer
 *     if !user_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
 *
 *     **user_account.try_borrow_mut_lamports()? -= amount;
 *     **destination_account.try_borrow_mut_lamports()? += amount;
 *
 *     Ok(())
 * }
 */

/*
 * EXPLOIT SCENARIO:
 *
 * 1. Attacker sees this program being used
 * 2. Attacker creates transaction with:
 *    - user_account: VICTIM's account (without victim's signature!)
 *    - destination_account: ATTACKER's account
 *    - instruction_data: amount to steal
 * 3. Program doesn't check if user_account signed the transaction
 * 4. Funds transferred from victim to attacker
 */
