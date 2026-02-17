/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * Rent Exemption Vulnerability
 *
 * This program fails to ensure accounts have enough lamports to be rent-exempt,
 * leading to accounts being garbage collected by the runtime.
 */

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct UserData {
    pub owner: Pubkey,
    pub balance: u64,
    pub metadata: [u8; 32],
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data[0];

    match instruction {
        0 => initialize(program_id, accounts, &instruction_data[1..]),
        1 => withdraw_all(program_id, accounts, &instruction_data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub fn initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: No Rent Exemption Check");

    let accounts_iter = &mut accounts.iter();
    let user_data_account = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;

    if user_data_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY: No check that user_data_account has enough lamports for rent exemption
    // Account might be garbage collected if not rent-exempt
    // Should check: let rent = Rent::get()?;
    //               if !rent.is_exempt(user_data_account.lamports(), user_data_account.data_len()) {
    //                   return Err(...);
    //               }

    let user_data = UserData {
        owner: *user_account.key,
        balance: 0,
        metadata: [0u8; 32],
    };

    user_data.serialize(&mut &mut user_data_account.data.borrow_mut()[..])?;

    msg!("User data initialized");

    Ok(())
}

pub fn withdraw_all(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Draining Below Rent Exemption");

    let accounts_iter = &mut accounts.iter();
    let user_data_account = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;
    let recipient_account = next_account_info(accounts_iter)?;

    if user_data_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut user_data = UserData::try_from_slice(&user_data_account.data.borrow())?;

    if user_data.owner != *user_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    let balance = **user_data_account.lamports.borrow();

    msg!("Withdrawing all {} lamports", balance);

    // VULNERABILITY: Withdraws ALL lamports without leaving rent exemption minimum
    // Account will be garbage collected and data lost
    // Should keep enough lamports for rent exemption:
    //   let rent = Rent::get()?;
    //   let min_balance = rent.minimum_balance(user_data_account.data_len());
    //   let withdrawable = balance.saturating_sub(min_balance);

    **user_data_account.try_borrow_mut_lamports()? = 0;
    **recipient_account.try_borrow_mut_lamports()? += balance;

    Ok(())
}

/*
 * SECURE VERSION:
 *
 * pub fn initialize_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     _instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let user_data_account = next_account_info(accounts_iter)?;
 *     let user_account = next_account_info(accounts_iter)?;
 *
 *     if user_data_account.owner != program_id {
 *         return Err(ProgramError::IncorrectProgramId);
 *     }
 *
 *     if !user_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     // CHECK: Verify account is rent-exempt
 *     let rent = Rent::get()?;
 *     if !rent.is_exempt(
 *         user_data_account.lamports(),
 *         user_data_account.data_len()
 *     ) {
 *         msg!("Account is not rent-exempt");
 *         return Err(ProgramError::AccountNotRentExempt);
 *     }
 *
 *     let user_data = UserData {
 *         owner: *user_account.key,
 *         balance: 0,
 *         metadata: [0u8; 32],
 *     };
 *
 *     user_data.serialize(&mut &mut user_data_account.data.borrow_mut()[..])?;
 *
 *     Ok(())
 * }
 *
 * pub fn withdraw_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     _instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let user_data_account = next_account_info(accounts_iter)?;
 *     let user_account = next_account_info(accounts_iter)?;
 *     let recipient_account = next_account_info(accounts_iter)?;
 *
 *     if user_data_account.owner != program_id {
 *         return Err(ProgramError::IncorrectProgramId);
 *     }
 *
 *     if !user_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     let user_data = UserData::try_from_slice(&user_data_account.data.borrow())?;
 *
 *     if user_data.owner != *user_account.key {
 *         return Err(ProgramError::InvalidAccountData);
 *     }
 *
 *     let balance = **user_data_account.lamports.borrow();
 *
 *     // SAFE: Calculate minimum balance for rent exemption
 *     let rent = Rent::get()?;
 *     let min_balance = rent.minimum_balance(user_data_account.data_len());
 *
 *     // SAFE: Only withdraw excess above rent exemption
 *     let withdrawable = balance.checked_sub(min_balance)
 *         .ok_or(ProgramError::InsufficientFunds)?;
 *
 *     if withdrawable == 0 {
 *         msg!("No funds available for withdrawal");
 *         return Err(ProgramError::InsufficientFunds);
 *     }
 *
 *     msg!("Withdrawing {} lamports (keeping {} for rent)", withdrawable, min_balance);
 *
 *     **user_data_account.try_borrow_mut_lamports()? -= withdrawable;
 *     **recipient_account.try_borrow_mut_lamports()? += withdrawable;
 *
 *     Ok(())
 * }
 */

/*
 * WHAT IS RENT ON SOLANA:
 *
 * - Solana charges "rent" to store account data
 * - Accounts with insufficient balance are garbage collected
 * - Accounts with >= 2 years of rent are "rent-exempt" and never collected
 * - Rent exemption threshold depends on account data size
 * - Most programs should require accounts to be rent-exempt
 *
 * CURRENT RENT RATES (as of 2024):
 * - ~0.00000348 SOL per byte per year
 * - Example: 128 byte account needs ~0.00089 SOL for 2 years (rent exempt)
 * - Rates are very low but must be considered
 */

/*
 * EXPLOIT SCENARIO:
 *
 * 1. Attacker creates user_data_account with:
 *    - 0.0001 SOL (not rent-exempt for 128 bytes)
 *    - Valid UserData structure
 *
 * 2. Attacker calls initialize, program accepts it
 *    - No rent exemption check
 *
 * 3. Some time passes, rent is collected
 *
 * 4. Account balance drops to zero
 *
 * 5. Solana runtime garbage collects the account
 *
 * 6. UserData is permanently lost
 *
 * 7. If user later deposits funds, there's no account to track them
 *
 * WITHDRAWAL SCENARIO:
 *
 * 1. User has account with 0.001 SOL (barely rent-exempt)
 * 2. User calls withdraw_all
 * 3. Program drains all 0.001 SOL
 * 4. Account now has 0 SOL
 * 5. Account garbage collected on next epoch
 * 6. User's data permanently lost
 */

/*
 * REAL-WORLD IMPACT:
 *
 * - Lost user data when accounts garbage collected
 * - Permanent loss of program state
 * - Broken program functionality
 * - User funds inaccessible if tracking account is lost
 */
