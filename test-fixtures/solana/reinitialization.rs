/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * Reinitialization Vulnerability
 *
 * This program fails to prevent reinitialization of accounts,
 * allowing attackers to reset state or take over ownership.
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
pub struct VaultConfig {
    pub authority: Pubkey,
    pub total_deposited: u64,
    pub fee_percentage: u8,
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
        1 => deposit(program_id, accounts, &instruction_data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub fn initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Initialize (No Reinitialization Check)");

    let accounts_iter = &mut accounts.iter();
    let vault_account = next_account_info(accounts_iter)?;
    let authority_account = next_account_info(accounts_iter)?;

    if vault_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if !authority_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY: No check if vault is already initialized
    // Attacker can call initialize again to take over ownership
    // Should check: if vault_config data is not all zeros, return error

    let fee_percentage = instruction_data[0];

    let vault_config = VaultConfig {
        authority: *authority_account.key, // VULNERABILITY: Attacker becomes new authority!
        total_deposited: 0, // VULNERABILITY: Resets to zero!
        fee_percentage,
    };

    vault_config.serialize(&mut &mut vault_account.data.borrow_mut()[..])?;

    msg!("Vault initialized with authority: {}", authority_account.key);

    Ok(())
}

pub fn deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault_account = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;

    if vault_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut vault_config = VaultConfig::try_from_slice(&vault_account.data.borrow())?;

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    vault_config.total_deposited += amount;
    vault_config.serialize(&mut &mut vault_account.data.borrow_mut()[..])?;

    **user_account.try_borrow_mut_lamports()? -= amount;
    **vault_account.try_borrow_mut_lamports()? += amount;

    Ok(())
}

/*
 * SECURE VERSION:
 *
 * #[derive(BorshSerialize, BorshDeserialize, Debug)]
 * pub struct VaultConfig {
 *     pub is_initialized: bool,  // ADD THIS FIELD
 *     pub authority: Pubkey,
 *     pub total_deposited: u64,
 *     pub fee_percentage: u8,
 * }
 *
 * pub fn initialize_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let vault_account = next_account_info(accounts_iter)?;
 *     let authority_account = next_account_info(accounts_iter)?;
 *
 *     if vault_account.owner != program_id {
 *         return Err(ProgramError::IncorrectProgramId);
 *     }
 *
 *     if !authority_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     // CHECK: Try to deserialize existing data
 *     if let Ok(existing_config) = VaultConfig::try_from_slice(&vault_account.data.borrow()) {
 *         // CHECK: If already initialized, reject
 *         if existing_config.is_initialized {
 *             msg!("Vault already initialized");
 *             return Err(ProgramError::AccountAlreadyInitialized);
 *         }
 *     }
 *
 *     let fee_percentage = instruction_data[0];
 *
 *     let vault_config = VaultConfig {
 *         is_initialized: true,  // SET FLAG
 *         authority: *authority_account.key,
 *         total_deposited: 0,
 *         fee_percentage,
 *     };
 *
 *     vault_config.serialize(&mut &mut vault_account.data.borrow_mut()[..])?;
 *
 *     Ok(())
 * }
 *
 * // Alternative: Use Anchor framework which handles this automatically
 * // with #[account(init)] macro
 */

/*
 * EXPLOIT SCENARIO:
 *
 * 1. User initializes vault with 100 SOL deposited:
 *    - authority: USER
 *    - total_deposited: 100 SOL
 *    - fee_percentage: 1%
 *
 * 2. Attacker calls initialize again:
 *    - authority: ATTACKER
 *    - total_deposited: 0 (RESET!)
 *    - fee_percentage: 99%
 *
 * 3. Vault state is now:
 *    - authority: ATTACKER (took over!)
 *    - total_deposited: 0 (lost track of 100 SOL!)
 *    - fee_percentage: 99% (malicious fee)
 *
 * 4. Attacker now controls vault with user's 100 SOL still in it
 * 5. User's deposit records lost
 * 6. Attacker can drain vault or set malicious fees
 */

/*
 * REAL-WORLD IMPACT:
 *
 * - Wormhole Bridge Hack (2022): Similar initialization issues
 * - Cashio Hack (2022): Infinite mint due to reinitialization
 * - Multiple DeFi protocols on Solana affected
 * - Losses in millions of dollars
 */
