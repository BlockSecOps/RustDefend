/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * Arithmetic Errors and Integer Overflow/Underflow
 *
 * This program has arithmetic operations that can overflow, underflow,
 * or lose precision, leading to incorrect calculations and vulnerabilities.
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
pub struct StakingPool {
    pub total_staked: u64,
    pub reward_rate: u64,  // Rewards per second
    pub last_update: i64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct UserStake {
    pub amount: u64,
    pub last_claim: i64,
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = instruction_data[0];

    match instruction {
        0 => stake(program_id, accounts, &instruction_data[1..]),
        1 => calculate_rewards(program_id, accounts, &instruction_data[1..]),
        2 => vulnerable_transfer(program_id, accounts, &instruction_data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub fn stake(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Arithmetic Overflow");

    let accounts_iter = &mut accounts.iter();
    let pool_account = next_account_info(accounts_iter)?;
    let user_stake_account = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;

    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut pool_data = StakingPool::try_from_slice(&pool_account.data.borrow())?;
    let mut user_data = UserStake::try_from_slice(&user_stake_account.data.borrow())?;

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    // VULNERABILITY 1: Unchecked addition can overflow
    // If total_staked is near u64::MAX, this panics in debug or wraps in release
    pool_data.total_staked += amount;  // Should use checked_add()

    // VULNERABILITY 2: Another unchecked addition
    user_data.amount += amount;  // Should use checked_add()

    pool_data.serialize(&mut &mut pool_account.data.borrow_mut()[..])?;
    user_data.serialize(&mut &mut user_stake_account.data.borrow_mut()[..])?;

    msg!("Staked {} tokens", amount);

    Ok(())
}

pub fn calculate_rewards(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Arithmetic Precision Loss");

    let accounts_iter = &mut accounts.iter();
    let pool_account = next_account_info(accounts_iter)?;
    let user_stake_account = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;
    let clock_sysvar = next_account_info(accounts_iter)?;

    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let pool_data = StakingPool::try_from_slice(&pool_account.data.borrow())?;
    let user_data = UserStake::try_from_slice(&user_stake_account.data.borrow())?;

    // Get current timestamp (simplified - normally use Clock sysvar)
    let current_time = 1000000_i64;  // Placeholder

    // VULNERABILITY 3: Unchecked subtraction can underflow
    let time_elapsed = current_time - user_data.last_claim;  // Should use checked_sub()

    // VULNERABILITY 4: Multiplication can overflow
    let time_elapsed_u64 = time_elapsed as u64;
    let reward_per_second = pool_data.reward_rate;

    // This multiplication can overflow
    let base_reward = time_elapsed_u64 * reward_per_second;  // Should use checked_mul()

    // VULNERABILITY 5: Division causes precision loss
    // Integer division truncates, losing fractional rewards
    let user_share = user_data.amount / pool_data.total_staked;  // Should multiply first
    let user_reward = base_reward * user_share;  // Wrong order - precision lost

    // CORRECT: let user_reward = (base_reward * user_data.amount) / pool_data.total_staked;

    msg!("User reward calculated: {}", user_reward);

    Ok(())
}

pub fn vulnerable_transfer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Underflow");

    let accounts_iter = &mut accounts.iter();
    let from_account = next_account_info(accounts_iter)?;
    let to_account = next_account_info(accounts_iter)?;
    let user_account = next_account_info(accounts_iter)?;

    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    // VULNERABILITY 6: No balance check before subtraction
    // If amount > from_account.lamports(), this underflows
    **from_account.try_borrow_mut_lamports()? -= amount;  // Should check balance first
    **to_account.try_borrow_mut_lamports()? += amount;

    Ok(())
}

/*
 * SECURE VERSION USING CHECKED ARITHMETIC:
 *
 * pub fn stake_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let pool_account = next_account_info(accounts_iter)?;
 *     let user_stake_account = next_account_info(accounts_iter)?;
 *     let user_account = next_account_info(accounts_iter)?;
 *
 *     if !user_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     let mut pool_data = StakingPool::try_from_slice(&pool_account.data.borrow())?;
 *     let mut user_data = UserStake::try_from_slice(&user_stake_account.data.borrow())?;
 *
 *     let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
 *
 *     // SAFE: Use checked arithmetic
 *     pool_data.total_staked = pool_data.total_staked
 *         .checked_add(amount)
 *         .ok_or(ProgramError::ArithmeticOverflow)?;
 *
 *     user_data.amount = user_data.amount
 *         .checked_add(amount)
 *         .ok_or(ProgramError::ArithmeticOverflow)?;
 *
 *     pool_data.serialize(&mut &mut pool_account.data.borrow_mut()[..])?;
 *     user_data.serialize(&mut &mut user_stake_account.data.borrow_mut()[..])?;
 *
 *     Ok(())
 * }
 *
 * pub fn calculate_rewards_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     _instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let pool_account = next_account_info(accounts_iter)?;
 *     let user_stake_account = next_account_info(accounts_iter)?;
 *     let user_account = next_account_info(accounts_iter)?;
 *
 *     if !user_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     let pool_data = StakingPool::try_from_slice(&pool_account.data.borrow())?;
 *     let user_data = UserStake::try_from_slice(&user_stake_account.data.borrow())?;
 *
 *     let current_time = 1000000_i64;
 *
 *     // SAFE: Checked subtraction
 *     let time_elapsed = current_time
 *         .checked_sub(user_data.last_claim)
 *         .ok_or(ProgramError::InvalidAccountData)? as u64;
 *
 *     // SAFE: Checked multiplication
 *     let base_reward = time_elapsed
 *         .checked_mul(pool_data.reward_rate)
 *         .ok_or(ProgramError::ArithmeticOverflow)?;
 *
 *     // SAFE: Correct order to minimize precision loss
 *     let numerator = base_reward
 *         .checked_mul(user_data.amount)
 *         .ok_or(ProgramError::ArithmeticOverflow)?;
 *
 *     // Check for division by zero
 *     if pool_data.total_staked == 0 {
 *         return Err(ProgramError::DivisionByZero);
 *     }
 *
 *     let user_reward = numerator / pool_data.total_staked;
 *
 *     msg!("User reward calculated: {}", user_reward);
 *
 *     Ok(())
 * }
 *
 * pub fn transfer_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let from_account = next_account_info(accounts_iter)?;
 *     let to_account = next_account_info(accounts_iter)?;
 *     let user_account = next_account_info(accounts_iter)?;
 *
 *     if !user_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
 *
 *     // SAFE: Check balance first
 *     if **from_account.lamports.borrow() < amount {
 *         return Err(ProgramError::InsufficientFunds);
 *     }
 *
 *     // Now safe to perform operations
 *     **from_account.try_borrow_mut_lamports()? -= amount;
 *     **to_account.try_borrow_mut_lamports()? += amount;
 *
 *     Ok(())
 * }
 */

/*
 * EXPLOIT SCENARIOS:
 *
 * Overflow Attack:
 * 1. Attacker stakes u64::MAX - 100
 * 2. Pool total_staked = u64::MAX - 100
 * 3. Attacker stakes 200 more
 * 4. total_staked wraps to 99
 * 5. Reward calculations completely wrong
 * 6. Attacker gets disproportionate rewards
 *
 * Underflow Attack:
 * 1. Account has 100 SOL
 * 2. Attacker requests transfer of 150 SOL
 * 3. Subtraction underflows: 100 - 150 wraps to huge number
 * 4. Account balance becomes near u64::MAX
 * 5. Attacker can drain entire program
 *
 * Precision Loss:
 * 1. Pool has 1,000,000 total staked
 * 2. User has 10 staked
 * 3. Wrong: user_share = 10 / 1,000,000 = 0 (integer division)
 * 4. User gets 0 rewards even though they should get some
 */
