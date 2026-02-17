/*
 * VULNERABLE SOLANA PROGRAM - DO NOT USE IN PRODUCTION
 *
 * Arbitrary CPI (Cross-Program Invocation) Vulnerability
 *
 * This program allows users to specify which program to call via CPI,
 * enabling attackers to invoke malicious programs or drain funds.
 */

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Vulnerable: Arbitrary CPI");

    let accounts_iter = &mut accounts.iter();
    let user_account = next_account_info(accounts_iter)?;
    let target_program = next_account_info(accounts_iter)?;
    let target_account = next_account_info(accounts_iter)?;

    if !user_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY: User controls which program to invoke
    // Attacker can specify malicious program or system program
    // Should have: whitelist of allowed programs to call

    let instruction = Instruction {
        program_id: *target_program.key, // VULNERABILITY: User-controlled!
        accounts: vec![
            AccountMeta::new(*user_account.key, true),
            AccountMeta::new(*target_account.key, false),
        ],
        data: instruction_data.to_vec(), // VULNERABILITY: User-controlled data!
    };

    msg!("Invoking program: {}", target_program.key);

    // VULNERABILITY: This can invoke ANY program with ANY data
    invoke(
        &instruction,
        &[user_account.clone(), target_account.clone()],
    )?;

    Ok(())
}

/*
 * SECURE VERSION:
 *
 * use solana_program::system_program;
 *
 * // Define allowed programs
 * const ALLOWED_PROGRAMS: &[Pubkey] = &[
 *     solana_program::system_program::ID,
 *     // Add other trusted programs here
 * ];
 *
 * pub fn process_instruction_secure(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     instruction_data: &[u8],
 * ) -> ProgramResult {
 *     let accounts_iter = &mut accounts.iter();
 *     let user_account = next_account_info(accounts_iter)?;
 *     let target_program = next_account_info(accounts_iter)?;
 *     let target_account = next_account_info(accounts_iter)?;
 *
 *     if !user_account.is_signer {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *
 *     // CHECK: Whitelist allowed programs
 *     if !ALLOWED_PROGRAMS.contains(target_program.key) {
 *         msg!("Program not in whitelist");
 *         return Err(ProgramError::InvalidInstructionData);
 *     }
 *
 *     // CHECK: Validate instruction data based on target program
 *     // Parse and validate the specific instruction for the target program
 *
 *     let instruction = Instruction {
 *         program_id: *target_program.key,
 *         accounts: vec![
 *             AccountMeta::new(*user_account.key, true),
 *             AccountMeta::new(*target_account.key, false),
 *         ],
 *         data: instruction_data.to_vec(),
 *     };
 *
 *     invoke(
 *         &instruction,
 *         &[user_account.clone(), target_account.clone()],
 *     )?;
 *
 *     Ok(())
 * }
 */

/*
 * EXPLOIT SCENARIOS:
 *
 * Scenario 1: Drain via System Program
 * 1. Attacker calls vulnerable program with:
 *    - target_program: System Program
 *    - instruction_data: Transfer instruction transferring user's SOL to attacker
 * 2. Program invokes System Program on behalf of user
 * 3. User's SOL transferred to attacker
 *
 * Scenario 2: Invoke Malicious Program
 * 1. Attacker deploys malicious program
 * 2. Attacker calls vulnerable program with:
 *    - target_program: Attacker's malicious program
 *    - instruction_data: Malicious payload
 * 3. Malicious program executes with user's signature
 *
 * Scenario 3: Close Account
 * 1. Attacker crafts instruction to close important account
 * 2. Vulnerable program invokes close instruction
 * 3. Critical data lost
 */
