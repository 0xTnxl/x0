//! Migrate reputation instruction - upgrades v1 accounts to v2 layout
//! This handles the transition when failed_transactions field was added

use anchor_lang::prelude::*;
use x0_common::constants::GUARD_PROGRAM_ID;

/// Accounts for migrating a reputation account from v1 to v2
#[derive(Accounts)]
pub struct MigrateReputation<'info> {
    /// The policy owner (must match policy.owner)
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The agent's policy PDA - verifies ownership
    /// CHECK: We manually verify this is owned by x0-guard
    #[account()]
    pub agent_policy: UncheckedAccount<'info>,

    /// The reputation account to migrate
    /// CHECK: We manually verify PDA and do raw read/write
    #[account(
        mut,
        seeds = [b"reputation", agent_policy.key().as_ref()],
        bump,
    )]
    pub reputation: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

/// V1 account layout (without failed_transactions):
/// - discriminator: 8 bytes
/// - version: 1 byte
/// - agent_id: 32 bytes
/// - total_transactions: 8 bytes
/// - successful_transactions: 8 bytes
/// - disputed_transactions: 8 bytes
/// - resolved_in_favor: 8 bytes
/// - average_response_time_ms: 4 bytes
/// - cumulative_response_time_ms: 8 bytes
/// - last_updated: 8 bytes
/// - last_decay_applied: 8 bytes
/// - bump: 1 byte
/// - _reserved: 31 bytes
/// Total: 8 + 1 + 32 + 8 + 8 + 8 + 8 + 4 + 8 + 8 + 8 + 1 + 31 = 133 bytes

/// V2 account layout (with failed_transactions):
/// - discriminator: 8 bytes
/// - version: 1 byte
/// - agent_id: 32 bytes
/// - total_transactions: 8 bytes
/// - successful_transactions: 8 bytes
/// - disputed_transactions: 8 bytes
/// - resolved_in_favor: 8 bytes
/// - failed_transactions: 8 bytes  <-- NEW (inserted)
/// - average_response_time_ms: 4 bytes
/// - cumulative_response_time_ms: 8 bytes
/// - last_updated: 8 bytes
/// - last_decay_applied: 8 bytes
/// - bump: 1 byte
/// - _reserved: 23 bytes  <-- REDUCED by 8
/// Total: 8 + 1 + 32 + 8 + 8 + 8 + 8 + 8 + 4 + 8 + 8 + 8 + 1 + 23 = 133 bytes (same!)
const ACCOUNT_SIZE: usize = 133;

pub fn handler(ctx: Context<MigrateReputation>) -> Result<()> {
    // Verify the policy account is owned by x0-guard
    let policy_info = &ctx.accounts.agent_policy;
    require!(
        policy_info.owner == &GUARD_PROGRAM_ID,
        x0_common::error::X0ReputationError::InvalidPolicyAccount
    );

    // Deserialize to verify owner matches
    let policy_data = policy_info.try_borrow_data()?;
    if policy_data.len() < 41 {
        return Err(x0_common::error::X0ReputationError::InvalidPolicyAccount.into());
    }
    let owner_bytes: [u8; 32] = policy_data[9..41].try_into().unwrap();
    let policy_owner = Pubkey::new_from_array(owner_bytes);
    
    require!(
        policy_owner == ctx.accounts.owner.key(),
        x0_common::error::X0ReputationError::Unauthorized
    );
    drop(policy_data);

    // Read the current account data
    let reputation_info = &ctx.accounts.reputation;
    let current_size = reputation_info.data_len();
    
    msg!("Current reputation account size: {}", current_size);
    
    if current_size != ACCOUNT_SIZE {
        msg!("Unexpected account size: {}, expected {}", current_size, ACCOUNT_SIZE);
        return Err(x0_common::error::X0ReputationError::InvalidReputationUpdate.into());
    }

    // Read the version byte (offset 8 after discriminator)
    let data = reputation_info.try_borrow_data()?;
    let version = data[8];
    drop(data);
    
    msg!("Current version: {}", version);

    if version >= 2 {
        msg!("Account already at version 2 or higher, no migration needed");
        return Ok(());
    }

    // Both V1 and V2 are 133 bytes, but fields are in different positions.
    // We need to shift data to insert failed_transactions at offset 74.
    //
    // V1 offsets:
    //   0-7: discriminator
    //   8: version
    //   9-40: agent_id
    //   41-48: total_transactions
    //   49-56: successful_transactions
    //   57-64: disputed_transactions
    //   65-72: resolved_in_favor
    //   73-76: average_response_time_ms (4 bytes)
    //   77-84: cumulative_response_time_ms
    //   85-92: last_updated
    //   93-100: last_decay_applied
    //   101: bump
    //   102-132: _reserved (31 bytes)
    //
    // V2 offsets:
    //   0-7: discriminator
    //   8: version
    //   9-40: agent_id  
    //   41-48: total_transactions
    //   49-56: successful_transactions
    //   57-64: disputed_transactions
    //   65-72: resolved_in_favor
    //   73-80: failed_transactions  <-- NEW
    //   81-84: average_response_time_ms (4 bytes)
    //   85-92: cumulative_response_time_ms
    //   93-100: last_updated
    //   101-108: last_decay_applied
    //   109: bump
    //   110-132: _reserved (23 bytes)

    let mut data = reputation_info.try_borrow_mut_data()?;
    
    // Read V1 values that need to be shifted (from offset 73 onward)
    let avg_response_time: [u8; 4] = data[73..77].try_into().unwrap();
    let cumulative_response: [u8; 8] = data[77..85].try_into().unwrap();
    let last_updated: [u8; 8] = data[85..93].try_into().unwrap();
    let last_decay: [u8; 8] = data[93..101].try_into().unwrap();
    let bump = data[101];
    
    // Write V2 layout:
    
    // 1. Update version to 2
    data[8] = 2;
    
    // 2. Write failed_transactions = 0 at offset 73
    data[73..81].copy_from_slice(&0u64.to_le_bytes());
    
    // 3. Write avg_response_time at offset 81
    data[81..85].copy_from_slice(&avg_response_time);
    
    // 4. Write cumulative_response at offset 85
    data[85..93].copy_from_slice(&cumulative_response);
    
    // 5. Write last_updated at offset 93
    data[93..101].copy_from_slice(&last_updated);
    
    // 6. Write last_decay at offset 101
    data[101..109].copy_from_slice(&last_decay);
    
    // 7. Write bump at offset 109
    data[109] = bump;
    
    // 8. Zero out remaining reserved bytes (offset 110 to 133)
    data[110..133].fill(0);
    
    msg!("Migrated reputation account from v1 to v2");
    msg!("Added failed_transactions field (initialized to 0)");
    
    Ok(())
}
