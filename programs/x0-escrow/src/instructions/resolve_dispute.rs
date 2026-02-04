//! Resolve a dispute

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Token2022, TransferChecked};

use crate::state::{EscrowAccount, EscrowState};
use x0_common::{
    constants::*,
    error::X0EscrowError,
    events::{DisputeResolved, FundsRefunded, FundsReleased},
};

/// Accounts for resolving a dispute
#[derive(Accounts)]
pub struct ResolveDispute<'info> {
    /// The arbiter (must sign)
    pub arbiter: Signer<'info>,

    /// The escrow account
    #[account(
        mut,
        seeds = [ESCROW_SEED, escrow.buyer.as_ref(), escrow.seller.as_ref(), &escrow.memo_hash],
        bump = escrow.bump,
        constraint = Some(arbiter.key()) == escrow.arbiter @ X0EscrowError::OnlyArbiterCanResolve,
        constraint = escrow.state == EscrowState::Disputed @ X0EscrowError::InvalidEscrowState,
    )]
    pub escrow: Account<'info, EscrowAccount>,

    /// The escrow token account (source)
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub escrow_token_account: UncheckedAccount<'info>,

    /// The buyer's token account (for refund)
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub buyer_token_account: UncheckedAccount<'info>,

    /// The seller's token account (for release)
    /// CHECK: Validated by Token-2022 program
    #[account(mut)]
    pub seller_token_account: UncheckedAccount<'info>,

    /// The token mint
    /// CHECK: Must match escrow.mint
    pub mint: UncheckedAccount<'info>,

    /// The seller's reputation account (optional - for CPI update)
    /// CHECK: Validated by reputation program via CPI
    #[account(mut)]
    pub seller_reputation: Option<UncheckedAccount<'info>>,

    /// The reputation program
    /// CHECK: Validated by program ID
    pub reputation_program: Option<UncheckedAccount<'info>>,

    /// Token-2022 program
    pub token_program: Program<'info, Token2022>,
}

pub fn handler(ctx: Context<ResolveDispute>, release_to_seller: bool) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    let clock = Clock::get()?;

    // ========================================================================
    // MEDIUM-6 FIX: Arbiter must wait for resolution delay
    // ========================================================================
    // This prevents rushed malicious resolutions and gives parties time to respond
    require!(
        clock.slot >= escrow.dispute_initiated_slot.saturating_add(ARBITER_RESOLUTION_DELAY_SLOTS),
        X0EscrowError::ArbiterResolutionTooEarly
    );

    // MEDIUM-6 FIX: Require dispute evidence before arbiter resolution
    require!(
        escrow.dispute_evidence.is_some(),
        X0EscrowError::DisputeEvidenceRequired
    );

    // ========================================================================
    // CRITICAL-2 FIX: Update state BEFORE transfer to prevent reentrancy
    // ========================================================================
    // Capture values before state update (in case of complex struct interactions)
    let transfer_amount = escrow.amount;
    let buyer = escrow.buyer;
    let seller = escrow.seller;
    let token_decimals = escrow.token_decimals; // MEDIUM-11: Use stored decimals
    
    // Update state BEFORE transfer (prevents reentrancy)
    // Any reentrant call will fail the state constraint (must be Disputed)
    if release_to_seller {
        escrow.state = EscrowState::Released;
    } else {
        escrow.state = EscrowState::Refunded;
    }

    // Prepare PDA signer
    let seeds = &[
        ESCROW_SEED,
        buyer.as_ref(),
        seller.as_ref(),
        &escrow.memo_hash,
        &[escrow.bump],
    ];
    let signer_seeds = &[&seeds[..]];

    let destination = if release_to_seller {
        ctx.accounts.seller_token_account.to_account_info()
    } else {
        ctx.accounts.buyer_token_account.to_account_info()
    };

    let cpi_accounts = TransferChecked {
        from: ctx.accounts.escrow_token_account.to_account_info(),
        mint: ctx.accounts.mint.to_account_info(),
        to: destination.clone(),
        authority: escrow.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );

    // MEDIUM-11: Use stored decimals instead of hardcoded 6
    token_2022::transfer_checked(cpi_ctx, transfer_amount, token_decimals)?;

    // Emit events after successful transfer
    if release_to_seller {
        emit!(FundsReleased {
            escrow: escrow.key(),
            amount: transfer_amount,
            recipient: seller,
            is_auto_release: false,
            timestamp: clock.unix_timestamp,
        });
    } else {
        emit!(FundsRefunded {
            escrow: escrow.key(),
            amount: transfer_amount,
            recipient: buyer,
            reason: "Dispute resolved in buyer's favor".to_string(),
            timestamp: clock.unix_timestamp,
        });
    }

    let winner = if release_to_seller { seller } else { buyer };

    emit!(DisputeResolved {
        escrow: escrow.key(),
        resolver: ctx.accounts.arbiter.key(),
        winner,
        amount: transfer_amount,
        timestamp: clock.unix_timestamp,
    });

    // ========================================================================
    // CPI: Update seller's reputation based on dispute resolution
    // ========================================================================
    if let (Some(reputation_account), Some(reputation_program)) = (
        &ctx.accounts.seller_reputation,
        &ctx.accounts.reputation_program,
    ) {
        if release_to_seller {
            // Seller won the dispute - record resolution in their favor
            let cpi_accounts = x0_reputation::cpi::accounts::RecordResolutionFavor {
                authority: escrow.to_account_info(),
                reputation: reputation_account.to_account_info(),
            };
            
            let cpi_ctx = CpiContext::new_with_signer(
                reputation_program.to_account_info(),
                cpi_accounts,
                signer_seeds,
            );

            x0_reputation::cpi::record_resolution_favor(cpi_ctx)?;
            
            msg!("Reputation updated: resolution in favor of seller {}", seller);
        }
        // Note: If buyer wins, seller's reputation already took a hit from the dispute
        // No additional penalty needed here
    }

    msg!(
        "Dispute resolved: escrow={}, winner={}, amount={}",
        escrow.key(),
        winner,
        transfer_amount
    );

    Ok(())
}
