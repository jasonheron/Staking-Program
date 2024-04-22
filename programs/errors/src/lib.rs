use anchor_lang::prelude::*;
use mpl_bubblegum;
use solana_program::pubkey::Pubkey;
mod errors;
use anchor_spl::token::Transfer;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{Mint, Token, TokenAccount},
};
use mpl_token_metadata::accounts::Metadata;

// This is your program's public key and it will update
// automatically when you build the project.
declare_id!("B5L952dSGoLmV6Pbh3Yafc17fDKYVVe8H9mZiTthSHdx");
pub const STAKE_POOL_PREFIX: &str = "stake-pool";
pub const STAKE_ENTRY_PREFIX: &str = "stake-entry";
pub const USER_ESCROW_PREFIX: &str = "escrow_wallet";

#[program]
mod football_staking {
    use super::*;
    pub fn init_pool(ctx: Context<InitPool>, ix: InitPoolIx) -> Result<()> {
        let stake_pool = &mut ctx.accounts.stake_pool;

        // stake_pool.bump = *ctx.bumps.get("stake_pool").unwrap();
        stake_pool.bump = ctx.bumps.stake_pool;
        stake_pool.authority = ctx.accounts.payer.key();
        stake_pool.min_stake_seconds = ix.min_stake_seconds;
        stake_pool.allowed_creators = ix.allowed_creators;
        stake_pool.total_staked_entries = 0;
        stake_pool.identifier = ix.identifier;
        stake_pool.token_address = ix.token_address;
        stake_pool.reward_amount = ix.reward_amount;
        stake_pool.reward_seconds = ix.reward_seconds;

        Ok(())
    }

    pub fn update_pool(ctx: Context<UpdatePoolCtx>, ix: UpdatePoolIx) -> Result<()> {
        let stake_pool = &mut ctx.accounts.stake_pool;
        stake_pool.min_stake_seconds = ix.min_stake_seconds;
        Ok(())
    }

    pub fn init_stake_entry(ctx: Context<InitEntryCtx>) -> Result<()> {
        let stake_entry = &mut ctx.accounts.stake_entry;
        // stake_entry.bump = *ctx.bumps.get("stake_entry");
        stake_entry.bump = ctx.bumps.stake_entry;
        stake_entry.pool = ctx.accounts.stake_pool.key();
        stake_entry.stake_mint = ctx.accounts.stake_mint.key();
        stake_entry.amount = 0;
        Ok(())
    }

    pub fn stake_cnft<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, StakeCnftCtx<'info>>,
        root: [u8; 32],
        data_hash: [u8; 32],
        creator_hash: [u8; 32],
        nonce: u64,
        index: u32,
    ) -> Result<()> {
        let payer = ctx.accounts.leaf_owner.key();
        let token_mint = ctx.accounts.stake_mint.key();

        let stake_pool = &mut ctx.accounts.stake_pool;
        let stake_entry = &mut ctx.accounts.stake_entry;

        stake_entry.last_staker = payer;
        stake_entry.last_staked_at = Clock::get().unwrap().unix_timestamp;
        stake_entry.amount = stake_entry.amount.checked_add(1).unwrap();
        stake_pool.total_staked_entries = stake_pool
            .total_staked_entries
            .checked_add(1)
            .expect("Add error");

        // remaining_accounts are the accounts that make up the required proof
        let remaining_accounts_len = ctx.remaining_accounts.len();
        let mut accounts = Vec::with_capacity(
            8 // space for the 8 AccountMetas that are always included  (below)
           + remaining_accounts_len,
        );
        accounts.extend(vec![
            AccountMeta::new_readonly(ctx.accounts.tree_authority.key(), false),
            AccountMeta::new_readonly(ctx.accounts.leaf_owner.key(), true),
            AccountMeta::new_readonly(ctx.accounts.leaf_delegate.key(), false),
            AccountMeta::new_readonly(ctx.accounts.new_leaf_owner.key(), false),
            AccountMeta::new(ctx.accounts.merkle_tree.key(), false),
            AccountMeta::new_readonly(ctx.accounts.log_wrapper.key(), false),
            AccountMeta::new_readonly(ctx.accounts.compression_program.key(), false),
            AccountMeta::new_readonly(ctx.accounts.system_program.key(), false),
        ]);

        let transfer_discriminator: [u8; 8] = [163, 52, 200, 231, 140, 3, 69, 186];

        let mut data = Vec::with_capacity(
            8 // The length of transfer_discriminator,
           + root.len()
           + data_hash.len()
           + creator_hash.len()
           + 8 // The length of the nonce
           + 8, // The length of the index
        );
        data.extend(transfer_discriminator);
        data.extend(root);
        data.extend(data_hash);
        data.extend(creator_hash);
        data.extend(nonce.to_le_bytes());
        data.extend(index.to_le_bytes());

        let mut account_infos = Vec::with_capacity(
            8 // space for the 8 AccountInfos that are always included (below)
           + remaining_accounts_len,
        );
        account_infos.extend(vec![
            ctx.accounts.tree_authority.to_account_info(),
            ctx.accounts.leaf_owner.to_account_info(),
            ctx.accounts.leaf_delegate.to_account_info(),
            ctx.accounts.new_leaf_owner.to_account_info(),
            ctx.accounts.merkle_tree.to_account_info(),
            ctx.accounts.log_wrapper.to_account_info(),
            ctx.accounts.compression_program.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ]);

        // Add "accounts" (hashes) that make up the merkle proof from the remaining accounts.
        for acc in ctx.remaining_accounts.iter() {
            accounts.push(AccountMeta::new_readonly(acc.key(), false));
            account_infos.push(acc.to_account_info());
        }

        let instruction = solana_program::instruction::Instruction {
            program_id: ctx.accounts.bubblegum_program.key(),
            accounts,
            data,
        };

        msg!("manual cpi call to bubblegum program transfer instruction");
        solana_program::program::invoke(&instruction, &account_infos[..])?;

        Ok(())
    }

    pub fn unstake_cnft<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, UnStakeCnftCtx<'info>>,
        root: [u8; 32],
        data_hash: [u8; 32],
        creator_hash: [u8; 32],
        nonce: u64,
        index: u32,
    ) -> Result<()> {
        let user_seeds = wallet_seeds(
            &ctx.accounts.stake_pool.key(),
            &ctx.accounts.stake_mint.key(),
        )?;
        let stake_pool = &mut ctx.accounts.stake_pool;
        let stake_entry = &mut ctx.accounts.stake_entry;
        //// FEATURE: Minimum stake seconds
        if stake_pool.min_stake_seconds > 0
            && ((Clock::get().unwrap().unix_timestamp - stake_entry.last_staked_at) as u32)
                < stake_pool.min_stake_seconds
        {
            return Err(error!(errors::ErrorCode::MinStakeSecondsNotSatisfied));
        }

        stake_entry.last_staker = Pubkey::default();
        stake_entry.amount = 0;
        stake_pool.total_staked_entries = stake_pool
            .total_staked_entries
            .checked_sub(1)
            .expect("Sub error");

        let binding = ctx.accounts.stake_pool.bump.to_le_bytes();
        let inner = vec![
            "stake-pool".as_ref(),
            ctx.accounts.stake_pool.identifier.as_bytes().as_ref(),
            &binding,
        ];
        let outer = vec![inner.as_slice()];

        let transfer_instruction = Transfer {
            from: ctx.accounts.pool_token_account.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.stake_pool.to_account_info(),
        };

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            transfer_instruction,
            outer.as_slice(),
        );

        msg!("transfer call start");

        anchor_spl::token::transfer(cpi_ctx, ctx.accounts.stake_pool.reward_amount.into())?;

        let mut accounts: Vec<solana_program::instruction::AccountMeta> = vec![
            AccountMeta::new_readonly(ctx.accounts.tree_authority.key(), false),
            AccountMeta::new_readonly(ctx.accounts.stake_entry.key(), true),
            AccountMeta::new_readonly(ctx.accounts.stake_entry.key(), false),
            AccountMeta::new_readonly(ctx.accounts.payer.key(), false),
            AccountMeta::new(ctx.accounts.merkle_tree.key(), false),
            AccountMeta::new_readonly(ctx.accounts.log_wrapper.key(), false),
            AccountMeta::new_readonly(ctx.accounts.compression_program.key(), false),
            AccountMeta::new_readonly(ctx.accounts.system_program.key(), false),
        ];

        let transfer_discriminator: [u8; 8] = [163, 52, 200, 231, 140, 3, 69, 186];

        let mut data: Vec<u8> = vec![];
        data.extend(transfer_discriminator);
        data.extend(root);
        data.extend(data_hash);
        data.extend(creator_hash);
        data.extend(nonce.to_le_bytes());
        data.extend(index.to_le_bytes());

        let mut account_infos: Vec<AccountInfo> = vec![
            ctx.accounts.tree_authority.to_account_info(),
            ctx.accounts.stake_entry.to_account_info(),
            ctx.accounts.stake_entry.to_account_info(),
            ctx.accounts.payer.to_account_info(),
            ctx.accounts.merkle_tree.to_account_info(),
            ctx.accounts.log_wrapper.to_account_info(),
            ctx.accounts.compression_program.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ];

        // add "accounts" (hashes) that make up the merkle proof
        for acc in ctx.remaining_accounts.iter() {
            accounts.push(AccountMeta::new_readonly(acc.key(), false));
            account_infos.push(acc.to_account_info());
        }

        msg!("manual cpi call");
        solana_program::program::invoke_signed(
            &solana_program::instruction::Instruction {
                program_id: ctx.accounts.bubblegum_program.key(),
                accounts,
                data,
            },
            &account_infos[..],
            &[&user_seeds
                .iter()
                .map(|s| s.as_slice())
                .collect::<Vec<&[u8]>>()],
        )?;

        Ok(())
    }

}

#[derive(Clone)]
pub struct MplBubblegum;

impl anchor_lang::Id for MplBubblegum {
    fn id() -> Pubkey {
        mpl_bubblegum::programs::MPL_BUBBLEGUM_ID
    }
}

#[derive(Clone)]
pub struct SplAccountCompression;

impl anchor_lang::Id for SplAccountCompression {
    fn id() -> Pubkey {
        mpl_bubblegum::programs::SPL_ACCOUNT_COMPRESSION_ID
    }
}

#[derive(Clone)]
pub struct Noop;

impl anchor_lang::Id for Noop {
    fn id() -> Pubkey {
        mpl_bubblegum::programs::SPL_NOOP_ID
    }
}

#[derive(Accounts)]
#[instruction(ix : InitPoolIx)]
pub struct InitPool<'info> {
    #[account(
        init, 
        payer=payer,
        space = 1024,
        seeds = [STAKE_POOL_PREFIX.as_bytes(), ix.identifier.as_ref()],
        bump)]
    pub stake_pool: Box<Account<'info, Pool>>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(ix: UpdatePoolIx)]
pub struct UpdatePoolCtx<'info> {
    #[account(mut, constraint = stake_pool.authority == authority.key() @ errors::ErrorCode::InvalidAdmin)]
    stake_pool: Account<'info, Pool>,
    authority: Signer<'info>,

    #[account(mut)]
    payer: Signer<'info>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitEntryCtx<'info> {
    #[account(
        init,
        payer = payer,
        space = 124,
        seeds = [STAKE_ENTRY_PREFIX.as_bytes(), stake_pool.key().as_ref(),stake_mint.key().as_ref()],
        bump,
    )]
    stake_entry: Box<Account<'info, StakeEntry>>,
    #[account(mut)]
    stake_pool: Box<Account<'info, Pool>>,

    stake_mint: UncheckedAccount<'info>,
    #[account(mut)]
    payer: Signer<'info>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StakeCnftCtx<'info> {
    #[account(mut, constraint = stake_entry.pool == stake_pool.key() @ errors::ErrorCode::InvalidStakePool)]
    stake_pool: Box<Account<'info, Pool>>,
    #[account(mut, seeds = [STAKE_ENTRY_PREFIX.as_bytes(), stake_entry.pool.as_ref(), stake_entry.stake_mint.as_ref()], bump=stake_entry.bump)]
    stake_entry: Box<Account<'info, StakeEntry>>,
    stake_mint: UncheckedAccount<'info>,

    #[account(mut)]
    pub leaf_owner: Signer<'info>,

    #[account(mut)]
    pub leaf_delegate: Signer<'info>,

    /// CHECK:
    #[account(
       mut,
       seeds = [merkle_tree.key().as_ref()],
       bump,
       seeds::program = bubblegum_program.key()
   )]
    pub tree_authority: UncheckedAccount<'info>,

    /// CHECK:
    #[account(mut)]
    pub merkle_tree: UncheckedAccount<'info>,

    /// CHECK:
    #[account(mut)]
    pub new_leaf_owner: UncheckedAccount<'info>,

    pub log_wrapper: Program<'info, Noop>,
    pub compression_program: Program<'info, SplAccountCompression>,
    pub bubblegum_program: Program<'info, MplBubblegum>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnStakeCnftCtx<'info> {
    #[account(mut, constraint = stake_entry.pool == stake_pool.key() @ errors::ErrorCode::InvalidStakePool)]
    stake_pool: Box<Account<'info, Pool>>,
    #[account(mut, seeds = [STAKE_ENTRY_PREFIX.as_bytes(), stake_entry.pool.as_ref(),  stake_entry.stake_mint.as_ref()], bump=stake_entry.bump)]
    stake_entry: Box<Account<'info, StakeEntry>>,

    stake_mint: UncheckedAccount<'info>,
    #[account(mut)]
    pool_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    user_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK:
    #[account(
       mut,
       seeds = [merkle_tree.key().as_ref()],
       bump,
       seeds::program = bubblegum_program.key()
   )]
    pub tree_authority: UncheckedAccount<'info>,

    /// CHECK:
    #[account(mut)]
    pub merkle_tree: UncheckedAccount<'info>,

    pub log_wrapper: Program<'info, Noop>,
    pub compression_program: Program<'info, SplAccountCompression>,
    pub bubblegum_program: Program<'info, MplBubblegum>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Pool {
    pub bump: u8,                  // --> 1
    pub allowed_creators: Pubkey,  //  --> 32
    pub min_stake_seconds: u32,    //  --> 8
    pub authority: Pubkey,         // --->  32
    pub total_staked_entries: u32, // -->  4
    pub identifier: String,
    pub token_address: Pubkey,
    pub reward_amount: u32,
    pub reward_seconds: u32,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct InitPoolIx {
    allowed_creators: Pubkey,
    min_stake_seconds: u32,
    identifier: String,
    token_address: Pubkey,
    reward_amount: u32,
    reward_seconds: u32,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct UpdatePoolIx {
    min_stake_seconds: u32,
}

#[account]
pub struct StakeEntry {
    pub bump: u8,
    pub pool: Pubkey,
    pub amount: u64,
    pub stake_mint: Pubkey,
    pub last_staker: Pubkey,
    pub last_staked_at: i64,
}

pub fn mint_is_allowed(
    stake_pool: &Account<Pool>,
    stake_mint_metadata: &AccountInfo,
    stake_mint: Pubkey,
) -> Result<()> {
    // assert_derivation(
    //     &mpl_token_metadata::ID,
    //     &stake_mint_metadata.to_account_info(),
    //     &[
    //         "metadata".to_string().as_bytes(),
    //         mpl_token_metadata::ID.as_ref(),
    //         stake_mint.as_ref(),
    //     ],
    //     error!(errors::ErrorCode::InvalidMintMetadataOwner),
    // )?;
    let mut allowed = false;

    if !stake_mint_metadata.data_is_empty() {
        let mint_metadata_data = stake_mint_metadata
            .try_borrow_mut_data()
            .expect("Failed to borrow data");
        if stake_mint_metadata.to_account_info().owner.key() != mpl_token_metadata::ID {
            return Err(error!(errors::ErrorCode::InvalidMintMetadataOwner));
        }
        let stake_mint_metadata = Metadata::deserialize(&mut mint_metadata_data.as_ref())
            .expect("Failed to deserialize metadata");
        if stake_mint_metadata.mint != stake_mint.key() {
            return Err(error!(errors::ErrorCode::InvalidMintMetadata));
        }

        if stake_mint_metadata.creators.is_some() {
            let creators = stake_mint_metadata.creators.unwrap();
            let find = creators
                .iter()
                .find(|c| stake_pool.allowed_creators == c.address);
            if find.is_some() {
                allowed = true
            };
        }
    }

    if !allowed {
        return Err(error!(errors::ErrorCode::MintNotAllowedInPool));
    }
    Ok(())
}

#[inline]
pub fn wallet_seeds(user: &Pubkey, expected_key: &Pubkey) -> Result<Vec<Vec<u8>>> {
    let mut seeds = vec![
        STAKE_ENTRY_PREFIX.as_bytes().as_ref().to_vec(),
        user.as_ref().to_vec(),
        expected_key.as_ref().to_vec(),
    ];
    let (key, bump) = Pubkey::find_program_address(
        &seeds.iter().map(|s| s.as_slice()).collect::<Vec<&[u8]>>(),
        &crate::id(),
    );
    seeds.push(vec![bump]);
    Ok(seeds)
}
