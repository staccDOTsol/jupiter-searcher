use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::prelude::InterfaceAccount;

const AUTHORITY_SEED: &[u8] = b"jarezi_arb";
declare_id!("EkdhhKgVtPowVseBcuRZsS2FhAeupqLxZ54xYrQEdo7q");


mod jupiter {
    use anchor_lang::declare_id;
    declare_id!("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
}

#[derive(Clone)]
pub struct Jupiter;

impl anchor_lang::Id for Jupiter {
    fn id() -> Pubkey {
        jupiter::id()
    }
}
#[program]
pub mod jupiter_searcher {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        msg!("Initialize");
        let pda = &mut ctx.accounts.pda;
        pda.bump = bump;

        Ok(())
    }
    pub fn swap (ctx: Context<Swap>, bump: u8, data: Vec<u8>) -> Result<()> {
        msg!("Swap on Jupiter");
        let bump = &[bump];
        let jarezi_arber = &ctx.accounts.jarezi_arber.key();

        let signer_seeds: &[&[&[u8]]] = &[&[AUTHORITY_SEED, jarezi_arber.as_ref(), bump.as_ref()]];

        let jupiter_program = *ctx.accounts.jupiter_program.to_account_info().key;
        let remaining_accounts = ctx.remaining_accounts;
        let accounts: Vec<AccountMeta> = remaining_accounts
            .iter()
            .map(|acc| AccountMeta {
                pubkey: *acc.key,
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            })
            .collect();
    
        let accounts_infos: Vec<AccountInfo> = remaining_accounts
            .iter()
            .map(|acc| AccountInfo { ..acc.clone() })
            .collect();
    
        invoke_signed(
            &Instruction {
                program_id: jupiter_program,
                accounts,
                data,
            },
            &accounts_infos,
            signer_seeds
        )?;

        Ok(())
    
    }
}
#[account]
pub struct Pda {
    pub bump: u8,
}
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut,
        seeds = [AUTHORITY_SEED, jarezi_arber.key().as_ref()],
        bump)]

    pub pda: Account<'info, Pda>,
    /// CHECK: it's a system account, it seeds the other guy, checked in init
    #[account(mut,
         constraint = jarezi_arber.owner == system_program.key,
    )]
    pub jarezi_arber: AccountInfo<'info>,
    #[account(mut)]
    pub pda_wsol: Box<InterfaceAccount<'info, anchor_spl::token_interface::TokenAccount>>,
    #[account(mut)]
    pub wsol_mint: Box<InterfaceAccount<'info, anchor_spl::token_interface::Mint>>,    
    pub jupiter_program: Program<'info, Jupiter>,
    #[account(
        constraint = spl_token_program.key == &anchor_spl::token::ID || spl_token_program.key == &anchor_spl::token_2022::ID,
    )]
    /// CHECK: constrained to either spl program
    pub spl_token_program: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}
#[derive(Accounts)]
pub struct Initialize<'info>
{
    #[account(init,
        seeds = [AUTHORITY_SEED, jarezi_arber.key().as_ref()],
        bump,
        payer = jarezi_arber,
        space = 8+8)]

    pub pda: Account<'info, Pda>,
    #[account(mut)]
    pub jarezi_arber: Signer<'info>,
    pub jupiter_program: Program<'info, Jupiter>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

