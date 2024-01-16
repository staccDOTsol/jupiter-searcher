
mod cli_args;
use anchor_client::Client;
use anchor_client::anchor_lang::{system_program, ToAccountMetas, InstructionData};
use clap::Parser;
use cli_args::CliArgs;
use marginfi::state::marginfi_account::{MarginfiAccount};
use marginfi::state::marginfi_group::{Bank, BankVaultType};
use marginfi::utils::find_bank_vault_authority_pda;
use reqwest::header::HeaderMap;
use serde_json::json;
use solana_client::rpc_filter::{RpcFilterType, Memcmp};
use solana_program::address_lookup_table_account::AddressLookupTableAccount;
use solana_program::instruction::{AccountMeta, InstructionError};
use solana_program::slot_hashes::{SlotHashes, MAX_ENTRIES};
use solana_program::slot_history::Slot;
use solana_sdk::commitment_config::CommitmentLevel;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_sdk::signature::Signature;
use std::borrow::Cow;

use std::mem::size_of;
use std::{str::FromStr};
use rand::{seq::SliceRandom};
use rand::Rng;
use solana_client::nonblocking::rpc_client::RpcClient;

use solana_program::message::{VersionedMessage, v0};
use serde::{Serialize, Deserialize};

use solana_sdk::{pubkey::Pubkey,
    instruction::Instruction,
    signer::{keypair::read_keypair_file, Signer, keypair::Keypair},
    transaction::{ VersionedTransaction}, commitment_config::CommitmentConfig, account::Account,
};


use std::{sync::Arc};
use spl_associated_token_account::{get_associated_token_address_with_program_id};

// create type of hashmap!{String => Instruction}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HashedAccount{

    pub is_signer: bool,
    pub is_writable: bool,
    pub pubkey: String,
}
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HashedIx{
    pub program_id: String,
    pub accounts: Vec<HashedAccount>,
    pub data: String
}
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SwapInstructions{
    //"swapInstruction\":{\"programId\":\"JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4\",\"accounts\":[{\"
    pub token_ledger_instruction: Option<HashedIx>,
    pub setup_instructions:Option<Vec<HashedIx>>,
    pub swap_instruction: HashedIx,
    pub cleanup_instruction: Option<HashedIx>,
    pub address_lookup_table_addresses: Vec<String>
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiquidityTokenJson {
    pub mint: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub logo: String,
    pub volume24h: String
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReserveConfigJson {
    pub liquidity_token: LiquidityTokenJson,
    pub pyth_oracle: String,
    pub switchboard_oracle: String,
    pub address: String,
    pub collateral_mint_address: String,
    pub collateral_supply_address: String,
    pub liquidity_address: String,
    pub liquidity_fee_receiver_address: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MarketConfigJson {
    pub name: String,
    pub is_primary: bool,
    pub description: String,
    pub creator: String,
    pub address: String,
    pub hidden: bool,
    pub is_permissionless: bool,
    pub authority_address: String,
    pub owner: String,
    pub reserves: Vec<ReserveConfigJson>,
    pub lookup_table_address: Option<String>
}
fn deserialize_instruction (instruction: HashedIx) -> Instruction {
    let mut accounts = instruction.accounts.clone();
    for i in 0..accounts.len() {
        accounts[i].pubkey = Pubkey::from_str(&accounts[i].pubkey).unwrap().to_string();
    }
    let data = base64::decode(&instruction.data).unwrap();
    let program_id = Pubkey::from_str(&instruction.program_id).unwrap();
    let instruction = Instruction {
        program_id,
        accounts: accounts.iter().map(|account| {
            solana_sdk::instruction::AccountMeta {
                pubkey: Pubkey::from_str(&account.pubkey).unwrap(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect::<Vec<solana_sdk::instruction::AccountMeta>>(),
        data,
    };
    instruction
}
async fn get_address_lookup_table_accounts(client: &RpcClient, keys: Vec<String>, payer: Pubkey) -> Vec<AddressLookupTableAccount> {
    let keys = &keys.iter().
    map(|key| {
        Pubkey::from_str(key).unwrap()
    })
    .collect::<Vec<Pubkey>>();
    let mut luts: Vec<AddressLookupTableAccount> = Vec::new();
    // do in chunks of 100
    let  keys = keys.clone();
    let  chunks= keys.chunks(100);
    
    for chunk in chunks {
            let raw_accounts = client.get_multiple_accounts(chunk).await.unwrap();

            for i in 0..raw_accounts.len() {
                if raw_accounts[i].is_some() {
                    let raw_account = raw_accounts[i].as_ref().unwrap();

                    let address_lookup_table = AddressLookupTable::deserialize(&raw_account.data).unwrap();

                    if address_lookup_table.meta.authority.unwrap() == payer {
                        let address_lookup_table_account = AddressLookupTableAccount {
                            key: chunk[i],
                            addresses: address_lookup_table.addresses.to_vec(),
                        };
                        luts.push(address_lookup_table_account);
                    }
                    
                }
            }
        }
    
    luts 
}
// from https://github.com/solana-labs/solana/blob/10d677a0927b2ca450b784f750477f05ff6afffe/sdk/program/src/message/versions/v0/mod.rs#L1269
async fn create_tx_with_address_table_lookup(
    client: &RpcClient,
    instructions: &[Instruction],
    luts: &[AddressLookupTableAccount],
    payer: &Keypair,
) -> VersionedTransaction {

    let blockhash = client.get_latest_blockhash().await.unwrap();
    VersionedTransaction::try_new(
        VersionedMessage::V0(v0::Message::try_compile(
            &payer.pubkey(),
            instructions,
            luts,
            blockhash,
        ).unwrap()),
        &[payer],
    ).unwrap()
}

pub async fn load_observation_account_metas(
    include_banks: Vec<(Pubkey, Bank)>,
    account: (Pubkey, MarginfiAccount),
) -> Vec<AccountMeta> {
    let marginfi_account = account.1;
    let mut bank_pks = marginfi_account
        .lending_account
        .balances
        .iter()
        .filter_map(|balance| {
            if balance.active {
                Some(balance.bank_pk)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for bank_pk in include_banks.clone() {
        if !bank_pks.contains(&bank_pk.0) {
            bank_pks.push(bank_pk.0);
        }
    }
//    bank_pks.retain(|bank_pk| !exclude_banks.contains(bank_pk));

    let mut banks = vec![];
    for bank_pk in bank_pks.clone() {
        for bank in include_banks.clone() {
            if bank.0 == bank_pk {
                banks.push(bank.1);
            }
        }
    }

    let account_metas = banks
        .iter()
        .zip(bank_pks.iter())
        .flat_map(|(bank, bank_pk)| {
            vec![
                AccountMeta {
                    pubkey: *bank_pk,
                    is_signer: false,
                    is_writable: false,
                },
                AccountMeta {
                    pubkey: bank.config.oracle_keys[0],
                    is_signer: false,
                    is_writable: false,
                },
            ]
        })
        .collect::<Vec<_>>();
    account_metas
}

pub async fn make_bank_borrow_ix(
    funding_account: Pubkey,
    bank: &(Pubkey, Bank),
    marginfi_account: &(Pubkey, MarginfiAccount),
    destination_account: Pubkey,
    amount: u64
) -> Instruction {
    let mut ix = Instruction {
        program_id: marginfi::id(),
        accounts: marginfi::accounts::LendingAccountBorrow {
            marginfi_group: marginfi_account.clone().1.group,
            marginfi_account: marginfi_account.clone().0,
            signer: funding_account ,
            bank: bank.0,
            destination_token_account: destination_account,
            bank_liquidity_vault: bank.clone().1.liquidity_vault,
            bank_liquidity_vault_authority: find_bank_vault_authority_pda(
                &bank.clone().0,
                BankVaultType::Liquidity,
            )
            .0,
            token_program: spl_token::ID,
        }
        .to_account_metas(Some(true)),
        data: marginfi::instruction::LendingAccountBorrow {
            amount
        }
        .data(),
    };
    ix.accounts.extend_from_slice(
        &load_observation_account_metas(vec![*bank], marginfi_account.clone())
            .await,
    );

    ix
}

pub async fn make_bank_deposit_ix(
    funding_account: Pubkey,
    funding_account_ata: Pubkey,
    bank: &(Pubkey, Bank),
    marginfi_account: &(Pubkey, MarginfiAccount),
    amount: u64
) -> Instruction {

    Instruction {
        program_id: marginfi::id(),
        accounts: marginfi::accounts::LendingAccountDeposit {
            marginfi_group: marginfi_account.clone().1.group,
            marginfi_account: marginfi_account.clone().0,
            signer: funding_account.clone(),
            bank: bank.clone().0,
            signer_token_account: funding_account_ata,
            bank_liquidity_vault: bank.clone().1.liquidity_vault,
            token_program: spl_token::ID,
        }
        .to_account_metas(Some(true)),
        data: marginfi::instruction::LendingAccountDeposit {
            amount
        }
        .data(),
    }
}
async fn doit(input: String, output: String, banks: &Vec<(Pubkey, Bank)>    
    , payer_wallet: &Arc<Keypair>,
    rpc_client: &Arc<RpcClient>, triton: &Arc<RpcClient>,
amount: u64,
mut lutties: Vec<AddressLookupTableAccount>, account: (Pubkey, MarginfiAccount)

)  {
    let pona = Keypair::from_base58_string("KkWmJYBZ5JEzMEhwfjdB7xgSMLCF1PiZwrte6T3PAUtEMnMfbYfaAWoa3PVo35f6eDqUqadx1K3Cpx268D71TxM");

        let input_mint = Pubkey::from_str(&input).unwrap();
        let pda = payer_wallet.pubkey();
        let input_bank = banks.iter().find(|bank| bank.1.mint == input_mint);
        if input_bank.is_none() {
            return;
        }
        let input_bank = input_bank.unwrap();
        let input_decimals = input_bank.1.mint_decimals;
        let amount = amount * 10u64.pow(input_decimals as u32);
       // let out_ata = get_associated_token_address_with_program_id(&pda, &output_mint, &token_program_output_mint);

       

        let mut ixs: Vec<Instruction> = Vec::new();
        /*
        let url = "http://127.0.0.1:8080/quote?slippageBps=9999&asLegacyTransaction=false&inputMint="
        .to_owned()
        +&USDC.to_string()+"&outputMint="
        +&input+"&amount=10000";
    
        let quote= (&reqwest::get(url.clone()).await.unwrap().text().await.unwrap());
        let quote = serde_json::from_str::<serde_json::Value>(&quote).unwrap();
        let output_amount: String = quote["outAmount"].to_string();
        let output_amount = ((output_amount[1..output_amount.len()-1].parse::<u64>().unwrap_or_default()) ) as f64;
        if output_amount == 0.0 {
            return;
        }
        let value = output_amount as f64;
         let amount = (amount as f64 * value) as u64;
 */
        // get an initial quote of 1 usdc to input
let max_accounts = std::env::var("MAX_ACCOUNTS").unwrap().parse::<u64>().unwrap();
let url = "http://127.0.0.1:8080/quote?slippageBps=9999&swapMode=ExactIn&asLegacyTransaction=false&inputMint="
.to_owned()
+&input+"&outputMint="
+&output+"&amount=" + &amount.to_string() + "&maxAccounts=" + &max_accounts.to_string();
    let quote= &reqwest::get(url.clone()).await.unwrap().text().await.unwrap();
    let quote = serde_json::from_str::<serde_json::Value>(quote).unwrap();
    let input_amount = quote["inAmount"].to_string();
    let output_amount: String = quote["outAmount"].to_string();
    let input_amount = input_amount[1..input_amount.len()-1].parse::<u64>().unwrap_or_default();
    let output_amount = ((output_amount[1..output_amount.len()-1].parse::<u64>().unwrap_or_default())) as u64;
    if output_amount == 0 || output_amount > u64::MAX - 1 {
        return;
    }
    let reverse_url = "http://127.0.0.1:8080/quote?asLegacyTransaction=false&slippageBps=9999&swapMode=ExactIn&inputMint=".to_owned()+&output+"&outputMint="+&input+"&amount=" + output_amount.to_string().as_str() + "&maxAccounts=" + &max_accounts.to_string();
    let reverse_quote=  &reqwest::get(reverse_url.clone()).await.unwrap().text().await.unwrap();

    let reverse_quote = serde_json::from_str::<serde_json::Value>(reverse_quote).unwrap();
    let reverse_output_amount:String = reverse_quote["outAmount"].to_string();
    let reverse_output_amount = reverse_output_amount[1..reverse_output_amount.len()-1].parse::<u64>().unwrap_or_default();
    println!("reverse quote: {:?}", reverse_output_amount as f64 / input_amount as f64);
    if reverse_output_amount as f64 > input_amount as f64 {
        let token_program_input_mint = rpc_client.get_account(&input_mint).await.unwrap().owner;
        

        let ata = get_associated_token_address_with_program_id(&pda, &input_mint, &token_program_input_mint);
        let ata_account_info = rpc_client.get_account(&ata).await;

        // if no ata, create it
        if ata_account_info.is_err() {
            let ix = spl_associated_token_account::instruction::create_associated_token_account(
                &payer_wallet.pubkey(),
                &payer_wallet.pubkey(),
                &input_mint,
                &token_program_input_mint
            );

            let tx = create_tx_with_address_table_lookup(
                rpc_client,
                &[ix],
                &[],
                payer_wallet).await;
                
                let signature = rpc_client
                    .send_transaction_with_config(
                        &tx,
                        solana_client::rpc_config::RpcSendTransactionConfig {
                            skip_preflight: false,max_retries: Some(10),
                            preflight_commitment: Some(CommitmentLevel::Confirmed),
                            ..solana_client::rpc_config::RpcSendTransactionConfig::default()
                        }, 
                    ).await
                    ;
                    if signature.is_ok() {
                    }
                    else {
                        println!("error: {:?}", signature.err().unwrap());
                    }
        }
        println!("Arb: {} {} {} {}", input_amount, reverse_output_amount, output, input);
        
        let wsol = banks.iter().find(|bank| bank.1.mint.to_string() == "So11111111111111111111111111111111111111112");
        let bonk = banks.iter().find(|bank| bank.1.mint.to_string() == "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263");
        let usdc = banks.iter().find(|bank| bank.1.mint.to_string() == "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        let bank = input_bank;
        
        let wsol = wsol.unwrap();
        let bonk = bonk.unwrap();
        let usdc = usdc.unwrap();
            //let out_ata = get_associated_token_address_with_program_id(&pda, &output_mint, &token_program_output_mint);
                let reqclient = reqwest::Client::new();
            let request_body: reqwest::Body = reqwest::Body::from(serde_json::json!({
                "quoteResponse": quote,
                "userPublicKey": pda.to_string(),
                "restrictIntermediateTokens": true,
                "useSharedAccounts": false,
                "useTokenLedger": false,
                "asLegacyTransaction": false,
                "wrapAndUnwrapSol": false
            }).to_string());
            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", "application/json".parse().unwrap());
            headers.insert("Accept", "application/json".parse().unwrap());
            let swap_transaction = reqclient.post("http://127.0.0.1:8080/swap-instructions")
            .body(request_body
            ).
            headers(headers
            ).

            send().await.unwrap().text().await.unwrap();
            // replace instances of / with nothing
            let swap_transaction = swap_transaction.replace('\\', "");
            let swap_transaction = serde_json::from_str::<SwapInstructions>(&swap_transaction).unwrap();
            
            let maybe_setup_ixs: Vec<Instruction>;

            if swap_transaction.setup_instructions.is_some() {
                 maybe_setup_ixs = swap_transaction.setup_instructions.clone().unwrap().iter().map(|instruction| {
                    deserialize_instruction(instruction.clone())
                }).collect::<Vec<Instruction>>();
            } else {
                 maybe_setup_ixs = vec![];
            }
            
        if !maybe_setup_ixs.is_empty() {
            let tx = create_tx_with_address_table_lookup(
                rpc_client,
                &maybe_setup_ixs,
                &[],
                payer_wallet).await;            
                let signature = rpc_client
                    .send_transaction_with_config(
                        &tx,
                        solana_client::rpc_config::RpcSendTransactionConfig {
                            skip_preflight: false,max_retries: Some(10),
                            preflight_commitment: Some(CommitmentLevel::Confirmed),
                            ..solana_client::rpc_config::RpcSendTransactionConfig::default()
                        }, 
                    ).await;
                    println!("https://solscan.io/tx/{}", signature.unwrap());
        }/*

        if maybe_cleanup_ix.is_some() {
                let maybe_cleanup_ix = deserialize_instruction(maybe_cleanup_ix.unwrap());
            if maybe_cleanup_ix.accounts.len() > 0 {
                swap_transaction_ixs.push(maybe_cleanup_ix);
            } 
        }
    */
            // reverse lol

            let request_body: reqwest::Body = reqwest::Body::from(serde_json::json!({
                "quoteResponse": reverse_quote,
                "userPublicKey": pda.to_string(),
                "restrictIntermediateTokens": true,
                "useSharedAccounts": false,
                "useTokenLedger": false,
                "asLegacyTransaction": false,
                "wrapAndUnwrapSol": false
            }).to_string());
            let swap_transaction_reverse = serde_json::from_str::<SwapInstructions>(&reqclient.post("http://127.0.0.1:8080/swap-instructions")
            .body(request_body
            ).send().await.unwrap().text().await.unwrap()).unwrap();


            
        println!("ata {:?}", ata);
        for ix in [deserialize_instruction(swap_transaction.swap_instruction.clone()),
        deserialize_instruction(swap_transaction_reverse.swap_instruction.clone())] {


        ixs.push(ix);

    }
    /*
                *token_lending_info.key,
                liquidity_amount,
                borrow_instruction_index,
                *source_liquidity_info.key,
                *destination_liquidity_info.key,
                *reserve_liquidity_fee_receiver_info.key,
                *host_fee_receiver_info.key,
                *reserve_info.key,
                *lending_market_info.key,
                *user_transfer_authority_info.key, */
    let mut balance_ata = 0;
    let bata = &rpc_client.get_token_account_balance(&ata).await;
  
    if !bata.is_err() {
        balance_ata =  u64::from_str(&bata.as_ref().unwrap().amount).unwrap();
    }
    let destination_ata = get_associated_token_address_with_program_id(
        &Pubkey::from_str("CaXvt6DsYGZevj7AmVd5FFYboyd8vLAEioPaQ7qbydMb").unwrap(),
        &input_mint,
        &token_program_input_mint
    );
    
let mut transfer_ixs = vec![];
let destination_ata_info = rpc_client.get_account(&destination_ata).await;
if destination_ata_info.is_err() {
    let ix = spl_associated_token_account::instruction::create_associated_token_account(
        &payer_wallet.pubkey(),
        &payer_wallet.pubkey(),
        &input_mint,
        &token_program_input_mint
    );
    ixs.push(ix);
}
let transfer_ix = spl_token::instruction::transfer(
    &spl_token::id(),
    &ata,
    &destination_ata,
    &pda,
    &[
    ],
    balance_ata,
).unwrap();
ixs.push(transfer_ix);

                     let tx = create_tx_with_address_table_lookup(
                    rpc_client,
                    &transfer_ixs,
                    &lutties,
                    payer_wallet).await;
                    let tx_size = bincode::serialize(&tx.clone()).unwrap().len();
                println!("tx size, probably: {:?}", tx_size);
                let signature = rpc_client
                .send_transaction(
                    &tx,
                ).await;
    let recent_fees = calculate_recent_fee().await;
        println!("recent fees: {:?}", recent_fees);

            let mut  needed_keys = ixs.
            iter()
            .flat_map(|ix| ix.accounts.iter().map(|acc| 
                acc.pubkey.to_string()
                )
                .collect::<Vec<String>>())
            .collect::<Vec<String>>();
        let mut missing_keys = Vec::new();

        let mut lutties_public_keys = lutties.
        iter()
        .flat_map(|lut| {
            lut.addresses.clone()
        })
        .collect::<Vec<Pubkey>>();

        lutties_public_keys.sort();
        lutties_public_keys.dedup();
        needed_keys.sort();
        needed_keys.dedup();
        for key in needed_keys.clone() {
            if !lutties_public_keys.contains(&Pubkey::from_str(&key).unwrap()) {
                missing_keys.push(key);
            }
        }
        println!("missing keys: {:?}", missing_keys.clone().len());
        // find the top 4 luts with the most needed keys
        let mut usized_lutties = lutties. 
        iter()
        .map(|lut| {
            let mut num_keys = 0;
            for key in &needed_keys.clone() {
                if lut.addresses.contains(&Pubkey::from_str(key).unwrap()) {
                    num_keys += 1;
                }
            }
            (lut.clone(), num_keys)
        })
        .collect::<Vec<(AddressLookupTableAccount, usize)>>()
        .iter().filter(|&lut| lut.1 > 2).cloned()
        .collect::<Vec<(AddressLookupTableAccount, usize)>>();
    usized_lutties.sort_by(|a, b| a.1.cmp(&b.1));
    usized_lutties.reverse();
    usized_lutties.truncate(9);
    lutties = usized_lutties.iter().map(|lut| lut.0.clone()).collect::<Vec<AddressLookupTableAccount>>();
        if missing_keys.len() > 3 {
        let mut new_lutties = create_and_or_extend_luts(
            &missing_keys.iter().map(|key| Pubkey::from_str(key).unwrap()).collect::<Vec<Pubkey>>(),
            rpc_client,
            &mut lutties,
            &pona,
        ).await.unwrap();
        lutties.append(&mut new_lutties);
    }
            
        println!("lutties: {:?}", lutties.len());
        // find needed_keys that are missing from lutties
        

            
            if !swap_transaction.address_lookup_table_addresses.is_empty() {
                println!("swap transaction address lookup table addresses: {:?}", swap_transaction.address_lookup_table_addresses.len());
                for lut in swap_transaction.address_lookup_table_addresses.clone() {
                    let lut = Pubkey::from_str(&lut).unwrap();
                    let account = rpc_client.get_account(&lut).await.unwrap();
                    let account = AddressLookupTable::deserialize(&account.data).unwrap();
                    let lookup_table_address_account = AddressLookupTableAccount {
                        key: lut,
                        addresses: account.addresses.to_vec(),
                    };
                    lutties.push(lookup_table_address_account);
                }
            }
            if !swap_transaction_reverse.address_lookup_table_addresses.is_empty() {
                println!("reverse swap transaction address lookup table addresses: {:?}", swap_transaction_reverse.address_lookup_table_addresses.len());
                for lut in swap_transaction_reverse.address_lookup_table_addresses.clone() {
                    let lut = Pubkey::from_str(&lut).unwrap();
                    let account = rpc_client.get_account(&lut).await.unwrap();
                    let account = AddressLookupTable::deserialize(&account.data).unwrap();
                    let lookup_table_address_account = AddressLookupTableAccount {
                        key: lut,
                        addresses: account.addresses.to_vec(),
                    };
                    lutties.push(lookup_table_address_account);
                }
            }
            let borrow_ix: Instruction  = make_bank_borrow_ix(
                payer_wallet.pubkey(),
                &bank,
                &account,
                ata,
                input_amount as u64
            ).await;
        ixs.insert(0, borrow_ix);
       ixs.insert(0, Instruction {
        program_id: marginfi::id(),
        accounts: marginfi::accounts::LendingAccountStartFlashloan {
            marginfi_account: account.0,
            signer: payer_wallet.clone().pubkey(),
            ixs_sysvar: solana_sdk::sysvar::instructions::id(),
        }
        .to_account_metas(Some(true)),
        data: marginfi::instruction::LendingAccountStartFlashloan { end_index: 6_u64 }.data(),
    });

    let priority_fee_ix = ComputeBudgetInstruction::set_compute_unit_price(
        recent_fees );
                ixs.insert(
                    0, priority_fee_ix
                );
                let mut account_metas = marginfi::accounts::LendingAccountEndFlashloan {
                    marginfi_account: account.0,
                     signer: payer_wallet.clone().pubkey(),
                }
                .to_account_metas(Some(true));
                account_metas.extend(
                    load_observation_account_metas(vec![*wsol, *usdc, *bonk], account)
                        .await,
                );
                ixs.push(make_bank_deposit_ix(
                    payer_wallet.clone().pubkey(),
                    ata.clone(),
                    &bank,
                    &account,
                    input_amount as u64
                ).await);
                ixs.push(Instruction {
                    program_id: marginfi::id(),
                    accounts: account_metas,
                    data: marginfi::instruction::LendingAccountEndFlashloan {}.data(),
                });
                let destination_ata = get_associated_token_address_with_program_id(
                    &Pubkey::from_str("CaXvt6DsYGZevj7AmVd5FFYboyd8vLAEioPaQ7qbydMb").unwrap(),
                    &input_mint,
                    &token_program_input_mint
                );
                
                let destination_ata_info = rpc_client.get_account(&destination_ata).await;
                let mut ata_balance = 0;
if destination_ata_info.is_err() {
    let ix = spl_associated_token_account::instruction::create_associated_token_account(
        &payer_wallet.pubkey(),
        &payer_wallet.pubkey(),
        &input_mint,
        &token_program_input_mint
    );
    ixs.push(ix);
}
else {
    ata_balance = u64::from_str(&rpc_client.get_token_account_balance(&destination_ata).await.unwrap().amount).unwrap();
}
let transfer_ix = spl_token::instruction::transfer(
    &spl_token::id(),
    &ata,
    &destination_ata,
    &pda,
    &[
    ],
    ata_balance,
).unwrap();
ixs.push(transfer_ix);
    

        let tx = create_tx_with_address_table_lookup(
                rpc_client,
                &ixs,
                &lutties,
                payer_wallet).await;
                let tx_size = bincode::serialize(&tx.clone()).unwrap().len();
            println!("tx size, probably: {:?}", tx_size);
            let signature = rpc_client
            .send_transaction_with_config(
                &tx,
                solana_client::rpc_config::RpcSendTransactionConfig {
                    skip_preflight: true,
                    max_retries: Some(10),
                    preflight_commitment: Some(CommitmentLevel::Confirmed),
                    ..solana_client::rpc_config::RpcSendTransactionConfig::default()
                }, 
            ).await
            ;
println!("https://solscan.io/tx/{}", signature.unwrap());
let ata_balance = rpc_client.get_token_account_balance(&ata).await.unwrap().amount.parse::<u64>().unwrap();
let destination_ata = get_associated_token_address_with_program_id(
    &Pubkey::from_str("CaXvt6DsYGZevj7AmVd5FFYboyd8vLAEioPaQ7qbydMb").unwrap(),
    &input_mint,
    &token_program_input_mint
);    
    }
                        
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum ProgramInstruction {
    /// Create an address lookup table
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized address lookup table account
    ///   1. `[SIGNER]` Account used to derive and control the new address lookup table.
    ///   2. `[SIGNER, WRITE]` Account that will fund the new address lookup table.
    ///   3. `[]` System program for CPI.
    CreateLookupTable {
        /// A recent slot must be used in the derivation path
        /// for each initialized table. When closing table accounts,
        /// the initialization slot must no longer be "recent" to prevent
        /// address tables from being recreated with reordered or
        /// otherwise malicious addresses.
        recent_slot: Slot,
        /// Address tables are always initialized at program-derived
        /// addresses using the funding address, recent blockhash, and
        /// the user-passed `bump_seed`.
        bump_seed: u8,
    },

    /// Permanently freeze an address lookup table, making it immutable.
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to freeze
    ///   1. `[SIGNER]` Current authority
    FreezeLookupTable,

    /// Extend an address lookup table with new addresses. Funding account and
    /// system program account references are only required if the lookup table
    /// account requires additional lamports to cover the rent-exempt balance
    /// after being extended.
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to extend
    ///   1. `[SIGNER]` Current authority
    ///   2. `[SIGNER, WRITE, OPTIONAL]` Account that will fund the table reallocation
    ///   3. `[OPTIONAL]` System program for CPI.
    ExtendLookupTable { new_addresses: Vec<Pubkey> },

    /// Deactivate an address lookup table, making it unusable and
    /// eligible for closure after a short period of time.
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to deactivate
    ///   1. `[SIGNER]` Current authority
    DeactivateLookupTable,

    /// Close an address lookup table account
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to close
    ///   1. `[SIGNER]` Current authority
    ///   2. `[WRITE]` Recipient of closed account lamports
    CloseLookupTable,
}

/// Derives the address of an address table account from a wallet address and a recent block's slot.
pub fn derive_lookup_table_address(
    authority_address: &Pubkey,
    recent_block_slot: Slot,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[authority_address.as_ref(), &recent_block_slot.to_le_bytes()],
        &Pubkey::from_str("AddressLookupTab1e1111111111111111111111111").unwrap(),
    )
}

/// Constructs an instruction which extends an address lookup
/// table account with new addresses.
pub fn extend_lookup_table(
    lookup_table_address: Pubkey,
    authority_address: Pubkey,
    payer_address: Option<Pubkey>,
    new_addresses: Vec<Pubkey>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(lookup_table_address, false),
        AccountMeta::new_readonly(authority_address, true),
    ];

    if let Some(payer_address) = payer_address {
        accounts.extend([
            AccountMeta::new(payer_address, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ]);
    }

    Instruction::new_with_bincode(
        Pubkey::from_str("AddressLookupTab1e1111111111111111111111111").unwrap(),
        &ProgramInstruction::ExtendLookupTable { new_addresses },
        accounts,
    )
}


/// Constructs an instruction to create a table account and returns
/// the instruction and the table account's derived address.
fn create_lookup_table_common(
    authority_address: Pubkey,
    payer_address: Pubkey,
    recent_slot: Slot,
) -> (Instruction, Pubkey) {
    let (lookup_table_address, bump_seed) =
        derive_lookup_table_address(&authority_address, recent_slot);
    let instruction = Instruction::new_with_bincode(
        
        Pubkey::from_str("AddressLookupTab1e1111111111111111111111111").unwrap(),
        &ProgramInstruction::CreateLookupTable {
            recent_slot,
            bump_seed,
        },
        vec![
            AccountMeta::new(lookup_table_address, false),
            AccountMeta::new_readonly(authority_address, true),
            AccountMeta::new(payer_address, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
    );

    (instruction, lookup_table_address)
}


async fn create_and_or_extend_luts(
    remaining_public_keys: &Vec<Pubkey>,
    rpc_client: &RpcClient,
    luts: &mut Vec<AddressLookupTableAccount>,
    payer: &Keypair,
) -> Result<Vec<AddressLookupTableAccount>, Box<dyn std::error::Error>> {
    let mut used_luts = Vec::new();
    let mut tx = Signature::default();
    for pubkeys in remaining_public_keys.chunks(25) {
        let (lut, _index) = find_or_create_lut(rpc_client, payer, luts, remaining_public_keys.len()).await?;
            let extend_ix = extend_lookup_table(
                lut.key,
                payer.pubkey(),
                Some(payer.pubkey()),
                pubkeys.to_vec(),
            );
            let latest_blockhash = rpc_client.get_latest_blockhash().await.unwrap(); 

           tx = rpc_client
                .send_transaction(&VersionedTransaction::try_new(
                        VersionedMessage::V0(v0::Message::try_compile(
                            &payer.pubkey(),
                            &[ComputeBudgetInstruction::set_compute_unit_price(
                                666420 ), extend_ix],
                            &[],
                            latest_blockhash,
                        ).unwrap()),
                        &[payer],
                    ).unwrap()
                ).await.unwrap();

                    
            used_luts.push(lut);
        }
        if (tx != Signature::default()) {
            rpc_client
            .confirm_transaction_with_spinner(
                &tx,
                &rpc_client.get_latest_blockhash().await.unwrap(),
                CommitmentConfig::confirmed(),
            ).await
            .unwrap();
        }


    Ok(used_luts)
}
async fn find_or_create_lut(
    rpc_client:  &RpcClient,
    payer: &Keypair,
    luts: &mut Vec<AddressLookupTableAccount>,
    howmany: usize
) -> Result<(AddressLookupTableAccount, usize), Box<dyn std::error::Error>> {
    luts.shuffle(&mut rand::thread_rng());
    for (index, lut) in luts.iter().enumerate() {
        let acc = rpc_client.get_account(&lut.key).await.unwrap();
        let address_lookup_table = AddressLookupTable::deserialize(&acc.data).unwrap();
        println!("{}, {}", lut.addresses.len(), address_lookup_table.meta.authority.unwrap() == payer.pubkey());
        if lut.addresses.len() < (210_usize -howmany) && address_lookup_table.meta.authority.unwrap() == payer.pubkey() {
            return Ok((lut.clone(), index));
        }
    }
    Ok((create_new_lut(rpc_client, payer).await.unwrap(), luts.len()))
}

#[cfg(not(target_os = "solana"))]
use solana_program::message::AddressLoaderError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AddressLookupError {
   /// Attempted to lookup addresses from a table that does not exist
   #[error("Attempted to lookup addresses from a table that does not exist")]
   LookupTableAccountNotFound,

   /// Attempted to lookup addresses from an account owned by the wrong program
   #[error("Attempted to lookup addresses from an account owned by the wrong program")]
   InvalidAccountOwner,

   /// Attempted to lookup addresses from an invalid account
   #[error("Attempted to lookup addresses from an invalid account")]
   InvalidAccountData,

   /// Address lookup contains an invalid index
   #[error("Address lookup contains an invalid index")]
   InvalidLookupIndex,
}

#[cfg(not(target_os = "solana"))]
impl From<AddressLookupError> for AddressLoaderError {
   fn from(err: AddressLookupError) -> Self {
       match err {
           AddressLookupError::LookupTableAccountNotFound => Self::LookupTableAccountNotFound,
           AddressLookupError::InvalidAccountOwner => Self::InvalidAccountOwner,
           AddressLookupError::InvalidAccountData => Self::InvalidAccountData,
           AddressLookupError::InvalidLookupIndex => Self::InvalidLookupIndex,
       }
   }
}
/// The maximum number of addresses that a lookup table can hold
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

/// The serialized size of lookup table metadata
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// Activation status of a lookup table
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LookupTableStatus {
    Activated,
    Deactivating { remaining_blocks: usize },
    Deactivated,
}


/// Address lookup table metadata
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct LookupTableMeta {
    /// Lookup tables cannot be closed until the deactivation slot is
    /// no longer "recent" (not accessible in the `SlotHashes` sysvar).
    pub deactivation_slot: Slot,
    /// The slot that the table was last extended. Address tables may
    /// only be used to lookup addresses that were extended before
    /// the current bank's slot.
    pub last_extended_slot: Slot,
    /// The start index where the table was last extended from during
    /// the `last_extended_slot`.
    pub last_extended_slot_start_index: u8,
    /// Authority address which must sign for each modification.
    pub authority: Option<Pubkey>,
    // Padding to keep addresses 8-byte aligned
    pub _padding: u16,
    // Raw list of addresses follows this serialized structure in
    // the account's data, starting from `LOOKUP_TABLE_META_SIZE`.
}

impl Default for LookupTableMeta {
    fn default() -> Self {
        Self {
            deactivation_slot: Slot::MAX,
            last_extended_slot: 0,
            last_extended_slot_start_index: 0,
            authority: None,
            _padding: 0,
        }
    }
}

impl LookupTableMeta {
    pub fn new(authority: Pubkey) -> Self {
        LookupTableMeta {
            authority: Some(authority),
            ..LookupTableMeta::default()
        }
    }

    /// Returns whether the table is considered active for address lookups
    pub fn is_active(&self, current_slot: Slot, slot_hashes: &SlotHashes) -> bool {
        match self.status(current_slot, slot_hashes) {
            LookupTableStatus::Activated => true,
            LookupTableStatus::Deactivating { .. } => true,
            LookupTableStatus::Deactivated => false,
        }
    }

    /// Return the current status of the lookup table
    pub fn status(&self, current_slot: Slot, slot_hashes: &SlotHashes) -> LookupTableStatus {
        if self.deactivation_slot == Slot::MAX {
            LookupTableStatus::Activated
        } else if self.deactivation_slot == current_slot {
            LookupTableStatus::Deactivating {
                remaining_blocks: MAX_ENTRIES.saturating_add(1),
            }
        } else if let Some(slot_hash_position) = slot_hashes.position(&self.deactivation_slot) {
            // Deactivation requires a cool-down period to give in-flight transactions
            // enough time to land and to remove indeterminism caused by transactions loading
            // addresses in the same slot when a table is closed. The cool-down period is
            // equivalent to the amount of time it takes for a slot to be removed from the
            // slot hash list.
            //
            // By using the slot hash to enforce the cool-down, there is a side effect
            // of not allowing lookup tables to be recreated at the same derived address
            // because tables must be created at an address derived from a recent slot.
            LookupTableStatus::Deactivating {
                remaining_blocks: MAX_ENTRIES.saturating_sub(slot_hash_position),
            }
        } else {
            LookupTableStatus::Deactivated
        }
    }
}
/// Program account states
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ProgramState {
    /// Account is not initialized.
    Uninitialized,
    /// Initialized `LookupTable` account.
    LookupTable(LookupTableMeta),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddressLookupTable<'a> {
    pub meta: LookupTableMeta,
    pub addresses: Cow<'a, [Pubkey]>,
}

impl<'a> AddressLookupTable<'a> {
    /// Serialize an address table's updated meta data and zero
    /// any leftover bytes.
    pub fn overwrite_meta_data(
        data: &mut [u8],
        lookup_table_meta: LookupTableMeta,
    ) -> Result<(), InstructionError> {
        let meta_data = data
            .get_mut(0..LOOKUP_TABLE_META_SIZE)
            .ok_or(InstructionError::InvalidAccountData)?;
        meta_data.fill(0);
        bincode::serialize_into(meta_data, &ProgramState::LookupTable(lookup_table_meta))
            .map_err(|_| InstructionError::GenericError)?;
        Ok(())
    }

    /// Get the length of addresses that are active for lookups
    pub fn get_active_addresses_len(
        &self,
        current_slot: Slot,
        slot_hashes: &SlotHashes,
    ) -> Result<usize, AddressLookupError> {
        if !self.meta.is_active(current_slot, slot_hashes) {
            // Once a lookup table is no longer active, it can be closed
            // at any point, so returning a specific error for deactivated
            // lookup tables could result in a race condition.
            return Err(AddressLookupError::LookupTableAccountNotFound);
        }

        // If the address table was extended in the same slot in which it is used
        // to lookup addresses for another transaction, the recently extended
        // addresses are not considered active and won't be accessible.
        let active_addresses_len = if current_slot > self.meta.last_extended_slot {
            self.addresses.len()
        } else {
            self.meta.last_extended_slot_start_index as usize
        };

        Ok(active_addresses_len)
    }

    /// Lookup addresses for provided table indexes. Since lookups are performed on
    /// tables which are not read-locked, this implementation needs to be careful
    /// about resolving addresses consistently.
    pub fn lookup(
        &self,
        current_slot: Slot,
        indexes: &[u8],
        slot_hashes: &SlotHashes,
    ) -> Result<Vec<Pubkey>, AddressLookupError> {
        let active_addresses_len = self.get_active_addresses_len(current_slot, slot_hashes)?;
        let active_addresses = &self.addresses[0..active_addresses_len];
        indexes
            .iter()
            .map(|idx| active_addresses.get(*idx as usize).cloned())
            .collect::<Option<_>>()
            .ok_or(AddressLookupError::InvalidLookupIndex)
    }

    /// Serialize an address table including its addresses
    pub fn serialize_for_tests(self) -> Result<Vec<u8>, InstructionError> {
        let mut data = vec![0; LOOKUP_TABLE_META_SIZE];
        Self::overwrite_meta_data(&mut data, self.meta)?;
        self.addresses.iter().for_each(|address| {
            data.extend_from_slice(address.as_ref());
        });
        Ok(data)
    }

    /// Efficiently deserialize an address table without allocating
    /// for stored addresses.
    pub fn deserialize(data: &'a [u8]) -> Result<AddressLookupTable<'a>, InstructionError> {
        let program_state: ProgramState =
            bincode::deserialize(data).map_err(|_| InstructionError::InvalidAccountData)?;

        let meta = match program_state {
            ProgramState::LookupTable(meta) => Ok(meta),
            ProgramState::Uninitialized => Err(InstructionError::UninitializedAccount),
        }?;

        let raw_addresses_data = data.get(LOOKUP_TABLE_META_SIZE..).ok_or({
            // Should be impossible because table accounts must
            // always be LOOKUP_TABLE_META_SIZE in length
            InstructionError::InvalidAccountData
        })?;
        let addresses: &[Pubkey] = bytemuck::try_cast_slice(raw_addresses_data).map_err(|_| {
            // Should be impossible because raw address data
            // should be aligned and sized in multiples of 32 bytes
            InstructionError::InvalidAccountData
        })?;

        Ok(Self {
            meta,
            addresses: Cow::Borrowed(addresses),
        })
    }
}


async fn create_new_lut(
    rpc_client: &RpcClient,
    payer: &Keypair,
) -> Result<AddressLookupTableAccount, Box<dyn std::error::Error>> {
    // Create a new AddressLookupTable
    let recent_slot = rpc_client
    .get_slot_with_commitment(CommitmentConfig::confirmed()).await
    .unwrap()//"237009123 is not a recent slot"
    - 138;
    let (create_ix, table_pk) =
    create_lookup_table_common(
            payer.pubkey(),
            payer.pubkey(),
            recent_slot,
        );
    let latest_blockhash = rpc_client.get_latest_blockhash().await.unwrap();  
    
    let tx = rpc_client
    .send_transaction(&VersionedTransaction::try_new(
            VersionedMessage::V0(v0::Message::try_compile(
                &payer.pubkey(),
                &[ComputeBudgetInstruction::set_compute_unit_price(
                    666420 ), create_ix],
                &[],
                latest_blockhash,
            ).unwrap()),
            &[payer],
        ).unwrap()
    ).await.unwrap();
    rpc_client
            .confirm_transaction_with_spinner(
                &tx,
                &rpc_client.get_latest_blockhash().await.unwrap(),
                CommitmentConfig::confirmed(),
            ).await
            .unwrap();

    let lut = AddressLookupTableAccount {
        key: table_pk,
        addresses: vec![],
    };


    let file = std::fs::read("./src/luts.json").unwrap();
    let string = String::from_utf8(file).unwrap();
        let mut lutties: Vec<String> = serde_json::from_str(&string).unwrap();
        println !("lutties: {:?}", lutties.len());
// dedupe
        lutties.sort();
        lutties.dedup();
        println !("lutties: {:?}", lutties.len());
    // write new lut to lutties to file
    lutties.push(lut.key.to_string());
    println !("lutties+1: {:?}", lutties.len());
    save_luts_to_file(&lutties).unwrap();
    
    Ok(lut)

}
use std::fs;

fn save_luts_to_file(lutties: &Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    // write to lut.json 
    let mut lutties = lutties.clone();
    lutties.sort();
    lutties.dedup();
    let lutties = serde_json::to_string(&lutties).unwrap();
    fs::write("./src/luts.json", lutties).unwrap();
    
    Ok(())
}
pub async fn calculate_recent_fee(
) -> u64 {
let request = reqwest::Client::new()
                                                                            .post("https://jarrett-solana-7ba9.mainnet.rpcpool.com/8d890735-edf2-4a75-af84-92f7c9e31718")
.body(json!(
    {
        "jsonrpc": "2.0",
        "id": "1",
        "method": "getPriorityFeeEstimate",
        "params": 
    [{
        "accountKeys": ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"],
        "options": {
            "priority_level": "HIGH"
        }
    }]
}
).to_string())
.send().await.unwrap().text().await.unwrap();
let request = serde_json::from_str::<serde_json::Value>(&request).unwrap();
request["result"]["priorityFeeEstimate"].as_f64().unwrap_or(1200.0) as u64 * 10
}

#[tokio::main(worker_threads = 20)]
async fn get_top_tokens(luts: Vec<String>, client: Arc<RpcClient>, triton: Arc<RpcClient>, payer_wallet: Arc<Keypair>, banks: Vec<(Pubkey, Bank)>,account: (Pubkey, MarginfiAccount)) {
    let url = "https://cache.jup.ag/top-tokens";
    let top_tokens = serde_json::from_str::<Vec<String>>(&reqwest::get(url).await.unwrap().text().await.unwrap()).unwrap();
    let lutties = get_address_lookup_table_accounts(&triton, luts.clone(), Pubkey::from_str("PoNA1qzqHWar3g8Hy9cxA2Ubi3hV7q84dtXAxD77CSD").unwrap()).await;
    println!("lutties: {:?}", lutties.len());
    println!("top tokens: {:?}", top_tokens.len());
    let mut input_mints: Vec<String> = banks.iter().map(|bank| bank.1.mint.to_string()).collect();
    input_mints.sort();
    
// write to file
    let input_mints = ["DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "So11111111111111111111111111111111111111112"].iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let mut divdiv = 2.0;
    loop {
        let mut tasks = Vec::new();
        for _i in 0..MAX_THREADS {
            let random_mint_rng = rand::thread_rng().gen_range(0..input_mints.len());
            let mint = input_mints[random_mint_rng].clone();
          
            let payer_wallet = payer_wallet.clone();
            let client = client.clone();
            let triton = triton.clone();
            let handle = tokio::runtime::Handle::current();
            let slice = top_tokens.clone();

            let random_number_1e9_to_1e12: f64 = rand::thread_rng().gen_range(1e8..1e12);
            let div: f64 = rand::thread_rng().gen_range(1e1..1e6) * divdiv;
            divdiv *= 2.0;
            if random_number_1e9_to_1e12 / div < 1e1 {
                divdiv = 2.0;
                continue;
            }
            let random_number_1e9_to_1e12 = random_number_1e9_to_1e12 / div;

            let random_number_1e9_to_1e12 = random_number_1e9_to_1e12 as u64;
            let rng_slice = rand::thread_rng().gen_range(0..69);
            let lutties = lutties.clone();
            let banks = banks.clone();
            let account = account;
            let task = handle.spawn(async move  {
                
            
                // get the quote
                doit(mint.to_string(), slice[rng_slice as usize].to_string(), &banks, &payer_wallet, &client, &triton, random_number_1e9_to_1e12,  lutties.clone(), account).await
            });
        
            tasks.push(task);
        }
        
        let _results = futures::future::join_all(tasks).await;
    }

}
const MAX_THREADS: usize = 20;

 fn main() {
    let file = std::fs::read("./src/luts.json").unwrap();
    let string = String::from_utf8(file).unwrap();
        let mut lutties: Vec<String> = serde_json::from_str(&string).unwrap();
        println !("lutties: {:?}", lutties.len());
// dedupe
        lutties.sort();
        lutties.dedup();
        println !("lutties: {:?}", lutties.len());
    let args = CliArgs::parse();
    let payer_wallet = Arc::new(read_keypair_file(&*args.payer_keypair).unwrap());
    let client = Client::new(
        anchor_client::Cluster::Custom("https://jarrett-solana-7ba9.mainnet.rpcpool.com/8d890735-edf2-4a75-af84-92f7c9e31718".to_string(), "https://jarrett-solana-7ba9.mainnet.rpcpool.com/8d890735-edf2-4a75-af84-92f7c9e31718".to_string()),
        payer_wallet.clone()
    );

    let program = client.program(marginfi::id()).unwrap();

    let accounts = program.accounts::<MarginfiAccount>(vec![]).unwrap();
    let mut account  = accounts[0];
    for acc in accounts {
        if acc.0 == Pubkey::from_str("EW1iozTBrCgyd282g2eemSZ8v5xs7g529WFv4g69uuj2").unwrap() {
            account = acc;
            break;
        }
    }
    let banks = program.accounts::<Bank>(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
        8 + size_of::<Pubkey>() + size_of::<u8>(),
        account.1.group.to_bytes().to_vec(),
    ))]).unwrap();
    println!("Found {} banks", banks.len());
    println!("Bank 0 {:?}", banks[0]);
    
    let client = Arc::new(RpcClient::new_with_commitment("https://jarrett-solana-7ba9.mainnet.rpcpool.com/8d890735-edf2-4a75-af84-92f7c9e31718".to_string(), CommitmentConfig::confirmed()));
    let triton = Arc::new(
        RpcClient::new_with_commitment("https://jarrett-solana-7ba9.mainnet.rpcpool.com/8d890735-edf2-4a75-af84-92f7c9e31718".to_string(), CommitmentConfig::confirmed()));

        let mut luts = Vec::new();
        let mut lutties = lutties. 
        iter()
        .map(|x| Pubkey::from_str(x).unwrap())
        .collect::<Vec<Pubkey>>();
        lutties.sort();
        lutties.reverse();
        let lutties = lutties.clone();
        luts.extend(lutties
            .iter()
            .map(|addy| addy.to_string())
            .collect::<Vec<String>>());

    get_top_tokens(luts, client, triton, payer_wallet, banks, account);
    

    
}