
#[macro_use(c)]
extern crate cute;
use rand::{seq::SliceRandom, Rng};
use switchboard_solana::{*, anchor_spl::{token_interface::spl_token_2022::onchain, token}};
mod cli_args;
use reqwest::header::HeaderMap;
use solana_sdk::{commitment_config::CommitmentConfig, signature::read_keypair_file, account::Account};
use switchboard_solana::SbFunctionResult;
use solana_program::address_lookup_table::{AddressLookupTableAccount};
use solana_client::rpc_client::RpcClient;
use solana_program::message::{VersionedMessage, v0};
use serde::{Serialize, Deserialize};
use solana_sdk::{pubkey::Pubkey,
    instruction::Instruction,
    transaction::{ VersionedTransaction}, compute_budget, signature::{Keypair}, signer::Signer,
};

use std::{sync::Arc, str::FromStr};
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
fn get_address_lookup_table_accounts(client: &RpcClient, keys: Vec<String>) -> Vec<AddressLookupTableAccount> {
    let keys = &keys.iter().
    map(|key| {
        Pubkey::from_str(key).unwrap()
    })
    .collect::<Vec<Pubkey>>();
    let mut luts: Vec<AddressLookupTableAccount> = Vec::new();
    let raw_accounts = client.get_multiple_accounts(keys).unwrap();

    for i in 0..raw_accounts.len() {
        if raw_accounts[i].is_some() {
            let raw_account = raw_accounts[i].as_ref().unwrap();
            let address_lookup_table = solana_sdk::address_lookup_table::state::AddressLookupTable::deserialize(&raw_account.data).unwrap();
            let address_lookup_table_account = AddressLookupTableAccount {
                key: keys[i],
                addresses: address_lookup_table.addresses.to_vec(),
            };
            luts.push(address_lookup_table_account);
        }
    }
    luts 
}

// from https://github.com/solana-labs/solana/blob/10d677a0927b2ca450b784f750477f05ff6afffe/sdk/program/src/message/versions/v0/mod.rs#L209
async fn create_tx_with_address_table_lookup(
    client: &RpcClient,
    instructions: &[Instruction],
    luts: &[AddressLookupTableAccount],
    payer: &Arc<Keypair>
) -> VersionedTransaction {

    let blockhash = client.get_latest_blockhash().unwrap();
    VersionedTransaction::try_new(
        VersionedMessage::V0(v0::Message::try_compile(
            &payer.as_ref().pubkey()    ,
            instructions,
            &luts,
            blockhash,
        ).unwrap()),
        &[payer],
    ).unwrap()
}


#[switchboard_function]
pub async fn my_function_logic(
    runner: FunctionRunner,
    params: Vec<u8>,
) -> Result<SbFunctionResult, SbFunctionError> {

        let rpc_client = runner.clone().client;
        let mut luts: Vec<String> = Vec::new();

    let mut ixs: Vec<Instruction> = Vec::new();

    let future: Vec<String> = get_top_tokens().await;
   
    let future = &future[0..40];

         // take any two of the top 20
        let slice = future.choose_multiple(&mut rand::thread_rng(), 2).cloned().collect::<Vec<String>>();
        // make a threadpool of 40 of these
        let random_number_1e9_to_1e12 = rand::thread_rng().gen_range(1e9..1e12);
        let amount = random_number_1e9_to_1e12 as u64;
// sleep random 1-10 seconds
        let input = slice[0].clone();
        let output = slice[1].clone();
    let url = "https://quote-api.jup.ag/v6/quote?inputMint="
    .to_owned()
    +&input+"&outputMint="
    +&output+"&amount=" + &amount.to_string();
    let quote = serde_json::from_str::<serde_json::Value>(&reqwest::get(url.clone()).await.unwrap().text().await.unwrap()).unwrap();
    let input_amount = quote["inAmount"].to_string();
    let output_amount: String = quote["outAmount"].to_string();
    let input_amount = input_amount[1..input_amount.len()-1].parse::<u64>().unwrap_or_default();
    let output_amount = output_amount[1..output_amount.len()-1].parse::<u64>().unwrap_or_default();
    let reverse_url = "https://quote-api.jup.ag/v6/quote?inputMint=".to_owned()+&output+"&outputMint="+&input+"&amount=" + output_amount.to_string().as_str();
    let reverse_quote = serde_json::from_str::<serde_json::Value>(&reqwest::get(reverse_url.clone()).await.unwrap().text().await.unwrap()).unwrap();
    let reverse_output_amount:String = reverse_quote["outAmount"].to_string();
    let reverse_output_amount = reverse_output_amount[1..reverse_output_amount.len()-1].parse::<u64>().unwrap_or_default();
    let reverse_input_amount:String = reverse_quote["inAmount"].to_string();
    let reverse_input_amount = reverse_input_amount[1..reverse_input_amount.len()-1].parse::<u64>().unwrap_or_default();
    if reverse_output_amount > input_amount {
        let input_mint = Pubkey::from_str(&input).unwrap();
        let output_mint = Pubkey::from_str(&output).unwrap();
        let token_program_input_mint = rpc_client.get_account(&input_mint).unwrap().owner;
        let token_program_output_mint = rpc_client.get_account(&output_mint).unwrap().owner;
        let mut market_addr = Pubkey::default();
        println!("Arb: {} {} {} {}", input_amount, reverse_output_amount, output, input);
        let  configs = get_configs(None).await;
        let mut market_addrs = Vec::new();
        let mut market_luts = Vec::new();
        let reserves_maybe = 
        configs.iter()
            .map(|config| {
                
                config.reserves
                .iter()
                .map(|reserve| {
                    if reserve.liquidity_token.mint == input {
                        market_addr = Pubkey::from_str(&config.address).unwrap();
                        market_addrs.push(market_addr);
                        market_luts.push(config.lookup_table_address.clone());
                        Some(reserve)
                    } else {
                        None
                    }
                })
                .collect::<Vec<Option<&ReserveConfigJson>>>()
            })
            .collect::<Vec<Vec<Option<&ReserveConfigJson>>>>()
            .iter()
            .flatten()
            .flatten()
            .cloned()
            .collect::<Vec<&ReserveConfigJson>>();

            let mut index = 0;
        for reserve in reserves_maybe {
            market_addr = market_addrs[index as usize];
            index +=1;
                let mut borrow_ix_index = 1;

            let pda = Pubkey::find_program_address(
                &[b"jarezi_arb", Pubkey::from_str("PoNA1qzqHWar3g8Hy9cxA2Ubi3hV7q84dtXAxD77CSD").unwrap().as_ref()],
                &jupiter_searcher::ID
            ).0;
            let ata = get_associated_token_address_with_program_id(&pda, &input_mint, &token_program_input_mint);

            let out_ata = get_associated_token_address_with_program_id(&pda, &output_mint, &token_program_output_mint);

            if rpc_client.get_account(&ata).is_err() {
                println!("Creating ATA for mint {:?}", input_mint);
                
            }
                let reqclient = reqwest::Client::new();
            let request_body: reqwest::Body = reqwest::Body::from(serde_json::json!({
                "quoteResponse": quote,
                "userPublicKey": pda.to_string(),
            }).to_string());
            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", "application/json".parse().unwrap());
            headers.insert("Accept", "application/json".parse().unwrap());
            let mut swap_transaction = reqclient.post("https://quote-api.jup.ag/v6/swap-instructions")
            .body(request_body
            ).
            headers(headers
            ).

            send().await.unwrap().text().await.unwrap();
            // replace instances of / with nothing
            let swap_transaction = swap_transaction.replace("\\", "");
            let swap_transaction = serde_json::from_str::<SwapInstructions>(&swap_transaction).unwrap();
            let swap_args: jupiter_amm_interface::SwapParams = jupiter_amm_interface::SwapParams {
                in_amount: input_amount,
                out_amount: output_amount,
                source_mint: input_mint,
                destination_mint: output_mint,
                source_token_account: ata,
                destination_token_account: out_ata,
                token_transfer_authority: pda,
                open_order_address: None,
                quote_mint_to_referrer: None,
                jupiter_program_id: &Pubkey::from_str("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4").unwrap()
            };
            luts = swap_transaction.address_lookup_table_addresses.clone();
            let maybe_setup_ixs: Vec<Instruction>;

            if swap_transaction.setup_instructions.is_some() {
                 maybe_setup_ixs = swap_transaction.setup_instructions.clone().unwrap().iter().map(|instruction| {
                    deserialize_instruction(instruction.clone())
                }).collect::<Vec<Instruction>>();
            } else {
                 maybe_setup_ixs = vec![];
            }
            let mut maybe_cleanup_ix: Option<HashedIx> = swap_transaction.cleanup_instruction;
            
        let mut swap_transaction_ixs = vec![
            
        ];
        if maybe_setup_ixs.len() > 0 {
            for maybe_setup_ix in maybe_setup_ixs.clone() {
            borrow_ix_index += 1;
            swap_transaction_ixs.insert(0,
                    maybe_setup_ix);
            }
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
                "quoteResponse": quote,
                "userPublicKey": pda.to_string(),
            }).to_string());
            let swap_transaction_reverse = serde_json::from_str::<SwapInstructions>(&reqclient.post("https://quote-api.jup.ag/v6/swap-instructions")
            .body(request_body
            ).send().await.unwrap().text().await.unwrap()).unwrap();
            let swap_args_reverse: jupiter_amm_interface::SwapParams = jupiter_amm_interface::SwapParams {
                in_amount: reverse_output_amount,
                out_amount: reverse_output_amount,
                source_mint: output_mint,
                destination_mint: input_mint,
                source_token_account: out_ata,
                destination_token_account: ata,
                token_transfer_authority: pda,
                open_order_address: None,
                quote_mint_to_referrer: None,
                jupiter_program_id: &Pubkey::from_str("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4").unwrap()
            };
            luts.extend( swap_transaction_reverse.address_lookup_table_addresses.clone());
            if market_luts[(index-1) as usize].is_some() {
                luts.push(market_luts[(index-1) as usize].clone().unwrap());
            }
            luts.extend((
                &[
                "GPWttHd9ddXSK9xPX3E2NLgyKRXTzH9TUhykq4XTp3UU",
                "BcGR4NsLPwsX1pFjKTrVprracwiJdRY5rAgpoQSfEpi2",
                "75PdmiD6WpdeW4dyXxVvLB6h1TbgaXib9YzYRXPHWUKk",
                "8HKWV5EHwg2pY7QnQATyXUHMSoRustXEyEqa5JvuRf89",
                "4ZCWXLRcAhaNJxDRBfpe9iM8nozPNHUGJyRAJGQNYUWr",
                "DWJWV2QMjFPxYh6za3B8esAs3BsFtfBmk18oRC1SMhqt"])
                .iter()
                .map(|addy| addy.to_string())
                .collect::<Vec<String>>());

            
            let maybe_cleanup_ix: Option<HashedIx> = swap_transaction_reverse.cleanup_instruction;
        

    ixs.push(solend_sdk::instruction::flash_borrow_reserve_liquidity(
        solend_sdk::solend_mainnet::ID,
        input_amount,
        Pubkey::from_str(&reserve.liquidity_address).unwrap(),
        ata,
        Pubkey::from_str(&reserve.address).unwrap(),
        market_addr
    ));
    let mut index = 0;
        for ix in vec![deserialize_instruction(swap_transaction.swap_instruction.clone()),
        deserialize_instruction(swap_transaction_reverse.swap_instruction.clone())] {


            let mut accounts = vec![
                AccountMeta {
                    pubkey: pda,
                    is_signer: false,
                    is_writable: true,
                },
                AccountMeta {
                    pubkey: Pubkey::from_str("PoNA1qzqHWar3g8Hy9cxA2Ubi3hV7q84dtXAxD77CSD").unwrap(),
                    is_signer: false, 
                    is_writable: true
                },
                AccountMeta {
                    pubkey: match index {
                        0 => ata,
                        1 => out_ata,
                        _ => Pubkey::default()
                    },
                    is_signer: false,
                    is_writable: true,
                },
                AccountMeta {
                    pubkey: match index {
                        0 => input_mint,
                        1 => output_mint,
                        _ => Pubkey::default()
                    },
                    is_signer: false,
                    is_writable: true,
                },
                AccountMeta {
                    pubkey: Pubkey::from_str("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4").unwrap(),
                    is_signer: false,
                    is_writable: false,
                },
                AccountMeta {
                    pubkey: match index {
                        0 => token_program_input_mint,
                        1 => token_program_output_mint,
                        _ => Pubkey::default()
                    },
                    is_signer: false,
                    is_writable: false,
                },
                AccountMeta {
                    pubkey: anchor_lang::system_program::ID,
                    is_signer: false,
                    is_writable: false,
                }];
                accounts.extend(ix.accounts.iter().map(|account| {
                    AccountMeta {
                        pubkey: account.pubkey,
                        is_signer: account.is_signer,
                        is_writable: account.is_writable,
                    }
                }).collect::<Vec<AccountMeta>>());
        let onchain_ix = Instruction {
            program_id : jupiter_searcher::ID,
            accounts,
                data: ix.data,
        };
        ixs.push(onchain_ix.clone());
        index+=1;

    }
            ixs.push(spl_token::instruction::transfer(
                &spl_token::id(),
                &ata,
                &ata,
                &pda,
                &[
                ],
                input_amount as u64,
            ).unwrap());

                     
    }
            
    } else {
        println!("{} {} {}", output, input, reverse_output_amount);
    }
    let recent_fees = calculate_recent_fee(ixs.
        iter()
        .map(|ix| ix.accounts.iter().map(|acc| 
            if acc.is_writable { acc.pubkey } else { Pubkey::default() })
            .collect::<Vec<Pubkey>>()
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<Pubkey>>()
            .iter()
            .filter(|pubkey| **pubkey != Pubkey::default())
            .cloned()
            .collect::<Vec<Pubkey>>())
        .flatten()
        .collect::<Vec<Pubkey>>().as_slice(),
        &rpc_client).await;
        let luts = get_address_lookup_table_accounts(
            &rpc_client, luts.clone());
    let sb_function_result: SbFunctionResult = SbFunctionResult {
        ixs,
        commitment: Some(CommitmentConfig::confirmed()),
        priority_fee: Some(recent_fees as u64),
        compute_limit: Some(1_400_000 as u32),
        address_lookup_table_accounts: Some(luts)
    };
    Ok(sb_function_result)
    }
pub async fn calculate_recent_fee(
    write_locked_accounts: &[Pubkey],
    rpc_client: &RpcClient
) -> u64 {
    println!("calculating recent fee");
    println!("write locked accounts: {:?}", write_locked_accounts.len());
    let account_infos = rpc_client.get_multiple_accounts_with_commitment(
        write_locked_accounts,
        CommitmentConfig::confirmed()
    ).unwrap().value;
    let mut index = 0;
    let write_locked_accounts = &account_infos
    .into_iter()
    .map(|account: Option<Account>| {
        index += 1;
        if account.is_some() {
            write_locked_accounts[index-1]
        }
        else {
            Pubkey::default()
        }
    })
    .collect::<Vec<Pubkey>>()
    .iter()
    .cloned()
    .collect::<std::collections::HashSet<Pubkey>>()
    .iter()
    .filter(|pubkey| **pubkey != Pubkey::default())
    .cloned()
    .collect::<Vec<Pubkey>>();
println!("write locked accounts that were resolved on this cluster: {:?}", write_locked_accounts.len());
        
    let recent_fees = rpc_client.get_recent_prioritization_fees(
        write_locked_accounts
    ).unwrap_or_default();
    recent_fees
    .iter()
    .map(|fee| fee.prioritization_fee)
    .filter(|fee| *fee != 0)
    .sum::<u64>()
    .checked_div(recent_fees.len() as u64).unwrap_or(138)
}
async fn get_top_tokens() -> Vec<String> {
    let url = "https://cache.jup.ag/top-tokens";
    let top_tokens = serde_json::from_str::<Vec<String>>(&reqwest::get(url).await.unwrap().text().await.unwrap()).unwrap();
    return top_tokens;
}

async fn get_configs(configs: Option<Vec<MarketConfigJson>>) -> Vec<MarketConfigJson> {
    if configs.is_some() {
        return configs.unwrap();
    }
    let file = std::fs::read("./src/configs.json").unwrap();
    let string = String::from_utf8(file).unwrap();
    let configs: Vec<MarketConfigJson> = serde_json::from_str(&string).unwrap();
    return configs;
}